#!/usr/bin/env python3
"""Read-only Yandex Disk backup. Token stays in process memory, never in logs.

python3 download.py --prompt-token
YANDEX_DISK_TOKEN may alternatively be supplied through the environment.
Official API: https://yandex.ru/dev/disk-api/doc/ru/reference/content
"""

import argparse
import concurrent.futures
import fcntl
import getpass
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request


API = "https://cloud-api.yandex.net/v1/disk"
PROGRESS = Path(__file__).with_name("progress.json")
INVENTORY_CACHE = Path(__file__).with_name("inventory-cache.json")
CACHE_MARKER = Path(__file__).with_name("use-inventory-cache")
CURL_MARKER = Path(__file__).with_name("use-curl-transport")
HTTP1_MARKER = Path(__file__).with_name("force-curl-http1")
IPV4_MARKER = Path(__file__).with_name("force-curl-ipv4")
RETRY_FAILED_MARKER = Path(__file__).with_name("retry-only-failed")
PROBE_MARKER = Path(__file__).with_name("probe-transport")
WORKERS_CONFIG = Path(__file__).with_name("workers.json")
RETRY_CODES = {408, 423, 429, 500, 502, 503, 504}


class BackupError(Exception):
    """Only deliberately safe messages may be passed to this exception."""


class FatalBackupError(BackupError):
    """A safety, authentication or local-storage failure stops the whole backup."""


class HTTPFailure(BackupError):
    def __init__(self, http_code):
        self.http_code = http_code
        super().__init__(f"File request returned HTTP {http_code}")


class CurlFailure(BackupError):
    def __init__(self, exit_code, http_code):
        self.exit_code, self.http_code = exit_code, http_code
        super().__init__(f"Curl transfer failed with exit code {exit_code}, HTTP {http_code or 0}")


def selected_workers(explicit=None, path=None):
    """CLI wins; otherwise use a bounded private configuration or eight workers."""
    if explicit is not None:
        if type(explicit) is not int or not 1 <= explicit <= 256:
            raise FatalBackupError("Workers must be an integer between 1 and 256")
        return explicit
    path = Path(path) if path is not None else WORKERS_CONFIG
    check_tree(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return 8
    except OSError:
        raise FatalBackupError("Workers configuration could not be opened safely") from None
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 4096):
                raise FatalBackupError("Workers configuration must be a small owned regular file with permissions 600")
            value = json.load(stream)
            after = os.fstat(stream.fileno())
            current = path.lstat()
            identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if identity(before) != identity(after) or identity(before) != identity(current):
                raise FatalBackupError("Workers configuration changed while being read")
    except (ValueError, UnicodeError, OSError):
        raise FatalBackupError("Workers configuration is unreadable or invalid") from None
    if not isinstance(value, dict) or set(value) != {"workers"}:
        raise FatalBackupError("Workers configuration must contain only a workers integer")
    if type(value["workers"]) is not int or not 1 <= value["workers"] <= 256:
        raise FatalBackupError("Workers must be an integer between 1 and 256")
    return selected_workers(value["workers"])


def curl_config_value(value):
    if not isinstance(value, str) or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise FatalBackupError("Unsafe control character in transfer configuration")
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def private_marker(path):
    check_tree(path)
    if not path.exists():
        return False
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise FatalBackupError("Run marker must be a private regular file owned by this user")
    return True


def selected_transport():
    return "curl" if private_marker(CURL_MARKER) else "urllib"


def selected_curl_profile():
    http1, ipv4 = private_marker(HTTP1_MARKER), private_marker(IPV4_MARKER)
    options = ("--http1.1",) if http1 else ()
    if ipv4:
        options += ("--ipv4",)
    profile = "http1_ipv4" if http1 and ipv4 else "http1" if http1 else "ipv4" if ipv4 else "default"
    return profile, options


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class MediaRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, on_redirect=None):
        super().__init__()
        self.on_redirect = on_redirect

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https":
            raise FatalBackupError("Download redirected to a non-HTTPS URL")
        if self.on_redirect:
            self.on_redirect(parsed.hostname or "")
        # Authorization is an unredirected header and is never forwarded.
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def atomic_json(path, value):
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


class DiskAPI:
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())
        self.rate_lock = threading.Lock()
        self.counter_lock = threading.Lock()
        self.next_request_at = 0.0
        self.api_requests_total = 0
        self.api_http_error_counts = {}

    def pace_request(self, _stop_event=None):
        # Do not accumulate permits during slow transfers or idle time.
        with self.rate_lock:
            if _stop_event is not None and _stop_event.is_set():
                raise BackupError("Directory scan stopped")
            delay = self.next_request_at - time.monotonic()
            if delay > 0:
                if _stop_event is None:
                    time.sleep(delay)
                elif _stop_event.wait(delay):
                    raise BackupError("Directory scan stopped")
            self.next_request_at = time.monotonic() + 0.05

    def request_snapshot(self):
        with self.counter_lock:
            return {"api_requests_total": self.api_requests_total,
                    "api_http_error_counts": dict(self.api_http_error_counts),
                    "api_http_429_count": self.api_http_error_counts.get("429", 0),
                    "api_rate_limit_rps": 20}

    def get(self, endpoint, _attempts=5, _timeout=60, _stop_event=None, **params):
        url = API + endpoint + ("?" + urllib.parse.urlencode(params) if params else "")
        for attempt in range(_attempts):
            request = urllib.request.Request(url, headers={"Accept": "application/json"})
            request.add_unredirected_header("Authorization", "OAuth " + self.token)
            try:
                if _stop_event is not None and _stop_event.is_set():
                    raise BackupError("Directory scan stopped")
                if _stop_event is None:
                    self.pace_request()
                else:
                    self.pace_request(_stop_event)
                if _stop_event is not None and _stop_event.is_set():
                    raise BackupError("Directory scan stopped")
                with self.counter_lock:
                    self.api_requests_total += 1
                with self.opener.open(request, timeout=_timeout) as response:
                    return json.load(response)
            except urllib.error.HTTPError as exc:
                code = exc.code
                exc.close()
                if type(code) is int and 100 <= code <= 599:
                    with self.counter_lock:
                        key = str(code)
                        self.api_http_error_counts[key] = self.api_http_error_counts.get(key, 0) + 1
                if code == 401:
                    raise FatalBackupError("API returned HTTP 401; check token and read permissions") from None
                if code not in RETRY_CODES:
                    raise HTTPFailure(code) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                pass
            if attempt + 1 < _attempts:
                delay = min(2 ** attempt, 16)
                if _stop_event is None:
                    time.sleep(delay)
                elif _stop_event.wait(delay):
                    raise BackupError("Directory scan stopped")
        raise BackupError("API unavailable after retry attempts")

    def file_inventory(self, progress=None):
        """List files globally before copying; keep paging until an empty page."""
        files, offset, pages, byte_count = [], 0, 0, 0
        while True:
            if progress:
                progress(file_list_offset=offset, listing_pages=pages,
                         files_discovered=len(files), bytes_discovered=byte_count)
            data = self.get("/resources/files", limit=200, offset=offset)
            items = data.get("items")
            if not isinstance(items, list):
                raise BackupError("Invalid flat file listing")
            pages += 1
            for item in items:
                if not isinstance(item, dict) or item.get("type", "file") != "file":
                    raise BackupError("Unsupported cloud resource type")
                resource = file_metadata(item)
                files.append(resource)
                byte_count += resource["size"]
            offset += len(items)
            if progress:
                progress(file_list_offset=offset, listing_pages=pages,
                         files_discovered=len(files), bytes_discovered=byte_count)
            if not items:
                break
        directories = set()
        for item in files:
            for parent in relative_path(item["path"]).parents:
                if parent != PurePosixPath("."):
                    directories.add("disk:/" + str(parent))
        return {"files": sorted(files, key=lambda item: item["path"]),
                "directories": sorted(directories)}

    def inventory(self, progress=None, workers=128):
        from parallel_inventory import parallel_inventory
        return parallel_inventory(self, sys.modules[__name__], progress, workers)


def relative_path(remote):
    if not isinstance(remote, str) or not remote.startswith("disk:/"):
        raise BackupError("Unexpected cloud path")
    value = remote[6:]
    if not value or "\x00" in value:
        raise BackupError("Unsafe cloud filename")
    parts = value.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise BackupError("Unsafe cloud path")
    return PurePosixPath(*parts)


def file_metadata(item):
    if not isinstance(item, dict):
        raise BackupError("Invalid cloud file metadata")
    relative_path(item.get("path", ""))
    if type(item.get("size")) is not int or item["size"] < 0:
        raise BackupError("A cloud file has no downloadable size metadata")
    md5 = item.get("md5")
    if md5 is not None and (not isinstance(md5, str) or
                            (md5 and (len(md5) != 32 or any(c not in "0123456789abcdefABCDEF" for c in md5)))):
        raise BackupError("Invalid cloud file checksum metadata")
    if "modified" in item and not isinstance(item["modified"], str):
        raise BackupError("Invalid cloud file modification metadata")
    resource = {key: item[key] for key in ("path", "size", "md5", "modified") if key in item}
    if md5:
        resource["md5"] = md5.lower()
    return resource


def canonical_inventory(raw):
    """Deduplicate identical file entries; an initial flat list remains provisional."""
    if not isinstance(raw, dict) or not isinstance(raw.get("files"), list) or not isinstance(raw.get("directories"), list):
        raise BackupError("Saved or received inventory has an invalid schema")
    files, duplicates = {}, 0
    for item in raw["files"]:
        resource = file_metadata(item)
        previous = files.get(resource["path"])
        if previous is not None:
            if resource != previous:
                raise BackupError("Duplicate cloud file paths have inconsistent metadata")
            duplicates += 1
        else:
            files[resource["path"]] = resource
    validate_paths(raw["directories"])
    directories = set(raw["directories"])
    for path in files:
        for parent in relative_path(path).parents:
            if parent != PurePosixPath("."):
                directories.add("disk:/" + str(parent))
    validate_paths(list(files) + list(directories))
    return {"files": sorted(files.values(), key=lambda item: item["path"]),
            "directories": sorted(directories), "duplicate_entries_count": duplicates}


def read_private_inventory(path):
    check_tree(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise BackupError("Inventory cache must be a private regular file owned by this user")
        return json.load(stream)


def validate_paths(paths):
    for path in paths:
        relative_path(path)
    if len(set(paths)) != len(paths):
        raise BackupError("Cloud listing contains an exact duplicate resource path")


def folded_name(name):
    return unicodedata.normalize("NFD", name).casefold()


def local_relative(value):
    if not isinstance(value, str) or value.startswith("/") or "\x00" in value:
        raise BackupError("Saved local path mapping is unsafe")
    parts = value.split("/")
    if any(part in ("", ".", "..") or len(part.encode("utf-8")) > 255 for part in parts):
        raise BackupError("Saved local path mapping is unsafe")
    return PurePosixPath(*parts)


def shorten_utf8(value, byte_limit):
    return value.encode("utf-8")[:byte_limit].decode("utf-8", errors="ignore")


class LocalPaths:
    """Persistent file and directory mappings in one safe sibling namespace."""

    def __init__(self, file_paths, directory_paths, existing=None, existing_directories=None):
        file_paths, directory_paths = list(file_paths), list(directory_paths)
        self.paths = dict(existing or {})
        self.directory_paths = dict(existing_directories or {})
        validate_paths(list(file_paths) + list(directory_paths))
        self.files = set(file_paths) | set(self.paths)
        self.directories = set(directory_paths) | set(self.directory_paths)
        self._allocate()

    def _allocate(self):
        for remote in self.files | self.directories:
            relative_path(remote)
        for remote in list(self.files | self.directories):
            for parent in relative_path(remote).parents:
                if parent != PurePosixPath("."):
                    self.directories.add("disk:/" + str(parent))
        children = {}
        for is_directory, remotes in ((False, self.files), (True, self.directories)):
            for remote in remotes:
                parent = str(relative_path(remote).parent)
                parent = "disk:/" + parent if parent != "." else "disk:/"
                children.setdefault(parent, []).append((remote, is_directory))
        parents = sorted(children, key=lambda remote: (remote.count("/"), remote))
        for parent in parents:
            parent_local = self.directory_paths[parent] if parent != "disk:/" else ""
            siblings = sorted(children[parent])
            original_names = {folded_name(relative_path(remote).name) for remote, _ in siblings}
            groups = {}
            for node in siblings:
                groups.setdefault(folded_name(relative_path(node[0]).name), []).append(node)
            occupied, new_nodes = set(), []
            for remote, is_directory in siblings:
                mapping = self.directory_paths if is_directory else self.paths
                if remote not in mapping:
                    new_nodes.append((remote, is_directory))
                    continue
                saved = local_relative(mapping[remote])
                if str(saved.parent) != (parent_local or "."):
                    raise BackupError("Saved local path mapping has inconsistent parents")
                folded = folded_name(saved.name)
                if folded in occupied:
                    raise BackupError("Saved local path mappings conflict")
                occupied.add(folded)
            for remote, is_directory in new_nodes:
                name = relative_path(remote).name
                key = folded_name(name)
                needs_suffix = len(groups[key]) > 1 or key in occupied or len(name.encode("utf-8")) > 255
                if needs_suffix:
                    name = self._suffixed_name(remote, is_directory, original_names | occupied)
                occupied.add(folded_name(name))
                mapping = self.directory_paths if is_directory else self.paths
                mapping[remote] = str(PurePosixPath(parent_local) / name)

    @staticmethod
    def _suffixed_name(remote, is_directory, occupied):
        original = relative_path(remote).name
        extension = "" if is_directory else PurePosixPath(original).suffix
        stem = original[:-len(extension)] if extension else original
        extension = shorten_utf8(extension, 64)
        digest = hashlib.sha256((('dir:' if is_directory else 'file:') + remote).encode("utf-8")).hexdigest()
        attempt = 0
        while True:
            length = min(8 + attempt * 4, len(digest))
            suffix = "~" + digest[:length]
            if length == len(digest) and attempt > 14:
                suffix += "-" + str(attempt - 14)
            stem_limit = 255 - len((suffix + extension).encode("utf-8"))
            name = shorten_utf8(stem, stem_limit) + suffix + extension
            if folded_name(name) not in occupied:
                return name
            attempt += 1

    def extend_directories(self, directories):
        validate_paths(list(directories))
        self.directories.update(directories)
        self._allocate()

    def local_path(self, remote, directory=False):
        mapping = self.directory_paths if directory else self.paths
        if remote not in mapping:
            raise BackupError("Resource has no local path mapping")
        return local_relative(mapping[remote])

    def manifest_fields(self):
        return {"local_paths": dict(sorted(self.paths.items())),
                "local_directory_paths": dict(sorted(self.directory_paths.items()))}

    def renamed_count(self):
        return sum(local_relative(local).name != relative_path(remote).name
                   for mapping in (self.paths, self.directory_paths) for remote, local in mapping.items())


def check_tree(path):
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise FatalBackupError("Destination contains a symbolic link")


def matches(path, item):
    return verified_file_snapshot(path, item) is not None


def verified_file_snapshot(path, item):
    """Hash one stable, no-follow inode and return the metadata actually verified."""
    from verified_journal import fingerprint
    check_tree(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        before = fingerprint(info)
        if not stat.S_ISREG(info.st_mode) or info.st_size != item["size"]:
            return None
        if item.get("md5"):
            digest = hashlib.md5()
            for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                digest.update(block)
            if digest.hexdigest() != item["md5"].lower():
                return None
        if fingerprint(os.fstat(stream.fileno())) != before:
            return None
    check_tree(path)
    try:
        return before if fingerprint(path.lstat()) == before else None
    except FileNotFoundError:
        return None


class Backup:
    def __init__(self, api, volume, destination):
        self.api, self.volume, self.destination = api, volume, destination
        self.device = volume.stat().st_dev
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.last_print = 0
        self.path_mapping = None
        self.transfers = {}
        self.transport = "urllib"
        self.transport_profile, self.curl_options = "default", ()
        self.retry_only_failed = False
        self.failed = {}
        self.failed_bytes = 0
        self.last_failure_save = 0
        self.journal = None
        self.state = {"phase": "listing", "files_verified": 0, "bytes_verified": 0,
                      "files_downloaded": 0, "destination": str(destination),
                      "cached_files_count": 0, "cached_bytes": 0, "hashed_existing_count": 0}

    def check_mount(self):
        if self.stop.is_set():
            raise FatalBackupError("Download stopped after another file failed")
        if not self.volume.is_mount() or self.volume.stat().st_dev != self.device:
            raise FatalBackupError("External disk disconnected or remounted")
        check_tree(self.destination)

    def progress(self, **changes):
        with self.lock:
            self._progress_locked(changes)

    def _progress_locked(self, changes):
        previous_phase = self.state["phase"]
        self.state.update(changes)
        snapshot = getattr(self.api, "request_snapshot", None)
        if callable(snapshot):
            self.state.update(snapshot())
        self.state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        atomic_json(PROGRESS, self.state)
        if self.state["phase"] != previous_phase or time.monotonic() - self.last_print >= 10:
            public_state = {key: value for key, value in self.state.items()
                            if key not in ("current_directory", "current_file")}
            print(json.dumps(public_state, ensure_ascii=False), flush=True)
            self.last_print = time.monotonic()

    def transfer_state(self, key, remove=False, **changes):
        """Publish only a hashed file identifier, stage and safe transport fields."""
        with self.lock:
            if remove:
                self.transfers.pop(key, None)
            else:
                transfer = self.transfers.setdefault(key, {})
                transfer.update(changes)
                transfer["last_update"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            self._progress_locked({"active_transfers": {identifier: dict(value)
                                                        for identifier, value in self.transfers.items()}})

    def local_path(self, remote, directory=False):
        if self.path_mapping is None:
            return relative_path(remote)
        return self.path_mapping.local_path(remote, directory)

    def local_matches(self, path, item):
        journal = getattr(self, "journal", None)
        if journal is None:
            return matches(path, item)
        local = str(self.local_path(item["path"]))
        if journal.hit(item["path"], item, local, path):
            with self.lock:
                self.state["cached_files_count"] += 1
                self.state["cached_bytes"] += item["size"]
            return True
        value = verified_file_snapshot(path, item)
        if value is None:
            return False
        if item.get("md5"):
            if not journal.record(item["path"], item, local, path, value):
                raise FatalBackupError("Verified local file changed or became unsafe before its checkpoint")
            with self.lock:
                self.state["hashed_existing_count"] += 1
        return True

    def saved_mapping(self):
        manifest_path = self.destination / "manifest.json"
        check_tree(manifest_path)
        if not manifest_path.exists():
            return {}, {}
        with manifest_path.open(encoding="utf-8") as stream:
            manifest = json.load(stream)
        if not isinstance(manifest, dict):
            raise BackupError("Saved backup manifest is invalid")
        files = manifest.get("local_paths")
        directories = manifest.get("local_directory_paths")
        if files is None and directories is None:
            files = {item["path"]: str(relative_path(item["path"])) for item in manifest.get("files", [])}
            directories = {path: str(relative_path(path)) for path in manifest.get("directories", [])}
        if not isinstance(files, dict) or not isinstance(directories, dict):
            raise BackupError("Saved backup path mapping is invalid")
        return files, directories

    def curl_download(self, href, output, transfer_key, host):
        config = ("url = " + curl_config_value(href) + "\nheader = " +
                  curl_config_value("Authorization: OAuth " + self.api.token) + "\n").encode("utf-8")
        arguments = ["/usr/bin/curl", "-q", "--config", "-", "--location", "--fail", "--silent",
                     "--globoff", "--proto", "=https", "--proto-redir", "=https",
                     "--connect-timeout", "10", "--speed-limit", "1024", "--speed-time", "15",
                     "--write-out", "%{stderr}%{http_code}", *self.curl_options]
        # Preserve configured networking, but never inherit the downloader's OAuth token.
        environment = {key: value for key, value in os.environ.items() if key != "YANDEX_DISK_TOKEN"}
        process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=output,
                                   stderr=subprocess.PIPE, env=environment)
        first, last_update = True, time.monotonic()
        try:
            self.transfer_state(transfer_key, stage="reading", host=host, transport="curl")
            while True:
                self.check_mount()
                try:
                    _, diagnostic = process.communicate(input=config if first else None, timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    first = False
                    if time.monotonic() - last_update >= 10:
                        self.transfer_state(transfer_key, bytes_written=os.fstat(output.fileno()).st_size)
                        last_update = time.monotonic()
            status = diagnostic.strip()
            http_code = int(status) if len(status) == 3 and all(48 <= byte <= 57 for byte in status) else None
            if http_code == 0:
                http_code = None
            if process.returncode != 0 or http_code is None or not 200 <= http_code < 300:
                raise CurlFailure(process.returncode, http_code)
            return os.fstat(output.fileno()).st_size
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            for pipe in (process.stdin, process.stderr):
                if pipe is not None:
                    pipe.close()

    def download(self, item):
        self.check_mount()
        target = self.destination / "data" / self.local_path(item["path"])
        check_tree(target)
        if self.local_matches(target, item):
            return False
        if target.exists():
            raise FatalBackupError("An existing local file differs; it was not overwritten")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        transfer_key = hashlib.sha256(item["path"].encode()).hexdigest()
        temporary = self.destination / ".partial" / transfer_key
        check_tree(temporary)
        opener = urllib.request.build_opener(MediaRedirect(
            lambda host: self.transfer_state(transfer_key, stage="opening", host=host)))
        for attempt in range(1):
            self.check_mount()
            self.transfer_state(transfer_key, stage="getting_link", host="cloud-api.yandex.net",
                                attempt=attempt + 1, bytes_written=0, error_type=None, http_code=None,
                                exit_code=None, transport=self.transport)
            link = self.api.get("/resources/download", _attempts=1, _timeout=15, path=item["path"])
            href = link.get("href", "")
            parsed = urllib.parse.urlsplit(href)
            host = parsed.hostname or ""
            trusted = any(host == d or host.endswith("." + d) for d in ("yandex.net", "yandex.ru", "yandex.com"))
            if parsed.scheme != "https" or not trusted or link.get("method") != "GET":
                raise FatalBackupError("Unexpected download endpoint")
            request = urllib.request.Request(href)
            request.add_unredirected_header("Authorization", "OAuth " + self.api.token)
            self.transfer_state(transfer_key, stage="opening", host=host)
            try:
                check_tree(temporary)
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as output:
                    if self.transport == "curl":
                        written = self.curl_download(href, output, transfer_key, host)
                    else:
                        with opener.open(request, timeout=15) as response:
                            self.transfer_state(transfer_key, stage="reading")
                            reader = getattr(response, "read1", None) or response.read
                            written, last_update = 0, time.monotonic()
                            for block in iter(lambda: reader(256 * 1024), b""):
                                self.check_mount()
                                output.write(block)
                                output.flush()
                                written += len(block)
                                if time.monotonic() - last_update >= 10:
                                    self.transfer_state(transfer_key, bytes_written=written)
                                    last_update = time.monotonic()
                    output.flush()
                    os.fsync(output.fileno())
                self.transfer_state(transfer_key, stage="verifying", bytes_written=written)
                verified = verified_file_snapshot(temporary, item)
                if verified is None:
                    raise BackupError("Downloaded file failed size/checksum verification")
                self.check_mount()
                # Atomic publish, with no overwrite of any pre-existing file.
                os.link(temporary, target)
                temporary.unlink()
                if self.journal is not None and item.get("md5"):
                    from verified_journal import snapshot
                    published = snapshot(target, sys.modules[__name__])
                    if published is None or published[:4] + published[5:] != verified[:4] + verified[5:]:
                        raise FatalBackupError("Published file changed before its verification checkpoint")
                    if not self.journal.record(item["path"], item, str(self.local_path(item["path"])),
                                               target, published):
                        raise FatalBackupError("Published file changed or became unsafe before its checkpoint")
                self.transfer_state(transfer_key, remove=True)
                return True
            except CurlFailure as exc:
                if exc.http_code == 401:
                    raise FatalBackupError("Download returned HTTP 401; authentication must be checked") from None
                if exc.exit_code in (1, 2, 3, 4, 23):
                    raise FatalBackupError(f"Curl configuration or local write failed with exit code {exc.exit_code}") from None
                self.transfer_state(transfer_key, stage="retrying", error_type="CurlFailure",
                                    http_code=exc.http_code, exit_code=exc.exit_code)
                raise
            except urllib.error.HTTPError as exc:
                code = exc.code
                exc.close()
                if code == 401:
                    raise FatalBackupError("Download returned HTTP 401; authentication must be checked") from None
                self.transfer_state(transfer_key, stage="retrying", error_type="HTTPError", http_code=code)
                raise HTTPFailure(code) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                self.transfer_state(transfer_key, stage="retrying", error_type=type(exc).__name__)
                raise

    def load_failures(self):
        path = self.destination / "failed-files.json"
        check_tree(path)
        self.failed = {}
        if path.exists():
            raw = read_private_inventory(path)
            saved = canonical_inventory(raw)
            records = {item["path"]: item for item in raw["files"]}
            for item in saved["files"]:
                record = dict(item, safe_reason="pending_retry", error_type="TransferFailure")
                previous = records[item["path"]]
                if previous.get("error_type") in ("CurlFailure", "HTTPFailure", "BackupError", "URLError", "TimeoutError",
                                                 "ConnectionError", "IncompleteRead", "RemoteDisconnected", "SSLError"):
                    record["error_type"] = previous["error_type"]
                if previous.get("safe_reason") == "transfer_unavailable":
                    record["safe_reason"] = "transfer_unavailable"
                for field in ("http_code", "curl_exit_code"):
                    if type(previous.get(field)) is int:
                        record[field] = previous[field]
                self.failed[item["path"]] = record
        elif self.retry_only_failed:
            raise FatalBackupError("Retry-only mode requires a saved failed-file queue")
        self.failed_bytes = sum(item["size"] for item in self.failed.values())

    def persist_failures(self, force=False):
        if not force and time.monotonic() - self.last_failure_save < 10:
            return
        self.check_mount()
        path = self.destination / "failed-files.json"
        check_tree(path)
        atomic_json(path, {"files": [self.failed[path] for path in sorted(self.failed)],
                           "directories": [], "files_failed_count": len(self.failed),
                           "bytes_failed": self.failed_bytes})
        self.last_failure_save = time.monotonic()

    def record_failure(self, item, exc):
        previous = self.failed.get(item["path"])
        if previous:
            self.failed_bytes -= previous["size"]
        record = dict(item, safe_reason="transfer_unavailable", error_type=type(exc).__name__)
        for name, field in (("http_code", "http_code"), ("exit_code", "curl_exit_code")):
            value = getattr(exc, name, None)
            if type(value) is int:
                record[field] = value
        self.failed[item["path"]] = record
        self.failed_bytes += item["size"]
        self.transfer_state(hashlib.sha256(item["path"].encode()).hexdigest(), remove=True)
        self.progress(files_failed_count=len(self.failed), bytes_failed=self.failed_bytes)
        self.persist_failures()

    def initial_inventory(self):
        if self.retry_only_failed:
            self.progress(phase="loading_failed_inventory", inventory_source="saved_failed_retry")
            inventory = canonical_inventory(read_private_inventory(self.destination / "manifest.json"))
            summary = read_private_inventory(self.destination / "summary.json")
            expected_files = len(inventory["files"])
            expected_bytes = sum(item["size"] for item in inventory["files"])
            attempted_files = summary.get("inventory_files_attempted")
            attempted_bytes = summary.get("inventory_bytes_attempted")
            if attempted_files is None and not summary.get("retry_only_failed"):
                counts = [summary.get(key) for key in ("files_verified", "files_failed_count", "bytes_verified", "bytes_failed")]
                if all(type(value) is int for value in counts):
                    attempted_files, attempted_bytes = counts[0] + counts[1], counts[2] + counts[3]
            if (summary.get("phase") != "complete_with_errors" or summary.get("inventory_verified") is not True or
                    attempted_files != expected_files or attempted_bytes != expected_bytes):
                raise FatalBackupError("Retry-only mode requires a completed partial backup; resume the full saved inventory instead")
            known = {item["path"]: item for item in inventory["files"]}
            for path, failed in self.failed.items():
                if path not in known or any(failed.get(key) != known[path].get(key) for key in ("size", "md5")):
                    raise FatalBackupError("Saved failed-file queue does not match the backup manifest")
            return inventory
        check_tree(CACHE_MARKER)
        if CACHE_MARKER.exists():
            marker_info = CACHE_MARKER.stat()
            if not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != os.getuid() or marker_info.st_mode & 0o077:
                raise BackupError("Inventory resume marker must be a private regular file owned by this user")
            self.progress(phase="loading_saved_inventory", inventory_source="saved_provisional", current_directory=None)
            raw = read_private_inventory(INVENTORY_CACHE)
            inventory = canonical_inventory(raw)
            current = CACHE_MARKER.stat()
            if (current.st_dev, current.st_ino) != (marker_info.st_dev, marker_info.st_ino):
                raise BackupError("Inventory resume marker changed while loading")
            CACHE_MARKER.unlink()
        else:
            self.progress(phase="listing_files", inventory_source="flat_provisional", current_directory=None)
            raw = self.api.file_inventory(self.inventory_progress)
            # Keep raw entries available locally even if consistency validation stops the run.
            check_tree(INVENTORY_CACHE)
            atomic_json(INVENTORY_CACHE, raw)
            inventory = canonical_inventory(raw)
        self.progress(duplicate_entries_count=inventory["duplicate_entries_count"],
                      files_discovered=len(inventory["files"]),
                      bytes_discovered=sum(item["size"] for item in inventory["files"]))
        return inventory

    def preflight_files(self, files):
        remaining, bytes_already_present, pending, failure_queue_changed = 0, 0, [], False
        self.progress(phase="checking_local_files", files_checked=0, bytes_already_present=0)
        verified_count, verified_bytes = self.state["files_verified"], self.state["bytes_verified"]
        last_update = time.monotonic()
        for index, item in enumerate(files, 1):
            self.check_mount()
            target = self.destination / "data" / self.local_path(item["path"])
            if self.local_matches(target, item):
                bytes_already_present += item["size"]
                previous = self.failed.pop(item["path"], None)
                if previous:
                    self.failed_bytes -= previous["size"]
                    failure_queue_changed = True
                verified_count += 1
                verified_bytes += item["size"]
            else:
                if target.exists():
                    raise BackupError("An existing local file differs; it was not overwritten")
                remaining += item["size"]
                pending.append(item)
            if time.monotonic() - last_update >= 1:
                self.progress(files_checked=index, bytes_already_present=bytes_already_present,
                              files_verified=verified_count, bytes_verified=verified_bytes,
                              files_failed_count=len(self.failed), bytes_failed=self.failed_bytes,
                              current_file=item["path"])
                last_update = time.monotonic()
        self.progress(files_checked=len(files), bytes_already_present=bytes_already_present,
                      files_verified=verified_count, bytes_verified=verified_bytes,
                      files_failed_count=len(self.failed), bytes_failed=self.failed_bytes,
                      current_file=None)
        if failure_queue_changed:
            self.persist_failures(force=True)
        if remaining + 256 * 1024 * 1024 > shutil.disk_usage(self.volume).free:
            raise BackupError("Insufficient space on the external disk")
        self.progress(files_pending_count=len(pending), download_order="largest_first")
        return pending

    def download_batch(self, files, workers, phase="downloading"):
        files = sorted(files, key=lambda item: (-item["size"], item["path"]))
        remaining_files = len(files)
        self.progress(phase=phase, current_file=None, current_directory=None,
                      download_order="largest_first", files_pending_count=remaining_files)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            pending = {}
            try:
                for item in files:
                    self.check_mount()
                    pending[pool.submit(self.download, item)] = item
                for future in concurrent.futures.as_completed(pending):
                    item = pending[future]
                    try:
                        downloaded = future.result()
                    except FatalBackupError:
                        raise
                    except (BackupError, urllib.error.URLError, TimeoutError, ConnectionError,
                            http.client.HTTPException, ssl.SSLError) as exc:
                        self.record_failure(item, exc)
                        remaining_files -= 1
                        self.progress(files_pending_count=remaining_files)
                        continue
                    except OSError:
                        raise FatalBackupError("Local storage operation failed; remaining downloads were stopped") from None
                    previous = self.failed.pop(item["path"], None)
                    if previous:
                        self.failed_bytes -= previous["size"]
                    remaining_files -= 1
                    self.progress(files_verified=self.state["files_verified"] + 1,
                                  bytes_verified=self.state["bytes_verified"] + item["size"],
                                  files_downloaded=self.state["files_downloaded"] + int(downloaded),
                                  files_failed_count=len(self.failed), bytes_failed=self.failed_bytes,
                                  files_pending_count=remaining_files)
                    self.persist_failures()
            except BaseException:
                try:
                    self.persist_failures(force=True)
                except (BackupError, OSError):
                    pass
                finally:
                    self.stop.set()
                    for future in pending:
                        future.cancel()
                raise
        self.persist_failures(force=True)

    def save_snapshot(self, inventory, after=None, source_changed=False):
        self.check_mount()
        inventory.update(self.path_mapping.manifest_fields())
        atomic_json(self.destination / "manifest.json", inventory)
        if after is not None:
            after.update(self.path_mapping.manifest_fields())
            atomic_json(self.destination / "manifest-after.json", after)
        self.progress(phase="creating_folders", current_directory=None,
                      folders_total=len(inventory["directories"]), source_changed=source_changed,
                      folder_conflicts=0, mapped_names_count=self.path_mapping.renamed_count())
        folder_conflicts = 0
        for directory in inventory["directories"]:
            self.check_mount()
            target = self.destination / "data" / self.local_path(directory, directory=True)
            check_tree(target)
            if source_changed and any(parent.exists() and not parent.is_dir() for parent in (target, *target.parents)):
                # A changed cloud directory may conflict with a file in the saved snapshot.
                folder_conflicts += 1
                self.progress(current_directory=directory, folder_conflicts=folder_conflicts)
                continue
            target.mkdir(parents=True, exist_ok=True, mode=0o700)

    def run(self, plan_only, workers):
        self.check_mount()
        self.transport = selected_transport()
        self.transport_profile, self.curl_options = selected_curl_profile()
        self.retry_only_failed = private_marker(RETRY_FAILED_MARKER)
        self.load_failures()
        self.progress(phase="authenticating", transport=self.transport, transport_profile=self.transport_profile,
                      retry_only_failed=self.retry_only_failed,
                      files_failed_count=len(self.failed), bytes_failed=self.failed_bytes)
        account = self.api.get("/")
        self.progress(cloud_used_bytes=account.get("used_space"), cloud_trash_bytes=account.get("trash_size"))
        inventory = self.initial_inventory()
        if not self.retry_only_failed:
            known = {item["path"]: item for item in inventory["files"]}
            unchanged = {}
            for path, item in self.failed.items():
                current = known.get(path)
                if current and current.get("md5") and item.get("md5") == current["md5"] and item["size"] == current["size"]:
                    item.update(current)
                    unchanged[path] = item
            self.failed = unchanged
            self.failed_bytes = sum(item["size"] for item in self.failed.values())
        selected = [item for item in inventory["files"]
                    if (item["path"] in self.failed) == self.retry_only_failed]
        scope = selected if self.retry_only_failed else inventory["files"]
        self.progress(phase="mapping_paths")
        existing, existing_directories = self.saved_mapping()
        self.path_mapping = LocalPaths([item["path"] for item in inventory["files"]],
                                       inventory["directories"], existing, existing_directories)
        inventory.update(self.path_mapping.manifest_fields())
        self.progress(phase="plan", files_total=len(scope), bytes_total=sum(item["size"] for item in scope),
                      files_deferred_count=0 if self.retry_only_failed else len(self.failed),
                      files_scheduled_count=len(selected), workers=workers,
                      files_failed_count=len(self.failed), bytes_failed=self.failed_bytes,
                      inventory_files_total=len(inventory["files"]),
                      inventory_bytes_total=sum(item["size"] for item in inventory["files"]),
                      folders_total=len(inventory["directories"]), free_bytes=shutil.disk_usage(self.volume).free,
                      files_without_md5=sum(not item.get("md5") for item in inventory["files"]),
                      mapped_names_count=self.path_mapping.renamed_count(), additional_files_discovered=0)
        if plan_only:
            return
        self.check_mount()
        self.destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        for child in (".partial", "data"):
            check_tree(self.destination / child)
            (self.destination / child).mkdir(exist_ok=True, mode=0o700)
        from verified_journal import VerifiedJournal
        self.journal = VerifiedJournal(self.destination / "verified.sqlite3", sys.modules[__name__])
        pending = self.preflight_files(selected)
        self.save_snapshot(inventory)
        self.persist_failures(force=True)
        self.download_batch(pending, workers)
        # A flat list is provisional: omitted files must be copied and then rechecked.
        for verification_pass in range(3):
            self.progress(phase="scanning_folders", reconciliation_pass=verification_pass + 1,
                          current_directory="disk:/", directory_offset=0, folders_scanned=0,
                          folders_remaining=0, folders_discovered=0, files_discovered=0, bytes_discovered=0)
            after = canonical_inventory(self.api.inventory(self.inventory_progress, workers=min(workers, 128)))
            self.check_mount()
            atomic_json(self.destination / "manifest-after.json", after)
            observed = {item["path"]: item for item in after["files"]}
            known = {item["path"]: item for item in inventory["files"]}
            removed = set(known) - set(observed)
            changed = []
            for path, old in list(known.items()):
                new = observed.get(path)
                if new is None:
                    continue
                same_content = old["size"] == new["size"] and old.get("md5") == new.get("md5")
                modified_only = old.get("modified") != new.get("modified")
                if not same_content or (modified_only and not old.get("md5")):
                    changed.append(path)
                else:
                    known[path] = new
                    if path in self.failed:
                        self.failed[path].update(new)
            missing = [observed[path] for path in sorted(set(observed) - set(known))]
            inventory["files"] = sorted(known.values(), key=lambda item: item["path"])
            inventory["directories"] = sorted(set(inventory["directories"]) | set(after["directories"]))
            unsafe = bool(removed or changed or (missing and (verification_pass == 2 or self.retry_only_failed)))
            if not unsafe and missing:
                inventory["files"] = sorted(inventory["files"] + missing, key=lambda item: item["path"])
                self.path_mapping = LocalPaths([item["path"] for item in inventory["files"]],
                                               after["directories"], self.path_mapping.paths,
                                               self.path_mapping.directory_paths)
            else:
                self.path_mapping.extend_directories(inventory["directories"])
            if not unsafe and missing:
                self.progress(files_total=self.state["files_total"] + len(missing),
                              bytes_total=self.state["bytes_total"] + sum(item["size"] for item in missing))
            self.progress(inventory_files_total=len(inventory["files"]),
                          inventory_bytes_total=sum(item["size"] for item in inventory["files"]),
                          files_changed=len(changed), files_removed=len(removed),
                          files_missing=len(missing), mapped_names_count=self.path_mapping.renamed_count())
            self.save_snapshot(inventory, after, source_changed=unsafe)
            self.persist_failures(force=True)
            if unsafe:
                self.progress(phase="source_changed", source_changed=True, inventory_verified=False,
                              current_directory=None)
                atomic_json(self.destination / "summary.json", self.state)
                raise BackupError("Cloud contents changed or kept growing; the downloaded snapshot and both manifests were retained")
            if missing:
                self.progress(additional_files_discovered=self.state["additional_files_discovered"] + len(missing))
                pending = self.preflight_files(missing)
                self.download_batch(pending, workers, phase="downloading_missing")
                continue
            self.progress(phase="complete_with_errors" if self.failed else "complete",
                          source_changed=False, inventory_verified=True,
                          backup_complete=not self.failed, current_directory=None, files_missing=0,
                          files_failed_count=len(self.failed), bytes_failed=self.failed_bytes,
                          inventory_files_attempted=len(inventory["files"]),
                          inventory_bytes_attempted=sum(item["size"] for item in inventory["files"]))
            atomic_json(self.destination / "summary.json", self.state)
            return

    def inventory_progress(self, **changes):
        self.check_mount()
        self.progress(**changes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompt-token", action="store_true")
    parser.add_argument("--plan", action="store_true", help="List counts and required space without downloading")
    parser.add_argument("--status", action="store_true", help="Show only aggregate local progress")
    parser.add_argument("--volume", type=Path, default=Path("/Volumes/ADATA"))
    parser.add_argument("--workers", type=int, choices=range(1, 257), default=None,
                        help="Parallel downloads (1..256); default from private workers.json, otherwise 8")
    args = parser.parse_args()
    if args.status:
        print(PROGRESS.read_text() if PROGRESS.exists() else '{"phase":"not_started"}')
        return
    workers = selected_workers(args.workers)
    os.umask(0o077)
    token = getpass.getpass("OAuth token (hidden input): ").strip() if args.prompt_token else os.environ.get("YANDEX_DISK_TOKEN", "").strip()
    if not token:
        raise BackupError("No token. Use --prompt-token or set YANDEX_DISK_TOKEN")
    volume = args.volume.absolute()
    check_tree(volume)
    if not volume.is_mount() or volume.stat().st_dev == Path("/").stat().st_dev:
        raise BackupError("Destination must be a mounted external volume")
    backup = Backup(DiskAPI(token), volume, volume / "YandexDisk-backup")
    lock_path = Path(__file__).with_name("download.lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BackupError("Another backup is already running") from None
        try:
            def interrupted(signum, frame):
                raise KeyboardInterrupt
            signal.signal(signal.SIGTERM, interrupted)
            if private_marker(PROBE_MARKER):
                from newtransport_probe import run_probe
                run_probe(backup, sys.modules[__name__])
                return 2
            backup.run(args.plan, workers)
        except Exception:
            if backup.state["phase"] != "source_changed":
                backup.progress(phase="failed")
            raise
        finally:
            if backup.journal is not None:
                backup.journal.close()
    return 2 if backup.state["phase"] == "complete_with_errors" else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BackupError as exc:
        print("Stopped: " + str(exc), flush=True)
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        print("Interrupted. Verified files are retained; rerun to continue.", flush=True)
        raise SystemExit(130) from None
    except Exception as exc:
        # Raw exception messages may include presigned URLs or private filenames.
        print("Stopped: " + type(exc).__name__ + "; details deliberately omitted", flush=True)
        raise SystemExit(1) from None
