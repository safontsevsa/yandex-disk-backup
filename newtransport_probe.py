"""Bounded read-only transport comparisons; credentials never leave curl stdin."""

import hashlib
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import urllib.parse


PROFILES = (("default", ()), ("http1", ("--http1.1",)),
            ("ipv4", ("--ipv4",)), ("http1_ipv4", ("--http1.1", "--ipv4")))
FIELDS = ("http_code", "num_redirects", "http_version", "time_namelookup", "time_connect",
          "time_appconnect", "time_starttransfer", "time_redirect", "time_total",
          "size_download", "speed_download")
WRITE_OUT = "%{stderr}" + "|".join("%{" + field + "}" for field in FIELDS)
COUNTERS = ("files_total", "bytes_total", "files_verified", "bytes_verified", "files_downloaded",
            "files_failed_count", "bytes_failed", "inventory_files_total", "inventory_bytes_total",
            "files_deferred_count", "files_scheduled_count", "workers")


def parse_metrics(diagnostic):
    """Reject all free text, URL-bearing diagnostics and non-finite numbers."""
    if not isinstance(diagnostic, bytes) or len(diagnostic) > 1024:
        raise ValueError("Invalid numerical transfer diagnostics")
    try:
        values = diagnostic.decode("ascii").strip().split("|")
    except UnicodeDecodeError:
        raise ValueError("Invalid numerical transfer diagnostics") from None
    if len(values) != len(FIELDS):
        raise ValueError("Invalid numerical transfer diagnostics")
    result = {}
    for field, value in zip(FIELDS, values):
        if field == "http_version":
            if value not in ("0", "1", "1.0", "1.1", "2", "3"):
                raise ValueError("Invalid numerical transfer diagnostics")
            result[field] = value
        elif field in ("http_code", "num_redirects", "size_download"):
            if not re.fullmatch(r"[0-9]+", value):
                raise ValueError("Invalid numerical transfer diagnostics")
            result[field] = int(value)
        else:
            if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value):
                raise ValueError("Invalid numerical transfer diagnostics")
            number = float(value)
            if not math.isfinite(number) or number < 0:
                raise ValueError("Invalid numerical transfer diagnostics")
            result[field] = number
    if len(values[0]) != 3 or (result["http_code"] != 0 and not 100 <= result["http_code"] <= 599):
        raise ValueError("Invalid numerical transfer diagnostics")
    return result


def claim_marker(marker, core):
    core.check_tree(marker)
    fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise core.FatalBackupError("Probe marker must be a private regular file owned by this user")
        current = marker.lstat()
        if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise core.FatalBackupError("Probe marker changed while claiming it")
        marker.unlink()
    finally:
        os.close(fd)


def select_cases(backup, core):
    raw = core.read_private_inventory(backup.destination / "manifest.json")
    inventory = core.canonical_inventory(raw)
    files, directories = raw.get("local_paths"), raw.get("local_directory_paths")
    if not isinstance(files, dict) or not isinstance(directories, dict):
        raise core.BackupError("Transport probe requires saved local path mappings")
    mapping = core.LocalPaths([item["path"] for item in inventory["files"]],
                              inventory["directories"], files, directories)
    failed_raw = core.read_private_inventory(backup.destination / "failed-files.json")
    failed = core.canonical_inventory(failed_raw)
    records = {item["path"]: item for item in failed_raw["files"]}
    known = {item["path"]: item for item in inventory["files"]}
    for item in failed["files"]:
        original = known.get(item["path"])
        if original is None or any(item.get(key) != original.get(key) for key in ("size", "md5")):
            raise core.BackupError("Probe failure queue differs from the saved manifest")
    failed_paths = set(records)
    control = None
    for item in inventory["files"]:
        if not 0 < item["size"] <= 256 * 1024 or item["path"] in failed_paths:
            continue
        target = backup.destination / "data" / mapping.local_path(item["path"])
        core.check_tree(target)
        try:
            info = target.stat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode) and info.st_size == item["size"]:
            control = item
            break
    timeout = next((item for item in failed["files"] if 0 < item["size"] <= 256 * 1024
                    and records[item["path"]].get("curl_exit_code") == 28
                    and records[item["path"]].get("http_code") == 302), None)
    if control is None or timeout is None:
        raise core.BackupError("Transport probe requires a saved small control and a small prior timeout")
    return (("control", control), ("previous_timeout", timeout))


def probe_request(backup, core, href, profile_options):
    config = ("url = " + core.curl_config_value(href) + "\nheader = " +
              core.curl_config_value("Authorization: OAuth " + backup.api.token) + "\n").encode("utf-8")
    arguments = ["/usr/bin/curl", "-q", "--config", "-", "--location", "--fail", "--silent",
                 "--globoff", "--proto", "=https", "--proto-redir", "=https",
                 "--connect-timeout", "10", "--speed-limit", "1024", "--speed-time", "15",
                 "--max-time", "20", "--write-out", WRITE_OUT, *profile_options]
    environment = {key: value for key, value in os.environ.items() if key != "YANDEX_DISK_TOKEN"}
    process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, env=environment)
    first, started = True, time.monotonic()
    try:
        while True:
            backup.check_mount()
            try:
                _, diagnostic = process.communicate(input=config if first else None, timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                first = False
                if time.monotonic() - started > 25:
                    return {"exit_code": None, "error_type": "ProbeDeadline"}
        result = {"exit_code": process.returncode}
        try:
            result.update(parse_metrics(diagnostic))
        except ValueError:
            result["error_type"] = "InvalidMetrics"
        return result
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


def run_probe(backup, core):
    marker = Path(core.__file__).with_name("probe-transport")
    claim_marker(marker, core)
    backup.check_mount()
    if core.PROGRESS.exists():
        previous = core.read_private_inventory(core.PROGRESS)
        if isinstance(previous, dict):
            backup.state.update({key: previous[key] for key in COUNTERS
                                 if type(previous.get(key)) is int and previous[key] >= 0})
    backup.progress(phase="probing_transport", probe_tests_completed=0, probe_tests_total=8,
                    active_transfers={}, current_file=None, current_directory=None)
    cases = select_cases(backup, core)
    report_path = Path(core.__file__).with_name("transport-probe.json")
    report = {"version": 1, "complete": False, "tests_total": 8, "tests_completed": 0, "cases": []}

    def save_report():
        core.check_tree(report_path)
        core.atomic_json(report_path, report)

    save_report()
    completed = 0
    try:
        for label, item in cases:
            backup.check_mount()
            case = {"label": label, "file_id": hashlib.sha256(item["path"].encode()).hexdigest(),
                    "expected_size": item["size"], "results": []}
            report["cases"].append(case)
            try:
                link = backup.api.get("/resources/download", _attempts=1, _timeout=15, path=item["path"])
            except core.FatalBackupError:
                raise
            except Exception as exc:
                case["link_error_type"] = "LinkUnavailable"
                if type(getattr(exc, "http_code", None)) is int:
                    case["http_code"] = exc.http_code
                save_report()
                continue
            href = link.get("href", "") if isinstance(link, dict) else ""
            parsed = urllib.parse.urlsplit(href)
            host = parsed.hostname or ""
            trusted = any(host == domain or host.endswith("." + domain)
                          for domain in ("yandex.net", "yandex.ru", "yandex.com"))
            if parsed.scheme != "https" or not trusted or link.get("method") != "GET":
                raise core.FatalBackupError("Unexpected download endpoint")
            for profile, options in PROFILES:
                backup.progress(probe_case=label, probe_profile=profile, probe_test_index=completed + 1)
                result = probe_request(backup, core, href, options)
                result.update(profile=profile, success=result.get("exit_code") == 0
                              and result.get("http_code") == 200 and result.get("size_download") == item["size"])
                case["results"].append(result)
                completed += 1
                report["tests_completed"] = completed
                save_report()
                backup.progress(probe_tests_completed=completed)
        report["complete"] = completed == 8
        save_report()
        backup.progress(phase="probe_complete" if completed == 8 else "probe_incomplete",
                        probe_tests_completed=completed)
    except BaseException:
        save_report()
        raise
    return True
