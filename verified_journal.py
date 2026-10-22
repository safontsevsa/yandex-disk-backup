"""Private, durable certificates for already verified published files."""

import json
import os
from pathlib import Path
import sqlite3
import stat
import threading


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_uid, stat.S_IMODE(info.st_mode))


def snapshot(path, core):
    core.check_tree(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return fingerprint(info)


def private_snapshot(value):
    return (isinstance(value, (list, tuple)) and len(value) == 7
            and all(type(number) is int and number >= 0 for number in value)
            # Some removable filesystems expose owner-only files as executable.
            # All identity fields still have to match the actual regular inode.
            and value[5] == os.getuid() and value[6] in (0o600, 0o700))


class VerifiedJournal:
    def __init__(self, path, core):
        self.path, self.core = Path(path), core
        self.lock = threading.Lock()
        core.check_tree(self.path)
        parent = self.path.parent.stat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            raise core.FatalBackupError("Verification journal directory is unsafe")
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            created = True
        except FileExistsError:
            fd = os.open(self.path, os.O_RDWR | os.O_NOFOLLOW)
            created = False
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise core.FatalBackupError("Verification journal must be an owned private regular file")
        finally:
            os.close(fd)
        self._check_sidecars()
        try:
            self.db = sqlite3.connect(self.path, timeout=30, check_same_thread=False, isolation_level=None)
            self.db.execute("PRAGMA trusted_schema=OFF")
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=EXTRA")
            self.db.execute("PRAGMA fullfsync=ON")
            if created:
                self.db.executescript("BEGIN IMMEDIATE; CREATE TABLE version (number INTEGER NOT NULL); "
                                     "INSERT INTO version VALUES (1); "
                                     "CREATE TABLE verified (remote TEXT PRIMARY KEY, local TEXT NOT NULL, "
                                     "md5 TEXT NOT NULL, size INTEGER NOT NULL, fingerprint TEXT NOT NULL, "
                                     "origin TEXT NOT NULL); COMMIT;")
            self._validate()
        except (sqlite3.Error, ValueError, TypeError, core.BackupError):
            if hasattr(self, "db"):
                self.db.close()
            raise core.FatalBackupError("Verification journal is unavailable or invalid") from None

    def _check_sidecars(self):
        for path in (self.path, *(self.path.with_name(self.path.name + suffix)
                                  for suffix in ("-journal", "-wal", "-shm"))):
            self.core.check_tree(path)
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise self.core.FatalBackupError("Verification journal or its sidecar is unsafe")

    def _validate(self):
        if self.db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise ValueError()
        schema = {(kind, name) for kind, name in self.db.execute("SELECT type,name FROM sqlite_master")}
        if schema != {("table", "version"), ("table", "verified"), ("index", "sqlite_autoindex_verified_1")}:
            raise ValueError()
        if self.db.execute("SELECT number FROM version").fetchall() != [(1,)]:
            raise ValueError()
        for remote, local, md5, size, encoded, origin in self.db.execute("SELECT * FROM verified"):
            self.core.file_metadata({"path": remote, "size": size, "md5": md5})
            self.core.local_relative(local)
            value = json.loads(encoded)
            if (not md5 or not private_snapshot(value) or value[2] != size
                    or origin not in ("verified_md5", "trusted_previous_verified_run")):
                raise ValueError()

    def hit(self, remote, item, local, path):
        if not item.get("md5"):
            return False
        before = snapshot(path, self.core)
        if before is None or not private_snapshot(before):
            return False
        try:
            with self.lock:
                self._check_sidecars()
                row = self.db.execute("SELECT local,md5,size,fingerprint FROM verified WHERE remote=?", (remote,)).fetchone()
            return (row is not None and row[:3] == (local, item["md5"].lower(), item["size"])
                    and tuple(json.loads(row[3])) == before and snapshot(path, self.core) == before)
        except (sqlite3.Error, ValueError, TypeError):
            raise self.core.FatalBackupError("Verification journal is unavailable or invalid") from None

    def record(self, remote, item, local, path, verified_snapshot, origin="verified_md5"):
        if (not item.get("md5") or not private_snapshot(verified_snapshot)
                or verified_snapshot[2] != item["size"] or snapshot(path, self.core) != verified_snapshot):
            return False
        self.core.file_metadata(dict(item, path=remote))
        if origin not in ("verified_md5", "trusted_previous_verified_run"):
            raise self.core.FatalBackupError("Verification checkpoint has an invalid origin")
        self.core.relative_path(remote)
        self.core.local_relative(local)
        try:
            with self.lock:
                self._check_sidecars()
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    if snapshot(path, self.core) != verified_snapshot:
                        self.db.execute("ROLLBACK")
                        return False
                    self.db.execute("INSERT OR REPLACE INTO verified VALUES (?,?,?,?,?,?)",
                                    (remote, local, item["md5"].lower(), item["size"],
                                     json.dumps(verified_snapshot), origin))
                    self.db.execute("COMMIT")
                except BaseException:
                    if self.db.in_transaction:
                        self.db.execute("ROLLBACK")
                    raise
                self._check_sidecars()
            return True
        except sqlite3.Error:
            raise self.core.FatalBackupError("Verification journal could not be saved") from None

    def close(self):
        with self.lock:
            self.db.close()


def bootstrap_previous_verified(backup_root, manifest_path, *, expected_count, expected_bytes, cutoff_ns, core):
    """Explicit trust migration from a previously verified run; never reads file bodies."""
    if any(type(value) is not int or value <= 0 for value in (expected_count, expected_bytes, cutoff_ns)):
        raise core.FatalBackupError("Bootstrap requires explicit positive count, bytes and cutoff")
    backup_root = Path(backup_root)
    core.check_tree(backup_root)
    raw = core.read_private_inventory(Path(manifest_path))
    inventory = core.canonical_inventory(raw)
    if not isinstance(raw.get("local_paths"), dict) or not isinstance(raw.get("local_directory_paths"), dict):
        raise core.FatalBackupError("Trusted bootstrap requires the saved local path mappings")
    mapping = core.LocalPaths([item["path"] for item in inventory["files"]], inventory["directories"],
                              raw.get("local_paths"), raw.get("local_directory_paths"))
    known = {str(mapping.local_path(item["path"])): item for item in inventory["files"]}
    data = backup_root / "data"
    core.check_tree(data)
    device = backup_root.stat().st_dev
    records, pending = [], [data]
    while pending:
        directory = pending.pop()
        core.check_tree(directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                core.check_tree(path)
                info = entry.stat(follow_symlinks=False)
                if info.st_dev != device:
                    raise core.FatalBackupError("Bootstrap data moved to another device")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                    continue
                local = str(path.relative_to(data))
                item = known.get(local)
                if item is None and entry.name == ".DS_Store" and stat.S_ISREG(info.st_mode):
                    continue
                value = fingerprint(info)
                if (item is None or not stat.S_ISREG(info.st_mode) or not item.get("md5")
                        or not private_snapshot(value) or value[2] != item["size"]
                        or value[3] > cutoff_ns or value[4] > cutoff_ns):
                    raise core.FatalBackupError("Published file metadata does not qualify for trusted bootstrap")
                records.append((path, local, item, value))
    if len(records) != expected_count or sum(item["size"] for _, _, item, _ in records) != expected_bytes:
        raise core.FatalBackupError("Published bootstrap totals differ from the previous verified run")
    journal = VerifiedJournal(backup_root / "verified.sqlite3", core)
    try:
        with journal.lock:
            journal._check_sidecars()
            journal.db.execute("BEGIN IMMEDIATE")
            try:
                for path, local, item, value in records:
                    if snapshot(path, core) != value:
                        raise core.FatalBackupError("Published files changed during trusted bootstrap")
                journal.db.executemany("INSERT OR REPLACE INTO verified VALUES (?,?,?,?,?,?)",
                                      [(item["path"], local, item["md5"].lower(), item["size"], json.dumps(value),
                                        "trusted_previous_verified_run") for _, local, item, value in records])
                journal.db.execute("COMMIT")
            except BaseException:
                if journal.db.in_transaction:
                    journal.db.execute("ROLLBACK")
                raise
            journal._check_sidecars()
    except sqlite3.Error:
        raise core.FatalBackupError("Trusted verification journal could not be saved") from None
    finally:
        journal.close()
    return {"files": len(records), "bytes": expected_bytes, "origin": "trusted_previous_verified_run"}
