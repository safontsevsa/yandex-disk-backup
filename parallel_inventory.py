"""Bounded metadata-only directory scan; aggregation runs in the caller thread."""

import concurrent.futures
from collections import deque
import threading
import time


def parallel_inventory(api, core, progress=None, workers=128):
    """Fetch independent folders together and each folder's pages in order.

    ``core`` supplies the existing safe path/metadata validators and error types.
    No partial inventory is returned when an API, validation or callback fails.
    """
    if type(workers) is not int or not 1 <= workers <= 128:
        raise core.BackupError("Directory scan workers must be an integer from 1 to 128")
    stop = threading.Event()
    queue = deque(["disk:/"])
    contexts = {"disk:/": {"offset": 0, "total": None}}
    pending = {}
    files, directories, seen = [], [], set()
    folders_scanned, byte_count = 0, 0
    current_directory, directory_offset = "disk:/", 0
    last_progress = float("-inf")

    def publish(force=False):
        nonlocal last_progress
        now = time.monotonic()
        if progress and (force or now - last_progress >= 0.25):
            progress(current_directory=current_directory, directory_offset=directory_offset,
                     folders_scanned=folders_scanned, folders_remaining=len(queue),
                     folders_discovered=len(directories), files_discovered=len(files),
                     bytes_discovered=byte_count, scan_workers=workers,
                     scan_active_directories=len(pending))
            last_progress = now

    def fetch(directory, offset):
        if stop.is_set():
            raise core.BackupError("Directory scan stopped")
        return api.get("/resources", path=directory, limit=200, offset=offset,
                       sort="path", _stop_event=stop)

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    try:
        publish(force=True)
        while queue or pending:
            while queue and len(pending) < workers:
                directory = queue.popleft()
                pending[pool.submit(fetch, directory, contexts[directory]["offset"])] = directory
            publish()
            done, _ = concurrent.futures.wait(pending, timeout=0.25,
                                             return_when=concurrent.futures.FIRST_COMPLETED)
            if not done:
                publish()
                continue
            # Resolve all failures before accepting pages or submitting more work.
            completed = [(pending[future], future.result())
                         for future in sorted(done, key=lambda value: pending[value])]
            for future in done:
                del pending[future]
            for directory, data in completed:
                context = contexts[directory]
                offset, initial_total = context["offset"], context["total"]
                listing = data.get("_embedded") if isinstance(data, dict) else None
                if not isinstance(listing, dict):
                    raise core.BackupError("Directory listing is missing")
                total, items = listing.get("total"), listing.get("items")
                if type(total) is not int or total < 0 or not isinstance(items, list):
                    raise core.BackupError("Invalid directory listing")
                if initial_total is not None and total != initial_total:
                    raise core.BackupError("Cloud directory changed during listing; retry when changes finish")
                if len(items) > 200 or offset + len(items) > total:
                    raise core.BackupError("Inconsistent directory listing")
                if not items and offset < total:
                    raise core.BackupError("Incomplete directory listing")
                additions, page_paths = [], set()
                for item in items:
                    if not isinstance(item, dict):
                        raise core.BackupError("Invalid directory resource")
                    path = item.get("path", "")
                    relative = core.relative_path(path)
                    parent = relative.parent
                    expected_parent = "disk:/" if str(parent) == "." else "disk:/" + str(parent)
                    if expected_parent != directory:
                        raise core.BackupError("Directory listing contains a resource outside its parent")
                    if path in seen or path in page_paths:
                        raise core.BackupError("Cloud listing contains an exact duplicate resource path")
                    page_paths.add(path)
                    if item.get("type") == "dir":
                        additions.append(("dir", path))
                    elif item.get("type") == "file":
                        additions.append(("file", core.file_metadata(item)))
                    else:
                        raise core.BackupError("Unsupported cloud resource type")
                # Commit a page only after all of its resource metadata passed validation.
                seen.update(page_paths)
                for kind, resource in additions:
                    if kind == "dir":
                        directories.append(resource)
                        contexts[resource] = {"offset": 0, "total": None}
                        queue.append(resource)
                    else:
                        files.append(resource)
                        byte_count += resource["size"]
                offset += len(items)
                context.update(offset=offset, total=total)
                current_directory, directory_offset = directory, offset
                if offset < total:
                    # One in-flight page per directory; pagination stays sequential.
                    queue.appendleft(directory)
                else:
                    folders_scanned += 1
                    del contexts[directory]
                publish()
        core.validate_paths([item["path"] for item in files] + directories)
        publish(force=True)
        return {"files": sorted(files, key=lambda item: item["path"]),
                "directories": sorted(directories)}
    except BaseException:
        stop.set()
        for future in pending:
            future.cancel()
        raise
    finally:
        # API checks cancellation before the network and between retries. An
        # already-started request retains the existing 60-second socket timeout.
        pool.shutdown(wait=True, cancel_futures=True)
