def _yandex_backup_status_probe_20261011():
    import json
    import os
    import sys
    import threading
    import time

    result = {"observed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "stage": "unknown"}
    try:
        frame = sys._current_frames().get(threading.main_thread().ident)
        while frame is not None:
            if frame.f_code.co_filename == "/Users/safoncev/yandex-disk-backup/download.py":
                if frame.f_code.co_qualname == "DiskAPI.inventory":
                    result.update({
                        "stage": "listing",
                        "directory": frame.f_locals.get("directory"),
                        "files_discovered": len(frame.f_locals.get("files", ())),
                        "folders_discovered": len(frame.f_locals.get("dirs", ())),
                        "folders_pending": len(frame.f_locals.get("pending", ())),
                        "folders_processed": max(0, len(frame.f_locals.get("seen", ())) - 1),
                        "page_offset": frame.f_locals.get("offset"),
                    })
                    break
                if frame.f_code.co_qualname == "Backup.run":
                    state = frame.f_locals.get("self").state
                    for key in ("phase", "files_total", "files_verified", "bytes_total", "bytes_verified"):
                        if key in state:
                            result[key] = state[key]
            frame = frame.f_back
    except Exception as exc:
        result = {"probe_error": type(exc).__name__}
    output = "/Users/safoncev/yandex-disk-backup/live-status.json"
    fd = os.open(output + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False)
    os.replace(output + ".tmp", output)


_yandex_backup_status_probe_20261011()
