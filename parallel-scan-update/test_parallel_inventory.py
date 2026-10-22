"""Synthetic metadata-only scans. No cloud, credentials or backup files are used."""

import concurrent.futures
import io
import threading
import time
import unittest
import urllib.error
from unittest.mock import patch

import download as core


def directory(path):
    return {"path": path, "type": "dir"}


def file(path, size=3):
    return {"path": path, "type": "file", "size": size}


def page(total, items):
    return {"_embedded": {"total": total, "items": items}}


class FakeAPI(core.DiskAPI):
    def __init__(self, pages):
        self.pages = pages
        self.calls = []
        self.lock = threading.Lock()

    def get(self, endpoint, **params):
        self.assert_request(endpoint, params)
        with self.lock:
            self.calls.append((params["path"], params["offset"]))
        return self.pages[(params["path"], params["offset"])]

    @staticmethod
    def assert_request(endpoint, params):
        assert endpoint == "/resources"
        assert params["limit"] == 200 and params["sort"] == "path"
        assert isinstance(params["_stop_event"], threading.Event)


class ParallelInventoryTests(unittest.TestCase):
    def test_multiple_folders_run_in_parallel_with_bounded_pool_and_main_thread_progress(self):
        paths = ["disk:/folder-%d" % index for index in range(6)]
        api = FakeAPI({("disk:/", 0): page(6, [directory(path) for path in paths]),
                       **{(path, 0): page(1, [file(path + "/file", index + 1)])
                          for index, path in enumerate(paths)}})
        original_get = api.get
        active, peak = [0], [0]
        lock, full, release = threading.Lock(), threading.Event(), threading.Event()

        def blocking_get(endpoint, **params):
            if params["path"] == "disk:/":
                return original_get(endpoint, **params)
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
                if active[0] == 3:
                    full.set()
            try:
                if not release.wait(3):
                    raise AssertionError("Synthetic workers did not start together")
                return original_get(endpoint, **params)
            finally:
                with lock:
                    active[0] -= 1

        api.get = blocking_get
        owner = threading.get_ident()
        updates = []

        def progress(**values):
            self.assertEqual(threading.get_ident(), owner)
            self.assertLessEqual(values["scan_active_directories"], 3)
            self.assertGreaterEqual(values["folders_remaining"], 0)
            updates.append(values)

        def unblock():
            full.wait(3)
            release.set()

        coordinator = threading.Thread(target=unblock)
        coordinator.start()
        try:
            result = api.inventory(progress, workers=3)
        finally:
            release.set()
            coordinator.join(3)
        self.assertEqual(peak[0], 3)
        self.assertEqual(result["directories"], sorted(paths))
        self.assertEqual(len(result["files"]), 6)
        self.assertEqual(updates[-1]["folders_scanned"], 7)
        self.assertEqual(updates[-1]["folders_remaining"], 0)
        self.assertEqual(updates[-1]["scan_active_directories"], 0)
        self.assertEqual(updates[-1]["bytes_discovered"], 21)

    def test_pages_stay_sequential_empty_directories_are_kept_and_results_sorted(self):
        api = FakeAPI({("disk:/", 0): page(3, [directory("disk:/b")]),
                       ("disk:/", 1): page(3, [file("disk:/z"), directory("disk:/a")]),
                       ("disk:/a", 0): page(0, []),
                       ("disk:/b", 0): page(2, [file("disk:/b/z")]),
                       ("disk:/b", 1): page(2, [file("disk:/b/a")])})
        result = api.inventory(workers=128)
        self.assertEqual(result["directories"], ["disk:/a", "disk:/b"])
        self.assertEqual([item["path"] for item in result["files"]],
                         ["disk:/b/a", "disk:/b/z", "disk:/z"])
        for path in ("disk:/", "disk:/b"):
            self.assertEqual([offset for directory_path, offset in api.calls if directory_path == path], [0, 1])

    def test_scan_worker_bounds_are_strict(self):
        api = FakeAPI({("disk:/", 0): page(0, [])})
        for workers in (1, 128):
            self.assertEqual(api.inventory(workers=workers), {"files": [], "directories": []})
        for workers in (True, 0, 129, "128", 128.0):
            with self.subTest(workers=workers):
                before = len(api.calls)
                with self.assertRaises(core.BackupError):
                    api.inventory(workers=workers)
                self.assertEqual(len(api.calls), before)

    def test_changed_total_and_incomplete_pages_fail_without_an_inventory(self):
        cases = [({("disk:/", 0): page(2, [file("disk:/a")]),
                   ("disk:/", 1): page(3, [file("disk:/b")])}, "changed during listing"),
                 ({("disk:/", 0): page(1, [])}, "Incomplete directory listing"),
                 ({("disk:/", 0): page(0, [file("disk:/a")])}, "Inconsistent directory listing")]
        for pages, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(core.BackupError, message):
                    FakeAPI(pages).inventory(workers=2)

    def test_duplicate_files_folders_and_file_folder_collisions_are_rejected(self):
        for first, second in ((file("disk:/a"), file("disk:/a")),
                              (directory("disk:/a"), directory("disk:/a")),
                              (file("disk:/a"), directory("disk:/a"))):
            with self.subTest(first=first["type"], second=second["type"]):
                api = FakeAPI({("disk:/", 0): page(2, [first]),
                               ("disk:/", 1): page(2, [second]),
                               ("disk:/a", 0): page(0, [])})
                with self.assertRaisesRegex(core.BackupError, "duplicate resource path"):
                    api.inventory(workers=2)

    def test_unsafe_paths_unsupported_types_and_bad_metadata_fail_closed(self):
        cases = [file("disk:/../outside"), file("disk:/folder/wrong-parent"),
                 {"path": "disk:/a", "type": "link"}, file("disk:/a", size=True),
                 {"path": "disk:/a", "type": "file", "size": 2, "md5": "invalid"}]
        for item in cases:
            with self.subTest(item=item):
                with self.assertRaises(core.BackupError):
                    FakeAPI({("disk:/", 0): page(1, [item])}).inventory(workers=2)

    def test_failure_cancels_other_workers_before_their_next_page_and_preserves_error(self):
        failure = core.FatalBackupError("Synthetic fatal API error")
        api = FakeAPI({("disk:/", 0): page(3, [directory("disk:/a-failing"),
                                                directory("disk:/b"), directory("disk:/c")])})
        original_get = api.get

        def fail_or_wait(endpoint, **params):
            if params["path"] == "disk:/":
                return original_get(endpoint, **params)
            api.assert_request(endpoint, params)
            with api.lock:
                api.calls.append((params["path"], params["offset"]))
            if params["path"] == "disk:/a-failing":
                raise failure
            if not params["_stop_event"].wait(3):
                raise AssertionError("Failed scan did not cancel its peers")
            return page(2, [file(params["path"] + "/first")])

        api.get = fail_or_wait
        with self.assertRaises(core.FatalBackupError) as stopped:
            api.inventory(workers=3)
        self.assertIs(stopped.exception, failure)
        self.assertTrue(all(offset == 0 for _, offset in api.calls))

    def test_progress_stop_prevents_all_api_requests(self):
        api = FakeAPI({("disk:/", 0): page(0, [])})
        failure = KeyboardInterrupt()

        def pause(**values):
            raise failure

        with self.assertRaises(KeyboardInterrupt) as stopped:
            api.inventory(pause, workers=128)
        self.assertIs(stopped.exception, failure)
        self.assertEqual(api.calls, [])


class RequestCancellationTests(unittest.TestCase):
    def test_cancellation_before_or_during_pacing_prevents_network_access(self):
        for cancel_during_pacing in (False, True):
            with self.subTest(cancel_during_pacing=cancel_during_pacing):
                api, stop = core.DiskAPI("synthetic-test-value"), threading.Event()
                if not cancel_during_pacing:
                    stop.set()
                with patch.object(api, "pace_request", side_effect=lambda *args: stop.set()), \
                        patch.object(api.opener, "open") as opened:
                    with self.assertRaisesRegex(core.BackupError, "Directory scan stopped"):
                        api.get("/resources", _stop_event=stop)
                opened.assert_not_called()
                self.assertEqual(api.request_snapshot()["api_requests_total"], 0)

    def test_cancellation_while_waiting_for_api_budget_prevents_network_access(self):
        api, stop = core.DiskAPI("synthetic-test-value"), threading.Event()
        api.next_request_at = time.monotonic() + 10
        with patch.object(stop, "wait", return_value=True) as waited, \
                patch.object(api.opener, "open") as opened:
            with self.assertRaisesRegex(core.BackupError, "Directory scan stopped"):
                api.get("/resources", _stop_event=stop)
        waited.assert_called_once()
        opened.assert_not_called()
        self.assertEqual(api.request_snapshot()["api_requests_total"], 0)

    def test_cancellation_during_backoff_prevents_retry(self):
        api, stop = core.DiskAPI("synthetic-test-value"), threading.Event()
        failure = urllib.error.HTTPError("https://synthetic.invalid/", 503, "synthetic", {}, io.BytesIO())
        with patch.object(api, "pace_request"), patch.object(api.opener, "open", side_effect=failure) as opened, \
                patch.object(stop, "wait", return_value=True):
            with self.assertRaisesRegex(core.BackupError, "Directory scan stopped"):
                api.get("/resources", _stop_event=stop)
        self.assertEqual(opened.call_count, 1)
        self.assertEqual(api.request_snapshot()["api_http_error_counts"], {"503": 1})


if __name__ == "__main__":
    unittest.main()
