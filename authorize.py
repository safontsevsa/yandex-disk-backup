#!/usr/bin/env python3
"""Local token authorization from the environment or a single-use form."""
import argparse
from contextlib import ExitStack
import fcntl
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.parse


def valid_token(token):
    return (bool(token) and len(token) <= 2048
            and all(c.isascii() and (c.isalnum() or c in "_-.") for c in token))


def main():
    with ExitStack() as cleanup:
        return run_authorizer(cleanup)


def run_authorizer(cleanup):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--replace-pid", type=int)
    parser.add_argument("--wait-ready-file", type=Path)
    parser.add_argument("--availability-only", action="store_true", help="Check saved unavailable files without downloading file bodies.")
    parser.add_argument("--volume", type=Path)
    parser.add_argument("--workers", type=int, choices=range(1, 129))
    parser.add_argument("--journal-path", type=Path, help="Private local verification journal for the selected volume.")
    args = parser.parse_args()
    if args.availability_only and args.volume is None:
        parser.error("--availability-only requires --volume")
    if args.availability_only and (args.replace_pid or args.wait_ready_file):
        parser.error("Availability checks cannot replace or resume a downloader")
    if args.availability_only and args.journal_path is not None:
        parser.error("Availability checks do not use a verification journal")
    if len(args.client_id) != 32 or any(c not in "0123456789abcdef" for c in args.client_id.lower()):
        raise ValueError("Invalid ClientID")
    environment_token = os.environ.pop("YANDEX_DISK_TOKEN", "")
    if environment_token and not valid_token(environment_token):
        raise ValueError("Invalid environment token")
    oauth = "https://oauth.yandex.ru/authorize?" + urllib.parse.urlencode({
        "response_type": "token", "client_id": args.client_id,
        "scope": "cloud_api:disk.read cloud_api:disk.info",
    })
    availability_guard = None
    if args.availability_only:
        os.umask(0o077)
        path = Path(__file__).with_name("availability-auth.lock")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        availability_guard = cleanup.enter_context(os.fdopen(fd, "r+"))
        info = os.fstat(availability_guard.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Unsafe availability authorization lock")
        fcntl.flock(availability_guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
    page_title = "Проверка доступности Яндекс Диска" if args.availability_only else "Скачать Яндекс Диск"
    volume = args.volume if args.volume is not None else Path('/Volumes/ADATA')
    heading = "Проверить ранее недоступные файлы" if args.availability_only else "Скачать Яндекс Диск на " + html.escape(volume.name)
    button_label = "Проверить доступность" if args.availability_only else "Начать скачивание"
    if args.availability_only:
        explanation = ("Сохранённая очередь: " + html.escape(str(args.volume / "YandexDisk-backup"), quote=True)
                       + ". Проверим ответы серверов по этой очереди. Содержимое файлов не читается и не сохраняется; миграция остаётся на паузе.")
        accepted = "Токен принят локально. Проверяем доступность файлов по сохранённой очереди. Скачивание файлов не запускается. Эту вкладку можно закрыть."
    else:
        explanation = ("Папка назначения: " + html.escape(str(volume / 'YandexDisk-backup' / 'data'), quote=True)
                       + ". Используем сохранённую очередь, если выбран режим докачки. Готовые файлы проверяются по размеру и контрольной сумме.")
        accepted = "Токен принят локально. Проверяем доступ к API и начинаем скачивание. Эту вкладку можно закрыть, компьютер оставь включённым."
    nonce = os.environ.pop("YANDEX_AUTH_FORM_NONCE", "") or secrets.token_urlsafe(32)
    ready = threading.Event()
    token_holder = [environment_token] if environment_token else []

    class Form(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, body):
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(payload)

        def valid_host(self):
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

        def do_GET(self):
            if self.path != "/" or not self.valid_host():
                self.reply(404, "Not found")
                return
            self.reply(200, f'''<!doctype html><html lang="ru"><meta charset="utf-8">
<title>{page_title}</title><style>body{{font:18px system-ui;max-width:700px;margin:60px auto;padding:20px;line-height:1.6}}input{{width:95%;font-size:18px;padding:10px}}button{{font-size:18px;padding:10px;margin-top:15px}}</style>
<h1>{heading}</h1>
<p>1. <a href="{html.escape(oauth, quote=True)}" target="_blank" rel="noreferrer">Авторизуйся в Яндексе</a> и скопируй полученный токен.</p>
<p>2. Вставь токен ниже. Эта форма работает только на твоём Mac. Токен не сохраняется в файлы и не отправляется в чат.</p>
<form method="post" action="/token"><input type="hidden" name="csrf" value="{nonce}"><input type="password" name="token" autocomplete="off" required aria-label="OAuth токен"><button type="submit">{button_label}</button></form>
<p>{explanation}</p></html>''')

        def do_POST(self):
            origin = f"http://127.0.0.1:{self.server.server_port}"
            # Some embedded browsers omit Origin or use an opaque Origin.
            # A valid same-page CSRF nonce is still required in every case.
            supplied_origin = self.headers.get("Origin")
            if self.path != "/token" or not self.valid_host() or supplied_origin not in (None, "null", origin):
                print("FORM_REJECTED=" + str({"host_match": self.valid_host(), "origin_present": supplied_origin is not None, "origin_match": supplied_origin == origin}), flush=True)
                self.reply(403, "Forbidden")
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size <= 0 or size > 4096:
                    raise ValueError()
                values = urllib.parse.parse_qs(self.rfile.read(size).decode("utf-8"))
                if not secrets.compare_digest(values.get("csrf", [""])[0], nonce):
                    raise ValueError()
                token = values.get("token", [""])[0].strip()
                if not valid_token(token):
                    raise ValueError()
                token_holder.append(token)
                self.reply(200, '<meta charset="utf-8"><p>' + accepted + '</p>')
                ready.set()
            except (ValueError, UnicodeError):
                self.reply(400, "Invalid request")

    if not environment_token:
        server = HTTPServer(("127.0.0.1", args.port), Form)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(f"LOCAL_AUTH_URL=http://127.0.0.1:{server.server_port}/", flush=True)
        ready.wait()
        server.shutdown()
        server.server_close()
        thread.join()
    child_env = os.environ.copy()
    child_env["YANDEX_DISK_TOKEN"] = token_holder.pop()
    from download import DiskAPI, BackupError, atomic_json
    broker_path = Path(__file__).with_name("availability-broker.json" if args.availability_only else "broker.json")
    retry_path = Path(__file__).with_name("availability-retry" if args.availability_only else "retry-download")
    log_path = Path(__file__).with_name("availability.log" if args.availability_only else "download.log")

    def broker_state(status, **values):
        atomic_json(broker_path, {"status": status, "broker_pid": os.getpid(), **values})

    broker_state("validating_token")
    account = DiskAPI(child_env["YANDEX_DISK_TOKEN"]).get("/")
    print("Authorization verified; cloud used bytes=" + str(account.get("used_space")), flush=True)
    if args.wait_ready_file:
        broker_state("waiting_for_ready")
        while not args.wait_ready_file.exists():
            time.sleep(1)
    if args.replace_pid:
        broker_state("replacing_old_downloader")
        previous = subprocess.run(["/bin/ps", "-p", str(args.replace_pid), "-o", "command="], capture_output=True, text=True).stdout
        if previous:
            if str(Path(__file__).with_name("download.py")) not in previous:
                raise BackupError("Old downloader ownership mismatch")
            try:
                os.kill(args.replace_pid, signal.SIGINT)
            except ProcessLookupError:
                pass
            for _ in range(100):
                try:
                    os.kill(args.replace_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.2)
            else:
                raise BackupError("Old downloader has not stopped; no second download was started")
    command = [sys.executable, str(Path(__file__).with_name("availability.py" if args.availability_only else "download.py"))]
    if args.volume is not None:
        command.extend(["--volume", str(args.volume)])
    if args.workers is not None:
        command.extend(["--workers", str(args.workers)])
    if args.journal_path is not None:
        command.extend(["--journal-path", str(args.journal_path)])
    if Path("/usr/bin/caffeinate").exists():
        command = ["/usr/bin/caffeinate", "-im", *command]
    if retry_path.exists():
        retry_path.unlink()
    while True:
        fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as log:
            process = subprocess.Popen(command, env=child_env, stdout=log, stderr=subprocess.STDOUT)
            broker_state("running", child_pid=process.pid)
            return_code = process.wait()
        if args.availability_only:
            broker_state("complete" if return_code == 0 else "failed", return_code=return_code)
            child_env.pop("YANDEX_DISK_TOKEN", None)
            raise SystemExit(return_code)
        if return_code == 0:
            broker_state("complete", return_code=return_code)
            child_env.pop("YANDEX_DISK_TOKEN", None)
            raise SystemExit(0)
        broker_state("failed_waiting_retry", return_code=return_code)
        print("Downloader stopped; credentials retained only in memory while awaiting retry", flush=True)
        while not retry_path.exists():
            time.sleep(1)
        retry_path.unlink()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Authorization interrupted", flush=True)
        raise SystemExit(130) from None
    except Exception as exc:
        print("Authorization stopped: " + type(exc).__name__, flush=True)
        raise SystemExit(1) from None
