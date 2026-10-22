#!/usr/bin/env python3
"""Read-only live terminal view of the backup. Never reads tokens or logs."""
import argparse
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time
import unicodedata

BASE = Path(__file__).resolve().parent
PHASES = {
    'downloading': 'Докачка файлов', 'downloading_missing': 'Дополнительные файлы',
    'scanning_folders': 'Сверка папок', 'checking_local_files': 'Проверка сохранённых файлов',
    'loading_failed_inventory': 'Загрузка очереди докачки', 'loading_saved_inventory': 'Загрузка сохранённого списка',
    'listing_files': 'Сбор списка файлов', 'mapping_paths': 'Подготовка имён',
    'creating_folders': 'Создание папок', 'authenticating': 'Проверка доступа',
    'complete': 'Завершено', 'complete_with_errors': 'Завершено с очередью недоступных файлов',
    'source_changed': 'Состав облака изменился', 'failed': 'Загрузка остановлена', 'paused': 'Пауза',
}
STAGES = {'getting_link': 'получение ссылки', 'opening': 'подключение',
          'reading': 'скачивание', 'verifying': 'проверка размера и MD5', 'retrying': 'ожидание повторной попытки'}


def clean(value):
    text = str(value)
    return ''.join(ch if unicodedata.category(ch) not in ('Cc', 'Cf') else f'\\u{ord(ch):04x}' for ch in text)


def number(value):
    return value if type(value) is int and value >= 0 else 0


def read_json(path, limit=128 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'r', encoding='utf-8') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > limit:
            raise ValueError('unsafe status file')
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError('invalid status')
    return value


def optional_json(path):
    try:
        return read_json(path)
    except FileNotFoundError:
        return {}


def identities(progress, broker):
    child = broker.get('child_pid') or (broker.get('child_identity') or {}).get('pid')
    return child, progress.get('retry_only_failed'), progress.get('files_total')


def active(progress):
    value = progress.get('active_transfers', {})
    return {k:v for k,v in value.items() if isinstance(k, str) and isinstance(v, dict)} if isinstance(value, dict) else {}


def rates(previous, progress, elapsed, same_run=True):
    if previous is None or not same_run or elapsed <= 0:
        return None, None
    verified = number(progress.get('bytes_verified')) - number(previous.get('bytes_verified'))
    if verified < 0:
        return None, None
    old = active(previous)
    # Removed transfers are not credited without a final byte counter. This is
    # observed writing between snapshots, not an exact network speed meter.
    written = sum(max(0, number(v.get('bytes_written')) - number(old.get(k, {}).get('bytes_written')))
                  for k,v in active(progress).items() if v.get('stage') != 'retrying')
    return verified / elapsed / 1e6, written / elapsed / 1e6


def summary(progress, retry, verified_rate=None, written_rate=None):
    verified_files, verified_bytes = number(progress.get('files_verified')), number(progress.get('bytes_verified'))
    overall_files, overall_bytes = verified_files, verified_bytes
    if progress.get('retry_only_failed') is True:
        previous = retry.get('previous_verified', {})
        if isinstance(previous, dict):
            overall_files += number(previous.get('files_verified'))
            overall_bytes += number(previous.get('bytes_verified'))
    counts = {}
    written = 0
    for transfer in active(progress).values():
        stage = transfer.get('stage', 'unknown')
        if stage in STAGES:
            counts[stage] = counts.get(stage, 0) + 1
        if stage != 'retrying':
            written += number(transfer.get('bytes_written'))
    files_label = f'{overall_files:,}'.replace(',', ' ')
    lines = [f"{PHASES.get(progress.get('phase'), 'Подготовка')}. Потоков загрузки: {number(progress.get('workers'))}.",
             f'Сохранено и проверено всего: {files_label} файлов, {overall_bytes/1e9:.2f} ГБ.']
    if progress.get('phase') == 'complete' and progress.get('prior_copy_integrity_confirmed') is False:
        lines[0] = 'Очередь докачки завершена. Перенесённая ранее копия ещё не прошла повторную проверку целостности.'
    attempts_max = number(progress.get('download_attempts_max'))
    if attempts_max:
        lines.append(f'Попыток на файл за проход: до {attempts_max}.')
    if progress.get('retry_only_failed') is True:
        lines.append(f"В этой очереди проверено: {verified_files}/{number(progress.get('files_total'))}, {verified_bytes/1e9:.2f}/{number(progress.get('bytes_total'))/1e9:.2f} ГБ.")
        pending = progress.get('files_pending_count')
        if type(pending) is int and progress.get('phase') in ('downloading', 'downloading_missing'):
            finished = max(0, number(progress.get('files_total')) - pending)
            lines.append(f'Завершено обработок: {finished}; неудачных: {max(0, finished-verified_files)}. Осталось обработать, включая активные: {pending}.')
    lines.append(f"В очереди недокачки: {number(progress.get('files_failed_count'))} файлов. HTTP 429 от API: {number(progress.get('api_http_429_count'))}.")
    if counts:
        lines.append('Сейчас: ' + ', '.join(f'{STAGES[k]}: {v}' for k,v in sorted(counts.items())) + f'. Непроверенных данных в активных загрузках: {written/1e9:.2f} ГБ.')
    if progress.get('phase') == 'scanning_folders':
        lines.append(f"Потоков сверки: {number(progress.get('scan_workers'))}; папок обработано: {number(progress.get('folders_scanned'))}; активных: {number(progress.get('scan_active_directories'))}; текущая очередь: {number(progress.get('folders_remaining'))}.")
    if verified_rate is not None:
        lines.append(f'Скорость готовых файлов: {verified_rate:.2f} МБ/с. Наблюдаемая запись: ≈{written_rate:.2f} МБ/с (≈{written_rate*8:.1f} Мбит/с).')
    updated = progress.get('updated_at')
    if isinstance(updated, str):
        try:
            age = datetime.now().astimezone().timestamp() - datetime.fromisoformat(updated).timestamp()
            if age > 120:
                lines.append(f'Статус не обновлялся {int(age)} секунд.')
        except ValueError:
            pass
    return '\n'.join(lines)


def file_names(progress):
    destination = progress.get('destination')
    if not isinstance(destination, str) or not Path(destination).is_absolute():
        return {}
    metadata = read_json(Path(destination) / 'manifest.json')
    names = {}
    for item in metadata.get('files', []):
        if isinstance(item, dict) and isinstance(item.get('path'), str):
            key = hashlib.sha256(item['path'].encode()).hexdigest()
            names[key] = (item['path'].removeprefix('disk:/'), number(item.get('size')))
    return names


def transfer_line(key, transfer, names):
    name, size = names.get(key, (key[:12], 0))
    written = number(transfer.get('bytes_written'))
    label = STAGES.get(transfer.get('stage'), 'подготовка')
    text = f'{label}: {clean(name)} | получено {written/1e6:.1f} МБ'
    attempt, attempts_max = number(transfer.get('attempt')), number(transfer.get('attempts_max'))
    if attempt and attempts_max:
        text += f' | попытка {attempt}/{attempts_max}'
    if size:
        text += f' / {size/1e6:.1f} МБ ({min(100, written/size*100):.1f}%)'
    code = transfer.get('http_code')
    if type(code) is int and code > 0:
        text += f' | HTTP {code}'
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, default=BASE)
    parser.add_argument('--interval', type=float, default=5)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--summary-only', action='store_true')
    args = parser.parse_args()
    if not math.isfinite(args.interval) or args.interval < .5:
        parser.error('--interval must be finite and at least 0.5')
    state = args.state_dir.resolve()
    previous = None
    previous_time = None
    previous_identity = None
    names, reported = {}, {}
    print('Живой монитор миграции. Ctrl+C закрывает только монитор. Токены и ссылки скачивания не выводятся.', flush=True)
    while True:
        try:
            p = read_json(state / 'progress.json')
            b = optional_json(state / 'broker.json')
            r = optional_json(state / 'retry-remaining.json')
            now = time.monotonic()
            identity = identities(p, b)
            same_run = identity == previous_identity
            vr, wr = rates(previous, p, now-previous_time if previous_time is not None else 0, same_run)
            stamp = datetime.now().astimezone().strftime('%H:%M:%S')
            print(f'\n[{stamp}]\n{summary(p, r, vr, wr)}', flush=True)
            if not args.summary_only:
                if not same_run:
                    reported = {}
                    try:
                        names = file_names(p)
                    except (OSError, ValueError):
                        names = {}
                for key, transfer in sorted(active(p).items()):
                    old = reported.get(key)
                    written = number(transfer.get('bytes_written'))
                    attempt = number(transfer.get('attempt'))
                    if old is None or old[0] != transfer.get('stage') or old[2] != attempt or written-old[1] >= 64*1024*1024:
                        print(f'[{stamp}] {transfer_line(key, transfer, names)}', flush=True)
                        reported[key] = (transfer.get('stage'), written, attempt)
                reported = {key:value for key,value in reported.items() if key in active(p)}
            previous, previous_time, previous_identity = p, now, identity
        except (OSError, ValueError) as exc:
            print(f'Статус временно недоступен ({type(exc).__name__}).', flush=True)
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nМонитор закрыт.')
