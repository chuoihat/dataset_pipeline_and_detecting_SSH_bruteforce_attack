from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from utils.report_utils import (
    ViLogger, html_header, html_footer, html_toc, html_section, html_cards,
    html_table, html_chart, html_debug_log, html_decision,
    html_verification_section, write_html,
    make_bar_chart, make_pie_chart, make_histogram, make_timeline_chart,
)


MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}

SYSLOG_RE = re.compile(
    r'^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$'
)

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ('accepted_password', re.compile(r'Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)')),
    ('accepted_publickey', re.compile(r'Accepted publickey for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)')),
    ('failed_password', re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)')),
    ('invalid_user', re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>\S+)')),
    ('auth_failure', re.compile(r'authentication failure;.*?(?:rhost=(?P<ip>\S+))?.*?user=(?P<user>\S+)')),
    ('max_auth_exceeded', re.compile(r'Maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)')),
    ('session_opened', re.compile(r'session opened for user (?P<user>\S+)')),
    ('session_closed', re.compile(r'session closed for user (?P<user>\S+)')),
    ('disconnect_received', re.compile(r'Received disconnect from (?P<ip>\S+) port (?P<port>\d+):(?P<reason>.*)')),
    ('disconnected_auth_user', re.compile(r'Disconnected from authenticating user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)')),
    ('disconnected', re.compile(r'Disconnected from (?P<ip>\S+) port (?P<port>\d+)')),
]


@dataclass
class ParsedEvent:
    timestamp: str
    host: str
    process: str
    pid: int | None
    event_type: str
    username: str | None
    src_ip: str | None
    src_port: int | None
    message: str
    source_file: str
    line_no: int


def discover_server_dirs(logs_dir: Path) -> list[Path]:
    dirs: list[Path] = []
    for p in sorted(logs_dir.iterdir()):
        if p.is_dir() and re.match(r'^\d+\.\d+$', p.name):
            dirs.append(p)
    return dirs


def discover_secure_files(server_dir: Path) -> list[Path]:
    files: list[Path] = []
    for p in sorted(server_dir.glob('secure*')):
        if p.is_file():
            files.append(p)
    return files


def infer_file_year(file_path: Path, fallback_year: int) -> int:
    m = re.search(r'secure-(\d{4})(\d{2})(\d{2})$', file_path.name)
    if m:
        return int(m.group(1))
    return fallback_year


def parse_ts(mon: str, day: str, time_str: str, year: int) -> datetime | None:
    month = MONTHS.get(mon)
    if month is None:
        return None
    try:
        hh, mm, ss = [int(x) for x in time_str.split(':')]
        return datetime(year, month, int(day), hh, mm, ss)
    except Exception:
        return None


def classify_message(msg: str) -> tuple[str, str | None, str | None, int | None]:
    for event_type, pattern in PATTERNS:
        m = pattern.search(msg)
        if not m:
            continue
        gd = m.groupdict()
        user = gd.get('user')
        ip = gd.get('ip')
        port = gd.get('port')
        src_port = int(port) if port and port.isdigit() else None
        return event_type, user, ip, src_port
    return 'other', None, None, None


def parse_secure_file(file_path: Path, year: int) -> tuple[list[ParsedEvent], list[dict[str, Any]]]:
    events: list[ParsedEvent] = []
    merged_rows: list[dict[str, Any]] = []
    with file_path.open('r', encoding='utf-8', errors='replace') as f:
        for line_no, line in enumerate(f, start=1):
            line = line.rstrip('\n')
            if not line.strip():
                continue
            merged_rows.append({'source_file': file_path.name, 'line_no': line_no, 'line': line})
            m = SYSLOG_RE.match(line)
            if not m:
                continue
            gd = m.groupdict()
            dt = parse_ts(gd['mon'], gd['day'], gd['time'], year)
            if dt is None:
                continue
            event_type, user, ip, port = classify_message(gd['msg'])
            pid = int(gd['pid']) if gd.get('pid') and gd['pid'].isdigit() else None
            events.append(ParsedEvent(
                timestamp=dt.isoformat(sep=' '), host=gd['host'], process=gd['proc'],
                pid=pid, event_type=event_type, username=user, src_ip=ip, src_port=port,
                message=gd['msg'], source_file=file_path.name, line_no=line_no,
            ))
    return events, merged_rows


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def to_dict(e: ParsedEvent) -> dict[str, Any]:
    return {
        'timestamp': e.timestamp, 'host': e.host, 'process': e.process,
        'pid': e.pid, 'event_type': e.event_type, 'username': e.username,
        'src_ip': e.src_ip, 'src_port': e.src_port, 'message': e.message,
        'source_file': e.source_file, 'line_no': e.line_no,
    }


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


def write_csv(path: Path, rows: list[dict[str, Any]], headers: list[str]) -> None:
    import csv
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        w.writerows(rows)


def build_analytics(server_name: str, events: list[ParsedEvent]) -> dict[str, Any]:
    events_sorted = sorted(events, key=lambda x: (x.timestamp, x.source_file, x.line_no))
    event_counts = Counter(e.event_type for e in events_sorted)
    ip_total = Counter(e.src_ip for e in events_sorted if e.src_ip)
    ip_failed = Counter(e.src_ip for e in events_sorted if e.src_ip and e.event_type in {'failed_password', 'invalid_user', 'auth_failure', 'max_auth_exceeded'})
    ip_success = Counter(e.src_ip for e in events_sorted if e.src_ip and e.event_type in {'accepted_password', 'accepted_publickey'})
    failed_usernames = Counter(e.username for e in events_sorted if e.username and e.event_type in {'failed_password', 'invalid_user', 'auth_failure', 'max_auth_exceeded'})
    success_usernames = Counter(e.username for e in events_sorted if e.username and e.event_type in {'accepted_password', 'accepted_publickey'})

    brute_force_candidates: list[dict[str, Any]] = []
    all_ips = sorted(set(list(ip_failed.keys()) + list(ip_success.keys())))
    for ip in all_ips:
        failed = ip_failed.get(ip, 0)
        success = ip_success.get(ip, 0)
        total_auth = failed + success
        ratio = (success / total_auth) if total_auth else 0.0
        uniq_failed_users = len({e.username for e in events_sorted if e.src_ip == ip and e.username and e.event_type in {'failed_password', 'invalid_user', 'auth_failure', 'max_auth_exceeded'}})
        if failed >= 10 or (failed >= 5 and uniq_failed_users >= 3 and ratio < 0.3):
            brute_force_candidates.append({
                'src_ip': ip, 'failed': failed, 'success': success,
                'success_ratio': round(ratio, 4), 'unique_failed_usernames': uniq_failed_users,
            })
    brute_force_candidates.sort(key=lambda x: (x['failed'], x['unique_failed_usernames']), reverse=True)

    success_after_fail: list[dict[str, Any]] = []
    recent_failures: dict[tuple[str, str], datetime] = {}
    for e in events_sorted:
        try:
            dt = datetime.fromisoformat(e.timestamp)
        except Exception:
            continue
        if e.src_ip and e.username and e.event_type in {'failed_password', 'invalid_user', 'auth_failure', 'max_auth_exceeded'}:
            recent_failures[(e.src_ip, e.username)] = dt
        if e.src_ip and e.username and e.event_type in {'accepted_password', 'accepted_publickey'}:
            key = (e.src_ip, e.username)
            fail_dt = recent_failures.get(key)
            if fail_dt and (dt - fail_dt) <= timedelta(minutes=30):
                success_after_fail.append({
                    'timestamp': e.timestamp, 'src_ip': e.src_ip, 'username': e.username,
                    'delta_seconds_from_last_failure': int((dt - fail_dt).total_seconds()),
                })

    opened: dict[tuple[str, int, str], datetime] = {}
    session_durations: list[dict[str, Any]] = []
    for e in events_sorted:
        if e.pid is None or not e.username:
            continue
        try:
            dt = datetime.fromisoformat(e.timestamp)
        except Exception:
            continue
        key = (e.host, e.pid, e.username)
        if e.event_type == 'session_opened':
            opened[key] = dt
        elif e.event_type == 'session_closed':
            start = opened.pop(key, None)
            if start:
                session_durations.append({
                    'host': e.host, 'pid': e.pid, 'username': e.username,
                    'start': start.isoformat(sep=' '), 'end': dt.isoformat(sep=' '),
                    'duration_seconds': int((dt - start).total_seconds()),
                })

    session_duration_summary = {
        'count': len(session_durations),
        'avg_seconds': round(sum(x['duration_seconds'] for x in session_durations) / len(session_durations), 2) if session_durations else 0.0,
        'max_seconds': max((x['duration_seconds'] for x in session_durations), default=0),
    }

    hour_counter = Counter()
    for e in events_sorted:
        try:
            dt = datetime.fromisoformat(e.timestamp)
        except Exception:
            continue
        hour_counter[dt.strftime('%Y-%m-%d %H:00:00')] += 1

    overview = {
        'server': server_name,
        'total_parsed_events': len(events_sorted),
        'distinct_src_ips': len({e.src_ip for e in events_sorted if e.src_ip}),
        'distinct_usernames': len({e.username for e in events_sorted if e.username}),
        'event_type_counts': dict(event_counts),
        'auth_failures_total': int(sum(event_counts.get(k, 0) for k in ['failed_password', 'invalid_user', 'auth_failure', 'max_auth_exceeded'])),
        'auth_success_total': int(sum(event_counts.get(k, 0) for k in ['accepted_password', 'accepted_publickey'])),
    }
    return {
        'overview': overview,
        'top_src_ip_total': [{'src_ip': ip, 'count': int(cnt)} for ip, cnt in ip_total.most_common(20)],
        'top_src_ip_failed': [{'src_ip': ip, 'count': int(cnt)} for ip, cnt in ip_failed.most_common(20)],
        'top_src_ip_success': [{'src_ip': ip, 'count': int(cnt)} for ip, cnt in ip_success.most_common(20)],
        'top_failed_usernames': [{'username': u, 'count': int(c)} for u, c in failed_usernames.most_common(20)],
        'top_success_usernames': [{'username': u, 'count': int(c)} for u, c in success_usernames.most_common(20)],
        'brute_force_candidates': brute_force_candidates,
        'success_after_recent_failure': success_after_fail[:500],
        'session_duration_summary': session_duration_summary,
        'session_durations_top': sorted(session_durations, key=lambda x: x['duration_seconds'], reverse=True)[:200],
        'hourly_activity': [{'hour': h, 'count': int(c)} for h, c in sorted(hour_counter.items())],
    }


def build_step1_html(
    server_name: str,
    analytics: dict[str, Any],
    log: ViLogger,
    file_stats: list[tuple[str, int, int]],
    verifications: list[tuple[str, bool, str]],
) -> str:
    ov = analytics['overview']
    parts = [html_header(
        f'Step 1 — Phân tích SSHD Secure Log: {server_name}',
        'Step 1: Parse SSHD',
        f'Server {server_name} | {ov["total_parsed_events"]:,} sự kiện đã phân tích',
    )]

    sections = [
        ('overview', '1. Tổng quan dữ liệu'),
        ('files', '2. File nguồn đã đọc'),
        ('events', '3. Phân phối loại sự kiện'),
        ('ips', '4. Phân tích IP nguồn'),
        ('users', '5. Phân tích Username'),
        ('bruteforce', '6. Phát hiện Brute-Force'),
        ('timeline', '7. Hoạt động theo thời gian'),
        ('sessions', '8. Phân tích Session Duration'),
        ('verify', '9. Kiểm tra & Xác minh (Verification)'),
        ('debug', '10. Debug Log'),
    ]
    parts.append(html_toc(sections))

    # 1. Overview
    parts.append(html_section('overview', '1. Tổng quan dữ liệu'))
    parts.append(html_cards([
        ('Tổng sự kiện', ov['total_parsed_events']),
        ('IP nguồn duy nhất', ov['distinct_src_ips']),
        ('Username duy nhất', ov['distinct_usernames']),
        ('Xác thực thất bại', ov['auth_failures_total']),
        ('Xác thực thành công', ov['auth_success_total']),
    ]))
    parts.append(
        '<details open><summary><b>Giải thích các chỉ số</b></summary>'
        '<table><tr><th>Chỉ số</th><th>Ý nghĩa</th><th>Cách xác định</th></tr>'
        '<tr><td><b>Tổng sự kiện</b></td>'
        '<td>Tổng số sự kiện SSH đã trích xuất được từ các file <code>/var/log/secure*</code></td>'
        '<td>Đếm tất cả dòng log khớp regex: <code>failed_password</code>, <code>invalid_user</code>, '
        '<code>accepted_password</code>, <code>accepted_publickey</code>, <code>session_opened</code>, '
        '<code>session_closed</code>, <code>max_auth_exceeded</code>, <code>disconnect</code>, …</td></tr>'
        '<tr><td><b>IP nguồn duy nhất</b></td>'
        '<td>Số địa chỉ IP khác nhau đã kết nối SSH đến server này</td>'
        '<td><code>len(set(event.src_ip for all events))</code> — mỗi IP đại diện 1 máy/người dùng</td></tr>'
        '<tr><td><b>Username duy nhất</b></td>'
        '<td>Số tài khoản khác nhau được sử dụng trong các lần đăng nhập</td>'
        '<td><code>len(set(event.username for all events))</code> — bao gồm cả username hợp lệ và sai</td></tr>'
        '<tr><td><b>Xác thực thất bại</b></td>'
        '<td>Tổng số lần đăng nhập SSH thất bại (sai mật khẩu, user không tồn tại, vượt giới hạn)</td>'
        '<td><code>failed_password + invalid_user + auth_failure + max_auth_exceeded</code></td></tr>'
        '<tr><td><b>Xác thực thành công</b></td>'
        '<td>Tổng số lần đăng nhập SSH thành công</td>'
        '<td><code>accepted_password + accepted_publickey</code> — password hoặc SSH key</td></tr>'
        '</table></details>'
    )

    # 2. Files
    parts.append(html_section('files', '2. File nguồn đã đọc'))
    parts.append(html_table(
        ['File', 'Dòng thô', 'Sự kiện đã parse'],
        [[f, lines, evts] for f, lines, evts in file_stats],
    ))

    # 3. Event type distribution
    parts.append(html_section('events', '3. Phân phối loại sự kiện'))
    evt_items = sorted(ov['event_type_counts'].items(), key=lambda x: -x[1])
    parts.append(html_chart(
        make_bar_chart(
            [e[0] for e in evt_items], [e[1] for e in evt_items],
            title=f'Phân phối sự kiện — {server_name}',
            xlabel='Loại sự kiện', ylabel='Số lượng',
            horizontal=True, figsize=(10, max(4, len(evt_items) * 0.4)),
        ),
        f'Tổng: {ov["total_parsed_events"]:,} sự kiện từ server {server_name}',
    ))
    parts.append(html_table(
        ['Loại sự kiện', 'Số lượng', '%'],
        [[k, v, f'{v/max(ov["total_parsed_events"],1)*100:.1f}%'] for k, v in evt_items],
    ))
    parts.append(html_chart(
        make_pie_chart(
            ['Xác thực thất bại', 'Xác thực thành công', 'Khác'],
            [ov['auth_failures_total'], ov['auth_success_total'],
             ov['total_parsed_events'] - ov['auth_failures_total'] - ov['auth_success_total']],
            title=f'Tỉ lệ xác thực — {server_name}',
        ),
        'Phân bố: Thất bại vs Thành công vs Sự kiện khác (session, disconnect, ...)',
    ))

    # 4. IP analysis
    parts.append(html_section('ips', '4. Phân tích IP nguồn'))
    failed_ips = analytics['top_src_ip_failed']
    if failed_ips:
        parts.append('<h3>Top IP xác thực thất bại</h3>')
        parts.append(html_chart(
            make_bar_chart(
                [x['src_ip'] for x in failed_ips[:15]],
                [x['count'] for x in failed_ips[:15]],
                title='Top 15 IP — Xác thực thất bại', ylabel='Số lần fail',
                color='#e53e3e', horizontal=True,
            ),
            'IP có nhiều lần xác thực thất bại nhất → ứng viên tấn công brute-force',
        ))
    success_ips = analytics['top_src_ip_success']
    if success_ips:
        parts.append('<h3>Top IP xác thực thành công</h3>')
        parts.append(html_chart(
            make_bar_chart(
                [x['src_ip'] for x in success_ips[:10]],
                [x['count'] for x in success_ips[:10]],
                title='Top 10 IP — Xác thực thành công', ylabel='Số lần success',
                color='#38a169', horizontal=True,
            ),
            'IP có nhiều lần đăng nhập thành công → nhân viên/hệ thống hợp lệ',
        ))

    # 5. Username analysis
    parts.append(html_section('users', '5. Phân tích Username'))
    fail_users = analytics['top_failed_usernames']
    succ_users = analytics['top_success_usernames']
    if fail_users:
        parts.append(html_chart(
            make_bar_chart(
                [x['username'] for x in fail_users[:15]],
                [x['count'] for x in fail_users[:15]],
                title='Top Username bị brute-force', ylabel='Số lần thất bại',
                color='#e53e3e',
            ),
            'Username bị tấn công nhiều nhất → mục tiêu chính của attacker',
        ))
    if succ_users:
        parts.append(html_chart(
            make_bar_chart(
                [x['username'] for x in succ_users[:10]],
                [x['count'] for x in succ_users[:10]],
                title='Top Username đăng nhập thành công', ylabel='Số lần thành công',
                color='#38a169',
            ),
            'Username hợp lệ thường xuyên đăng nhập → cơ sở dữ liệu benign',
        ))

    # 6. Brute-force candidates
    parts.append(html_section('bruteforce', '6. Phát hiện Brute-Force'))
    bfc = analytics['brute_force_candidates']
    parts.append(html_decision(
        f'Phát hiện {len(bfc)} IP ứng viên Brute-Force',
        f'<p>Tiêu chí: <code>failed ≥ 10</code> HOẶC <code>(failed ≥ 5 AND unique_users ≥ 3 AND success_ratio &lt; 0.3)</code></p>'
        f'<p>Trong {ov["distinct_src_ips"]} IP, có <b>{len(bfc)}</b> IP thỏa mãn tiêu chí brute-force.</p>',
        'Owezarski (2015): IP với failed_count ≥ 10 hoặc high username diversity + low success rate là dấu hiệu brute-force tự động.',
    ))
    if bfc:
        parts.append(html_table(
            ['IP', 'Failed', 'Success', 'Success Ratio', 'Unique Failed Users'],
            [[x['src_ip'], x['failed'], x['success'], f'{x["success_ratio"]:.4f}', x['unique_failed_usernames']] for x in bfc[:30]],
        ))

    sarf = analytics['success_after_recent_failure']
    if sarf:
        parts.append(f'<h3>⚠ Đăng nhập thành công sau thất bại gần đây ({len(sarf)} trường hợp)</h3>')
        parts.append(html_table(
            ['Thời gian', 'IP', 'Username', 'Δ giây từ fail'],
            [[x['timestamp'], x['src_ip'], x['username'], x['delta_seconds_from_last_failure']] for x in sarf[:20]],
        ))

    # 7. Timeline
    parts.append(html_section('timeline', '7. Hoạt động theo thời gian'))
    hourly = analytics['hourly_activity']
    if hourly:
        parts.append(html_chart(
            make_timeline_chart(
                [x['hour'] for x in hourly], [x['count'] for x in hourly],
                title=f'Hoạt động SSH theo giờ — {server_name}',
                ylabel='Số sự kiện',
            ),
            'Biểu đồ timeline cho thấy mật độ sự kiện SSH theo thời gian. Đỉnh cao có thể chỉ ra giờ làm việc (benign) hoặc đợt tấn công (attack).',
        ))

    # 8. Session durations
    parts.append(html_section('sessions', '8. Phân tích Session Duration'))
    sds = analytics['session_duration_summary']
    parts.append(html_cards([
        ('Tổng sessions', sds['count']),
        ('Trung bình (giây)', sds['avg_seconds']),
        ('Dài nhất (giây)', sds['max_seconds']),
    ]))
    dur_list = [x['duration_seconds'] for x in analytics['session_durations_top'] if x['duration_seconds'] > 0]
    if dur_list:
        parts.append(html_chart(
            make_histogram(
                dur_list, title='Phân phối Session Duration',
                xlabel='Thời lượng (giây)', bins=min(50, len(dur_list)),
                log_scale=True,
            ),
            'Trục Y logarithmic. Duration ngắn (< 60s) thường là kết nối tự động/script; dài (> 3600s) là phiên làm việc thật.',
        ))

    # 9. Verification
    parts.append(html_section('verify', '9. Kiểm tra & Xác minh (Verification)'))
    parts.append(html_verification_section(verifications))

    # 10. Debug log
    parts.append(html_section('debug', '10. Debug Log'))
    parts.append(html_debug_log(log))

    parts.append(html_footer())
    return '\n'.join(parts)


def merge_server_logs(server_dir: Path, merged_path: Path, fallback_year: int) -> tuple[list[ParsedEvent], list[dict[str, Any]], list[Path]]:
    files = discover_secure_files(server_dir)
    all_events: list[ParsedEvent] = []
    merged_rows: list[dict[str, Any]] = []
    for fp in files:
        year = infer_file_year(fp, fallback_year)
        events, rows = parse_secure_file(fp, year)
        all_events.extend(events)
        merged_rows.extend(rows)

    def row_key(row: dict[str, Any]) -> tuple[int, str, str, int]:
        m = SYSLOG_RE.match(row['line'])
        if not m:
            return (1, '', row['source_file'], row['line_no'])
        gd = m.groupdict()
        dt = parse_ts(gd['mon'], gd['day'], gd['time'], fallback_year)
        if dt is None:
            return (1, '', row['source_file'], row['line_no'])
        return (0, dt.isoformat(sep=' '), row['source_file'], row['line_no'])

    merged_rows.sort(key=row_key)
    ensure_dir(merged_path.parent)
    with merged_path.open('w', encoding='utf-8') as f:
        for r in merged_rows:
            f.write(f"[{r['source_file']}:{r['line_no']}] {r['line']}\n")
    all_events.sort(key=lambda x: (x.timestamp, x.source_file, x.line_no))
    return all_events, merged_rows, files


def build_global_summary(per_server: dict[str, dict[str, Any]]) -> dict[str, Any]:
    total_events = sum(v['overview']['total_parsed_events'] for v in per_server.values())
    total_fail = sum(v['overview']['auth_failures_total'] for v in per_server.values())
    total_success = sum(v['overview']['auth_success_total'] for v in per_server.values())
    ip_fail = Counter()
    for server_data in per_server.values():
        for item in server_data.get('top_src_ip_failed', []):
            ip_fail[item['src_ip']] += item['count']
    return {
        'servers_analyzed': sorted(per_server.keys()),
        'total_parsed_events': total_events,
        'total_auth_failures': total_fail,
        'total_auth_success': total_success,
        'top_failed_src_ip_global': [{'src_ip': ip, 'count': int(c)} for ip, c in ip_fail.most_common(30)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description='RHEL secure SSHD analyzer with auto merge per server folder')
    _root = Path(__file__).resolve().parent.parent
    parser.add_argument('--logs-dir', default=str(_root / 'logs'))
    parser.add_argument('--out-dir', default=str(_root / 'output' / 'step1'))
    parser.add_argument('--year', type=int, default=datetime.now().year)
    args = parser.parse_args()

    log = ViLogger('Step1')
    logs_dir = Path(args.logs_dir)
    out_dir = Path(args.out_dir)
    ensure_dir(out_dir)

    log.section('BƯỚC 1: PHÂN TÍCH SSHD SECURE LOG')
    log.info(f'Thư mục log nguồn: {logs_dir}')
    log.info(f'Thư mục output: {out_dir}')
    log.info(f'Năm mặc định cho file không có năm: {args.year}')

    server_dirs = discover_server_dirs(logs_dir)
    if not server_dirs:
        log.warn(f'Không tìm thấy thư mục server nào trong {logs_dir}. Cần cấu trúc: 8.68, 8.69, ...')
        return

    log.info(f'Tìm thấy {len(server_dirs)} thư mục server: {[d.name for d in server_dirs]}')

    per_server_results: dict[str, dict[str, Any]] = {}

    for sdir in server_dirs:
        server = sdir.name
        log.section(f'PHÂN TÍCH SERVER: {server}')

        merged_path = out_dir / 'merged' / f'{server}_secure_merged.log'
        events, merged_rows, files = merge_server_logs(sdir, merged_path, fallback_year=args.year)

        if not files:
            log.warn(f'Không tìm thấy file secure* trong {sdir}')
            continue

        log.info(f'Đọc {len(files)} file, tổng {len(merged_rows):,} dòng thô, parse được {len(events):,} sự kiện')

        file_stats: list[tuple[str, int, int]] = []
        for fp in files:
            year = infer_file_year(fp, args.year)
            evts_f, rows_f = parse_secure_file(fp, year)
            file_stats.append((fp.name, len(rows_f), len(evts_f)))
            log.debug(f'  {fp.name}: {len(rows_f):,} dòng → {len(evts_f):,} sự kiện (năm={year})')

        parsed_rows = [to_dict(e) for e in events]
        analytics = build_analytics(server, events)
        ov = analytics['overview']

        log.info(f'Tổng sự kiện đã parse: {ov["total_parsed_events"]:,}')
        log.info(f'IP nguồn duy nhất: {ov["distinct_src_ips"]}')
        log.info(f'Username duy nhất: {ov["distinct_usernames"]}')
        log.info(f'Xác thực thất bại: {ov["auth_failures_total"]:,}')
        log.info(f'Xác thực thành công: {ov["auth_success_total"]:,}')

        for evt, cnt in sorted(ov['event_type_counts'].items(), key=lambda x: -x[1]):
            pct = cnt / max(ov['total_parsed_events'], 1) * 100
            log.debug(f'  Loại sự kiện: {evt} = {cnt:,} ({pct:.1f}%)')

        bfc = analytics['brute_force_candidates']
        log.info(f'Phát hiện {len(bfc)} IP ứng viên brute-force (failed≥10 hoặc failed≥5+unique_users≥3+ratio<0.3)')
        for bf in bfc[:5]:
            log.debug(f'  IP {bf["src_ip"]}: failed={bf["failed"]}, success={bf["success"]}, ratio={bf["success_ratio"]:.4f}, unique_users={bf["unique_failed_usernames"]}')

        sarf = analytics['success_after_recent_failure']
        if sarf:
            log.warn(f'Phát hiện {len(sarf)} lần đăng nhập thành công sau thất bại gần đây (<30 phút) → có thể là compromise')

        sds = analytics['session_duration_summary']
        log.info(f'Sessions: {sds["count"]}, trung bình {sds["avg_seconds"]:.1f}s, dài nhất {sds["max_seconds"]}s')

        # Verification tests
        verifications: list[tuple[str, bool, str]] = []

        verifications.append((
            'Tất cả sự kiện có timestamp hợp lệ',
            all(e.timestamp for e in events),
            f'{len(events):,} sự kiện đều có timestamp',
        ))

        valid_types = set(t for t, _ in PATTERNS) | {'other'}
        all_types = set(e.event_type for e in events)
        verifications.append((
            'Tất cả event_type thuộc danh sách pattern đã định nghĩa',
            all_types.issubset(valid_types),
            f'Các loại: {sorted(all_types)}',
        ))

        auth_fail_events = [e for e in events if e.event_type in {'failed_password', 'invalid_user', 'auth_failure', 'max_auth_exceeded'}]
        auth_fail_with_ip = [e for e in auth_fail_events if e.src_ip]
        pct_ip = len(auth_fail_with_ip) / max(len(auth_fail_events), 1) * 100
        verifications.append((
            'Sự kiện auth failure có src_ip ≥ 95%',
            pct_ip >= 95.0,
            f'{len(auth_fail_with_ip)}/{len(auth_fail_events)} ({pct_ip:.1f}%) có IP nguồn',
        ))

        success_events = [e for e in events if e.event_type in {'accepted_password', 'accepted_publickey'}]
        success_with_user = [e for e in success_events if e.username]
        pct_user = len(success_with_user) / max(len(success_events), 1) * 100
        verifications.append((
            'Sự kiện success có username ≥ 95%',
            pct_user >= 95.0,
            f'{len(success_with_user)}/{len(success_events)} ({pct_user:.1f}%) có username',
        ))

        n_with_pid = sum(1 for e in events if e.pid is not None)
        pct_pid = n_with_pid / max(len(events), 1) * 100
        verifications.append((
            'Sự kiện SSHD có PID ≥ 80%',
            pct_pid >= 80.0,
            f'{n_with_pid}/{len(events)} ({pct_pid:.1f}%) có PID → cần thiết cho session grouping ở Step 2',
        ))

        for name, passed, detail in verifications:
            if passed:
                log.ok(f'VERIFY: {name} → PASS ({detail})')
            else:
                log.fail(f'VERIFY: {name} → FAIL ({detail})')

        # Write outputs
        server_dir_out = out_dir / server
        ensure_dir(server_dir_out)

        write_json(server_dir_out / f'{server}_parsed_events.json', parsed_rows)
        write_csv(
            server_dir_out / f'{server}_parsed_events.csv', parsed_rows,
            headers=['timestamp', 'host', 'process', 'pid', 'event_type', 'username', 'src_ip', 'src_port', 'message', 'source_file', 'line_no'],
        )
        write_json(server_dir_out / f'{server}_analysis.json', analytics)
        write_csv(server_dir_out / f'{server}_bruteforce_candidates.csv', analytics['brute_force_candidates'], headers=['src_ip', 'failed', 'success', 'success_ratio', 'unique_failed_usernames'])
        write_csv(server_dir_out / f'{server}_top_failed_src_ip.csv', analytics['top_src_ip_failed'], headers=['src_ip', 'count'])
        write_csv(server_dir_out / f'{server}_top_success_src_ip.csv', analytics['top_src_ip_success'], headers=['src_ip', 'count'])
        write_csv(server_dir_out / f'{server}_success_after_recent_failure.csv', analytics['success_after_recent_failure'], headers=['timestamp', 'src_ip', 'username', 'delta_seconds_from_last_failure'])
        write_csv(server_dir_out / f'{server}_hourly_activity.csv', analytics['hourly_activity'], headers=['hour', 'count'])

        log.info(f'Đã ghi JSON, CSV, analytics cho server {server}')

        # Build comprehensive HTML report
        html_content = build_step1_html(server, analytics, log, file_stats, verifications)
        html_path = server_dir_out / f'{server}_analysis.html'
        write_html(html_path, html_content)
        log.ok(f'HTML report → {html_path}')

        per_server_results[server] = analytics

    if per_server_results:
        global_summary = build_global_summary(per_server_results)
        write_json(out_dir / 'global_summary.json', global_summary)
        log.ok(f'Phân tích hoàn tất cho {len(per_server_results)} server. Output: {out_dir}')
    else:
        log.warn('Không có dữ liệu server nào được phân tích.')


if __name__ == '__main__':
    main()
