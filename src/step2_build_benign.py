from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from utils.report_utils import (
    ViLogger,
    html_header,
    html_footer,
    html_toc,
    html_section,
    html_cards,
    html_table,
    html_chart,
    html_debug_log,
    html_decision,
    html_verification_section,
    write_html,
    make_bar_chart,
    make_pie_chart,
    make_histogram,
)


# ---------------------------------------------------------------------------
# FIX #2: Single fixed dst_ip — matches attack logs (10.0.0.4)
# Prevents the ML model from learning a shortcut based on variable dst_ip
# in benign vs single dst_ip in attack.
# ---------------------------------------------------------------------------
DEFAULT_DST_IP   = '10.0.0.4'
DEFAULT_DST_PORT = 22

# ---------------------------------------------------------------------------
# FIX (improvement): Expanded CLIENT_VERSION_POOL for enterprise realism
# Weighted toward common RHEL/enterprise clients to avoid fingerprint bias.
# ---------------------------------------------------------------------------
CLIENT_VERSION_POOL = [
    'SSH-2.0-OpenSSH_7.4',              # RHEL 7 default
    'SSH-2.0-OpenSSH_8.0',              # RHEL 8 default
    'SSH-2.0-OpenSSH_8.7',              # RHEL 9 default
    'SSH-2.0-OpenSSH_9.0',
    'SSH-2.0-OpenSSH_9.3',
    'SSH-2.0-OpenSSH_for_Windows_8.1',
    'SSH-2.0-OpenSSH_for_Windows_9.5',
    'SSH-2.0-PuTTY_Release_0.78',
    'SSH-2.0-PuTTY_Release_0.81',
    'SSH-2.0-WinSCP_5.21.5',
    'SSH-2.0-JSCH-0.1.54',              # Java automation (banks use this)
    'SSH-2.0-paramiko_3.4.0',           # Python automation
]
CLIENT_VERSION_WEIGHTS = [
    0.15, 0.20, 0.10, 0.08, 0.05,      # OpenSSH variants
    0.05, 0.03,                          # Windows OpenSSH
    0.15, 0.07,                          # PuTTY
    0.05,                                # WinSCP
    0.04,                                # JSCH
    0.03,                                # paramiko
]

AUTH_EVENT_TYPES = {
    'accepted_password',
    'accepted_publickey',
    'failed_password',
    'invalid_user',
    'auth_failure',
    'max_auth_exceeded',
}
CLOSE_EVENT_TYPES = {
    'session_closed',
    'disconnect_received',
    'disconnected_auth_user',
    'disconnected',
}
RELEVANT_EVENT_TYPES = AUTH_EVENT_TYPES | CLOSE_EVENT_TYPES | {'session_opened'}


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------
def to_iso_z(ts: str) -> str:
    dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def add_millis(ts_iso_z: str, millis: int) -> str:
    fmt = '%Y-%m-%dT%H:%M:%S.%fZ' if '.' in ts_iso_z else '%Y-%m-%dT%H:%M:%SZ'
    dt = datetime.strptime(ts_iso_z, fmt) + timedelta(milliseconds=millis)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def load_parsed_events(path: Path) -> list[dict[str, Any]]:
    with path.open('r', encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, list):
        return []
    return [x for x in data if isinstance(x, dict)]


# ---------------------------------------------------------------------------
# FIX #3: Load Vietnamese IPs from IPvn.log for realistic src_ip remapping
# ---------------------------------------------------------------------------
def load_vn_ips(path: Path) -> list[str]:
    ips: list[str] = []
    with path.open('r', encoding='utf-8') as f:
        for line in f:
            stripped = line.strip()
            if stripped and stripped != 'IP' and not stripped.startswith('#'):
                ips.append(stripped)
    return ips


def build_ip_mapping(
    events: list[dict[str, Any]],
    vn_ips: list[str],
    seed: int = 42,
) -> dict[str, str]:
    """Deterministic mapping: each unique internal src_ip → a unique Vietnamese IP."""
    unique_src = sorted({
        str(e['src_ip'])
        for e in events
        if e.get('src_ip') not in (None, '')
    })

    rng = random.Random(seed)
    pool = list(vn_ips)
    rng.shuffle(pool)

    mapping: dict[str, str] = {}
    for i, internal_ip in enumerate(unique_src):
        mapping[internal_ip] = pool[i % len(pool)]
    return mapping


# ---------------------------------------------------------------------------
# FIX #1: Session model — group RHEL events by (host, pid)
#
# In real sshd, one PID handles one SSH connection.  Multiple auth attempts
# (failed_password → failed_password → accepted_password) under the same PID
# belong to the SAME Cowrie session, not separate ones.
#
# Previous code created a new session per event (using line_no in the hash),
# which inflated session count and destroyed multi-attempt behavioral patterns.
# ---------------------------------------------------------------------------
def build_enriched_benign(
    events: list[dict[str, Any]],
    sensor_name: str,
    ip_mapping: dict[str, str],
    dst_ip: str = DEFAULT_DST_IP,
    dst_port: int = DEFAULT_DST_PORT,
    log: ViLogger | None = None,
) -> list[dict[str, Any]]:
    rng = random.Random(42)

    # Group by (host, pid) — each group = one SSH connection
    pid_groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    skipped_no_pid = 0
    skipped_irrelevant = 0
    for e in events:
        et = str(e.get('event_type') or '')
        if et not in RELEVANT_EVENT_TYPES:
            skipped_irrelevant += 1
            continue
        host = str(e.get('host') or 'unknown-host')
        pid = e.get('pid')
        if not isinstance(pid, int):
            skipped_no_pid += 1
            continue
        pid_groups[(host, pid)].append(e)

    if log:
        log.debug(f'Nhóm theo (host, pid): {len(pid_groups):,} nhóm')
        log.debug(f'Bỏ qua {skipped_irrelevant:,} event không liên quan, {skipped_no_pid:,} event thiếu PID')

    output: list[dict[str, Any]] = []
    skipped_no_auth = 0
    skipped_no_ip = 0

    for (host, pid), group in pid_groups.items():
        group.sort(key=lambda x: (x.get('timestamp', ''), int(x.get('line_no', 0))))

        auth_events  = [e for e in group if str(e.get('event_type') or '') in AUTH_EVENT_TYPES]
        open_events  = [e for e in group if str(e.get('event_type') or '') == 'session_opened']
        close_events = [e for e in group if str(e.get('event_type') or '') in CLOSE_EVENT_TYPES]

        if not auth_events:
            skipped_no_auth += 1
            continue

        # Resolve src_ip from the first auth event that has one
        first_auth_with_ip = next(
            (ae for ae in auth_events if ae.get('src_ip') not in (None, '')),
            None,
        )
        if first_auth_with_ip is None:
            skipped_no_ip += 1
            continue

        original_src = str(first_auth_with_ip['src_ip'])
        src_port = first_auth_with_ip.get('src_port')
        if not isinstance(src_port, int):
            src_port = rng.randint(1024, 65535)

        remapped_src = ip_mapping.get(original_src, original_src)

        # One session ID per (host, pid) — NOT per event
        session_id = hashlib.sha1(f'{host}|{pid}'.encode('utf-8')).hexdigest()[:12]

        client_ver = rng.choices(CLIENT_VERSION_POOL, weights=CLIENT_VERSION_WEIGHTS, k=1)[0]

        # Compute realistic duration from first auth → last close
        first_ts_str = str(auth_events[0].get('timestamp') or '')
        first_ts = datetime.strptime(first_ts_str, '%Y-%m-%d %H:%M:%S')

        duration = 0.0
        if close_events:
            last_close_str = str(close_events[-1].get('timestamp') or '')
            last_close_ts = datetime.strptime(last_close_str, '%Y-%m-%d %H:%M:%S')
            duration = max(0.0, (last_close_ts - first_ts).total_seconds())
        elif open_events:
            duration = rng.uniform(300, 7200)

        first_iso = to_iso_z(first_ts_str)

        # --- cowrie.session.connect (once per session) ---
        output.append({
            'eventid': 'cowrie.session.connect',
            'src_ip': remapped_src,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'session': session_id,
            'protocol': 'ssh',
            'message': (
                f'New connection: {remapped_src}:{src_port} '
                f'({dst_ip}:{dst_port}) [session: {session_id}]'
            ),
            'sensor': sensor_name,
            'timestamp': add_millis(first_iso, 0),
        })

        # --- cowrie.client.version (once, right after connect) ---
        output.append({
            'eventid': 'cowrie.client.version',
            'version': client_ver,
            'message': f'Remote SSH version: {client_ver}',
            'sensor': sensor_name,
            'timestamp': add_millis(first_iso, 80),
            'src_ip': remapped_src,
            'session': session_id,
        })

        # --- login events (one per auth attempt in this SSH connection) ---
        for idx, ae in enumerate(auth_events):
            ae_ts = to_iso_z(str(ae.get('timestamp') or first_ts_str))
            ae_et = str(ae.get('event_type') or '')
            username = ae.get('username') or 'unknown'

            if ae_et in {'accepted_password', 'accepted_publickey'}:
                output.append({
                    'eventid': 'cowrie.login.success',
                    'username': username,
                    'password': None,
                    'message': f'login attempt [{username}/<unknown>] succeeded',
                    'sensor': sensor_name,
                    'timestamp': add_millis(ae_ts, 100 + 50 * idx),
                    'src_ip': remapped_src,
                    'session': session_id,
                })
            else:
                output.append({
                    'eventid': 'cowrie.login.failed',
                    'username': username,
                    'password': None,
                    'message': f'login attempt [{username}/<unknown>] failed',
                    'sensor': sensor_name,
                    'timestamp': add_millis(ae_ts, 100 + 50 * idx),
                    'src_ip': remapped_src,
                    'session': session_id,
                })

        # --- cowrie.session.closed (once, with real duration) ---
        if close_events:
            close_iso = to_iso_z(str(close_events[-1].get('timestamp') or first_ts_str))
        else:
            close_iso = add_millis(first_iso, int(duration * 1000))

        output.append({
            'eventid': 'cowrie.session.closed',
            'duration': round(duration, 2),
            'message': f'Connection lost after {int(duration)} seconds',
            'sensor': sensor_name,
            'timestamp': close_iso,
            'src_ip': remapped_src,
            'session': session_id,
        })

    if log:
        log.debug(f'Bỏ qua {skipped_no_auth:,} nhóm không có auth event')
        log.debug(f'Bỏ qua {skipped_no_ip:,} nhóm không có src_ip')
        log.info(f'Tạo {len(output):,} event Cowrie từ {len(pid_groups) - skipped_no_auth - skipped_no_ip:,} session hợp lệ')

    output.sort(key=lambda x: x.get('timestamp', ''))
    return output


def build_normal_login_only(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_session: dict[str, list[dict[str, Any]]] = {}
    for e in events:
        sid = str(e.get('session') or '')
        if not sid:
            continue
        by_session.setdefault(sid, []).append(e)

    out: list[dict[str, Any]] = []
    for sid, rows in by_session.items():
        eids = {r.get('eventid') for r in rows}
        if 'cowrie.session.connect' in eids and 'cowrie.login.success' in eids and 'cowrie.client.version' in eids:
            out.extend(sorted(rows, key=lambda x: x.get('timestamp', '')))

    out.sort(key=lambda x: x.get('timestamp', ''))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Build benign Cowrie-like logs from parsed OpenSSH events',
    )
    _root = Path(__file__).resolve().parent.parent
    parser.add_argument('--input-68', default=str(_root / 'output' / 'step1' / '8.68' / '8.68_parsed_events.json'))
    parser.add_argument('--input-69', default=str(_root / 'output' / 'step1' / '8.69' / '8.69_parsed_events.json'))
    parser.add_argument('--ipvn', default=str(_root / 'logs' / 'IPvn.log'))
    parser.add_argument('--output', default=str(_root / 'output' / 'step2' / 'cowrie_benign_corp.json'))
    parser.add_argument('--output-normal-login', default=str(_root / 'output' / 'step2' / 'corp_ssh_benign_cowrie.normal_login.json'))
    parser.add_argument('--sensor', default='corp-ssh-benign')
    parser.add_argument('--dst-ip', default=DEFAULT_DST_IP)
    parser.add_argument('--dst-port', type=int, default=DEFAULT_DST_PORT)
    args = parser.parse_args()

    log = ViLogger('Step2')
    log.section('STEP 2 — Xây dựng log benign từ OpenSSH → Cowrie format')
    log.info('Bắt đầu xây dựng dữ liệu SSH benign dạng Cowrie')

    # ── Load parsed events ──
    log.section('Tải dữ liệu đầu vào')
    p68 = load_parsed_events(Path(args.input_68))
    log.info(f'Đã tải {len(p68):,} event từ server 8.68')
    log.debug(f'  Đường dẫn: {args.input_68}')

    p69 = load_parsed_events(Path(args.input_69))
    log.info(f'Đã tải {len(p69):,} event từ server 8.69')
    log.debug(f'  Đường dẫn: {args.input_69}')

    merged = p68 + p69
    log.ok(f'Tổng cộng: {len(merged):,} event từ 2 server')

    # Event type distribution from source
    src_event_types = Counter(str(e.get('event_type', '')) for e in merged)
    log.debug(f'Phân bố event_type nguồn: {len(src_event_types)} loại')
    for et, cnt in src_event_types.most_common(10):
        log.debug(f'  {et}: {cnt:,}')

    # ── Load Vietnamese IPs ──
    log.section('Tải danh sách IP Việt Nam')
    vn_ip_path = Path(args.ipvn)
    if vn_ip_path.exists():
        vn_ips = load_vn_ips(vn_ip_path)
        log.ok(f'Đã tải {len(vn_ips):,} IP Việt Nam từ {args.ipvn}')
    else:
        vn_ips = []
        log.warn(f'Không tìm thấy IPvn.log tại {args.ipvn} — dùng phương pháp hash để remap')

    # ── Build IP mapping ──
    log.section('Xây dựng bảng ánh xạ IP')
    if vn_ips:
        ip_mapping = build_ip_mapping(merged, vn_ips)
        log.info(f'Sử dụng IP Việt Nam thật — {len(ip_mapping):,} ánh xạ')
    else:
        unique_src = sorted({
            str(e['src_ip']) for e in merged if e.get('src_ip') not in (None, '')
        })
        ip_mapping = {}
        for src in unique_src:
            h = hashlib.sha1(src.encode('utf-8')).hexdigest()
            o2 = int(h[0:2], 16) % 200 + 20
            o3 = int(h[2:4], 16)
            o4 = int(h[4:6], 16)
            ip_mapping[src] = f'{o2}.{o3}.{o4}.{(o4 % 253) + 1}'
        log.warn(f'Dùng hash-based remap — {len(ip_mapping):,} ánh xạ')

    log.info(f'Bảng ánh xạ IP ({len(ip_mapping)} mục):')
    for src, dst in sorted(ip_mapping.items()):
        log.debug(f'  {src} → {dst}')

    # ── Build enriched benign ──
    log.section('Tạo dữ liệu Cowrie benign')
    log.info(f'Sensor: {args.sensor} | dst_ip: {args.dst_ip} | dst_port: {args.dst_port}')

    enriched = build_enriched_benign(
        merged,
        sensor_name=args.sensor,
        ip_mapping=ip_mapping,
        dst_ip=args.dst_ip,
        dst_port=args.dst_port,
        log=log,
    )

    # ── Build normal login subset ──
    log.section('Lọc subset normal_login (chỉ session đăng nhập thành công)')
    normal_login = build_normal_login_only(enriched)
    log.ok(f'Đã lọc {len(normal_login):,} event normal_login')

    # ── Write output files ──
    log.section('Ghi file đầu ra')

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        for obj in enriched:
            f.write(json.dumps(obj, ensure_ascii=False) + '\n')
    log.ok(f'Đã ghi {len(enriched):,} event → {out_path}')

    out_normal = Path(args.output_normal_login)
    out_normal.parent.mkdir(parents=True, exist_ok=True)
    with out_normal.open('w', encoding='utf-8') as f:
        for obj in normal_login:
            f.write(json.dumps(obj, ensure_ascii=False) + '\n')
    log.ok(f'Đã ghi {len(normal_login):,} event → {out_normal}')

    # ── Compute stats ──
    log.section('Thống kê kết quả')

    counts = Counter(e.get('eventid', 'N/A') for e in enriched)
    sessions = {e.get('session') for e in enriched}
    durations: dict[str, float] = {}
    for e in enriched:
        if e.get('eventid') == 'cowrie.session.closed':
            durations[e.get('session')] = e.get('duration', 0.0)

    log.ok(f'Tổng: {len(enriched):,} event trong {len(sessions):,} session')
    for k in sorted(counts.keys()):
        log.debug(f'  {k}: {counts[k]:,}')

    dur_vals = list(durations.values())
    nonzero = [d for d in dur_vals if d > 0]
    if nonzero:
        log.info(f'Thời lượng session: min={min(nonzero):.1f}s, max={max(nonzero):.1f}s, trung bình={sum(nonzero)/len(nonzero):.1f}s')
        log.debug(f'  Tổng session có close event: {len(dur_vals):,}')
        log.debug(f'  Session có duration > 0: {len(nonzero):,}')

    # Client version distribution
    client_versions = Counter(
        e.get('version', '') for e in enriched if e.get('eventid') == 'cowrie.client.version'
    )

    # Username distribution
    usernames = Counter(
        e.get('username', '') for e in enriched
        if e.get('eventid') in ('cowrie.login.success', 'cowrie.login.failed') and e.get('username')
    )

    # Unique src_ips in output
    unique_src_ips = {e.get('src_ip') for e in enriched if e.get('src_ip')}

    # Normal login session stats
    normal_sessions = {e.get('session') for e in normal_login}

    log.info(f'IP nguồn duy nhất: {len(unique_src_ips):,}')
    log.info(f'Username duy nhất: {len(usernames):,}')
    log.info(f'Session normal_login: {len(normal_sessions):,}')

    # ══════════════════════════════════════════════════════════════════════
    # HTML REPORT
    # ══════════════════════════════════════════════════════════════════════
    log.section('Tạo báo cáo HTML')

    html_parts: list[str] = []

    html_parts.append(html_header(
        'Step 2 — Xây dựng log benign (OpenSSH → Cowrie)',
        'step2_build_benign',
        subtitle=f'Sensor: {args.sensor} | dst_ip: {args.dst_ip}:{args.dst_port}',
    ))

    toc_items = [
        ('overview', '1. Tổng quan'),
        ('charts', '2. Biểu đồ phân tích'),
        ('ip-mapping', '3. Bảng ánh xạ IP'),
        ('decisions', '4. Quyết định thiết kế'),
        ('verification', '5. Kiểm tra xác minh'),
        ('debug-log', '6. Debug log'),
    ]
    html_parts.append(html_toc(toc_items))

    # ── Section 1: Overview ──
    html_parts.append(html_section('overview', '1. Tổng quan'))
    html_parts.append(html_cards([
        ('Event từ 8.68', len(p68)),
        ('Event từ 8.69', len(p69)),
        ('Tổng event nguồn', len(merged)),
        ('Event Cowrie đầu ra', len(enriched)),
        ('Số session', len(sessions)),
        ('IP ánh xạ', len(ip_mapping)),
        ('IP nguồn duy nhất', len(unique_src_ips)),
        ('Username duy nhất', len(usernames)),
        ('Event normal_login', len(normal_login)),
        ('Session normal_login', len(normal_sessions)),
    ]))
    html_parts.append(
        '<details open><summary><b>Giải thích các chỉ số</b></summary>'
        '<table><tr><th>Chỉ số</th><th>Ý nghĩa</th><th>Cách xác định</th></tr>'
        '<tr><td><b>Event từ 8.68 / 8.69</b></td>'
        '<td>Số sự kiện SSH đã parse từ mỗi server RHEL nội bộ</td>'
        '<td>Đọc file <code>output/step1/8.68/8.68_parsed_events.json</code> và <code>8.69</code> — '
        'đầu ra của Step 1</td></tr>'
        '<tr><td><b>Tổng event nguồn</b></td>'
        '<td>Tổng event từ cả 2 server gộp lại trước khi chuyển đổi format</td>'
        '<td><code>len(events_8.68) + len(events_8.69)</code></td></tr>'
        '<tr><td><b>Event Cowrie đầu ra</b></td>'
        '<td>Số event sau khi chuyển đổi từ OpenSSH syslog → Cowrie JSONL format</td>'
        '<td>Mỗi event OpenSSH (login, session open/close) được mapping sang eventid Cowrie tương ứng. '
        'Số lượng có thể khác nguồn vì thêm event <code>cowrie.session.connect</code> '
        'và <code>cowrie.session.closed</code> cho mỗi session</td></tr>'
        '<tr><td><b>Số session</b></td>'
        '<td>Tổng số phiên SSH riêng biệt (= số kết nối SSH)</td>'
        '<td>Nhóm theo <code>(host, PID)</code> trong OpenSSH — mỗi PID là 1 tiến trình sshd phục vụ 1 kết nối</td></tr>'
        '<tr><td><b>IP ánh xạ</b></td>'
        '<td>Số cặp ánh xạ IP nội bộ → IP Việt Nam</td>'
        '<td>IP nội bộ ngân hàng (10.x.x.x) được thay bằng IP từ <code>logs/IPvn.log</code> '
        'để tránh lộ thông tin mạng nội bộ và tạo tính đa dạng</td></tr>'
        '<tr><td><b>IP nguồn duy nhất</b></td>'
        '<td>Số IP khác nhau sau khi ánh xạ</td>'
        '<td><code>len(set(src_ip))</code> trong toàn bộ event đầu ra</td></tr>'
        '<tr><td><b>Username duy nhất</b></td>'
        '<td>Số tài khoản khác nhau xuất hiện trong các event đăng nhập</td>'
        '<td>Đếm username từ event <code>cowrie.login.success</code> và <code>cowrie.login.failed</code></td></tr>'
        '<tr><td><b>Event normal_login</b></td>'
        '<td>Số event thuộc các session có ít nhất 1 lần đăng nhập thành công</td>'
        '<td>Lọc session chứa event <code>cowrie.login.success</code>, '
        'rồi lấy toàn bộ event của các session đó (bao gồm cả failed nếu có)</td></tr>'
        '<tr><td><b>Session normal_login</b></td>'
        '<td>Số session có ít nhất 1 lần đăng nhập thành công</td>'
        '<td>Tập con của "Số session" — session chỉ có <code>login.failed</code> rồi ngắt kết nối '
        '(gõ sai mật khẩu rồi bỏ cuộc) sẽ không nằm trong nhóm này</td></tr>'
        '</table></details>'
    )

    # Event type counts table
    html_parts.append('<h3>Phân bố eventid trong đầu ra</h3>')
    eid_rows = [[eid, cnt, f'{cnt/len(enriched)*100:.1f}%'] for eid, cnt in sorted(counts.items())]
    html_parts.append(html_table(['eventid', 'Số lượng', 'Tỷ lệ'], eid_rows))

    # Duration stats
    if nonzero:
        html_parts.append('<h3>Thống kê thời lượng session</h3>')
        html_parts.append(html_cards([
            ('Tổng session có close', len(dur_vals)),
            ('Duration > 0', len(nonzero)),
            ('Min (giây)', round(min(nonzero), 1)),
            ('Max (giây)', round(max(nonzero), 1)),
            ('Trung bình (giây)', round(sum(nonzero) / len(nonzero), 1)),
        ]))

    # ── Section 2: Charts ──
    html_parts.append(html_section('charts', '2. Biểu đồ phân tích'))

    # Chart 1: Client version distribution (pie)
    if client_versions:
        cv_labels = [v for v, _ in client_versions.most_common()]
        cv_values = [c for _, c in client_versions.most_common()]
        html_parts.append(html_chart(
            make_pie_chart(cv_labels, cv_values, title='Phân bố phiên bản SSH client'),
            caption=f'Tổng cộng {sum(cv_values):,} event cowrie.client.version từ {len(cv_labels)} phiên bản',
        ))

    # Chart 2: Session duration histogram
    if nonzero:
        html_parts.append(html_chart(
            make_histogram(
                nonzero,
                title='Phân bố thời lượng session (giây)',
                xlabel='Thời lượng (giây)',
                ylabel='Số session',
                bins=min(50, max(10, len(nonzero) // 5)),
                log_scale=len(nonzero) > 100,
            ),
            caption=f'{len(nonzero):,} session có duration > 0',
        ))

    # Chart 3: Event type bar chart
    eid_labels = [k for k in sorted(counts.keys())]
    eid_values = [counts[k] for k in eid_labels]
    html_parts.append(html_chart(
        make_bar_chart(
            eid_labels, eid_values,
            title='Số lượng theo eventid',
            xlabel='Event ID',
            ylabel='Số lượng',
            color='#2c5282',
        ),
        caption='Phân bố các loại event trong đầu ra Cowrie',
    ))

    # Chart 4: Source event type distribution (bar)
    if src_event_types:
        src_et_labels = [k for k, _ in src_event_types.most_common(15)]
        src_et_values = [c for _, c in src_event_types.most_common(15)]
        html_parts.append(html_chart(
            make_bar_chart(
                src_et_labels, src_et_values,
                title='Event type từ dữ liệu nguồn (top 15)',
                xlabel='event_type',
                ylabel='Số lượng',
                color='#805ad5',
                horizontal=True,
                figsize=(9, 5),
            ),
            caption=f'Tổng {len(src_event_types)} loại event_type từ OpenSSH logs',
        ))

    # Chart 5: Top usernames bar chart
    if usernames:
        top_users = usernames.most_common(20)
        u_labels = [u for u, _ in top_users]
        u_values = [c for _, c in top_users]
        html_parts.append(html_chart(
            make_bar_chart(
                u_labels, u_values,
                title='Top 20 username trong login events',
                xlabel='Username',
                ylabel='Số lần xuất hiện',
                color='#38a169',
                horizontal=True,
                figsize=(9, 5),
            ),
            caption=f'Tổng {len(usernames)} username duy nhất',
        ))

    # ── Section 3: IP mapping table ──
    html_parts.append(html_section('ip-mapping', '3. Bảng ánh xạ IP'))
    ip_rows = [[src, dst] for src, dst in sorted(ip_mapping.items())]
    html_parts.append(html_table(['IP nội bộ (gốc)', 'IP Việt Nam (remap)'], ip_rows))

    # ── Section 4: Design decisions ──
    html_parts.append(html_section('decisions', '4. Quyết định thiết kế'))

    html_parts.append(html_decision(
        'FIX #2: Sử dụng dst_ip cố định (10.0.0.4)',
        f'<p>Tất cả event benign sử dụng <code>dst_ip={args.dst_ip}</code> và '
        f'<code>dst_port={args.dst_port}</code>, khớp với log tấn công Cowrie.</p>',
        'Nếu benign có dst_ip ngẫu nhiên trong khi attack luôn là 10.0.0.4, '
        'mô hình ML sẽ học shortcut dựa trên dst_ip thay vì hành vi thực sự. '
        'Giữ dst_ip cố định buộc mô hình phải học từ đặc trưng hành vi '
        '(timing, auth pattern, client version) — đây mới là tín hiệu hữu ích.',
    ))

    html_parts.append(html_decision(
        'FIX #1: Nhóm session theo (host, pid)',
        '<p>Trong sshd thực, mỗi PID xử lý đúng một kết nối SSH. '
        'Nhiều lần thử xác thực (failed → failed → accepted) dưới cùng PID '
        'thuộc về CÙNG MỘT session Cowrie.</p>'
        '<p>Code cũ tạo session mới cho từng event (dùng line_no trong hash), '
        'làm tăng giả tạo số session và phá hủy pattern multi-attempt.</p>',
        'Mô hình SSH: 1 PID = 1 TCP connection = 1 Cowrie session. '
        'Nhóm theo (host, pid) bảo toàn chuỗi xác thực (auth sequence) — '
        'đặc trưng phân biệt quan trọng nhất giữa benign (ít attempt, thành công nhanh) '
        'và attacker (brute-force, nhiều attempt liên tục).',
    ))

    html_parts.append(html_decision(
        'FIX #3: Remap IP nguồn → IP Việt Nam',
        f'<p>Sử dụng {len(vn_ips):,} IP Việt Nam thật từ IPvn.log để thay thế '
        f'IP nội bộ của doanh nghiệp.</p>'
        f'<p>Ánh xạ deterministic (seed=42) đảm bảo reproducibility.</p>',
        'IP nội bộ (10.x, 192.168.x) sẽ tạo bias vì attack logs chứa IP public. '
        'Remap sang IP VN thật tạo phân bố IP giống thực tế cho cả hai lớp. '
        'Deterministic mapping đảm bảo cùng IP nội bộ luôn map sang cùng IP VN, '
        'bảo toàn tính nhất quán của src_ip trong session.',
    ))

    html_parts.append(html_decision(
        'Client version pool có trọng số',
        f'<p>Pool gồm {len(CLIENT_VERSION_POOL)} phiên bản SSH client, '
        f'trọng số thiên về RHEL/enterprise (OpenSSH 7.4–9.3, PuTTY, WinSCP, JSCH, paramiko).</p>',
        'Môi trường doanh nghiệp VN chủ yếu dùng RHEL/CentOS (OpenSSH 7.4–8.7). '
        'Phân bố có trọng số tạo fingerprint thực tế hơn so với uniform random. '
        'Điều này ngăn mô hình ML học bias từ client version phân bố đều — '
        'vốn không xuất hiện trong thực tế.',
    ))

    html_parts.append(html_decision(
        'Giải thích chênh lệch Session & normal_login subset',
        f'<p><b>Tổng số session (thực tế: {len(sessions):,})</b> là toàn bộ các kết nối SSH hợp lệ có diễn ra hành động xác thực (1 session = 1 PID). '
        f'<br><b>Session normal_login (thực tế: {len(normal_sessions):,})</b> là tập con chỉ chứa các session có ít nhất một lần đăng nhập thành công (<code>cowrie.login.success</code>).</p>'
        f'<p>Phần chênh lệch <b>{len(sessions) - len(normal_sessions):,} session</b> đại diện cho các cuộc tấn công quét hoặc kết nối truy cập hoàn toàn thất bại '
        f'(chỉ chứa sự kiện <code>cowrie.login.failed</code> và kết thúc mà không đăng nhập được), '
        f'như người dùng gõ sai mật khẩu quá số lần rồi bỏ cuộc hoặc bị server block.</p>'
        f'<p><b>Các sự kiện cowrie.login.failed nằm ở đâu:</b> Chúng phân bố ở cả 2 nhóm. '
        f'<br>- Trong nhóm 886 session <code>normal_login</code>, có thể có failed event do người dùng gõ nhầm mật khẩu (typo) VÀI LẦN TRƯỚC KHI thành công. '
        f'<br>- Trong các session chênh lệch còn lại, toàn bộ nỗ lực login đều là thất bại (give_up).</p>',
        'Giữ lại tổng số session toàn vẹn (893) giúp mô hình ML không học sai lệch một bức tranh "tốt đẹp quá mức" về môi trường nội bộ, trong khi '
        'khi subset normal_login (886) cung cấp mẫu đăng nhập trong sạch để đánh giá chuyên sâu.',
    ))

    failed_session_ids = sessions - normal_sessions
    if failed_session_ids:
        html_parts.append('<h3>Chi tiết Log của các Session chênh lệch (Failed Sessions)</h3>')
        failed_details = []
        for sid in sorted(failed_session_ids):
            s_events = [e for e in enriched if e.get('session') == sid]
            lines = [f"====== Session: {sid} ======"]
            for e in s_events:
                ts = e.get('timestamp')
                eid = e.get('eventid')
                msg = e.get('message', '')
                user = e.get('username')
                user_str = f" user={user}" if user else ""
                lines.append(f"[{ts}] {eid}{user_str} - {msg}")
            failed_details.append('\n'.join(lines))
        html_parts.append('<details><summary>Nhấn để xem log chi tiết</summary><pre style="background:#0f172a; color:#e2e8f0; padding:14px; border-radius:10px; font-size:12px; line-height:1.4; white-space:pre-wrap;">' + '\n\n'.join(failed_details) + '</pre></details>')

    # ── Section 5: Verification tests ──
    html_parts.append(html_section('verification', '5. Kiểm tra xác minh'))
    log.section('Chạy kiểm tra xác minh')

    tests: list[tuple[str, bool, str]] = []

    # Test 1: All sessions have connect + closed events
    sessions_with_connect = {e['session'] for e in enriched if e.get('eventid') == 'cowrie.session.connect'}
    sessions_with_closed = {e['session'] for e in enriched if e.get('eventid') == 'cowrie.session.closed'}
    all_have_connect_close = sessions_with_connect == sessions_with_closed == sessions
    missing_connect = sessions - sessions_with_connect
    missing_closed = sessions - sessions_with_closed
    detail_cc = (f'{len(sessions):,} session, {len(sessions_with_connect):,} có connect, '
                 f'{len(sessions_with_closed):,} có closed')
    if missing_connect:
        detail_cc += f' | Thiếu connect: {len(missing_connect)}'
    if missing_closed:
        detail_cc += f' | Thiếu closed: {len(missing_closed)}'
    tests.append(('Tất cả session có cả connect + closed', all_have_connect_close, detail_cc))
    if all_have_connect_close:
        log.ok('✓ Tất cả session đều có connect + closed')
    else:
        log.fail(f'✗ Thiếu connect: {len(missing_connect)}, thiếu closed: {len(missing_closed)}')

    # Test 2: All usernames are preserved
    login_events = [e for e in enriched if e.get('eventid') in ('cowrie.login.success', 'cowrie.login.failed')]
    all_have_username = all(e.get('username') for e in login_events)
    empty_username_count = sum(1 for e in login_events if not e.get('username'))
    tests.append((
        'Tất cả login event có username',
        all_have_username,
        f'{len(login_events):,} login event, {empty_username_count} thiếu username',
    ))
    if all_have_username:
        log.ok(f'✓ Tất cả {len(login_events):,} login event đều có username')
    else:
        log.fail(f'✗ {empty_username_count} login event thiếu username')

    # Test 3: No duplicate session IDs (each session ID appears in exactly one group)
    session_id_list = [e.get('session') for e in enriched if e.get('eventid') == 'cowrie.session.connect']
    dup_session_ids = len(session_id_list) - len(set(session_id_list))
    no_dup = dup_session_ids == 0
    tests.append((
        'Không có session ID trùng lặp',
        no_dup,
        f'{len(session_id_list):,} session connect, {dup_session_ids} trùng lặp',
    ))
    if no_dup:
        log.ok(f'✓ Không có session ID trùng lặp ({len(session_id_list):,} session)')
    else:
        log.fail(f'✗ Phát hiện {dup_session_ids} session ID trùng lặp')

    # Test 4: All events have timestamps
    all_have_ts = all(e.get('timestamp') for e in enriched)
    missing_ts = sum(1 for e in enriched if not e.get('timestamp'))
    tests.append((
        'Tất cả event có timestamp',
        all_have_ts,
        f'{len(enriched):,} event, {missing_ts} thiếu timestamp',
    ))
    if all_have_ts:
        log.ok(f'✓ Tất cả {len(enriched):,} event đều có timestamp')
    else:
        log.fail(f'✗ {missing_ts} event thiếu timestamp')

    # Test 5: dst_ip and dst_port are consistent
    dst_ips = {e.get('dst_ip') for e in enriched if 'dst_ip' in e}
    dst_ports = {e.get('dst_port') for e in enriched if 'dst_port' in e}
    consistent_dst = dst_ips <= {args.dst_ip} and dst_ports <= {args.dst_port}
    tests.append((
        'dst_ip/dst_port nhất quán',
        consistent_dst,
        f'dst_ip: {dst_ips}, dst_port: {dst_ports} (kỳ vọng: {args.dst_ip}:{args.dst_port})',
    ))
    if consistent_dst:
        log.ok(f'✓ dst_ip/dst_port nhất quán: {args.dst_ip}:{args.dst_port}')
    else:
        log.fail(f'✗ dst_ip/dst_port không nhất quán: {dst_ips}, {dst_ports}')

    # Test 6: All session events have src_ip
    events_needing_ip = [e for e in enriched if e.get('eventid') in (
        'cowrie.session.connect', 'cowrie.client.version',
        'cowrie.login.success', 'cowrie.login.failed', 'cowrie.session.closed',
    )]
    all_have_src_ip = all(e.get('src_ip') for e in events_needing_ip)
    missing_src_ip = sum(1 for e in events_needing_ip if not e.get('src_ip'))
    tests.append((
        'Tất cả event chính có src_ip',
        all_have_src_ip,
        f'{len(events_needing_ip):,} event, {missing_src_ip} thiếu src_ip',
    ))
    if all_have_src_ip:
        log.ok(f'✓ Tất cả {len(events_needing_ip):,} event chính đều có src_ip')
    else:
        log.fail(f'✗ {missing_src_ip} event thiếu src_ip')

    # Test 7: Normal login subset is valid (all sessions have success)
    normal_login_sessions_check = set()
    for e in normal_login:
        if e.get('eventid') == 'cowrie.login.success':
            normal_login_sessions_check.add(e.get('session'))
    normal_valid = normal_sessions == normal_login_sessions_check or not normal_sessions
    tests.append((
        'Subset normal_login chỉ chứa session thành công',
        normal_valid,
        f'{len(normal_sessions):,} session, {len(normal_login_sessions_check):,} có login.success',
    ))
    if normal_valid:
        log.ok(f'✓ Subset normal_login hợp lệ: {len(normal_sessions):,} session thành công')
    else:
        log.warn(f'⚠ {len(normal_sessions - normal_login_sessions_check)} session thiếu login.success')

    html_parts.append(html_verification_section(tests))

    # ── Section 6: Debug log ──
    html_parts.append(html_section('debug-log', '6. Debug log'))
    log.section('Hoàn thành — ghi báo cáo HTML')
    html_parts.append(html_debug_log(log))

    html_parts.append(html_footer())

    report_path = _root / 'output' / 'step2' / 'step2_build_benign.html'
    write_html(report_path, '\n'.join(html_parts))
    log.ok(f'Đã ghi báo cáo HTML → {report_path}')

    log.section('STEP 2 HOÀN TẤT')
    log.ok(f'Tổng kết: {len(enriched):,} event, {len(sessions):,} session, {len(normal_login):,} normal_login event')


if __name__ == '__main__':
    main()
