"""
merge_dataset.py – Step 3C: Merge Attack + Benign Logs & Neutralize Shortcuts
==============================================================================

Simple merge script that replaces the complex clean_synthetic.py.
All filtering, bias correction, and upscaling is handled by the expert tools
(attack_expert.py and benign_expert.py).

This script only:
  1. Reads selected attack events (from Step 3A)
  2. Reads upscaled benign events (from Step 3B)
  3. Neutralizes domain shortcuts (sensor, dst_port)
  4. Sorts by timestamp and writes merged NDJSON

Usage::

    python3 merge_dataset.py
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
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
    make_timeline_chart,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

ATTACK_SELECTED = _PROJECT_ROOT / 'output' / 'step3a' / 'attack_selected.json'
BENIGN_UPSCALED = _PROJECT_ROOT / 'output' / 'step3b' / 'benign_upscaled.json'
OUTPUT_FILE     = _PROJECT_ROOT / 'output' / 'step3c' / 'cowrie_merged.json'
REPORT_HTML     = _PROJECT_ROOT / 'output' / 'step3c' / 'step3c_merge.html'

UNIFIED_SENSOR   = 'cowrie-ssh'
UNIFIED_DST_PORT = 22


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------
def _read_ndjson(filepath: Path) -> list[dict]:
    events: list[dict] = []
    with filepath.open('r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(obj)
            except json.JSONDecodeError:
                continue
    return events


def _write_ndjson(filepath: Path, events: list[dict]) -> None:
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with filepath.open('w', encoding='utf-8', newline='\n') as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + '\n')


# ---------------------------------------------------------------------------
# Neutralize domain shortcuts
# ---------------------------------------------------------------------------
def neutralize_shortcuts(events: list[dict]) -> None:
    """In-place neutralization of sensor name and dst_port to prevent leakage."""
    for ev in events:
        if 'sensor' in ev:
            ev['sensor'] = UNIFIED_SENSOR
        if 'dst_port' in ev:
            ev['dst_port'] = UNIFIED_DST_PORT


# ---------------------------------------------------------------------------
# Timeline helpers
# ---------------------------------------------------------------------------
def _build_hourly_timeline(events: list[dict]) -> tuple[list[str], list[int]]:
    buckets: dict[str, int] = defaultdict(int)
    for ev in events:
        ts = ev.get('timestamp', '')
        if len(ts) >= 13:
            buckets[ts[:13]] += 1
    if not buckets:
        return [], []
    sorted_keys = sorted(buckets.keys())
    return sorted_keys, [buckets[k] for k in sorted_keys]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description='Step 3C: Merge & Neutralize')
    parser.add_argument('--attack', default=str(ATTACK_SELECTED),
                        help='Selected attack events (from Step 3A)')
    parser.add_argument('--benign', default=str(BENIGN_UPSCALED),
                        help='Upscaled benign events (from Step 3B)')
    parser.add_argument('--output', default=str(OUTPUT_FILE))
    args = parser.parse_args()

    log = ViLogger('Step3C')

    log.section('Step 3C — Ghép dữ liệu & Trung hoà shortcut')
    log.info(f'Thời gian bắt đầu: {datetime.now():%Y-%m-%d %H:%M:%S}')
    log.info(f'Sensor thống nhất: {UNIFIED_SENSOR}')
    log.info(f'dst_port thống nhất: {UNIFIED_DST_PORT}')

    # ── 1. Read attack events ──────────────────────────────────────────
    attack_path = Path(args.attack)
    benign_path = Path(args.benign)

    log.section('[1/6] Đọc dữ liệu tấn công')
    log.info(f'Đường dẫn: {attack_path}')
    attack_events = _read_ndjson(attack_path)
    n_attack = len(attack_events)
    log.ok(f'Đã tải {n_attack:,} sự kiện tấn công')

    if n_attack == 0:
        log.warn('Không có sự kiện tấn công — tệp đầu vào rỗng!')

    attack_origins = Counter(ev.get('data_origin', 'unknown') for ev in attack_events)
    for origin, cnt in attack_origins.most_common():
        log.debug(f'  Nguồn gốc tấn công: {origin} → {cnt:,} sự kiện')

    # ── 2. Read benign events ──────────────────────────────────────────
    log.section('[2/6] Đọc dữ liệu lành tính')
    log.info(f'Đường dẫn: {benign_path}')
    benign_events = _read_ndjson(benign_path)
    n_benign = len(benign_events)
    log.ok(f'Đã tải {n_benign:,} sự kiện lành tính')

    if n_benign == 0:
        log.warn('Không có sự kiện lành tính — tệp đầu vào rỗng!')

    benign_origins = Counter(ev.get('data_origin', 'unknown') for ev in benign_events)
    for origin, cnt in benign_origins.most_common():
        log.debug(f'  Nguồn gốc lành tính: {origin} → {cnt:,} sự kiện')

    # ── 3. Merge ───────────────────────────────────────────────────────
    log.section('[3/6] Ghép dữ liệu')
    merged = attack_events + benign_events
    n_merged = len(merged)
    log.ok(f'Đã ghép: {n_merged:,} tổng sự kiện ({n_attack:,} tấn công + {n_benign:,} lành tính)')

    if n_merged != n_attack + n_benign:
        log.warn(f'CẢNH BÁO: Tổng không khớp! {n_merged} ≠ {n_attack} + {n_benign}')

    # ── 4. Neutralize ──────────────────────────────────────────────────
    log.section('[4/6] Trung hoà domain shortcut')
    log.info(f'Ghi đè sensor → "{UNIFIED_SENSOR}" cho tất cả sự kiện')
    log.info(f'Ghi đè dst_port → {UNIFIED_DST_PORT} cho tất cả sự kiện')

    sensors_before = Counter(ev.get('sensor', '<missing>') for ev in merged)
    ports_before = Counter(ev.get('dst_port', '<missing>') for ev in merged)
    log.debug(f'Sensor trước trung hoà: {dict(sensors_before.most_common(5))}')
    log.debug(f'dst_port trước trung hoà: {dict(ports_before.most_common(5))}')

    neutralize_shortcuts(merged)

    sensors_after = Counter(ev.get('sensor', '<missing>') for ev in merged)
    ports_after = Counter(ev.get('dst_port', '<missing>') for ev in merged)
    log.ok(f'Sensor sau trung hoà: {dict(sensors_after.most_common())}')
    log.ok(f'dst_port sau trung hoà: {dict(ports_after.most_common())}')

    # ── 5. Sort by timestamp ───────────────────────────────────────────
    log.section('[5/6] Sắp xếp theo timestamp')
    merged.sort(key=lambda e: e.get('timestamp', ''))

    ts_first = merged[0].get('timestamp', 'N/A') if merged else 'N/A'
    ts_last = merged[-1].get('timestamp', 'N/A') if merged else 'N/A'
    log.ok(f'Đã sắp xếp {n_merged:,} sự kiện theo thời gian')
    log.debug(f'Timestamp đầu tiên: {ts_first}')
    log.debug(f'Timestamp cuối cùng: {ts_last}')

    # ── Compute statistics ─────────────────────────────────────────────
    origin_dist = Counter(ev.get('data_origin', 'unknown') for ev in merged)
    eventid_dist = Counter(ev.get('eventid', 'unknown') for ev in merged)

    attack_sessions: set[str] = set()
    benign_sessions: set[str] = set()
    missing_session_ids: list[dict] = []
    for ev in merged:
        sid = ev.get('session', '')
        origin = ev.get('data_origin', '')
        if not sid:
            missing_session_ids.append(ev)
        if 'attack' in origin:
            attack_sessions.add(sid)
        elif 'benign' in origin:
            benign_sessions.add(sid)

    log.info(f'Phân bố data_origin:')
    for origin, cnt in origin_dist.most_common():
        pct = cnt / n_merged * 100 if n_merged else 0
        log.debug(f'  {origin:30s}: {cnt:>8,} ({pct:.1f}%)')
    log.info(f'Số phiên tấn công : {len(attack_sessions):,}')
    log.info(f'Số phiên lành tính: {len(benign_sessions):,}')
    log.info(f'Phân bố EventID (top 10):')
    for eid, cnt in eventid_dist.most_common(10):
        pct = cnt / n_merged * 100 if n_merged else 0
        log.debug(f'  {eid:40s}: {cnt:>8,} ({pct:.1f}%)')

    if missing_session_ids:
        log.warn(f'Có {len(missing_session_ids)} sự kiện thiếu session ID!')
    else:
        log.ok('Tất cả sự kiện đều có session ID')

    # ── 6. Write merged output ─────────────────────────────────────────
    log.section('[6/6] Ghi tệp kết quả')
    output_path = Path(args.output)
    _write_ndjson(output_path, merged)
    log.ok(f'Đã ghi dataset đã ghép → {output_path}')
    log.info(f'Tổng số sự kiện: {n_merged:,}')

    file_size_mb = output_path.stat().st_size / (1024 * 1024)
    log.debug(f'Kích thước tệp: {file_size_mb:.1f} MB')

    # ===================================================================
    # HTML Report
    # ===================================================================
    log.section('Tạo báo cáo HTML')

    sections = [
        ('overview', 'Tổng quan dữ liệu'),
        ('charts', 'Biểu đồ phân bố'),
        ('timeline', 'Phân bố thời gian'),
        ('verification', 'Kiểm tra xác minh'),
        ('decisions', 'Giải thích quyết định'),
        ('debug', 'Nhật ký gỡ lỗi'),
    ]

    html_parts: list[str] = []
    html_parts.append(html_header(
        'Step 3C — Ghép dữ liệu & Trung hoà shortcut',
        'Step3C: merge_dataset.py',
        f'Ghép {n_attack:,} sự kiện tấn công + {n_benign:,} sự kiện lành tính → {n_merged:,} tổng',
    ))
    html_parts.append(html_toc(sections))

    # ── Overview cards ─────────────────────────────────────────────────
    html_parts.append(html_section('overview', 'Tổng quan dữ liệu'))
    html_parts.append(html_cards([
        ('Sự kiện tấn công', n_attack),
        ('Sự kiện lành tính', n_benign),
        ('Tổng đã ghép', n_merged),
        ('Phiên tấn công', len(attack_sessions)),
        ('Phiên lành tính', len(benign_sessions)),
        ('Kích thước tệp', f'{file_size_mb:.1f} MB'),
    ]))
    html_parts.append(
        '<details open><summary><b>Giải thích các chỉ số</b></summary>'
        '<table><tr><th>Chỉ số</th><th>Ý nghĩa</th><th>Cách xác định</th></tr>'
        '<tr><td><b>Sự kiện tấn công</b></td>'
        '<td>Tổng event từ file attack đã lọc và sửa bias của Step 3A</td>'
        '<td>Đếm dòng trong <code>output/step3a/attack_selected.json</code> — '
        'chỉ chứa session đã qua chấm điểm (score=1) và Cowrie bias correction</td></tr>'
        '<tr><td><b>Sự kiện lành tính</b></td>'
        '<td>Tổng event benign (thực + synthetic) từ Step 3B</td>'
        '<td>Đếm dòng trong <code>output/step3b/benign_upscaled.json</code> — '
        'bao gồm 893 session thực và session synthetic để balance</td></tr>'
        '<tr><td><b>Tổng đã ghép</b></td>'
        '<td>Tổng event sau khi merge attack + benign</td>'
        '<td><code>sự kiện tấn công + sự kiện lành tính</code>. Đây là kích thước toàn bộ dataset</td></tr>'
        '<tr><td><b>Phiên tấn công</b></td>'
        '<td>Số session tấn công riêng biệt</td>'
        '<td><code>len(set(session))</code> từ event có <code>data_origin=attack_cowrie</code></td></tr>'
        '<tr><td><b>Phiên lành tính</b></td>'
        '<td>Số session benign riêng biệt (thực + synthetic)</td>'
        '<td><code>len(set(session))</code> từ event có <code>data_origin=benign_corp/benign_corp_synthetic</code></td></tr>'
        '<tr><td><b>Kích thước tệp</b></td>'
        '<td>Dung lượng file JSONL đầu ra sau merge</td>'
        '<td>Kích thước <code>output/step3c/cowrie_merged.json</code> tính bằng MB</td></tr>'
        '</table></details>'
    )

    origin_rows = [[origin, cnt, f'{cnt / n_merged * 100:.1f}%'] for origin, cnt in origin_dist.most_common()]
    html_parts.append('<h3>Phân bố data_origin</h3>')
    html_parts.append(html_table(['Nguồn gốc', 'Số lượng', 'Tỉ lệ'], origin_rows))

    eid_rows = [[eid, cnt, f'{cnt / n_merged * 100:.1f}%'] for eid, cnt in eventid_dist.most_common(15)]
    html_parts.append('<h3>Phân bố EventID (top 15)</h3>')
    html_parts.append(html_table(['EventID', 'Số lượng', 'Tỉ lệ'], eid_rows))

    log.debug('Đã tạo phần tổng quan')

    # ── Charts ─────────────────────────────────────────────────────────
    html_parts.append(html_section('charts', 'Biểu đồ phân bố'))

    origin_labels = [o for o, _ in origin_dist.most_common()]
    origin_values = [c for _, c in origin_dist.most_common()]
    html_parts.append(html_chart(
        make_pie_chart(origin_labels, origin_values, title='Phân bố data_origin'),
        caption='Tỉ lệ sự kiện tấn công / lành tính trong dataset đã ghép',
    ))

    eid_labels = [e for e, _ in eventid_dist.most_common(15)]
    eid_values = [c for _, c in eventid_dist.most_common(15)]
    html_parts.append(html_chart(
        make_bar_chart(eid_labels, eid_values,
                       title='Phân bố EventID (top 15)',
                       xlabel='EventID', ylabel='Số lượng',
                       color='#3182ce', horizontal=True,
                       figsize=(10, 6)),
        caption='Top 15 loại sự kiện phổ biến nhất',
    ))

    session_labels = ['Phiên tấn công', 'Phiên lành tính']
    session_values = [len(attack_sessions), len(benign_sessions)]
    html_parts.append(html_chart(
        make_bar_chart(session_labels, session_values,
                       title='Số phiên theo nguồn gốc',
                       ylabel='Số phiên', color='#e53e3e'),
        caption='So sánh số lượng phiên tấn công và lành tính',
    ))

    log.debug('Đã tạo biểu đồ phân bố')

    # ── Timeline ───────────────────────────────────────────────────────
    html_parts.append(html_section('timeline', 'Phân bố thời gian'))

    tl_labels, tl_values = _build_hourly_timeline(merged)
    html_parts.append(html_chart(
        make_timeline_chart(tl_labels, tl_values,
                            title='Phân bố sự kiện theo giờ',
                            ylabel='Số sự kiện / giờ',
                            color='#805ad5'),
        caption='Timeline hiển thị mật độ sự kiện theo giờ trong dataset đã ghép',
    ))

    attack_tl_labels, attack_tl_values = _build_hourly_timeline(
        [ev for ev in merged if 'attack' in ev.get('data_origin', '')]
    )
    html_parts.append(html_chart(
        make_timeline_chart(attack_tl_labels, attack_tl_values,
                            title='Timeline sự kiện tấn công',
                            ylabel='Số sự kiện / giờ',
                            color='#e53e3e'),
        caption='Phân bố thời gian chỉ dành cho sự kiện tấn công',
    ))

    benign_tl_labels, benign_tl_values = _build_hourly_timeline(
        [ev for ev in merged if 'benign' in ev.get('data_origin', '')]
    )
    html_parts.append(html_chart(
        make_timeline_chart(benign_tl_labels, benign_tl_values,
                            title='Timeline sự kiện lành tính',
                            ylabel='Số sự kiện / giờ',
                            color='#38a169'),
        caption='Phân bố thời gian chỉ dành cho sự kiện lành tính',
    ))

    log.debug('Đã tạo biểu đồ timeline')

    # ── Verification tests ─────────────────────────────────────────────
    html_parts.append(html_section('verification', 'Kiểm tra xác minh'))

    all_sensors = set(ev.get('sensor') for ev in merged if 'sensor' in ev)
    sensor_pass = all_sensors == {UNIFIED_SENSOR}

    all_ports = set(ev.get('dst_port') for ev in merged if 'dst_port' in ev)
    port_pass = all_ports == {UNIFIED_DST_PORT}

    count_match = (n_merged == n_attack + n_benign)

    no_events_lost = n_merged >= n_attack and n_merged >= n_benign

    timestamps = [ev.get('timestamp', '') for ev in merged]
    ts_sorted = all(timestamps[i] <= timestamps[i + 1] for i in range(len(timestamps) - 1)) if len(timestamps) > 1 else True

    origin_preserved = all(ev.get('data_origin') for ev in merged)

    no_missing_sessions = len(missing_session_ids) == 0

    tests = [
        (
            'Tất cả sensor = cowrie-ssh sau trung hoà',
            sensor_pass,
            f'Các giá trị sensor tìm thấy: {all_sensors}' if not sensor_pass
            else f'Tất cả {n_merged:,} sự kiện có sensor="{UNIFIED_SENSOR}"',
        ),
        (
            'Tất cả dst_port = 22',
            port_pass,
            f'Các giá trị dst_port tìm thấy: {all_ports}' if not port_pass
            else f'Tất cả {n_merged:,} sự kiện có dst_port={UNIFIED_DST_PORT}',
        ),
        (
            'Tổng merged = attack + benign',
            count_match,
            f'{n_merged:,} = {n_attack:,} + {n_benign:,}' if count_match
            else f'KHÔNG KHỚP: {n_merged:,} ≠ {n_attack:,} + {n_benign:,}',
        ),
        (
            'Không mất sự kiện trong quá trình ghép',
            no_events_lost,
            f'merged ({n_merged:,}) ≥ attack ({n_attack:,}) và ≥ benign ({n_benign:,})'
            if no_events_lost
            else f'MẤT DỮ LIỆU: merged={n_merged:,}, attack={n_attack:,}, benign={n_benign:,}',
        ),
        (
            'Timestamp có thể sắp xếp',
            ts_sorted,
            f'Timestamps đã được sắp xếp tăng dần ({ts_first} → {ts_last})'
            if ts_sorted else 'Timestamps KHÔNG theo thứ tự tăng dần!',
        ),
        (
            'data_origin được bảo toàn',
            origin_preserved,
            f'Tất cả {n_merged:,} sự kiện đều có trường data_origin'
            if origin_preserved
            else f'{sum(1 for ev in merged if not ev.get("data_origin"))} sự kiện thiếu data_origin',
        ),
        (
            'Không có sự kiện thiếu session ID',
            no_missing_sessions,
            'Tất cả sự kiện đều có session ID hợp lệ'
            if no_missing_sessions
            else f'{len(missing_session_ids)} sự kiện thiếu session ID',
        ),
    ]

    html_parts.append(html_verification_section(tests))

    for name, passed, detail in tests:
        if passed:
            log.ok(f'PASS: {name} — {detail}')
        else:
            log.fail(f'FAIL: {name} — {detail}')

    n_pass = sum(1 for _, p, _ in tests if p)
    log.info(f'Kết quả kiểm tra: {n_pass}/{len(tests)} PASS')

    # ── Decision explanations ──────────────────────────────────────────
    html_parts.append(html_section('decisions', 'Giải thích quyết định'))

    html_parts.append(html_decision(
        'Tại sao trung hoà sensor?',
        '<p>Trường <code>sensor</code> gốc chứa tên honeypot cụ thể (vd: '
        '<code>cowrie-hp1</code> vs <code>cowrie-benign-sim</code>). '
        'Nếu giữ nguyên, mô hình ML có thể "gian lận" bằng cách học sensor name '
        'thay vì hành vi thực sự → <b>domain shortcut</b>.</p>',
        rationale='Sommer & Paxson (2010): Behavioral features phải được ưu tiên '
        'hơn metadata artifacts. Việc trung hoà sensor ngăn chặn data leakage '
        'từ deployment-specific identifiers.',
    ))

    html_parts.append(html_decision(
        'Tại sao thống nhất dst_port = 22?',
        '<p>Dữ liệu gốc có thể chứa các dst_port khác nhau giữa attack và benign. '
        'Vì toàn bộ pipeline tập trung vào phân tích SSH (port 22), '
        'việc thống nhất dst_port loại bỏ một shortcut tiềm ẩn khác.</p>',
        rationale='RFC 4253 (Ylonen & Lonvick, 2006): SSH Protocol mặc định port 22. '
        'Thống nhất dst_port đảm bảo mô hình học từ nội dung session, '
        'không phải từ port number.',
    ))

    html_parts.append(html_decision(
        'Chiến lược ghép dữ liệu',
        '<p>Ghép đơn giản (concatenation) thay vì interleaving phức tạp. '
        'Sau khi ghép, sắp xếp theo timestamp để tạo thứ tự tự nhiên.</p>'
        '<ul>'
        '<li>Attack events giữ nguyên từ Step 3A (đã lọc và đánh giá)</li>'
        '<li>Benign events giữ nguyên từ Step 3B (đã upscale)</li>'
        '<li>Trường <code>data_origin</code> được bảo toàn để training pipeline phân biệt</li>'
        '</ul>',
        rationale='Việc giữ nguyên data_origin cho phép supervised learning, '
        'trong khi neutralization ngăn chặn leakage từ metadata.',
    ))

    log.debug('Đã tạo phần giải thích quyết định')

    # ── Debug log ──────────────────────────────────────────────────────
    html_parts.append(html_section('debug', 'Nhật ký gỡ lỗi'))
    html_parts.append(html_debug_log(log))

    html_parts.append(html_footer())

    report_path = REPORT_HTML
    write_html(report_path, '\n'.join(html_parts))
    log.ok(f'Đã ghi báo cáo HTML → {report_path}')

    # ── Final summary ──────────────────────────────────────────────────
    log.section('Step 3C hoàn tất')
    log.ok(f'Dataset đã ghép: {output_path} ({n_merged:,} sự kiện)')
    log.ok(f'Báo cáo HTML: {report_path}')
    log.info(f'Thời gian kết thúc: {datetime.now():%Y-%m-%d %H:%M:%S}')


if __name__ == '__main__':
    main()
