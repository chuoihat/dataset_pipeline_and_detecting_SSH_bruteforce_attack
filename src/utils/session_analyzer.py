from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from html import escape as html_escape


def _parse_ts(ts_value: Any) -> datetime | None:
    if not isinstance(ts_value, str) or not ts_value:
        return None
    try:
        return datetime.fromisoformat(ts_value.replace('Z', '+00:00')).astimezone(timezone.utc)
    except Exception:
        return None


def _to_value_key(value: Any) -> str:
    if value is None:
        return 'null'
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(value)


def _fmt_ts(ts_value: datetime | None) -> str:
    if ts_value is None:
        return 'N/A'
    return ts_value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def _safe_duration_seconds(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    duration = (end - start).total_seconds()
    return round(duration, 6)


def _html_table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ['<table class="dataframe">']
    out.append('<thead><tr>')
    for h in headers:
        out.append(f'<th>{html_escape(str(h))}</th>')
    out.append('</tr></thead>')
    out.append('<tbody>')
    for row in rows:
        out.append('<tr>')
        for cell in row:
            out.append(f'<td>{html_escape("" if cell is None else str(cell))}</td>')
        out.append('</tr>')
    out.append('</tbody></table>')
    return ''.join(out)


def analyze_single_json_log(
    json_log_path: str | Path,
    output_json_path: str | Path | None = None,
    output_html_path: str | Path | None = None,
    top_values_per_field: int = 20,
) -> dict[str, Any]:
    """
    Analyze one newline-delimited JSON Cowrie log file.

    Returned structure has two key sections:
    1) eventid_field_statistics:
       - For each eventid: total events, number of unique fields, and per-field value stats.
    2) session_correlation:
       - Per-session timeline ordered by timestamp.
       - Event transitions and timing deltas.
       - Timestamp correlation across sessions from the same src_ip.
    """
    path = Path(json_log_path)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f'Log file not found: {path}')

    events: list[dict[str, Any]] = []
    with path.open('r', encoding='utf-8') as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                obj['_line_no'] = line_no
                events.append(obj)

    if not events:
        result = {
            'source_file': str(path),
            'total_events': 0,
            'eventid_field_statistics': {},
            'session_correlation': {
                'sessions': [],
                'event_transitions': [],
                'src_ip_session_timing': [],
            },
        }
        if output_json_path:
            Path(output_json_path).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        return result

    # ---------- EventID -> fields/value statistics ----------
    eventid_total: Counter[str] = Counter()
    eventid_field_presence: dict[str, Counter[str]] = defaultdict(Counter)
    eventid_field_values: dict[str, dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))

    # ---------- Session + timestamp correlation ----------
    events_by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
    sessions_by_src_ip: dict[str, set[str]] = defaultdict(set)
    global_transitions: Counter[str] = Counter()

    global_time_min: datetime | None = None
    global_time_max: datetime | None = None

    for event in events:
        eventid = str(event.get('eventid') or 'N/A')
        session = str(event.get('session') or 'N/A')
        src_ip = str(event.get('src_ip') or 'N/A')
        ts = _parse_ts(event.get('timestamp'))

        eventid_total[eventid] += 1

        for field, value in event.items():
            if field == '_line_no':
                continue
            eventid_field_presence[eventid][field] += 1
            value_key = _to_value_key(value)
            eventid_field_values[eventid][field][value_key] += 1

        event_copy = dict(event)
        event_copy['_parsed_ts'] = ts
        events_by_session[session].append(event_copy)
        sessions_by_src_ip[src_ip].add(session)

        if ts is not None:
            if global_time_min is None or ts < global_time_min:
                global_time_min = ts
            if global_time_max is None or ts > global_time_max:
                global_time_max = ts

    eventid_field_statistics: dict[str, Any] = {}
    for eventid, total_count in eventid_total.items():
        fields_summary: list[dict[str, Any]] = []

        for field, present_count in eventid_field_presence[eventid].items():
            value_counter = eventid_field_values[eventid][field]
            top_values = value_counter.most_common(top_values_per_field)
            fields_summary.append(
                {
                    'field': field,
                    'present_count': int(present_count),
                    'missing_count': int(total_count - present_count),
                    'present_ratio': round(present_count / total_count, 6) if total_count else 0.0,
                    'distinct_values': int(len(value_counter)),
                    'top_values': [
                        {
                            'value': value,
                            'count': int(count),
                            'ratio_in_field': round(count / present_count, 6) if present_count else 0.0,
                        }
                        for value, count in top_values
                    ],
                }
            )

        fields_summary.sort(key=lambda x: (x['present_count'], x['distinct_values']), reverse=True)

        eventid_field_statistics[eventid] = {
            'event_count': int(total_count),
            'unique_field_count': int(len(eventid_field_presence[eventid])),
            'fields': fields_summary,
        }

    # Build per-session timelines and transition stats
    session_rows: list[dict[str, Any]] = []
    src_ip_timing_rows: list[dict[str, Any]] = []

    session_first_seen: dict[str, datetime | None] = {}
    session_src_ip_map: dict[str, str] = {}

    for session, sess_events in events_by_session.items():
        sess_events.sort(
            key=lambda e: (
                e.get('_parsed_ts') is None,
                e.get('_parsed_ts') or datetime.max.replace(tzinfo=timezone.utc),
                e.get('_line_no', 0),
            )
        )

        src_ip = str(next((e.get('src_ip') for e in sess_events if e.get('src_ip')), 'N/A'))
        session_src_ip_map[session] = src_ip

        first_ts = next((e.get('_parsed_ts') for e in sess_events if e.get('_parsed_ts') is not None), None)
        last_ts = next((e.get('_parsed_ts') for e in reversed(sess_events) if e.get('_parsed_ts') is not None), None)
        session_first_seen[session] = first_ts

        event_path = [str(e.get('eventid') or 'N/A') for e in sess_events]
        timeline = []

        prev_ts = None
        for e in sess_events:
            curr_ts = e.get('_parsed_ts')
            timeline.append(
                {
                    'timestamp': _fmt_ts(curr_ts),
                    'eventid': str(e.get('eventid') or 'N/A'),
                    'delta_seconds_from_prev_event': None if prev_ts is None or curr_ts is None else round((curr_ts - prev_ts).total_seconds(), 6),
                    'line_no': int(e.get('_line_no', 0)),
                }
            )
            if curr_ts is not None:
                prev_ts = curr_ts

        for i in range(len(event_path) - 1):
            transition = f'{event_path[i]} -> {event_path[i + 1]}'
            global_transitions[transition] += 1

        session_rows.append(
            {
                'session': session,
                'src_ip': src_ip,
                'event_count': len(sess_events),
                'first_seen': _fmt_ts(first_ts),
                'last_seen': _fmt_ts(last_ts),
                'duration_seconds': _safe_duration_seconds(first_ts, last_ts),
                'event_path': event_path,
                'timeline': timeline,
            }
        )

    # Timestamp correlation between sessions (same src_ip)
    for src_ip, session_set in sessions_by_src_ip.items():
        sorted_sessions = sorted(
            list(session_set),
            key=lambda s: (
                session_first_seen.get(s) is None,
                session_first_seen.get(s) or datetime.max.replace(tzinfo=timezone.utc),
                s,
            ),
        )
        prev_session = None
        prev_ts = None
        for session in sorted_sessions:
            curr_ts = session_first_seen.get(session)
            src_ip_timing_rows.append(
                {
                    'src_ip': src_ip,
                    'session': session,
                    'session_first_seen': _fmt_ts(curr_ts),
                    'previous_session': prev_session,
                    'delta_seconds_from_previous_session': None if prev_ts is None or curr_ts is None else round((curr_ts - prev_ts).total_seconds(), 6),
                }
            )
            if curr_ts is not None:
                prev_ts = curr_ts
                prev_session = session

    session_rows.sort(key=lambda r: (r['first_seen'] == 'N/A', r['first_seen'], r['session']))
    src_ip_timing_rows.sort(key=lambda r: (r['src_ip'], r['session_first_seen'], r['session']))

    result: dict[str, Any] = {
        'source_file': str(path),
        'total_events': len(events),
        'time_range_utc': {
            'start': _fmt_ts(global_time_min),
            'end': _fmt_ts(global_time_max),
        },
        'eventid_field_statistics': eventid_field_statistics,
        'session_correlation': {
            'sessions': session_rows,
            'event_transitions': [
                {'transition': transition, 'count': int(count)}
                for transition, count in global_transitions.most_common()
            ],
            'src_ip_session_timing': src_ip_timing_rows,
        },
    }

    if output_json_path:
        Path(output_json_path).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')

    if output_html_path:
        _write_html_report(result, Path(output_html_path), top_values_per_field=top_values_per_field)

    return result


def _write_html_report(result: dict[str, Any], output_html_path: Path, top_values_per_field: int) -> None:
    output_html_path.parent.mkdir(parents=True, exist_ok=True)

    eventid_overview_rows: list[list[Any]] = []
    eventid_details_blocks: list[str] = []

    eventid_stats = result.get('eventid_field_statistics', {})
    for eventid, details in sorted(eventid_stats.items(), key=lambda x: x[1].get('event_count', 0), reverse=True):
        eventid_overview_rows.append([
            eventid,
            details.get('event_count', 0),
            details.get('unique_field_count', 0),
        ])

        for f in details.get('fields', []):
            top_values = f.get('top_values', [])
            value_rows = [[v.get('value'), v.get('count'), v.get('ratio_in_field')] for v in top_values]
            eventid_details_blocks.append(
                '<details>'
                f'<summary>{html_escape(eventid)} | field={html_escape(str(f.get("field")))} '
                f'| present={html_escape(str(f.get("present_count")))} '
                f'| distinct={html_escape(str(f.get("distinct_values")))}</summary>'
                + _html_table(['value', 'count', 'ratio_in_field'], value_rows)
                + '</details>'
            )

    transitions_rows = [
        [x.get('transition'), x.get('count')]
        for x in result.get('session_correlation', {}).get('event_transitions', [])
    ]

    sessions_rows = [
        [
            s.get('session'),
            s.get('src_ip'),
            s.get('event_count'),
            s.get('first_seen'),
            s.get('last_seen'),
            s.get('duration_seconds'),
            ' -> '.join(s.get('event_path', [])),
        ]
        for s in result.get('session_correlation', {}).get('sessions', [])
    ]

    src_timing_rows = [
        [
            x.get('src_ip'),
            x.get('session'),
            x.get('session_first_seen'),
            x.get('previous_session'),
            x.get('delta_seconds_from_previous_session'),
        ]
        for x in result.get('session_correlation', {}).get('src_ip_session_timing', [])
    ]

    html_parts = [
        '<!doctype html>',
        '<html lang="en">',
        '<head>',
        '<meta charset="utf-8" />',
        '<meta name="viewport" content="width=device-width, initial-scale=1" />',
        '<title>Single Log EventID/Session Analyzer</title>',
        '<style>',
        'body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; color: #111; }',
        'details { border: 1px solid #e5e7eb; border-radius: 8px; padding: 8px 10px; margin: 10px 0; }',
        'summary { cursor: pointer; font-weight: 700; }',
        'table.dataframe { border-collapse: collapse; width: 100%; margin-top: 8px; }',
        'table.dataframe th, table.dataframe td { border: 1px solid #e5e7eb; padding: 6px 8px; font-size: 12px; }',
        'table.dataframe thead th { background: #f8fafc; }',
        '.muted { color: #666; font-size: 12px; }',
        '</style>',
        '</head>',
        '<body>',
        '<h1>Single Log EventID/Session Analyzer</h1>',
        f"<div class='muted'>source={html_escape(str(result.get('source_file')))} | total_events={html_escape(str(result.get('total_events')))} | time_range={html_escape(str(result.get('time_range_utc', {}).get('start')))} → {html_escape(str(result.get('time_range_utc', {}).get('end')))}</div>",
        '<details open><summary>EventID overview</summary>',
        _html_table(['eventid', 'event_count', 'unique_field_count'], eventid_overview_rows),
        '</details>',
        f'<details><summary>EventID field value details (top {top_values_per_field} values per field)</summary>',
        ''.join(eventid_details_blocks) if eventid_details_blocks else '<div>No details</div>',
        '</details>',
        '<details><summary>Session timeline summary</summary>',
        _html_table(['session', 'src_ip', 'event_count', 'first_seen', 'last_seen', 'duration_seconds', 'event_path'], sessions_rows),
        '</details>',
        '<details><summary>Event transitions (global)</summary>',
        _html_table(['transition', 'count'], transitions_rows),
        '</details>',
        '<details><summary>Timestamp correlation by src_ip sessions</summary>',
        _html_table(['src_ip', 'session', 'session_first_seen', 'previous_session', 'delta_seconds_from_previous_session'], src_timing_rows),
        '</details>',
        '</body>',
        '</html>',
    ]

    output_html_path.write_text('\n'.join(html_parts), encoding='utf-8')


if __name__ == '__main__':
    import argparse as _ap
    _parser = _ap.ArgumentParser(description='Analyze a single Cowrie JSONL log')
    _parser.add_argument('input', nargs='?', default=None, help='Path to JSONL log file')
    _parser.add_argument('--output-json', default=None)
    _parser.add_argument('--output-html', default=None)
    _args = _parser.parse_args()

    _root = Path(__file__).resolve().parent.parent.parent
    _src = Path(_args.input) if _args.input else _root / 'logs' / 'cowrie_1.json'
    _stem = _src.stem
    _out_dir = _root / 'output' / 'reports'
    _out_dir.mkdir(parents=True, exist_ok=True)
    _json_out = Path(_args.output_json) if _args.output_json else _out_dir / f'{_stem}_session_stats.json'
    _html_out = Path(_args.output_html) if _args.output_html else _out_dir / f'{_stem}_session_stats.html'

    result = analyze_single_json_log(
        json_log_path=_src,
        output_json_path=_json_out,
        output_html_path=_html_out,
        top_values_per_field=20,
    )
    print(f'[OK] Source: {result["source_file"]}')
    print(f'[OK] Total events: {result["total_events"]}')
    print(f'[OK] JSON report: {_json_out}')
    print(f'[OK] HTML report: {_html_out}')
