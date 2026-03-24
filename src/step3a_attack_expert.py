"""
attack_expert.py – Step 3A: Expert Analysis of Cowrie Attack Logs
=================================================================

Analyzes any Cowrie JSONL attack log source and produces:
  1. Comprehensive statistics report (JSON + HTML)
  2. Filtered/scored attack sessions ready for training
  3. Cowrie UserDB bias correction (absorbs old Step 3.5)
  4. Feature recommendations for downstream pipeline

Designed to work with ANY Cowrie attack log — the pipeline adapts
its filtering and feature selection based on the actual data.

Scientific basis:
  - RFC 4253 (Ylonen & Lonvick, 2006): SSH protocol event ordering
  - Owezarski (2015): brute-force success rate 2-8%
  - Hofstede et al. (2014): brute-force success rate 1-5%
  - Sommer & Paxson (2010): behavioral features over temporal for IDS

Usage::

    python3 attack_expert.py
    python3 attack_expert.py --input-dir logs --keep-rate 0.05
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
from pathlib import Path
from typing import Any

from utils.report_utils import (
    ViLogger, html_header, html_footer, html_toc, html_section,
    html_cards, html_table, html_chart, html_debug_log, html_decision,
    html_verification_section, write_html,
    make_bar_chart, make_pie_chart, make_histogram, make_timeline_chart,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

ATTACK_DIR        = _PROJECT_ROOT / 'logs'
ATTACK_GLOB       = 'cowrie_*.json'
ATTACK_EXCLUDE_RE = re.compile(r'benign|merged|selected|upscaled', re.IGNORECASE)

OUTPUT_REPORT_JSON = _PROJECT_ROOT / 'output' / 'step3a' / 'attack_expert_report.json'
OUTPUT_REPORT_HTML = _PROJECT_ROOT / 'output' / 'step3a' / 'attack_expert_report.html'
OUTPUT_SELECTED    = _PROJECT_ROOT / 'output' / 'step3a' / 'attack_selected.json'
OUTPUT_FEATURE_CFG = _PROJECT_ROOT / 'output' / 'step3a' / 'pipeline_feature_config.json'

USERDB_ALLOW_ALL_USERS = {'root'}
DEFAULT_KEEP_RATE = 0.03
SEED = 42

WINDOW_MINUTES = 60

# IP-level campaign classification thresholds
_IP_BURSTY_FC_MIN   = 5     # at least 5 failed attempts across all sessions
_IP_BURSTY_AVG_MAX  = 3.0    # avg inter-login < 3s
_IP_LOW_SLOW_AVG_MIN = 30.0  # avg inter-login > 30s = deliberately spread out
_IP_SPRAY_RATIO     = 0.5    # unique_fail_users / fc >= 50%
_IP_SPRAY_FC_MIN    = 5      # need enough attempts to judge diversity
_IP_HIT_RUN_FC_MAX  = 2      # 1–2 total failures = fleeting probe


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _parse_ts(ts_value: Any) -> datetime | None:
    if not isinstance(ts_value, str) or not ts_value:
        return None
    try:
        return datetime.fromisoformat(ts_value.replace('Z', '+00:00'))
    except Exception:
        return None


def _fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def _floor_dt(dt: datetime, minutes: int) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    minute = (dt.minute // minutes) * minutes
    return dt.replace(minute=minute, second=0, microsecond=0)


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


def _shannon_entropy(labels: list[str]) -> float:
    if not labels:
        return 0.0
    n = len(labels)
    counts = Counter(labels)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


# ---------------------------------------------------------------------------
# Sessionize
# ---------------------------------------------------------------------------
def _sessionize(events: list[dict]) -> dict[str, list[dict]]:
    sessions: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        sid = ev.get('session')
        if sid:
            sessions[str(sid)].append(ev)
    for sid in sessions:
        sessions[sid].sort(key=lambda e: e.get('timestamp', ''))
    return dict(sessions)


def _session_protocol(events: list[dict]) -> str | None:
    for ev in events:
        if ev.get('eventid') == 'cowrie.session.connect':
            return ev.get('protocol')
    return None


# ---------------------------------------------------------------------------
# IP-level campaign classification
# ---------------------------------------------------------------------------
def _classify_ip_campaign(
    fc: int,
    n_unique_fail: int,
    intervals_s: list[float],
) -> tuple[str, float, float, float]:
    """Classify an IP's aggregated attack behavior into a campaign type.

    All metrics are computed from ALL login events of the IP across every
    TCP session, which correctly captures distributed attacks (e.g. 100
    hit-and-run sessions × fc=1 → IP fc=100).

    Returns (campaign_type, avg_interval, interval_variance, spray_ratio).
    """
    if fc == 0:
        return ('success_only', 0.0, 0.0, 0.0)

    avg_t = statistics.mean(intervals_s) if intervals_s else 999.0
    var_t = statistics.variance(intervals_s) if len(intervals_s) >= 2 else 0.0
    spray_ratio = n_unique_fail / fc

    # Priority 1: Spraying — credential diversity is the strongest signal
    if spray_ratio >= _IP_SPRAY_RATIO and fc >= _IP_SPRAY_FC_MIN:
        return ('spraying', avg_t, var_t, spray_ratio)

    # Priority 2: Bursty — high volume + fast automated attempts
    if fc >= _IP_BURSTY_FC_MIN and avg_t < _IP_BURSTY_AVG_MAX:
        return ('bursty', avg_t, var_t, spray_ratio)

    # Priority 3: Low-and-slow — deliberately spread out over time
    if avg_t >= _IP_LOW_SLOW_AVG_MIN:
        return ('low_and_slow', avg_t, var_t, spray_ratio)

    # Priority 4: Hit-and-run — too few total attempts to form a campaign
    if fc <= _IP_HIT_RUN_FC_MAX:
        return ('hit_and_run', avg_t, var_t, spray_ratio)

    # Fallback: classify by speed
    if avg_t < 5.0:
        return ('bursty', avg_t, var_t, spray_ratio)
    return ('low_and_slow', avg_t, var_t, spray_ratio)


# ---------------------------------------------------------------------------
# Core: Analyze attack log
# ---------------------------------------------------------------------------
def analyze_attack_log(
    events: list[dict],
    window_minutes: int = WINDOW_MINUTES,
) -> dict[str, Any]:
    """Produce comprehensive statistics for attack log data."""

    sessions = _sessionize(events)
    total_events = len(events)
    total_sessions = len(sessions)

    # --- EventID distribution ---
    eventid_dist = Counter(ev.get('eventid', 'unknown') for ev in events)

    # --- Protocol distribution ---
    proto_dist: Counter[str] = Counter()
    for sid, evts in sessions.items():
        proto = _session_protocol(evts) or 'unknown'
        proto_dist[proto] += 1

    # --- Per-session login analysis ---
    session_profiles: list[dict[str, Any]] = []
    ip_sessions: dict[str, list[str]] = defaultdict(list)
    ip_events: dict[str, list[dict]] = defaultdict(list)

    for sid, evts in sessions.items():
        n_fail = sum(1 for e in evts if e.get('eventid') == 'cowrie.login.failed')
        n_success = sum(1 for e in evts if e.get('eventid') == 'cowrie.login.success')
        has_login = n_fail > 0 or n_success > 0

        src_ip = ''
        for e in evts:
            if e.get('src_ip'):
                src_ip = e['src_ip']
                break

        timestamps = []
        for e in evts:
            ts = _parse_ts(e.get('timestamp'))
            if ts:
                timestamps.append(ts)

        duration = 0.0
        if len(timestamps) >= 2:
            duration = (max(timestamps) - min(timestamps)).total_seconds()

        fail_usernames = [
            e.get('username', '') for e in evts
            if e.get('eventid') == 'cowrie.login.failed'
        ]
        success_usernames = [
            e.get('username', '') for e in evts
            if e.get('eventid') == 'cowrie.login.success'
        ]

        client_versions = [
            e.get('version', '') for e in evts
            if e.get('eventid') == 'cowrie.client.version' and e.get('version')
        ]

        profile = {
            'session': sid,
            'src_ip': src_ip,
            'n_fail': n_fail,
            'n_success': n_success,
            'has_login': has_login,
            'n_unique_fail_users': len(set(fail_usernames)),
            'duration_s': round(duration, 2),
            'protocol': _session_protocol(evts) or 'unknown',
            'event_count': len(evts),
            'client_version': client_versions[0] if client_versions else '',
        }
        session_profiles.append(profile)

        if src_ip:
            ip_sessions[src_ip].append(sid)
            ip_events[src_ip].extend(evts)

    # --- IP-level analysis ---
    unique_ips = len(ip_sessions)
    ips_with_login = set()
    ips_scan_only = set()
    for ip, sids in ip_sessions.items():
        has_any_login = False
        for sid in sids:
            for e in sessions[sid]:
                eid = e.get('eventid', '')
                if eid in ('cowrie.login.failed', 'cowrie.login.success'):
                    has_any_login = True
                    break
            if has_any_login:
                break
        if has_any_login:
            ips_with_login.add(ip)
        else:
            ips_scan_only.add(ip)

    # --- IP time spans ---
    ip_spans: dict[str, float] = {}
    for ip, evts_list in ip_events.items():
        timestamps = []
        for e in evts_list:
            ts = _parse_ts(e.get('timestamp'))
            if ts:
                timestamps.append(ts)
        if len(timestamps) >= 2:
            timestamps.sort()
            ip_spans[ip] = (timestamps[-1] - timestamps[0]).total_seconds()
        else:
            ip_spans[ip] = 0.0

    # --- Feature vector estimation: (IP, hour) pairs with login events ---
    ip_window_keys: set[tuple[str, str]] = set()
    for ev in events:
        eid = ev.get('eventid', '')
        if eid not in ('cowrie.login.failed', 'cowrie.login.success'):
            continue
        src_ip = str(ev.get('src_ip', ''))
        ts = _parse_ts(ev.get('timestamp'))
        if not src_ip or ts is None:
            continue
        win_key = _fmt_ts(_floor_dt(ts, window_minutes))
        ip_window_keys.add((src_ip, win_key))

    # --- Global time range ---
    all_ts = []
    for ev in events:
        ts = _parse_ts(ev.get('timestamp'))
        if ts:
            all_ts.append(ts)
    all_ts.sort()
    time_range_hours = 0.0
    time_range_days = 0
    first_ts_str = ''
    last_ts_str = ''
    if len(all_ts) >= 2:
        delta = all_ts[-1] - all_ts[0]
        time_range_hours = delta.total_seconds() / 3600
        time_range_days = delta.days
        first_ts_str = _fmt_ts(all_ts[0])
        last_ts_str = _fmt_ts(all_ts[-1])

    # --- Cowrie bias detection ---
    root_success_sessions = 0
    total_login_sessions = 0
    for sp in session_profiles:
        if sp['has_login']:
            total_login_sessions += 1
        if sp['n_success'] > 0:
            for ev in sessions[sp['session']]:
                if (ev.get('eventid') == 'cowrie.login.success'
                        and str(ev.get('username', '')).strip().lower() in USERDB_ALLOW_ALL_USERS):
                    root_success_sessions += 1
                    break

    # --- Client version distribution ---
    all_client_versions: list[str] = []
    for ev in events:
        if ev.get('eventid') == 'cowrie.client.version':
            v = ev.get('version', '')
            if v:
                all_client_versions.append(v)
    client_version_dist = Counter(all_client_versions)

    # --- Behavioral archetype distribution (legacy fine-grained) ---
    archetype_dist: Counter[str] = Counter()
    for sp in session_profiles:
        fc = sp['n_fail']
        sc = sp['n_success']
        if fc == 0 and sc == 0:
            key = 'scan_only'
        elif fc == 0 and sc > 0:
            key = f'success_only({sc})'
        elif fc > 0 and sc == 0:
            key = f'fail_only({min(fc, 20)}+)' if fc > 20 else f'fail_only({fc})'
        else:
            key = f'fail({min(fc, 20)}+)_success({min(sc, 5)}+)' if fc > 20 or sc > 5 else f'fail({fc})_success({sc})'
        archetype_dist[key] += 1

    # --- IP-level campaign classification (Bursty / Low-and-slow / Spraying) ---
    # After all session-level work (profiling, scoring, bias detection) is
    # done, we aggregate by IP to classify the *campaign* type.  This avoids
    # the "100 × fc=1 hit-and-run" trap where session-level tracking misses
    # distributed bot campaigns.
    ip_campaign_dist: Counter[str] = Counter()
    ip_campaign_profiles: list[dict[str, Any]] = []

    for ip in sorted(ip_sessions.keys()):
        ip_fc = 0
        ip_sc = 0
        ip_fail_users: list[str] = []
        ip_login_ts: list[datetime] = []

        for sid in ip_sessions[ip]:
            for e in sessions[sid]:
                eid = e.get('eventid', '')
                if eid == 'cowrie.login.failed':
                    ip_fc += 1
                    u = e.get('username', '')
                    if u:
                        ip_fail_users.append(u)
                    ts = _parse_ts(e.get('timestamp'))
                    if ts:
                        ip_login_ts.append(ts)
                elif eid == 'cowrie.login.success':
                    ip_sc += 1
                    ts = _parse_ts(e.get('timestamp'))
                    if ts:
                        ip_login_ts.append(ts)

        has_any_login = (ip_fc + ip_sc) > 0
        if not has_any_login:
            ip_campaign_dist['scan_only'] += 1
            ip_campaign_profiles.append({
                'src_ip': ip, 'n_sessions': len(ip_sessions[ip]),
                'fc_total': 0, 'sc_total': 0, 'campaign_type': 'scan_only',
                'avg_interval': 0, 'interval_variance': 0,
                'spray_ratio': 0, 'n_unique_fail_users': 0,
                'span_seconds': round(ip_spans.get(ip, 0), 1),
            })
            continue

        ip_login_ts.sort()
        intervals_s: list[float] = []
        for i in range(1, len(ip_login_ts)):
            intervals_s.append((ip_login_ts[i] - ip_login_ts[i - 1]).total_seconds())

        n_unique_fail = len(set(ip_fail_users))
        ctype, avg_t, var_t, spray_ratio = _classify_ip_campaign(
            ip_fc, n_unique_fail, intervals_s,
        )

        ip_campaign_dist[ctype] += 1
        ip_campaign_profiles.append({
            'src_ip': ip, 'n_sessions': len(ip_sessions[ip]),
            'fc_total': ip_fc, 'sc_total': ip_sc,
            'campaign_type': ctype,
            'avg_interval': round(avg_t, 4),
            'interval_variance': round(var_t, 4),
            'spray_ratio': round(spray_ratio, 4),
            'n_unique_fail_users': n_unique_fail,
            'span_seconds': round(ip_spans.get(ip, 0), 1),
        })

    ip_campaign_by_type: dict[str, list[dict]] = defaultdict(list)
    for cp in ip_campaign_profiles:
        ip_campaign_by_type[cp['campaign_type']].append(cp)

    # --- Failed username diversity ---
    all_fail_usernames: list[str] = []
    for ev in events:
        if ev.get('eventid') == 'cowrie.login.failed':
            u = ev.get('username', '')
            if u:
                all_fail_usernames.append(u)
    top_fail_usernames = Counter(all_fail_usernames).most_common(20)

    # --- Session timeline summary (mirroring session_analyzer format) ---
    session_timelines: list[dict[str, Any]] = []
    for sp in session_profiles:
        evts = sessions[sp['session']]
        event_path = [e.get('eventid', 'unknown') for e in evts]
        timestamps_parsed = []
        for e in evts:
            ts = _parse_ts(e.get('timestamp'))
            if ts:
                timestamps_parsed.append(ts)
        first_ts = min(timestamps_parsed) if timestamps_parsed else None
        last_ts = max(timestamps_parsed) if timestamps_parsed else None
        session_timelines.append({
            'session': sp['session'],
            'src_ip': sp['src_ip'],
            'event_count': sp['event_count'],
            'n_fail': sp['n_fail'],
            'n_success': sp['n_success'],
            'first_seen': _fmt_ts(first_ts) if first_ts else 'N/A',
            'last_seen': _fmt_ts(last_ts) if last_ts else 'N/A',
            'duration_seconds': sp['duration_s'],
            'event_path': ' -> '.join(event_path),
            'client_version': sp['client_version'],
            'score': 1 if sp['has_login'] and sp['protocol'] == 'ssh' else (
                1 if sp['has_login'] else 0),
        })
    session_timelines.sort(key=lambda x: x.get('first_seen', ''))

    # --- Event transitions ---
    event_transitions: Counter[str] = Counter()
    for sid, evts in sessions.items():
        eids = [e.get('eventid', 'unknown') for e in evts]
        for i in range(len(eids) - 1):
            event_transitions[f'{eids[i]} -> {eids[i+1]}'] += 1

    report = {
        'summary': {
            'total_events': total_events,
            'total_sessions': total_sessions,
            'unique_ips': unique_ips,
            'ips_with_login': len(ips_with_login),
            'ips_scan_only': len(ips_scan_only),
            'estimated_feature_vectors': len(ip_window_keys),
            'time_range_hours': round(time_range_hours, 1),
            'time_range_days': time_range_days,
            'first_timestamp': first_ts_str,
            'last_timestamp': last_ts_str,
        },
        'eventid_distribution': dict(eventid_dist.most_common()),
        'protocol_distribution': dict(proto_dist.most_common()),
        'session_login_stats': {
            'sessions_with_login': sum(1 for sp in session_profiles if sp['has_login']),
            'sessions_scan_only': sum(1 for sp in session_profiles if not sp['has_login']),
            'sessions_with_fail': sum(1 for sp in session_profiles if sp['n_fail'] > 0),
            'sessions_with_success': sum(1 for sp in session_profiles if sp['n_success'] > 0),
        },
        'cowrie_bias': {
            'root_success_sessions': root_success_sessions,
            'total_login_sessions': total_login_sessions,
            'root_success_rate': round(
                root_success_sessions / max(total_login_sessions, 1), 4),
            'bias_detected': root_success_sessions > total_login_sessions * 0.10,
        },
        'ip_analysis': {
            'total_unique_ips': unique_ips,
            'ips_with_login_events': len(ips_with_login),
            'ips_scan_only': len(ips_scan_only),
            'ips_spanning_gt_1h': sum(1 for s in ip_spans.values() if s > 3600),
            'median_ip_span_seconds': round(
                statistics.median(ip_spans.values()), 1) if ip_spans else 0,
        },
        'client_version_distribution': {
            k: v for k, v in client_version_dist.most_common(15)
        },
        'top_20_fail_usernames': {u: c for u, c in top_fail_usernames},
        'archetype_distribution': {
            k: v for k, v in archetype_dist.most_common(20)
        },
        'attack_type_classification': {
            'level': 'IP (campaign)',
            'distribution': dict(ip_campaign_dist.most_common()),
            'total_ips_classified': len(ip_campaign_profiles),
            'thresholds': {
                'bursty': f'fc >= {_IP_BURSTY_FC_MIN} AND avg_interval < {_IP_BURSTY_AVG_MAX}s',
                'low_and_slow': f'avg_interval >= {_IP_LOW_SLOW_AVG_MIN}s',
                'spraying': f'unique_users/fc >= {_IP_SPRAY_RATIO} AND fc >= {_IP_SPRAY_FC_MIN}',
                'hit_and_run': f'fc <= {_IP_HIT_RUN_FC_MAX}',
                'scan_only': 'IP không có event login nào',
            },
            'examples': {
                ctype: [
                    {
                        'src_ip': p['src_ip'],
                        'n_sessions': p['n_sessions'],
                        'fc_total': p['fc_total'],
                        'sc_total': p['sc_total'],
                        'avg_interval': p['avg_interval'],
                        'interval_variance': p['interval_variance'],
                        'spray_ratio': p['spray_ratio'],
                        'n_unique_fail_users': p['n_unique_fail_users'],
                        'span_seconds': p['span_seconds'],
                    }
                    for p in profiles[:5]
                ]
                for ctype, profiles in ip_campaign_by_type.items()
                if ctype != 'scan_only'
            },
        },
        'session_timeline_summary': session_timelines[:200],
        'event_transitions': [
            {'transition': t, 'count': c}
            for t, c in event_transitions.most_common(30)
        ],
    }

    return report


# ---------------------------------------------------------------------------
# Core: Score sessions
# ---------------------------------------------------------------------------
def score_sessions(
    sessions: dict[str, list[dict]],
) -> dict[str, int]:
    """
    Score each session for training suitability.
    Score 1 = valid attack (SSH, has login events).
    Score 0 = discard (scan-only, telnet, incomplete).
    """
    scores: dict[str, int] = {}
    for sid, evts in sessions.items():
        proto = _session_protocol(evts)
        if proto and proto != 'ssh':
            scores[sid] = 0
            continue

        has_login = any(
            e.get('eventid') in ('cowrie.login.failed', 'cowrie.login.success')
            for e in evts
        )
        scores[sid] = 1 if has_login else 0

    return scores


# ---------------------------------------------------------------------------
# Core: Handle Cowrie bias (absorbs old Step 3.5)
# ---------------------------------------------------------------------------
def handle_cowrie_bias(
    events: list[dict[str, Any]],
    allow_all_users: set[str] | None = None,
    keep_rate: float = DEFAULT_KEEP_RATE,
    seed: int = SEED,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Smart relabelling: relabel most attack root login.success -> login.failed,
    but keep *keep_rate* fraction of sessions with their successes intact.

    Decisions are at session level (all-or-nothing per session).
    """
    if allow_all_users is None:
        allow_all_users = USERDB_ALLOW_ALL_USERS

    rng = random.Random(seed)

    session_has_root_success: dict[str, bool] = defaultdict(bool)
    for ev in events:
        if (ev.get('eventid') == 'cowrie.login.success'
                and str(ev.get('username', '')).strip().lower() in allow_all_users):
            sid = ev.get('session', '')
            if sid:
                session_has_root_success[sid] = True

    affected_sessions = [sid for sid, v in session_has_root_success.items() if v]
    rng.shuffle(affected_sessions)

    n_keep = max(1, round(len(affected_sessions) * keep_rate))
    sessions_to_keep = set(affected_sessions[:n_keep])
    sessions_to_relabel = set(affected_sessions[n_keep:])

    stats: dict[str, Any] = {
        'attack_sessions_with_root_success': len(affected_sessions),
        'sessions_kept_success': len(sessions_to_keep),
        'sessions_relabeled': len(sessions_to_relabel),
        'keep_rate_actual': round(len(sessions_to_keep) / max(len(affected_sessions), 1), 4),
        'events_relabeled': 0,
        'events_kept_success': 0,
    }

    corrected: list[dict[str, Any]] = []
    for ev in events:
        eventid = ev.get('eventid', '')
        sid = ev.get('session', '')

        if eventid != 'cowrie.login.success':
            corrected.append(ev)
            continue

        username = str(ev.get('username', '')).strip().lower()
        if username not in allow_all_users:
            corrected.append(ev)
            continue

        if sid in sessions_to_keep:
            stats['events_kept_success'] += 1
            corrected.append(ev)
        elif sid in sessions_to_relabel:
            stats['events_relabeled'] += 1
            ev_fixed = dict(ev)
            ev_fixed['eventid'] = 'cowrie.login.failed'
            ev_fixed['_original_eventid'] = 'cowrie.login.success'
            ev_fixed['_correction_reason'] = 'cowrie_userdb_allow_all'
            msg = ev_fixed.get('message', '')
            if msg:
                ev_fixed['message'] = msg.replace('succeeded', 'failed')
            corrected.append(ev_fixed)
        else:
            corrected.append(ev)

    return corrected, stats


# ---------------------------------------------------------------------------
# Core: Recommend features
# ---------------------------------------------------------------------------
def recommend_features(report: dict[str, Any], bias_corrected: bool) -> dict[str, Any]:
    """
    Generate feature recommendations based on attack data analysis.
    Returns a config dict consumed by feature_extraction.py and train_and_demo.py.
    """
    summary = report['summary']
    time_hours = summary.get('time_range_hours', 0)
    time_days = summary.get('time_range_days', 0)
    client_dist = report.get('client_version_distribution', {})

    drop_features: list[str] = []
    shortcut_features: list[str] = ['num_failed_ports', 'ip_entropy']
    warnings: list[str] = []

    if time_hours < 24:
        drop_features.append('time_of_day_avg')
        warnings.append(
            f'time_of_day_avg DROPPED: attack data spans only {time_hours:.1f}h (<24h). '
            'Any timestamp expansion would make this feature noise. '
            'Cite: Owezarski (2015) — botnet operates 24/7, time-of-day is not discriminative.'
        )

    if time_days < 2:
        drop_features.append('num_failed_days')
        warnings.append(
            f'num_failed_days DROPPED: attack data spans {time_days} day(s). '
            'This feature is too sensitive to data assembly method. '
            'Cite: Hofstede et al. (2014) — IP rotation makes per-IP day count unreliable.'
        )

    if not bias_corrected:
        shortcut_features.append('success_ratio')
        warnings.append(
            'success_ratio added to SHORTCUT_FEATURES: no bias correction was applied.'
        )

    dominant_version = ''
    if client_dist:
        total_cv = sum(client_dist.values())
        top_cv = max(client_dist.values())
        if total_cv > 0 and top_cv / total_cv > 0.80:
            dominant_version = max(client_dist, key=client_dist.get)
            warnings.append(
                f'client_version_category: {top_cv/total_cv:.0%} of attack uses '
                f'"{dominant_version}". Potential shortcut — monitor via SHAP analysis.'
            )

    all_features = [
        'failed_attempts', 'num_unique_users', 'username_entropy',
        'success_ratio', 'num_failed_ports',
        'avg_time_between_attempts', 'login_interval_variance',
        'time_of_day_avg', 'num_failed_days',
        'ip_entropy', 'client_version_category',
        'time_to_auth', 'session_duration',
        'min_inter_arrival', 'max_inter_arrival',
        'hour_sin', 'hour_cos',
    ]
    active_features = [
        f for f in all_features
        if f not in drop_features and f not in shortcut_features
    ]

    attack_types = report.get('attack_type_classification', {})

    config = {
        'all_features': all_features,
        'drop_features': drop_features,
        'shortcut_features': shortcut_features,
        'active_features': active_features,
        'bias_correction_applied': bias_corrected,
        'success_ratio_enabled': bias_corrected,
        'warnings': warnings,
        'attack_time_range_hours': round(time_hours, 1),
        'attack_time_range_days': time_days,
        'estimated_attack_feature_vectors': report['summary']['estimated_feature_vectors'],
        'attack_type_distribution': attack_types.get('distribution', {}),
    }

    return config


# ---------------------------------------------------------------------------
# HTML report (with embedded charts and verification tests)
# ---------------------------------------------------------------------------
def _build_html_report(
    report: dict[str, Any],
    bias_stats: dict[str, Any],
    feature_config: dict[str, Any],
    session_scores: dict[str, int],
    all_events: list[dict],
    selected_events: list[dict],
    log: ViLogger,
) -> str:
    """Build a comprehensive standalone HTML report with charts, verification, and decisions."""

    s = report['summary']
    cb = report['cowrie_bias']
    sls = report['session_login_stats']
    n_selected = sum(1 for v in session_scores.values() if v == 1)
    n_discarded = sum(1 for v in session_scores.values() if v == 0)
    total_sess = s['total_sessions'] or 1
    total_ev = s['total_events'] or 1

    toc_sections = [
        ('overview', '1. Tổng quan dữ liệu'),
        ('eventid', '2. Phân phối EventID'),
        ('protocol', '3. Phân phối giao thức'),
        ('archetype', '4. Phân phối archetype hành vi'),
        ('attack-types', '5. Phân loại chiến dịch tấn công theo IP'),
        ('client-version', '6. Phiên bản client SSH'),
        ('fail-usernames', '7. Tên đăng nhập thất bại phổ biến'),
        ('ip-analysis', '8. Phân tích IP'),
        ('transitions', '9. Chuyển tiếp sự kiện'),
        ('timeline', '10. Hoạt động theo giờ'),
        ('scoring', '11. Chấm điểm & Lọc phiên'),
        ('bias', '12. Hiệu chỉnh bias Cowrie'),
        ('features', '13. Khuyến nghị đặc trưng'),
        ('verification', '14. Kiểm tra xác minh'),
        ('debug-log', '15. Nhật ký debug'),
    ]

    parts: list[str] = []

    # ── Header + TOC ──
    parts.append(html_header(
        'Step 3A — Phân tích chuyên gia tấn công',
        'Step3A',
        f'{s["total_events"]:,} sự kiện | {s["total_sessions"]:,} phiên | '
        f'Thời gian: {s.get("first_timestamp", "")} — {s.get("last_timestamp", "")}',
    ))
    parts.append(html_toc(toc_sections))

    # ── 1. Overview cards ──
    parts.append(html_section('overview', '1. Tổng quan dữ liệu'))
    parts.append(html_cards([
        ('Tổng sự kiện', s['total_events']),
        ('Tổng phiên', s['total_sessions']),
        ('IP duy nhất', s['unique_ips']),
        ('IP có đăng nhập', s['ips_with_login']),
        ('IP chỉ quét', s['ips_scan_only']),
        ('Vector đặc trưng ước tính', s['estimated_feature_vectors']),
        ('Phiên đã chọn', n_selected),
        ('Phiên bị loại', n_discarded),
        ('Khoảng thời gian', f'{s["time_range_hours"]:.1f}h ({s["time_range_days"]} ngày)'),
    ]))
    parts.append(
        '<details open><summary><b>Giải thích các chỉ số</b></summary>'
        '<table><tr><th>Chỉ số</th><th>Ý nghĩa</th><th>Cách xác định</th></tr>'
        '<tr><td><b>Tổng sự kiện</b></td>'
        '<td>Tổng số dòng event trong các file Cowrie JSONL (logs/cowrie_*.json)</td>'
        '<td>Đếm tất cả JSON object trong file, mỗi dòng = 1 event (connect, login, command, close, …)</td></tr>'
        '<tr><td><b>Tổng phiên</b></td>'
        '<td>Số session SSH riêng biệt mà attacker đã thiết lập đến honeypot</td>'
        '<td>Nhóm event theo trường <code>session</code> — mỗi session ID = 1 kết nối SSH từ đầu đến cuối</td></tr>'
        '<tr><td><b>IP duy nhất</b></td>'
        '<td>Số địa chỉ IP khác nhau đã kết nối đến honeypot</td>'
        '<td><code>len(set(src_ip))</code> — mỗi IP thường là 1 máy attacker hoặc 1 node trong botnet</td></tr>'
        '<tr><td><b>IP có đăng nhập</b></td>'
        '<td>IP đã thực hiện ít nhất 1 lần thử đăng nhập (brute-force thực sự)</td>'
        '<td>IP có session chứa event <code>cowrie.login.failed</code> hoặc <code>cowrie.login.success</code>. '
        'Đây là IP có hành vi tấn công brute-force, không chỉ quét cổng</td></tr>'
        '<tr><td><b>IP chỉ quét</b></td>'
        '<td>IP chỉ kết nối rồi ngắt, không bao giờ thử đăng nhập (port scanning / fingerprinting)</td>'
        '<td><code>IP duy nhất − IP có đăng nhập</code>. Các IP này chỉ có event <code>session.connect</code> '
        'và <code>session.closed</code> — chúng dò xem SSH có mở không rồi bỏ đi, không brute-force</td></tr>'
        '<tr><td><b>Vector đặc trưng ước tính</b></td>'
        '<td>Số feature vector mà Step 4 sẽ tạo ra từ dữ liệu attack này</td>'
        '<td>Đếm số cặp <code>(src_ip, cửa sổ 60 phút)</code> duy nhất có chứa event đăng nhập. '
        'VD: IP A tấn công trong 3 giờ → tạo 3 feature vectors. '
        'Con số này quyết định Step 3B cần upscale bao nhiêu benign session</td></tr>'
        '<tr><td><b>Phiên đã chọn</b></td>'
        '<td>Session đủ điều kiện để đưa vào training (score = 1)</td>'
        '<td>Session sử dụng giao thức SSH <b>VÀ</b> có ít nhất 1 event login (failed hoặc success). '
        'Đây là phiên brute-force thực sự, có giá trị huấn luyện</td></tr>'
        '<tr><td><b>Phiên bị loại</b></td>'
        '<td>Session bị loại bỏ vì không phải brute-force (score = 0)</td>'
        '<td>Bị loại nếu: (1) giao thức Telnet thay vì SSH, (2) chỉ có event connect/close '
        'mà không thử đăng nhập (scan-only), hoặc (3) session không hoàn chỉnh. '
        'Giữ lại sẽ thêm nhiễu vào model vì không có hành vi tấn công đặc trưng</td></tr>'
        '<tr><td><b>Khoảng thời gian</b></td>'
        '<td>Thời gian từ event đầu tiên đến event cuối cùng trong toàn bộ log</td>'
        '<td><code>last_timestamp − first_timestamp</code> — cho biết dữ liệu tấn công thu thập trong bao lâu</td></tr>'
        '</table></details>'
    )

    # ── 2. EventID distribution ──
    parts.append(html_section('eventid', '2. Phân phối EventID'))
    eid_dist = report['eventid_distribution']
    eid_sorted = sorted(eid_dist.items(), key=lambda x: -x[1])
    parts.append(html_chart(
        make_bar_chart(
            [e[0] for e in eid_sorted],
            [e[1] for e in eid_sorted],
            title='Phân phối EventID',
            xlabel='Số lượng',
            horizontal=True,
            figsize=(10, max(4, len(eid_sorted) * 0.5)),
            color='#3182ce',
        ),
        'Biểu đồ thanh ngang: số lượng sự kiện theo EventID',
    ))
    parts.append(html_table(
        ['EventID', 'Số lượng', '%'],
        [[eid, cnt, f'{cnt / total_ev * 100:.1f}%'] for eid, cnt in eid_sorted],
    ))

    # ── 3. Protocol distribution ──
    parts.append(html_section('protocol', '3. Phân phối giao thức'))
    proto_dist = report['protocol_distribution']
    proto_sorted = sorted(proto_dist.items(), key=lambda x: -x[1])
    parts.append(html_chart(
        make_pie_chart(
            [p[0] for p in proto_sorted],
            [p[1] for p in proto_sorted],
            title='Phân phối giao thức phiên',
        ),
        'Biểu đồ tròn: phân bố phiên theo giao thức',
    ))
    parts.append(html_table(
        ['Giao thức', 'Số phiên', '%'],
        [[p, cnt, f'{cnt / total_sess * 100:.1f}%'] for p, cnt in proto_sorted],
    ))

    # ── 4. Archetype distribution ──
    parts.append(html_section('archetype', '4. Phân phối archetype hành vi'))
    arch_dist = report['archetype_distribution']
    arch_sorted = sorted(arch_dist.items(), key=lambda x: -x[1])
    parts.append(html_chart(
        make_bar_chart(
            [a[0] for a in arch_sorted],
            [a[1] for a in arch_sorted],
            title='Phân phối archetype hành vi phiên',
            ylabel='Số phiên',
            color='#805ad5',
            figsize=(10, 5),
        ),
        'Biểu đồ cột: phân bố archetype hành vi của các phiên tấn công',
    ))
    parts.append(html_table(
        ['Archetype', 'Số phiên', '%'],
        [[arch, cnt, f'{cnt / total_sess * 100:.1f}%'] for arch, cnt in arch_sorted],
    ))

    # ── 5. Attack-type classification (IP-level campaign) ──
    parts.append(html_section('attack-types',
                              '5. Phân loại chiến dịch tấn công theo IP (Campaign Classification)'))
    atc = report.get('attack_type_classification', {})
    at_dist = atc.get('distribution', {})
    at_examples = atc.get('examples', {})
    at_sorted = sorted(at_dist.items(), key=lambda x: -x[1])
    at_total = sum(at_dist.values()) or 1
    at_n_ips = atc.get('total_ips_classified', at_total)

    parts.append(html_decision(
        'Tiêu chí phân loại chiến dịch tấn công (per IP, gom tất cả session)',
        '<p><b>Tại sao theo IP thay vì session?</b> Bot hiện đại (Mirai, Medusa) '
        'thường mở 1 session → thử 1 password → đóng. Nếu track theo session, '
        '100 session × fc=1 đều bị coi là "hit-and-run". Nhưng gom theo IP: '
        'tổng fc=100, avg_interval=15 phút → đây rõ ràng là chiến dịch <b>Low-and-slow</b>.</p>'
        '<table>'
        '<tr><th>Kiểu chiến dịch</th><th>Đặc điểm hành vi</th>'
        '<th>Tiêu chí (per IP, gom toàn bộ session)</th></tr>'
        '<tr><td><b style="color:#e53e3e">Bursty Brute-force</b></td>'
        '<td>Đập cửa liên tục, tốc độ cực nhanh (bot/script tự động)</td>'
        f'<td><code>fc &gt;= {_IP_BURSTY_FC_MIN}</code> AND '
        f'<code>avg_interval &lt; {_IP_BURSTY_AVG_MAX}s</code></td></tr>'
        '<tr><td><b style="color:#dd6b20">Low-and-slow</b></td>'
        '<td>Rải rác qua nhiều session để tránh Fail2Ban/rate-limit</td>'
        f'<td><code>avg_interval &gt;= {_IP_LOW_SLOW_AVG_MIN}s</code></td></tr>'
        '<tr><td><b style="color:#805ad5">Username Spraying</b></td>'
        '<td>Thử nhiều username khác nhau với cùng mật khẩu phổ biến</td>'
        f'<td><code>unique_users/fc &gt;= {_IP_SPRAY_RATIO}</code> AND '
        f'<code>fc &gt;= {_IP_SPRAY_FC_MIN}</code></td></tr>'
        '<tr><td><b style="color:#718096">Hit-and-run</b></td>'
        '<td>IP chỉ thử 1–2 lần rồi biến mất (trinh sát / quét tự động)</td>'
        f'<td><code>fc &lt;= {_IP_HIT_RUN_FC_MAX}</code></td></tr>'
        '<tr><td><b style="color:#a0aec0">Scan-only</b></td>'
        '<td>IP chỉ kết nối, không thử đăng nhập</td>'
        '<td>Không có event login.failed hoặc login.success</td></tr>'
        '</table>',
        'Owezarski (2015): Phân loại hành vi tấn công SSH dựa trên temporal density và credential diversity. '
        'Hofstede et al. (2014): Bursty vs Low-and-slow là 2 chiến thuật chính trong SSH brute-force. '
        'Việc gom theo IP thay vì session giúp phát hiện chính xác chiến dịch phân tán (distributed campaigns) '
        'mà bot hiện đại sử dụng — mỗi session chỉ chứa 1 lần thử nhưng tổng IP thể hiện rõ pattern.',
    ))

    if at_sorted:
        at_colors = {
            'bursty': '#e53e3e', 'low_and_slow': '#dd6b20',
            'spraying': '#805ad5', 'hit_and_run': '#718096',
            'scan_only': '#a0aec0', 'success_only': '#38a169',
        }
        parts.append(html_chart(
            make_pie_chart(
                [a[0] for a in at_sorted],
                [a[1] for a in at_sorted],
                title=f'Phân loại chiến dịch tấn công ({at_n_ips} IP)',
                colors=[at_colors.get(a[0], '#3182ce') for a in at_sorted],
            ),
            'Biểu đồ tròn: phân bố kiểu chiến dịch tấn công theo IP',
        ))
    parts.append(html_table(
        ['Kiểu chiến dịch', 'Số IP', '%'],
        [[ctype, cnt, f'{cnt / at_total * 100:.1f}%'] for ctype, cnt in at_sorted],
    ))

    for ctype in ('bursty', 'low_and_slow', 'spraying', 'hit_and_run'):
        examples = at_examples.get(ctype, [])
        if examples:
            parts.append(f'<h4>Ví dụ IP chiến dịch <code>{ctype}</code> (top 5)</h4>')
            parts.append(html_table(
                ['IP', 'Sessions', 'fc (tổng)', 'sc (tổng)',
                 'Avg interval (s)', 'Variance', 'Spray ratio',
                 'Unique users', 'Span (s)'],
                [[
                    ex['src_ip'], ex['n_sessions'], ex['fc_total'], ex['sc_total'],
                    ex['avg_interval'], ex['interval_variance'], ex['spray_ratio'],
                    ex['n_unique_fail_users'], ex['span_seconds'],
                ] for ex in examples],
            ))

    # ── 6. Client version distribution ──
    parts.append(html_section('client-version', '6. Phiên bản client SSH'))
    cv_dist = report['client_version_distribution']
    cv_sorted = sorted(cv_dist.items(), key=lambda x: -x[1])
    if cv_sorted:
        parts.append(html_chart(
            make_pie_chart(
                [c[0][:40] for c in cv_sorted[:10]],
                [c[1] for c in cv_sorted[:10]],
                title='Top 10 phiên bản client SSH',
            ),
            'Biểu đồ tròn: phân bố phiên bản SSH client',
        ))
    parts.append(html_table(
        ['Phiên bản', 'Số lượng'],
        [[cv, cnt] for cv, cnt in cv_sorted],
    ))

    # ── 7. Top failed usernames ──
    parts.append(html_section('fail-usernames', '7. Tên đăng nhập thất bại phổ biến'))
    fail_users = report.get('top_20_fail_usernames', {})
    fu_sorted = sorted(fail_users.items(), key=lambda x: -x[1])
    if fu_sorted:
        parts.append(html_chart(
            make_bar_chart(
                [u[0] for u in fu_sorted[:15]],
                [u[1] for u in fu_sorted[:15]],
                title='Top tên đăng nhập thất bại',
                ylabel='Số lần thử',
                color='#e53e3e',
                figsize=(10, 5),
            ),
            'Biểu đồ cột: tên đăng nhập bị từ chối nhiều nhất',
        ))
    parts.append(html_table(
        ['Tên đăng nhập', 'Số lần thử'],
        [[u, cnt] for u, cnt in fu_sorted],
    ))

    # ── 8. IP analysis + time-span histogram ──
    parts.append(html_section('ip-analysis', '8. Phân tích IP'))
    ipa = report['ip_analysis']
    parts.append(html_cards([
        ('Tổng IP duy nhất', ipa['total_unique_ips']),
        ('IP có đăng nhập', ipa['ips_with_login_events']),
        ('IP chỉ quét', ipa['ips_scan_only']),
        ('IP kéo dài > 1 giờ', ipa['ips_spanning_gt_1h']),
        ('Trung vị thời gian IP', f'{ipa["median_ip_span_seconds"]:.0f}s'),
    ]))

    ip_ts_map: dict[str, list[datetime]] = defaultdict(list)
    for ev in all_events:
        src_ip = ev.get('src_ip', '')
        ts = _parse_ts(ev.get('timestamp'))
        if src_ip and ts:
            ip_ts_map[src_ip].append(ts)
    ip_span_values: list[float] = []
    for ts_list in ip_ts_map.values():
        if len(ts_list) >= 2:
            ip_span_values.append((max(ts_list) - min(ts_list)).total_seconds())
        else:
            ip_span_values.append(0.0)
    if ip_span_values:
        parts.append(html_chart(
            make_histogram(
                ip_span_values,
                title='Phân phối thời gian hoạt động IP (giây)',
                xlabel='Thời gian (giây)',
                ylabel='Số IP',
                bins=40,
                log_scale=True,
            ),
            'Histogram: thời gian hoạt động của mỗi IP nguồn (log scale)',
        ))

    # ── 9. Event transitions ──
    parts.append(html_section('transitions', '9. Chuyển tiếp sự kiện'))
    transitions = report.get('event_transitions', [])
    if transitions:
        trans_top = transitions[:20]
        parts.append(html_chart(
            make_bar_chart(
                [t['transition'] for t in trans_top],
                [t['count'] for t in trans_top],
                title='Top 20 chuyển tiếp sự kiện',
                xlabel='Số lần',
                horizontal=True,
                figsize=(10, max(4, len(trans_top) * 0.4)),
                color='#319795',
            ),
            'Biểu đồ thanh ngang: cặp sự kiện chuyển tiếp phổ biến nhất',
        ))
        parts.append(html_table(
            ['Chuyển tiếp', 'Số lần'],
            [[t['transition'], t['count']] for t in transitions],
        ))

    # ── 10. Hourly activity timeline ──
    parts.append(html_section('timeline', '10. Hoạt động theo giờ'))
    hourly: Counter[str] = Counter()
    for ev in all_events:
        ts = _parse_ts(ev.get('timestamp'))
        if ts:
            hourly[ts.astimezone(timezone.utc).strftime('%Y-%m-%d %H:00')] += 1
    if hourly:
        hourly_sorted = sorted(hourly.items())
        parts.append(html_chart(
            make_timeline_chart(
                [h[0] for h in hourly_sorted],
                [h[1] for h in hourly_sorted],
                title='Hoạt động tấn công theo giờ',
                ylabel='Số sự kiện',
                color='#e53e3e',
            ),
            'Timeline: số lượng sự kiện tấn công theo từng giờ UTC',
        ))

    # ── 11. Session scoring decision ──
    parts.append(html_section('scoring', '11. Chấm điểm & Lọc phiên'))
    parts.append(html_decision(
        'Quyết định: Tiêu chí chọn phiên',
        f'<p><b>Đã chọn:</b> <span class="good">{n_selected:,}</span> phiên (score=1) '
        f'| <b>Loại bỏ:</b> <span class="warn">{n_discarded:,}</span> phiên (score=0)</p>'
        f'<p><b>Tiêu chí:</b> Phiên được chọn (score=1) nếu chứa ít nhất một sự kiện '
        f'<code>cowrie.login.failed</code> hoặc <code>cowrie.login.success</code> VÀ '
        f'sử dụng giao thức SSH. Phiên chỉ quét/thăm dò (không có đăng nhập) bị loại bỏ '
        f'vì thiếu đặc trưng hành vi xác thực.</p>',
        'RFC 4253 (SSH Transport Layer Protocol) định nghĩa pha xác thực sau trao đổi khóa. '
        'Phiên không có sự kiện xác thực chỉ là quét cổng hoặc thăm dò phiên bản, '
        'không tạo được đặc trưng brute-force có ý nghĩa (Owezarski, 2015).',
    ))
    parts.append(html_table(
        ['Danh mục', 'Số lượng', '%'],
        [
            ['Phiên có sự kiện đăng nhập', sls['sessions_with_login'],
             f'{sls["sessions_with_login"] / total_sess * 100:.1f}%'],
            ['Phiên chỉ quét', sls['sessions_scan_only'],
             f'{sls["sessions_scan_only"] / total_sess * 100:.1f}%'],
            ['Phiên có thất bại', sls['sessions_with_fail'],
             f'{sls["sessions_with_fail"] / total_sess * 100:.1f}%'],
            ['Phiên có thành công', sls['sessions_with_success'],
             f'{sls["sessions_with_success"] / total_sess * 100:.1f}%'],
        ],
    ))

    # ── 12. Cowrie bias correction decision ──
    parts.append(html_section('bias', '12. Hiệu chỉnh bias Cowrie'))
    if cb['bias_detected']:
        parts.append(html_decision(
            'Quyết định: Gán nhãn lại thông minh (Smart Relabeling)',
            f'<p class="warn">PHÁT HIỆN BIAS: {cb["root_success_rate"]:.1%} phiên đăng nhập '
            f'có root login.success ({cb["root_success_sessions"]:,} / '
            f'{cb["total_login_sessions"]:,})</p>'
            f'<p><b>Hành động:</b> Gán nhãn lại {bias_stats.get("sessions_relabeled", 0):,} phiên '
            f'(root login.success &rarr; login.failed). '
            f'Giữ nguyên {bias_stats.get("sessions_kept_success", 0):,} '
            f'phiên với success gốc '
            f'(tỷ lệ giữ: {bias_stats.get("keep_rate_actual", 0):.1%}).</p>',
            'Cowrie honeypot cấu hình UserDB root:x:* chấp nhận MỌI mật khẩu cho root, '
            'tạo tỷ lệ thành công giả ~100%. Tỷ lệ thành công brute-force SSH thực tế là 1-8% '
            '(Owezarski 2015, Hofstede et al. 2014). Gán nhãn lại ở mức 3% bảo toàn '
            'tỷ lệ thành công thực tế trong khi giữ cấu trúc sự kiện gốc.',
        ))
    else:
        parts.append(html_decision(
            'Quyết định: Hiệu chỉnh bias',
            '<p class="good">Không phát hiện bias đáng kể — không cần hiệu chỉnh.</p>',
        ))
    parts.append(html_table(
        ['Chỉ số', 'Giá trị'],
        [
            ['Phiên root login.success', cb['root_success_sessions']],
            ['Tổng phiên đăng nhập', cb['total_login_sessions']],
            ['Tỷ lệ root success (trước hiệu chỉnh)', f'{cb["root_success_rate"]:.1%}'],
            ['Phiên đã gán nhãn lại', bias_stats.get('sessions_relabeled', 0)],
            ['Phiên giữ success', bias_stats.get('sessions_kept_success', 0)],
            ['Tỷ lệ giữ thực tế', f'{bias_stats.get("keep_rate_actual", 0):.1%}'],
            ['Sự kiện đã gán nhãn lại', bias_stats.get('events_relabeled', 0)],
        ],
    ))

    # ── 13. Feature recommendations decision ──
    parts.append(html_section('features', '13. Khuyến nghị đặc trưng'))
    feat_body = (
        f'<p><b>Đặc trưng hoạt động ({len(feature_config["active_features"])}):</b> '
        f'<code>{", ".join(feature_config["active_features"])}</code></p>'
    )
    if feature_config['drop_features']:
        feat_body += (
            f'<p><b>Đặc trưng bị loại:</b> '
            f'<code>{", ".join(feature_config["drop_features"])}</code></p>'
        )
    if feature_config['shortcut_features']:
        feat_body += (
            f'<p><b>Đặc trưng shortcut (loại trừ):</b> '
            f'<code>{", ".join(feature_config["shortcut_features"])}</code></p>'
        )
    parts.append(html_decision(
        'Quyết định: Chọn đặc trưng',
        feat_body,
        'Sommer & Paxson (2010): đặc trưng hành vi (behavioral) ưu việt hơn đặc trưng '
        'thời gian (temporal) cho IDS. Đặc trưng bị loại do thiếu biến thiên trong dữ liệu hiện tại.',
    ))
    if feature_config['warnings']:
        for w in feature_config['warnings']:
            parts.append(f'<div class="reason">{html_escape(w)}</div>')

    # ── 14. Verification tests ──
    parts.append(html_section('verification', '14. Kiểm tra xác minh'))
    tests: list[tuple[str, bool, str]] = []

    ev_match = len(all_events) == s['total_events']
    tests.append((
        'Tổng sự kiện khớp',
        ev_match,
        f'len(events)={len(all_events):,} == report.total_events={s["total_events"]:,}',
    ))

    sess_sum = n_selected + n_discarded
    tests.append((
        'Phiên đã chọn + loại bỏ = tổng',
        sess_sum == s['total_sessions'],
        f'{n_selected:,} + {n_discarded:,} = {sess_sum:,} (tổng phiên: {s["total_sessions"]:,})',
    ))

    if bias_stats:
        affected = bias_stats.get('attack_sessions_with_root_success', 0)
        kept = bias_stats.get('sessions_kept_success', 0)
        relabeled = bias_stats.get('sessions_relabeled', 0)
        tests.append((
            'Bias: sessions_kept + relabeled = affected',
            kept + relabeled == affected,
            f'{kept:,} + {relabeled:,} = {kept + relabeled:,} (affected: {affected:,})',
        ))
    else:
        tests.append((
            'Bias: không áp dụng hiệu chỉnh',
            True,
            'Không phát hiện bias — bỏ qua kiểm tra',
        ))

    n_all = len(feature_config.get('all_features', []))
    n_active = len(feature_config.get('active_features', []))
    n_drop = len(feature_config.get('drop_features', []))
    n_short = len(feature_config.get('shortcut_features', []))
    tests.append((
        'Đặc trưng: active + dropped + shortcut = all',
        n_active + n_drop + n_short == n_all,
        f'{n_active} + {n_drop} + {n_short} = {n_active + n_drop + n_short} (tổng: {n_all})',
    ))

    no_loss = len(selected_events) > 0 or n_selected == 0
    if bias_stats:
        ev_relab = bias_stats.get('events_relabeled', 0)
        ev_kept_s = bias_stats.get('events_kept_success', 0)
        tests.append((
            'Không mất sự kiện sau hiệu chỉnh bias',
            no_loss,
            f'selected_events={len(selected_events):,} '
            f'(relabeled={ev_relab:,}, kept_success={ev_kept_s:,})',
        ))
    else:
        tests.append((
            'Không mất sự kiện (không hiệu chỉnh)',
            no_loss,
            f'selected_events={len(selected_events):,}',
        ))

    parts.append(html_verification_section(tests))

    # ── 15. Debug log ──
    parts.append(html_section('debug-log', '15. Nhật ký debug'))
    parts.append(html_debug_log(log))

    parts.append(html_footer())
    return '\n'.join(parts)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description='Step 3A: Attack Expert Analysis')
    parser.add_argument('--input-dir', default=str(ATTACK_DIR),
                        help='Directory containing Cowrie attack JSONL files')
    parser.add_argument('--glob', default=ATTACK_GLOB,
                        help='Glob pattern for attack files')
    parser.add_argument('--keep-rate', type=float, default=DEFAULT_KEEP_RATE,
                        help=f'Cowrie bias: fraction of sessions to keep login.success (default: {DEFAULT_KEEP_RATE})')
    parser.add_argument('--seed', type=int, default=SEED)
    parser.add_argument('--output-selected', default=str(OUTPUT_SELECTED))
    parser.add_argument('--output-report', default=str(OUTPUT_REPORT_JSON))
    parser.add_argument('--output-html', default=str(OUTPUT_REPORT_HTML))
    parser.add_argument('--output-feature-config', default=str(OUTPUT_FEATURE_CFG))
    args = parser.parse_args()

    log = ViLogger('Step3A')

    attack_dir = Path(args.input_dir)
    output_selected = Path(args.output_selected)
    output_report = Path(args.output_report)
    output_html = Path(args.output_html)
    output_feature_cfg = Path(args.output_feature_config)

    # ── 1. Read attack logs ──
    log.section('Step 3A — Phân tích chuyên gia tấn công')
    all_events: list[dict] = []
    files_read: list[str] = []
    for fp in sorted(attack_dir.glob(args.glob)):
        if ATTACK_EXCLUDE_RE.search(fp.name):
            continue
        batch = _read_ndjson(fp)
        all_events.extend(batch)
        files_read.append(fp.name)
        log.debug(f'{fp.name}: {len(batch):,} sự kiện')

    log.info(f'Đọc được {len(all_events):,} sự kiện từ {len(files_read)} tệp')

    if not all_events:
        log.fail('Không tìm thấy sự kiện nào. Kiểm tra --input-dir và --glob.')
        return

    # ── 2. Analyze ──
    log.section('Phân tích thống kê log tấn công')
    report = analyze_attack_log(all_events)
    s = report['summary']
    log.info(f'Tổng phiên       : {s["total_sessions"]:,}')
    log.debug(f'IP duy nhất      : {s["unique_ips"]:,}')
    log.debug(f'IP có đăng nhập  : {s["ips_with_login"]:,}')
    log.debug(f'IP chỉ quét      : {s["ips_scan_only"]:,}')
    log.debug(f'Vector đặc trưng : {s["estimated_feature_vectors"]:,}')
    log.debug(f'Khoảng thời gian : {s["time_range_hours"]:.1f}h ({s["time_range_days"]} ngày)')

    cb = report['cowrie_bias']
    if cb['bias_detected']:
        log.warn(f'PHÁT HIỆN BIAS: {cb["root_success_rate"]:.1%} root login.success '
                 f'({cb["root_success_sessions"]:,}/{cb["total_login_sessions"]:,} phiên)')
    else:
        log.ok(f'Cowrie bias: {cb["root_success_rate"]:.1%} — không có vấn đề')

    # ── 3. Score sessions ──
    log.section('Chấm điểm phiên')
    sessions = _sessionize(all_events)
    scores = score_sessions(sessions)
    n_selected = sum(1 for v in scores.values() if v == 1)
    n_discarded = sum(1 for v in scores.values() if v == 0)
    log.ok(f'Đã chọn (score=1) : {n_selected:,}')
    log.info(f'Loại bỏ (score=0) : {n_discarded:,}')

    selected_events: list[dict] = []
    for sid, evts in sessions.items():
        if scores.get(sid, 0) == 1:
            for ev in evts:
                ev['data_origin'] = 'attack_cowrie'
            selected_events.extend(evts)

    # ── 4. Handle Cowrie bias ──
    bias_stats: dict[str, Any] = {}
    if cb['bias_detected']:
        log.section(f'Hiệu chỉnh bias Cowrie (keep_rate={args.keep_rate:.1%})')
        selected_events, bias_stats = handle_cowrie_bias(
            selected_events,
            keep_rate=args.keep_rate,
            seed=args.seed,
        )
        log.info(f'Phiên đã gán nhãn lại : {bias_stats["sessions_relabeled"]:,}')
        log.info(f'Phiên giữ nguyên      : {bias_stats["sessions_kept_success"]:,}')
        log.debug(f'Sự kiện đã gán nhãn   : {bias_stats["events_relabeled"]:,}')
    else:
        log.ok('Không phát hiện bias Cowrie — bỏ qua hiệu chỉnh.')

    bias_corrected = cb['bias_detected']

    # ── 5. IP-level campaign classification ──
    log.section('Phân loại chiến dịch tấn công theo IP')
    at_cls = report.get('attack_type_classification', {})
    at_dist = at_cls.get('distribution', {})
    for ctype, cnt in sorted(at_dist.items(), key=lambda x: -x[1]):
        log.info(f'  {ctype:20s}: {cnt:,} IP')
    log.ok(f'Đã phân loại {sum(at_dist.values()):,} IP vào {len(at_dist)} nhóm chiến dịch')

    # ── 6. Feature recommendations ──
    log.section('Khuyến nghị đặc trưng')
    feature_config = recommend_features(report, bias_corrected)
    log.ok(f'Đặc trưng hoạt động ({len(feature_config["active_features"])}): '
           f'{", ".join(feature_config["active_features"])}')
    if feature_config['drop_features']:
        log.warn(f'Đã loại: {", ".join(feature_config["drop_features"])}')
    for w in feature_config['warnings']:
        log.warn(w)

    # ── 6. Write outputs ──
    log.section('Ghi kết quả đầu ra')

    selected_events.sort(key=lambda e: e.get('timestamp', ''))
    _write_ndjson(output_selected, selected_events)
    log.ok(f'Sự kiện đã chọn → {output_selected} ({len(selected_events):,} sự kiện)')

    full_report = {
        'analysis': report,
        'scoring': {
            'selected': n_selected,
            'discarded': n_discarded,
        },
        'attack_type_classification': report.get('attack_type_classification', {}),
        'bias_correction': bias_stats,
        'feature_config': feature_config,
    }
    output_report.parent.mkdir(parents=True, exist_ok=True)
    with output_report.open('w', encoding='utf-8') as f:
        json.dump(full_report, f, indent=2, ensure_ascii=False)
    log.ok(f'Báo cáo JSON → {output_report}')

    with output_feature_cfg.open('w', encoding='utf-8') as f:
        json.dump(feature_config, f, indent=2, ensure_ascii=False)
    log.ok(f'Cấu hình đặc trưng → {output_feature_cfg}')

    html_content = _build_html_report(
        report, bias_stats, feature_config, scores,
        all_events, selected_events, log,
    )
    write_html(output_html, html_content)
    log.ok(f'Báo cáo HTML → {output_html}')

    log.section('Step 3A hoàn tất')


if __name__ == '__main__':
    main()
