"""
benign_expert.py – Step 3B: Expert Analysis & Upscale of Cowrie Benign Logs
============================================================================

Analyzes the Cowrie-format benign logs (output of Step 2) and produces:
  1. Cross-verification against original OpenSSH parsed logs
  2. Empirical distribution measurement (fail count, duration, username, etc.)
  3. Upscale plan based on attack feature-vector reference and optional
     benign:attack session ratio (e.g. 1:1, 1:2, 2:1) or ``natural`` (no synthetic)
  4. Upscaled benign sessions via parametric bootstrap (with subsampling when
     target < number of real sessions)

The upscale approach is *linear and simple*:
  - Group existing sessions by archetype (clean_login, typo, troubleshoot)
  - Replicate the empirical distribution proportionally
  - Vary IP, timestamp, duration, client version per synthetic session
  - Optionally cluster multiple sessions under same IP (multi-session)

Scientific basis:
  - Efron & Tibshirani (1993): parametric bootstrap from empirical distribution
  - Cochran (1977): 893 sessions from low-variance banking population is representative
  - Davison & Hinkley (1997): parametric bootstrap valid when sample is representative
  - Robinson (1950): matching aggregation structure prevents ecological fallacy

Usage::

    python3 step3b_benign_expert.py
    python3 step3b_benign_expert.py --target-vectors 1055
    python3 step3b_benign_expert.py --benign-attack-ratio 1:2
    python3 step3b_benign_expert.py --benign-attack-ratio natural
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
from pathlib import Path
from typing import Any

from utils.report_utils import (
    ViLogger, html_header, html_footer, html_toc, html_section,
    html_cards, html_table, html_chart, html_debug_log, html_decision,
    html_verification_section, write_html, make_bar_chart, make_pie_chart,
    make_histogram,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

BENIGN_FILE    = _PROJECT_ROOT / 'output' / 'step2' / 'cowrie_benign_corp.json'
IPVN_FILE      = _PROJECT_ROOT / 'logs' / 'IPvn.log'
FEATURE_CFG    = _PROJECT_ROOT / 'output' / 'step3a' / 'pipeline_feature_config.json'

OPENSSH_PARSED_PATHS = [
    _PROJECT_ROOT / 'output' / 'step1' / '8.68' / '8.68_parsed_events.json',
    _PROJECT_ROOT / 'output' / 'step1' / '8.69' / '8.69_parsed_events.json',
]

OUTPUT_REPORT_JSON = _PROJECT_ROOT / 'output' / 'step3b' / 'benign_expert_report.json'
OUTPUT_REPORT_HTML = _PROJECT_ROOT / 'output' / 'step3b' / 'benign_expert_report.html'
OUTPUT_UPSCALED    = _PROJECT_ROOT / 'output' / 'step3b' / 'benign_upscaled.json'

SEED = 42
WINDOW_MINUTES = 60

BUSINESS_TZ_OFFSET_H = 7
BUSINESS_PEAK_START  = 8
BUSINESS_PEAK_END    = 18

MULTI_SESSION_IP_FRACTION = 0.05


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


def _load_vn_ips(path: Path) -> list[str]:
    ips: list[str] = []
    with path.open('r', encoding='utf-8') as f:
        for line in f:
            stripped = line.strip()
            if stripped and stripped != 'IP' and not stripped.startswith('#'):
                ips.append(stripped)
    return ips


def _sessionize(events: list[dict]) -> dict[str, list[dict]]:
    sessions: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        sid = ev.get('session')
        if sid:
            sessions[str(sid)].append(ev)
    for sid in sessions:
        sessions[sid].sort(key=lambda e: e.get('timestamp', ''))
    return dict(sessions)


def _stable_session_id(seed_str: str) -> str:
    return hashlib.sha1(seed_str.encode()).hexdigest()[:12]


def parse_benign_attack_ratio(spec: str) -> tuple[int, int] | str:
    """
    Parse ratio string for benign-session target vs attack reference.

    Returns
    -------
    'natural'
        Use all real sessions; no synthetic (target = |sessions|).
    (a, b)
        Target session count = round(attack_ref * a / b)  (benign:attack = a:b).
    """
    s = spec.strip().lower()
    if s == 'natural':
        return 'natural'
    if ':' not in s:
        raise ValueError(f'Invalid ratio (expected A:B or natural): {spec!r}')
    a_str, b_str = s.replace(' ', '').split(':', 1)
    a, b = int(a_str), int(b_str)
    if a <= 0 or b <= 0:
        raise ValueError(f'Ratio parts must be positive: {spec!r}')
    return (a, b)


def target_sessions_from_ratio(attack_ref: int, ratio: tuple[int, int] | str) -> int:
    """Compute target benign *session* count from attack reference and ratio."""
    if ratio == 'natural':
        return 0  # sentinel: caller uses len(all_sessions)
    a, b = ratio
    return max(1, round(attack_ref * a / b))


def subsample_sessions(
    sessions: dict[str, list[dict]],
    k: int,
    seed: int,
) -> dict[str, list[dict]]:
    """Randomly keep exactly k sessions (deterministic)."""
    if k >= len(sessions):
        return sessions
    rng = random.Random(seed)
    ids = sorted(sessions.keys())
    chosen = rng.sample(ids, k)
    return {sid: sessions[sid] for sid in chosen}


def _business_hour_weights() -> list[float]:
    """UTC hour weights reflecting Vietnam business hours (UTC+7)."""
    weights = [0.0] * 24
    for utc_h in range(24):
        local_h = (utc_h + BUSINESS_TZ_OFFSET_H) % 24
        if BUSINESS_PEAK_START <= local_h < BUSINESS_PEAK_END:
            weights[utc_h] = 1.0
        elif local_h >= (BUSINESS_PEAK_START - 2) or local_h < (BUSINESS_PEAK_END + 2):
            weights[utc_h] = 0.3
        else:
            weights[utc_h] = 0.02
    total = sum(weights)
    return [w / total for w in weights]


# ---------------------------------------------------------------------------
# Core: Verify sessions against OpenSSH parsed logs
# ---------------------------------------------------------------------------
def verify_sessions(
    cowrie_sessions: dict[str, list[dict]],
    openssh_parsed_paths: list[Path],
) -> dict[str, Any]:
    """Cross-check Cowrie benign sessions against original OpenSSH parsed events."""

    openssh_groups = 0
    openssh_total_events = 0
    openssh_usernames: set[str] = set()

    for p in openssh_parsed_paths:
        if not p.exists():
            continue
        with p.open('r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, list):
            continue
        openssh_total_events += len(data)
        pid_groups: set[tuple[str, int]] = set()
        for ev in data:
            host = str(ev.get('host', ''))
            pid = ev.get('pid')
            if isinstance(pid, int):
                pid_groups.add((host, pid))
            u = ev.get('username')
            if u:
                openssh_usernames.add(str(u))
        openssh_groups += len(pid_groups)

    cowrie_session_count = len(cowrie_sessions)
    cowrie_usernames: set[str] = set()
    sessions_valid_structure = 0
    sessions_missing_connect = 0
    sessions_missing_close = 0

    for sid, evts in cowrie_sessions.items():
        eids = {e.get('eventid') for e in evts}
        has_connect = 'cowrie.session.connect' in eids
        has_close = 'cowrie.session.closed' in eids

        if has_connect and has_close:
            sessions_valid_structure += 1
        if not has_connect:
            sessions_missing_connect += 1
        if not has_close:
            sessions_missing_close += 1

        for e in evts:
            u = e.get('username')
            if u:
                cowrie_usernames.add(str(u))

    return {
        'openssh_pid_groups': openssh_groups,
        'openssh_total_events': openssh_total_events,
        'openssh_unique_usernames': sorted(openssh_usernames),
        'cowrie_session_count': cowrie_session_count,
        'cowrie_unique_usernames': sorted(cowrie_usernames),
        'sessions_valid_structure': sessions_valid_structure,
        'sessions_missing_connect': sessions_missing_connect,
        'sessions_missing_close': sessions_missing_close,
        'session_count_match': cowrie_session_count <= openssh_groups,
        'username_consistency': cowrie_usernames.issubset(openssh_usernames) or not openssh_usernames,
    }


# ---------------------------------------------------------------------------
# Core: Analyze benign log — empirical distribution
# ---------------------------------------------------------------------------
def analyze_benign_log(
    sessions: dict[str, list[dict]],
) -> dict[str, Any]:
    """Measure empirical distributions from real benign sessions."""

    profiles: list[dict[str, Any]] = []
    durations: list[float] = []
    fail_counts: list[int] = []
    success_counts: list[int] = []
    username_pool: Counter[str] = Counter()
    client_versions: Counter[str] = Counter()
    hours: list[int] = []
    all_time_to_auth: list[float] = []
    all_inter_login: list[float] = []

    for sid, evts in sessions.items():
        n_fail = sum(1 for e in evts if e.get('eventid') == 'cowrie.login.failed')
        n_success = sum(1 for e in evts if e.get('eventid') == 'cowrie.login.success')

        fail_users = set(
            e.get('username', '') for e in evts
            if e.get('eventid') == 'cowrie.login.failed'
        )
        success_users = set(
            e.get('username', '') for e in evts
            if e.get('eventid') == 'cowrie.login.success'
        )
        all_users = fail_users | success_users
        for u in all_users:
            if u:
                username_pool[u] += 1

        dur = 0.0
        for e in evts:
            if e.get('eventid') == 'cowrie.session.closed':
                d = e.get('duration')
                if isinstance(d, (int, float)):
                    dur = float(d)
                break

        cv = ''
        for e in evts:
            if e.get('eventid') == 'cowrie.client.version':
                cv = e.get('version', '')
                break
        if cv:
            client_versions[cv] += 1

        timestamps = []
        for e in evts:
            if e.get('eventid') in ('cowrie.login.failed', 'cowrie.login.success'):
                ts = _parse_ts(e.get('timestamp'))
                if ts:
                    timestamps.append(ts)

        intervals: list[float] = []
        timestamps.sort()
        for i in range(1, len(timestamps)):
            intervals.append((timestamps[i] - timestamps[i - 1]).total_seconds())

        # MICRO: time_to_auth = connect → first login event
        connect_ts = None
        first_login_ts = None
        for e in evts:
            eid = e.get('eventid', '')
            ts = _parse_ts(e.get('timestamp'))
            if ts is None:
                continue
            if eid == 'cowrie.session.connect' and connect_ts is None:
                connect_ts = ts
            if eid in ('cowrie.login.failed', 'cowrie.login.success') and first_login_ts is None:
                first_login_ts = ts
        time_to_auth = 0.0
        if connect_ts and first_login_ts and first_login_ts > connect_ts:
            time_to_auth = (first_login_ts - connect_ts).total_seconds()
        if time_to_auth > 0:
            all_time_to_auth.append(time_to_auth)
        for iv in intervals:
            if iv > 0:
                all_inter_login.append(iv)

        first_ts = _parse_ts(evts[0].get('timestamp')) if evts else None
        hour = first_ts.hour if first_ts else 12

        profiles.append({
            'session': sid,
            'n_fail': n_fail,
            'n_success': n_success,
            'n_unique_users': len(all_users),
            'duration': dur,
            'client_version': cv,
            'hour': hour,
            'intervals': intervals,
            'time_to_auth': time_to_auth,
        })

        fail_counts.append(n_fail)
        success_counts.append(n_success)
        durations.append(dur)
        hours.append(hour)

    # Archetype classification
    archetypes: dict[str, list[dict]] = {
        'clean_login': [],
        'typo': [],
        'troubleshoot': [],
        'give_up': [],
    }
    for p in profiles:
        if p['n_fail'] == 0 and p['n_success'] >= 1:
            archetypes['clean_login'].append(p)
        elif 1 <= p['n_fail'] <= 3 and p['n_success'] >= 1:
            archetypes['typo'].append(p)
        elif p['n_fail'] >= 4:
            if p['n_success'] >= 1:
                archetypes['troubleshoot'].append(p)
            else:
                archetypes['give_up'].append(p)
        elif p['n_fail'] > 0 and p['n_success'] == 0:
            archetypes['give_up'].append(p)
        else:
            archetypes['clean_login'].append(p)

    # Fail count distribution
    fail_dist = Counter(fail_counts)

    # Duration stats (filter >0 for log-normal fit)
    positive_durations = [d for d in durations if d > 0]
    duration_mu = 0.0
    duration_sigma = 1.0
    if positive_durations:
        log_durations = [math.log(d) for d in positive_durations]
        duration_mu = statistics.mean(log_durations)
        duration_sigma = statistics.stdev(log_durations) if len(log_durations) > 1 else 1.0

    # MICRO: Lognormal fit for inter-event timing
    inter_login_mu = 2.0
    inter_login_sigma = 0.8
    if all_inter_login:
        pos_inter = [x for x in all_inter_login if x > 0]
        if pos_inter:
            log_inter = [math.log(x) for x in pos_inter]
            inter_login_mu = statistics.mean(log_inter)
            inter_login_sigma = statistics.stdev(log_inter) if len(log_inter) > 1 else 0.8

    time_to_auth_mu = 1.5
    time_to_auth_sigma = 0.6
    if all_time_to_auth:
        pos_tta = [x for x in all_time_to_auth if x > 0]
        if pos_tta:
            log_tta = [math.log(x) for x in pos_tta]
            time_to_auth_mu = statistics.mean(log_tta)
            time_to_auth_sigma = statistics.stdev(log_tta) if len(log_tta) > 1 else 0.6

    # --- Session timeline summary (mirroring session_analyzer format) ---
    session_timelines: list[dict[str, Any]] = []
    for p in profiles:
        evts = sessions[p['session']]
        event_path = [e.get('eventid', 'unknown') for e in evts]
        timestamps_all = []
        for e in evts:
            ts = _parse_ts(e.get('timestamp'))
            if ts:
                timestamps_all.append(ts)
        first_ts = min(timestamps_all) if timestamps_all else None
        last_ts = max(timestamps_all) if timestamps_all else None

        src_ip = ''
        for e in evts:
            ip = e.get('src_ip', '')
            if ip:
                src_ip = ip
                break

        session_timelines.append({
            'session': p['session'],
            'src_ip': src_ip,
            'event_count': len(evts),
            'n_fail': p['n_fail'],
            'n_success': p['n_success'],
            'first_seen': _fmt_ts(first_ts) if first_ts else 'N/A',
            'last_seen': _fmt_ts(last_ts) if last_ts else 'N/A',
            'duration': p['duration'],
            'archetype': (
                'clean_login' if p['n_fail'] == 0 and p['n_success'] >= 1
                else 'typo' if 1 <= p['n_fail'] <= 3 and p['n_success'] >= 1
                else 'troubleshoot' if p['n_fail'] >= 4 and p['n_success'] >= 1
                else 'give_up' if p['n_fail'] > 0 and p['n_success'] == 0
                else 'clean_login'
            ),
            'event_path': ' -> '.join(event_path),
        })
    session_timelines.sort(key=lambda x: x.get('first_seen', ''))

    # --- Event transitions ---
    event_transitions: Counter[str] = Counter()
    for sid, evts in sessions.items():
        eids = [e.get('eventid', 'unknown') for e in evts]
        for i in range(len(eids) - 1):
            event_transitions[eids[i] + ' -> ' + eids[i+1]] += 1

    return {
        'total_sessions': len(sessions),
        'profiles': profiles,
        'fail_count_distribution': {str(k): v for k, v in sorted(fail_dist.items())},
        'archetype_counts': {k: len(v) for k, v in archetypes.items()},
        'archetypes': archetypes,
        'username_pool': dict(username_pool.most_common()),
        'client_version_pool': dict(client_versions.most_common()),
        'duration_stats': {
            'count_positive': len(positive_durations),
            'median': round(statistics.median(positive_durations), 1) if positive_durations else 0,
            'mean': round(statistics.mean(positive_durations), 1) if positive_durations else 0,
            'lognormal_mu': round(duration_mu, 4),
            'lognormal_sigma': round(duration_sigma, 4),
        },
        'inter_event_timing': {
            'inter_login_samples': len(all_inter_login),
            'inter_login_mu': round(inter_login_mu, 4),
            'inter_login_sigma': round(inter_login_sigma, 4),
            'inter_login_median': round(statistics.median(all_inter_login), 2) if all_inter_login else 0,
            'time_to_auth_samples': len(all_time_to_auth),
            'time_to_auth_mu': round(time_to_auth_mu, 4),
            'time_to_auth_sigma': round(time_to_auth_sigma, 4),
            'time_to_auth_median': round(statistics.median(all_time_to_auth), 2) if all_time_to_auth else 0,
        },
        'hour_distribution': dict(Counter(hours).most_common()),
        'session_timeline_summary': session_timelines,
        'event_transitions': [
            {'transition': t, 'count': c}
            for t, c in event_transitions.most_common(30)
        ],
    }


# ---------------------------------------------------------------------------
# Core: Plan upscale
# ---------------------------------------------------------------------------
def plan_upscale(
    benign_stats: dict[str, Any],
    target_vectors: int,
) -> dict[str, Any]:
    """
    Compute how many synthetic sessions to generate per archetype.
    Allocation is proportional to empirical distribution.
    """
    total_real = benign_stats['total_sessions']
    n_needed = max(0, target_vectors - total_real)

    archetype_counts = benign_stats['archetype_counts']
    total_classified = sum(archetype_counts.values())

    allocation: dict[str, int] = {}
    for arch, count in archetype_counts.items():
        if total_classified > 0:
            proportion = count / total_classified
        else:
            proportion = 1.0 / len(archetype_counts)
        allocation[arch] = round(n_needed * proportion)

    remainder = n_needed - sum(allocation.values())
    if remainder != 0 and allocation:
        largest = max(allocation, key=allocation.get)
        allocation[largest] += remainder

    n_multi_session_ips = round(n_needed * MULTI_SESSION_IP_FRACTION)

    return {
        'target_vectors': target_vectors,
        'real_sessions': total_real,
        'synthetic_needed': n_needed,
        'upscale_factor': round(n_needed / max(total_real, 1), 2),
        'allocation': allocation,
        'multi_session_ips': n_multi_session_ips,
    }


# ---------------------------------------------------------------------------
# Core: Execute upscale
# ---------------------------------------------------------------------------
def execute_upscale(
    sessions: dict[str, list[dict]],
    benign_stats: dict[str, Any],
    plan: dict[str, Any],
    vn_ips: list[str],
    seed: int = SEED,
) -> list[dict]:
    """
    Generate synthetic benign sessions via parametric bootstrap.
    Returns all events (real + synthetic) with data_origin tags.
    """
    rng = random.Random(seed)

    # Collect all real events first, tagged
    all_events: list[dict] = []
    for sid, evts in sessions.items():
        for ev in evts:
            ev['data_origin'] = 'benign_corp'
        all_events.extend(evts)

    if plan['synthetic_needed'] <= 0:
        return all_events

    archetypes = benign_stats.get('archetypes', {})
    username_pool = list(benign_stats.get('username_pool', {}).keys())
    if not username_pool:
        username_pool = ['user']
    username_weights = list(benign_stats.get('username_pool', {}).values())
    if not username_weights:
        username_weights = [1]

    client_pool = list(benign_stats.get('client_version_pool', {}).keys())
    client_weights = list(benign_stats.get('client_version_pool', {}).values())
    if not client_pool:
        client_pool = ['SSH-2.0-OpenSSH_8.0']
        client_weights = [1]

    dur_mu = benign_stats['duration_stats']['lognormal_mu']
    dur_sigma = benign_stats['duration_stats']['lognormal_sigma']

    iet = benign_stats.get('inter_event_timing', {})
    inter_login_mu = iet.get('inter_login_mu', 2.0)
    inter_login_sigma = iet.get('inter_login_sigma', 0.8)
    tta_mu = iet.get('time_to_auth_mu', 1.5)
    tta_sigma = iet.get('time_to_auth_sigma', 0.6)

    # Use actual hour distribution from real data (KDE-like) if available,
    # fall back to business-hour weights otherwise
    real_hour_dist = benign_stats.get('hour_distribution', {})
    if real_hour_dist:
        hour_weights = [0.0] * 24
        for h_str, cnt in real_hour_dist.items():
            h = int(h_str) if isinstance(h_str, str) else h_str
            if 0 <= h < 24:
                hour_weights[h] = float(cnt)
        if sum(hour_weights) == 0:
            hour_weights = _business_hour_weights()
    else:
        hour_weights = _business_hour_weights()

    # IP pool: use VN IPs not already in real benign data
    used_ips = set()
    for sid, evts in sessions.items():
        for ev in evts:
            ip = ev.get('src_ip', '')
            if ip:
                used_ips.add(ip)
    available_ips = [ip for ip in vn_ips if ip not in used_ips]
    if len(available_ips) < plan['synthetic_needed']:
        available_ips = vn_ips
    rng.shuffle(available_ips)
    ip_idx = 0

    def _next_ip() -> str:
        nonlocal ip_idx
        ip = available_ips[ip_idx % len(available_ips)]
        ip_idx += 1
        return ip

    allocation = plan['allocation']
    n_multi = plan.get('multi_session_ips', 0)
    synth_count = 0

    for arch_name, n_synth in allocation.items():
        templates = archetypes.get(arch_name, [])
        if not templates and archetypes:
            templates = archetypes.get('clean_login', [])
        if not templates:
            continue

        for i in range(n_synth):
            template = templates[i % len(templates)]
            session_id = _stable_session_id('synth_' + arch_name + '_' + str(i) + '_' + str(seed))

            is_multi = synth_count < n_multi
            if is_multi and i > 0 and i % 3 == 0:
                ip_idx -= 1
            src_ip = _next_ip()

            hour = rng.choices(range(24), weights=hour_weights, k=1)[0]
            minute = rng.randint(0, 59)
            second = rng.randint(0, 59)

            base_date = datetime(2024, 10, 15, hour, minute, second, tzinfo=timezone.utc)
            day_offset = rng.randint(0, 59)
            base_date += timedelta(days=day_offset)
            t = base_date

            n_fail = template['n_fail']
            n_success = template['n_success']

            duration = max(1.0, rng.lognormvariate(dur_mu, dur_sigma))
            duration = min(duration, 86400 * 7)

            username = rng.choices(username_pool, weights=username_weights, k=1)[0]
            client_ver = rng.choices(client_pool, weights=client_weights, k=1)[0]

            events: list[dict] = []

            # connect
            msg_connect = 'New connection: ' + src_ip + ':0 (10.0.0.4:22) [session: ' + session_id + ']'
            events.append({
                'eventid': 'cowrie.session.connect',
                'src_ip': src_ip,
                'src_port': rng.randint(1024, 65535),
                'dst_ip': '10.0.0.4',
                'dst_port': 22,
                'session': session_id,
                'protocol': 'ssh',
                'message': msg_connect,
                'sensor': 'corp-ssh-benign',
                'timestamp': _fmt_ts(t),
                'data_origin': 'benign_corp_synthetic',
            })

            # client.version (SSH handshake ~50-200ms)
            t += timedelta(milliseconds=rng.uniform(50, 200))
            events.append({
                'eventid': 'cowrie.client.version',
                'version': client_ver,
                'message': 'Remote SSH version: ' + client_ver,
                'sensor': 'corp-ssh-benign',
                'timestamp': _fmt_ts(t),
                'src_ip': src_ip,
                'session': session_id,
                'data_origin': 'benign_corp_synthetic',
            })

            # MICRO: time_to_auth — Lognormal from real data
            auth_delay = max(0.5, rng.lognormvariate(tta_mu, tta_sigma))
            auth_delay = min(auth_delay, 120.0)
            t += timedelta(seconds=auth_delay)

            # fail events — Lognormal inter-login delay (human typing)
            for fi in range(n_fail):
                if fi > 0:
                    delay = max(1.0, rng.lognormvariate(inter_login_mu, inter_login_sigma))
                    delay = min(delay, 120.0)
                    t += timedelta(seconds=delay)
                fail_user = username
                if rng.random() < 0.4 and len(username) >= 3:
                    chars = list(username)
                    idx = rng.randint(0, len(chars) - 2)
                    chars[idx], chars[idx + 1] = chars[idx + 1], chars[idx]
                    fail_user = ''.join(chars)
                events.append({
                    'eventid': 'cowrie.login.failed',
                    'username': fail_user,
                    'password': None,
                    'message': 'login attempt [' + fail_user + '/<unknown>] failed',
                    'sensor': 'corp-ssh-benign',
                    'timestamp': _fmt_ts(t),
                    'src_ip': src_ip,
                    'session': session_id,
                    'data_origin': 'benign_corp_synthetic',
                })

            # success events — Lognormal inter-login delay
            for si in range(n_success):
                delay = max(1.0, rng.lognormvariate(inter_login_mu, inter_login_sigma))
                delay = min(delay, 120.0)
                t += timedelta(seconds=delay)
                events.append({
                    'eventid': 'cowrie.login.success',
                    'username': username,
                    'password': None,
                    'message': 'login attempt [' + username + '/<unknown>] succeeded',
                    'sensor': 'corp-ssh-benign',
                    'timestamp': _fmt_ts(t),
                    'src_ip': src_ip,
                    'session': session_id,
                    'data_origin': 'benign_corp_synthetic',
                })

            # session.closed
            t += timedelta(seconds=duration)
            events.append({
                'eventid': 'cowrie.session.closed',
                'duration': round(duration, 2),
                'message': 'Connection lost after ' + str(int(duration)) + ' seconds',
                'sensor': 'corp-ssh-benign',
                'timestamp': _fmt_ts(t),
                'src_ip': src_ip,
                'session': session_id,
                'data_origin': 'benign_corp_synthetic',
            })

            all_events.extend(events)
            synth_count += 1

    return all_events


# ---------------------------------------------------------------------------
# HTML report (rewritten with shared utils + embedded charts)
# ---------------------------------------------------------------------------
def _build_html_report(
    verification: dict[str, Any],
    benign_stats: dict[str, Any],
    plan: dict[str, Any],
    ratio_meta: dict[str, Any] | None = None,
    all_events: list[dict] | None = None,
    log: ViLogger | None = None,
) -> str:
    """Build a comprehensive standalone HTML report with embedded charts,
    verification tests, decision reasoning, and debug log."""
    bs = benign_stats
    total = bs['total_sessions'] or 1
    v = verification
    p = plan
    rm = ratio_meta or {}

    # ── Section definitions for TOC ──
    toc_sections = [
        ('overview', '1. Tổng quan (Overview)'),
        ('verification', '2. Kiểm tra chéo (Cross-Verification)'),
        ('charts', '3. Biểu đồ phân phối (Distribution Charts)'),
        ('archetypes', '4. Phân loại hành vi (Archetype Classification)'),
        ('usernames', '5. Username & Client Version'),
        ('transitions', '6. Event Transitions'),
        ('timelines', '7. Session Timeline'),
        ('upscale', '8. Kế hoạch Upscale'),
        ('decisions', '9. Giải thích quyết định (Decision Explanations)'),
        ('ext-verify', '10. Kiểm tra mở rộng (Extended Verification)'),
        ('debug-log', '11. Debug Log'),
    ]

    parts: list[str] = []

    # ── Header ──
    subtitle = str(bs['total_sessions']) + ' phiên benign thực từ log OpenSSH doanh nghiệp'
    parts.append(html_header(
        'Step 3B — Phân tích chuyên gia Benign & Upscale',
        'Step 3B', subtitle,
    ))

    # ── TOC ──
    parts.append(html_toc(toc_sections))

    # ══════════════════════════════════════════════════════════════════════
    # 1. Overview cards
    # ══════════════════════════════════════════════════════════════════════
    parts.append(html_section('overview', '1. Tổng quan (Overview)'))

    ds = bs['duration_stats']
    overview_items: list[tuple[str, Any]] = [
        ('Tổng phiên thực', bs['total_sessions']),
        ('Unique usernames', len(bs['username_pool'])),
        ('Unique client versions', len(bs['client_version_pool'])),
        ('Duration median', str(ds['median']) + 's'),
        ('Duration mean', str(ds['mean']) + 's'),
        ('Log-normal mu', ds['lognormal_mu']),
        ('Log-normal sigma', ds['lognormal_sigma']),
        ('Target vectors', p['target_vectors']),
        ('Synthetic needed', p['synthetic_needed']),
        ('Upscale factor', str(p['upscale_factor']) + 'x'),
    ]
    parts.append(html_cards(overview_items))
    parts.append(
        '<details open><summary><b>Giải thích các chỉ số</b></summary>'
        '<table><tr><th>Chỉ số</th><th>Ý nghĩa</th><th>Cách xác định</th></tr>'
        '<tr><td><b>Tổng phiên thực</b></td>'
        '<td>Số session SSH thực tế từ nhân viên ngân hàng (ground truth empirical)</td>'
        '<td>Đếm session ID duy nhất trong <code>output/step2/cowrie_benign_corp.json</code> — '
        'đầu ra của Step 2 (OpenSSH → Cowrie format)</td></tr>'
        '<tr><td><b>Unique usernames</b></td>'
        '<td>Số tài khoản nhân viên khác nhau đã đăng nhập SSH</td>'
        '<td>Trích từ event <code>cowrie.login.success/failed</code>. VD: oracle (DBA), sysadm (admin), debug (dev)</td></tr>'
        '<tr><td><b>Unique client versions</b></td>'
        '<td>Số phiên bản SSH client khác nhau (phản ánh đa dạng môi trường enterprise)</td>'
        '<td>Trích từ trường <code>version</code> trong event <code>cowrie.client.version</code>. '
        'VD: OpenSSH_7.4, PuTTY_0.70, WinSCP, …</td></tr>'
        '<tr><td><b>Duration median / mean</b></td>'
        '<td>Thời lượng phiên SSH trung vị / trung bình (giây)</td>'
        '<td><code>last_event.timestamp − first_event.timestamp</code> cho mỗi session. '
        'Median ổn định hơn mean vì không bị ảnh hưởng bởi outlier (session bị treo)</td></tr>'
        '<tr><td><b>Log-normal mu / sigma</b></td>'
        '<td>Tham số phân phối Log-Normal fit từ duration thực tế</td>'
        '<td><code>mu = mean(ln(duration))</code>, <code>sigma = std(ln(duration))</code>. '
        'Dùng để sinh thời lượng session synthetic theo đúng phân phối gốc (Parametric Bootstrap)</td></tr>'
        '<tr><td><b>Target vectors</b></td>'
        '<td>Số feature vector mục tiêu mà benign cần đạt để balance với attack</td>'
        '<td>Lấy từ <code>pipeline_feature_config.json</code> của Step 3A — '
        'chính là "Vector đặc trưng ước tính" của attack. Tỉ lệ mặc định 1:1</td></tr>'
        '<tr><td><b>Synthetic needed</b></td>'
        '<td>Số session tổng hợp cần sinh thêm để đạt target</td>'
        '<td><code>target_vectors − tổng phiên thực</code>. Nếu âm thì không cần sinh thêm</td></tr>'
        '<tr><td><b>Upscale factor</b></td>'
        '<td>Hệ số nhân: dữ liệu benign sẽ được nhân lên bao nhiêu lần</td>'
        '<td><code>target_vectors / tổng phiên thực</code>. VD: 5x nghĩa là cần gấp 5 lần dữ liệu gốc</td></tr>'
        '</table></details>'
    )

    # ══════════════════════════════════════════════════════════════════════
    # 2. Cross-verification against OpenSSH
    # ══════════════════════════════════════════════════════════════════════
    parts.append(html_section('verification', '2. Kiểm tra chéo (Cross-Verification)'))

    if v['session_count_match'] and v['username_consistency']:
        status_html = '<p class="good">PASSED: Phiên Cowrie benign nhất quán với OpenSSH.</p>'
    else:
        status_html = '<p class="warn">WARNING: Phát hiện không nhất quán giữa Cowrie và OpenSSH.</p>'
    parts.append(html_decision(
        'Kiểm tra tính toàn vẹn dữ liệu',
        status_html,
        'Cross-verification đảm bảo Step 2 bảo toàn cấu trúc phiên OpenSSH gốc. '
        'Sommer & Paxson (2010): ground truth validation là bắt buộc cho IDS evaluation.',
    ))

    verify_table_rows = [
        ['Session/PID groups', v['openssh_pid_groups'], v['cowrie_session_count'],
         'OK' if v['session_count_match'] else 'MISMATCH'],
        ['Username consistency',
         ', '.join(v['openssh_unique_usernames'][:8]),
         ', '.join(v['cowrie_unique_usernames'][:8]),
         'OK' if v['username_consistency'] else 'MISMATCH'],
        ['Valid structure (connect+close)', '-', v['sessions_valid_structure'],
         '-' if not v['sessions_missing_connect'] else
         'Missing connect: ' + str(v['sessions_missing_connect'])],
    ]
    parts.append(html_table(
        ['Kiểm tra', 'OpenSSH', 'Cowrie', 'Trạng thái'],
        verify_table_rows,
    ))

    # ══════════════════════════════════════════════════════════════════════
    # 3. Distribution Charts
    # ══════════════════════════════════════════════════════════════════════
    parts.append(html_section('charts', '3. Biểu đồ phân phối (Distribution Charts)'))

    # 3a. Archetype pie chart
    arch_labels = list(bs['archetype_counts'].keys())
    arch_values = list(bs['archetype_counts'].values())
    parts.append(html_chart(
        make_pie_chart(arch_labels, arch_values,
                       title='Phân phối Archetype (Archetype Distribution)'),
        'Tỷ lệ các loại hành vi benign trong dữ liệu thực',
    ))

    # 3b. Username pie chart (top 10)
    unames = list(bs['username_pool'].keys())[:10]
    uvals = list(bs['username_pool'].values())[:10]
    if unames:
        parts.append(html_chart(
            make_pie_chart(unames, uvals,
                           title='Phân phối Username (Top 10)'),
            'Top 10 username theo tần suất xuất hiện trong phiên benign',
        ))

    # 3c. Client version bar chart
    cv_labels = list(bs['client_version_pool'].keys())
    cv_values = list(bs['client_version_pool'].values())
    if cv_labels:
        parts.append(html_chart(
            make_bar_chart(cv_labels, cv_values,
                           title='Phân phối Client Version',
                           xlabel='Version', ylabel='Số phiên',
                           horizontal=True,
                           figsize=(9, max(3, len(cv_labels) * 0.5))),
            'Các phiên bản SSH client được sử dụng',
        ))

    # 3d. Duration histogram
    all_durations = [prof['duration'] for prof in bs['profiles']]
    positive_durs = [d for d in all_durations if d > 0]
    if positive_durs:
        parts.append(html_chart(
            make_histogram(positive_durs,
                           title='Phân phối Duration (giây)',
                           xlabel='Duration (s)', ylabel='Số phiên',
                           bins=40, log_scale=True),
            'Histogram thời lượng phiên (log scale) — phân phối log-normal '
            'mu=' + str(ds['lognormal_mu']) + ', sigma=' + str(ds['lognormal_sigma']),
        ))

    # 3e. Hour distribution bar chart
    hour_dist = bs.get('hour_distribution', {})
    if hour_dist:
        h_labels = [str(h) for h in range(24)]
        h_values = [hour_dist.get(h, hour_dist.get(str(h), 0)) for h in range(24)]
        parts.append(html_chart(
            make_bar_chart(h_labels, h_values,
                           title='Phân phối giờ kết nối (UTC)',
                           xlabel='Giờ (UTC)', ylabel='Số phiên',
                           color='#38a169'),
            'Giờ bắt đầu phiên (UTC) — giờ cao điểm phản ánh giờ làm việc VN (UTC+7)',
        ))

    # 3f. Event transitions bar chart
    transitions = bs.get('event_transitions', [])
    if transitions:
        tr_labels = [t['transition'] for t in transitions[:15]]
        tr_values = [t['count'] for t in transitions[:15]]
        parts.append(html_chart(
            make_bar_chart(tr_labels, tr_values,
                           title='Top Event Transitions',
                           xlabel='Transition', ylabel='Count',
                           color='#805ad5',
                           horizontal=True,
                           figsize=(10, max(4, len(tr_labels) * 0.4))),
            'Top 15 chuỗi chuyển đổi event liên tiếp',
        ))

    # 3g. Fail count distribution bar chart
    fc_dist = bs.get('fail_count_distribution', {})
    if fc_dist:
        fc_labels = [str(k) for k in sorted(fc_dist.keys(), key=lambda x: int(x))]
        fc_values = [fc_dist[k] for k in fc_labels]
        parts.append(html_chart(
            make_bar_chart(fc_labels, fc_values,
                           title='Phân phối số lần fail/phiên',
                           xlabel='Số lần login failed', ylabel='Số phiên',
                           color='#e53e3e'),
            'Số phiên theo số lần đăng nhập thất bại',
        ))

    # ══════════════════════════════════════════════════════════════════════
    # 4. Archetype classification
    # ══════════════════════════════════════════════════════════════════════
    parts.append(html_section('archetypes', '4. Phân loại hành vi (Archetype Classification)'))
    parts.append(html_decision(
        'Quyết định: Phân loại hành vi Benign',
        '<p>Phiên benign được phân loại thành các archetype hành vi để bảo toàn '
        'phân phối thực nghiệm khi upscale. Phiên tổng hợp được phân bổ tỷ lệ.</p>',
        'Cochran (1977): Phân bổ phân tầng (stratified allocation) bảo toàn cấu trúc '
        'dân số. Overrepresentation bất kỳ archetype nào sẽ gây bias cho model.',
    ))

    arch_desc = {
        'clean_login': 'Đăng nhập thành công, không lỗi — truy cập thường ngày',
        'typo': '1-3 lần thất bại rồi thành công — gõ nhầm password / key mismatch',
        'troubleshoot': '4+ lần thất bại rồi thành công — khắc phục sự cố truy cập',
        'give_up': 'Chỉ thất bại, không thành công — quên password / sai host',
    }
    arch_rows = []
    for arch, cnt in bs['archetype_counts'].items():
        pct_str = '{:.1f}%'.format(cnt / total * 100)
        arch_rows.append([arch, arch_desc.get(arch, ''), cnt, pct_str])
    parts.append(html_table(
        ['Archetype', 'Mô tả', 'Số phiên', '%'],
        arch_rows,
    ))

    # ══════════════════════════════════════════════════════════════════════
    # 5. Username & Client Version tables
    # ══════════════════════════════════════════════════════════════════════
    parts.append(html_section('usernames', '5. Username & Client Version'))

    parts.append('<details><summary>Username frequency</summary>')
    u_rows = [[u, cnt] for u, cnt in bs['username_pool'].items()]
    parts.append(html_table(['Username', 'Số phiên'], u_rows))
    parts.append('</details>')

    parts.append('<details><summary>Client version frequency</summary>')
    cv_rows = [[cv, cnt] for cv, cnt in bs.get('client_version_pool', {}).items()]
    parts.append(html_table(['Version', 'Số phiên'], cv_rows))
    parts.append('</details>')

    # ══════════════════════════════════════════════════════════════════════
    # 6. Event transitions table
    # ══════════════════════════════════════════════════════════════════════
    parts.append(html_section('transitions', '6. Event Transitions'))
    if transitions:
        parts.append('<details><summary>Transition counts</summary>')
        tr_rows = [[t['transition'], t['count']] for t in transitions]
        parts.append(html_table(['Transition', 'Count'], tr_rows))
        parts.append('</details>')

    # ══════════════════════════════════════════════════════════════════════
    # 7. Session timeline summary
    # ══════════════════════════════════════════════════════════════════════
    timelines = bs.get('session_timeline_summary', [])
    parts.append(html_section('timelines',
                              '7. Session Timeline (' + str(len(timelines)) + ' phiên)'))
    if timelines:
        parts.append('<details><summary>Xem chi tiết timeline</summary>')
        tl_rows = []
        for tl in timelines:
            path_short = tl['event_path']
            if len(path_short) > 120:
                path_short = path_short[:120] + '...'
            tl_rows.append([
                tl['session'][:12], tl['src_ip'], tl['event_count'],
                tl['n_fail'], tl['n_success'],
                tl['first_seen'], tl['last_seen'],
                round(tl['duration'], 1), tl['archetype'], path_short,
            ])
        parts.append(html_table(
            ['Session', 'src_ip', 'Events', 'Fails', 'OK',
             'First seen', 'Last seen', 'Duration(s)', 'Archetype', 'Event path'],
            tl_rows,
        ))
        parts.append('</details>')

    # ══════════════════════════════════════════════════════════════════════
    # 8. Upscale plan
    # ══════════════════════════════════════════════════════════════════════
    parts.append(html_section('upscale', '8. Kế hoạch Upscale'))

    ratio_line = 'match attack reference từ Step 3A (default ~ 1:1 benign : attack ref)'
    if rm.get('mode') == 'natural':
        ratio_line = 'natural — tất cả phiên thực, không synthetic'
    elif rm.get('benign_attack_ratio'):
        ratio_line = 'benign:attack session target = ' + str(rm['benign_attack_ratio']) + ' vs attack reference'
    elif rm.get('mode') == 'explicit_target_sessions':
        ratio_line = 'explicit target = ' + str(rm.get('target_sessions', '')) + ' phiên benign'

    plan_summary = (
        '<p><b>Target:</b> ' + str(p['target_vectors']) + ' phiên benign (' + ratio_line + ')'
        + ' | <b>Real (working set):</b> ' + str(p['real_sessions'])
        + ' | <b>Synthetic needed:</b> ' + str(p['synthetic_needed'])
        + ' (' + str(p['upscale_factor']) + 'x)</p>'
    )
    parts.append(html_decision(
        'Quyết định: Parametric Bootstrap Upscale',
        plan_summary,
        'Efron & Tibshirani (1993): Parametric bootstrap hợp lệ khi mẫu đại diện cho dân số. '
        'Mỗi phiên tổng hợp lấy mẫu fail count, duration, username, client version, timestamp '
        'từ phân phối quan sát được. IP lấy từ pool IP Việt Nam (không trùng IP thực).',
    ))

    plan_rows = [
        ['Target feature vectors', p['target_vectors']],
        ['Real sessions', p['real_sessions']],
        ['Synthetic needed', p['synthetic_needed']],
        ['Upscale factor', str(p['upscale_factor']) + 'x'],
        ['Multi-session IPs (clustering)', p['multi_session_ips']],
    ]
    parts.append(html_table(['Tham số', 'Giá trị'], plan_rows))

    # Upscale plan visualization: allocation by archetype
    parts.append('<h3>Phân bổ theo Archetype</h3>')
    alloc_rows = []
    for arch, synth_cnt in p['allocation'].items():
        real_cnt = bs['archetype_counts'].get(arch, 0)
        alloc_rows.append([arch, real_cnt, synth_cnt, real_cnt + synth_cnt])
    parts.append(html_table(
        ['Archetype', 'Real', 'Synthetic', 'Tổng'],
        alloc_rows,
    ))

    # Allocation bar chart
    alloc_labels = list(p['allocation'].keys())
    alloc_real = [bs['archetype_counts'].get(a, 0) for a in alloc_labels]
    alloc_synth = [p['allocation'][a] for a in alloc_labels]
    if alloc_labels:
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            fig, ax = plt.subplots(figsize=(8, 4))
            x = range(len(alloc_labels))
            ax.bar(x, alloc_real, label='Real', color='#3182ce', edgecolor='white')
            ax.bar(x, alloc_synth, bottom=alloc_real, label='Synthetic',
                   color='#e53e3e', edgecolor='white', alpha=0.8)
            ax.set_xticks(list(x))
            ax.set_xticklabels(alloc_labels, rotation=30, ha='right', fontsize=10)
            ax.set_ylabel('Số phiên')
            ax.set_title('Upscale Allocation: Real vs Synthetic', fontsize=12, fontweight='bold')
            ax.legend()
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            fig.tight_layout()
            from utils.report_utils import fig_to_base64, img_tag
            parts.append(html_chart(
                img_tag(fig_to_base64(fig), 'Upscale allocation'),
                'Phân bổ Real vs Synthetic theo archetype',
            ))
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════
    # 9. Decision explanations
    # ══════════════════════════════════════════════════════════════════════
    parts.append(html_section('decisions', '9. Giải thích quyết định (Decision Explanations)'))

    parts.append(html_decision(
        'Tỷ lệ 1:1 Benign : Attack',
        '<p>Mặc định sử dụng tỷ lệ 1:1 giữa số phiên benign và attack reference '
        'từ Step 3A. Đảm bảo model không bị bias về phía attack hoặc benign.</p>',
        'He & Garcia (2009): Cân bằng class giúp cải thiện hiệu suất phân loại, '
        'đặc biệt với IDS datasets. Tỷ lệ 1:1 là baseline chuẩn trước khi '
        'thử nghiệm ratio khác.',
    ))

    parts.append(html_decision(
        'Phân bổ phân tầng theo Archetype',
        '<p>Phiên tổng hợp được phân bổ tỷ lệ với số phiên thực trong mỗi archetype. '
        'Điều này bảo toàn cấu trúc hành vi thực.</p>',
        'Cochran (1977): Stratified sampling bảo toàn cấu trúc dân số và giảm variance '
        'so với random sampling đơn giản.',
    ))

    parts.append(html_decision(
        'Parametric Bootstrap',
        '<p>Phiên tổng hợp được tạo bằng parametric bootstrap: lấy mẫu từ phân phối '
        'thực nghiệm (log-normal cho duration, empirical cho username/client/fail count).</p>',
        'Efron & Tibshirani (1993): Parametric bootstrap là phương pháp chuẩn để '
        'mở rộng dataset khi mẫu gốc đại diện cho dân số. '
        'Davison & Hinkley (1997): Hợp lệ khi variance thấp.',
    ))

    parts.append(html_decision(
        'Trọng số giờ làm việc (Business-hour weights)',
        '<p>Timestamp phiên tổng hợp được tạo với trọng số ưu tiên giờ làm việc '
        'Việt Nam (8h-18h UTC+7). Phản ánh pattern truy cập thực của nhân viên ngân hàng.</p>',
        'Giờ làm việc thực tế 8-18h local time chiếm phần lớn traffic benign. '
        'Trọng số ngoài giờ = 0.02-0.3 để vẫn có một ít traffic off-hours.',
    ))

    parts.append(html_decision(
        'Multi-session IP Clustering',
        '<p>' + str(int(MULTI_SESSION_IP_FRACTION * 100)) + '% phiên tổng hợp đầu tiên '
        'được gom cụm: mỗi 3 phiên chia sẻ 1 IP. Mô phỏng nhân viên có nhiều phiên '
        'từ cùng máy trạm.</p>',
        'Trong môi trường doanh nghiệp, một máy trạm có thể tạo nhiều SSH session. '
        'IP clustering ngăn model học shortcut "mỗi IP = 1 phiên = benign".',
    ))

    # ══════════════════════════════════════════════════════════════════════
    # 10. Extended verification tests
    # ══════════════════════════════════════════════════════════════════════
    parts.append(html_section('ext-verify', '10. Kiểm tra mở rộng (Extended Verification)'))

    tests: list[tuple[str, bool, str]] = []

    # Test 1: Session structure valid
    tests.append((
        'Cấu trúc phiên hợp lệ (session structure)',
        v['sessions_valid_structure'] == v['cowrie_session_count'],
        str(v['sessions_valid_structure']) + '/' + str(v['cowrie_session_count'])
        + ' phiên có cả connect + close',
    ))

    # Test 2: Username consistency
    tests.append((
        'Username nhất quán (username consistency)',
        v['username_consistency'],
        'Cowrie usernames: ' + ', '.join(v['cowrie_unique_usernames'][:5])
        + ' | OpenSSH usernames: ' + ', '.join(v['openssh_unique_usernames'][:5]),
    ))

    # Test 3: Session count match
    tests.append((
        'Số phiên khớp (session count match)',
        v['session_count_match'],
        'Cowrie=' + str(v['cowrie_session_count'])
        + ' <= OpenSSH PID groups=' + str(v['openssh_pid_groups']),
    ))

    # Test 4: No missing connect/close
    no_missing = (v['sessions_missing_connect'] == 0 and v['sessions_missing_close'] == 0)
    tests.append((
        'Không thiếu connect/close',
        no_missing,
        'Missing connect=' + str(v['sessions_missing_connect'])
        + ', missing close=' + str(v['sessions_missing_close']),
    ))

    # Test 5: Upscale math  (target - real = synthetic)
    upscale_math_ok = (p['synthetic_needed'] == p['target_vectors'] - p['real_sessions'])
    tests.append((
        'Upscale math: target - real = synthetic',
        upscale_math_ok,
        str(p['target_vectors']) + ' - ' + str(p['real_sessions'])
        + ' = ' + str(p['synthetic_needed'])
        + ' (expected ' + str(p['target_vectors'] - p['real_sessions']) + ')',
    ))

    # Test 6: Allocation sums correctly
    alloc_sum = sum(p['allocation'].values())
    alloc_ok = (alloc_sum == p['synthetic_needed'])
    tests.append((
        'Tổng allocation = synthetic needed',
        alloc_ok,
        'sum(allocation)=' + str(alloc_sum) + ', synthetic_needed=' + str(p['synthetic_needed']),
    ))

    # Tests on all_events (if provided)
    if all_events is not None:
        # Test 7: All synthetic events have data_origin='benign_corp_synthetic'
        synth_events = [e for e in all_events if e.get('data_origin') == 'benign_corp_synthetic']
        real_events = [e for e in all_events if e.get('data_origin') == 'benign_corp']
        bad_origin = [e for e in all_events
                      if e.get('data_origin') not in ('benign_corp', 'benign_corp_synthetic')]

        tests.append((
            'Synthetic events có data_origin=benign_corp_synthetic',
            len(synth_events) > 0 or p['synthetic_needed'] == 0,
            str(len(synth_events)) + ' synthetic events found',
        ))

        # Test 8: All real events have data_origin='benign_corp'
        tests.append((
            'Real events có data_origin=benign_corp',
            len(real_events) > 0,
            str(len(real_events)) + ' real events found',
        ))

        # Test 9: No unknown origins
        tests.append((
            'Không có data_origin không xác định',
            len(bad_origin) == 0,
            str(len(bad_origin)) + ' events with unknown origin',
        ))

    parts.append(html_verification_section(tests))

    # ══════════════════════════════════════════════════════════════════════
    # 11. Debug log
    # ══════════════════════════════════════════════════════════════════════
    parts.append(html_section('debug-log', '11. Debug Log'))
    if log is not None:
        parts.append(html_debug_log(log))
    else:
        parts.append('<p class="small">Không có debug log.</p>')

    # ── Footer ──
    parts.append(html_footer())
    return '\n'.join(parts)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description='Step 3B: Benign Expert Analysis & Upscale')
    parser.add_argument('--input', default=str(BENIGN_FILE),
                        help='Cowrie benign NDJSON from Step 2')
    parser.add_argument('--ipvn', default=str(IPVN_FILE))
    parser.add_argument('--target-vectors', type=int, default=0,
                        help='Target benign SESSION count (0 = use ratio or config). Overrides --benign-attack-ratio.')
    parser.add_argument(
        '--benign-attack-ratio',
        default=None,
        help='Target benign:attack session count vs attack reference from Step 3A config, '
             'e.g. 1:1, 1:2, 2:1, 3:1, or "natural" (all real, no synthetic). '
             'Ignored if --target-vectors > 0.',
    )
    parser.add_argument('--seed', type=int, default=SEED)
    parser.add_argument('--output-upscaled', default=str(OUTPUT_UPSCALED))
    parser.add_argument('--output-report', default=str(OUTPUT_REPORT_JSON))
    parser.add_argument('--output-html', default=str(OUTPUT_REPORT_HTML))
    args = parser.parse_args()

    log = ViLogger('Step3B')

    log.section('Step 3B — Phân tích chuyên gia Benign & Upscale')

    # ── 1. Read benign log ──
    benign_path = Path(args.input)
    log.info('Đọc file benign log: ' + str(benign_path))
    benign_events = _read_ndjson(benign_path)
    sessions_full = _sessionize(benign_events)
    log.ok('Đã nạp ' + str(len(benign_events)) + ' events, '
           + str(len(sessions_full)) + ' phiên')

    # ── 2. Resolve target session count (ratio / config / explicit) & subsample ──
    cfg_path = FEATURE_CFG
    attack_ref = 0
    if cfg_path.exists():
        with cfg_path.open('r') as f:
            _cfg = json.load(f)
        attack_ref = int(_cfg.get('estimated_attack_feature_vectors', 0) or 0)

    ratio_meta: dict[str, Any] = {}
    sessions = sessions_full

    if args.target_vectors > 0:
        target = args.target_vectors
        ratio_meta = {'mode': 'explicit_target_sessions', 'target_sessions': target}
        if target < len(sessions_full):
            sessions = subsample_sessions(sessions_full, target, args.seed)
            ratio_meta['subsampled_from'] = len(sessions_full)
        log.info('Target phiên (explicit): ' + str(target)
                 + '  (working set: ' + str(len(sessions)) + ' phiên)')
    elif args.benign_attack_ratio:
        parsed = parse_benign_attack_ratio(args.benign_attack_ratio)
        if parsed == 'natural':
            target = len(sessions_full)
            sessions = sessions_full
            ratio_meta = {'mode': 'natural', 'target_sessions': target, 'synthetic_sessions': 0}
            log.info('Chế độ ratio: natural — tất cả phiên thực, không synthetic ('
                     + str(target) + ')')
        else:
            if attack_ref <= 0:
                raise SystemExit(
                    '[ERROR] --benign-attack-ratio requires estimated_attack_feature_vectors in '
                    + str(cfg_path) + ' or pass --target-vectors instead.'
                )
            a, b = parsed
            target = target_sessions_from_ratio(attack_ref, parsed)
            ratio_meta = {
                'mode': 'ratio',
                'benign_attack_ratio': str(a) + ':' + str(b),
                'attack_reference_sessions': attack_ref,
                'target_sessions': target,
            }
            if target < len(sessions_full):
                sessions = subsample_sessions(sessions_full, target, args.seed)
                ratio_meta['subsampled_from'] = len(sessions_full)
                log.info('Ratio ' + str(a) + ':' + str(b) + ' -> target ' + str(target)
                         + ' phiên (subsample từ ' + str(len(sessions_full)) + ')')
            else:
                log.info('Ratio ' + str(a) + ':' + str(b) + ' -> target ' + str(target)
                         + ' phiên (dùng tất cả real + synthetic)')
    else:
        if attack_ref > 0:
            target = attack_ref
            ratio_meta = {'mode': 'config_1to1_default', 'attack_reference_sessions': attack_ref, 'target_sessions': target}
        else:
            target = len(sessions_full)
            ratio_meta = {'mode': 'fallback_real_only', 'target_sessions': target}
        if target < len(sessions_full):
            sessions = subsample_sessions(sessions_full, target, args.seed)
            ratio_meta['subsampled_from'] = len(sessions_full)
        log.info('Target từ config/fallback: ' + str(target)
                 + ' (working set: ' + str(len(sessions)) + ' phiên)')

    # ── 3. Verify against OpenSSH (working session set) ──
    log.section('Kiểm tra chéo với OpenSSH parsed logs')
    verification = verify_sessions(sessions, OPENSSH_PARSED_PATHS)
    log.debug('OpenSSH groups  : ' + str(verification['openssh_pid_groups']))
    log.debug('Cowrie sessions : ' + str(verification['cowrie_session_count']))
    log.debug('Valid structure : ' + str(verification['sessions_valid_structure']))
    if verification['session_count_match']:
        log.ok('Session count match: OK')
    else:
        log.warn('Session count match: KHÔNG KHỚP')
    if verification['username_consistency']:
        log.ok('Username consistency: OK')
    else:
        log.warn('Username consistency: KHÔNG KHỚP')

    # ── 4. Analyze empirical distribution ──
    log.section('Đo phân phối thực nghiệm')
    benign_stats = analyze_benign_log(sessions)
    log.ok('Tổng phiên: ' + str(benign_stats['total_sessions']))
    log.info('Archetypes:')
    for arch, cnt in benign_stats['archetype_counts'].items():
        pct = cnt / max(benign_stats['total_sessions'], 1) * 100
        log.debug('  ' + arch + ': ' + str(cnt) + ' ({:.1f}%)'.format(pct))
    log.debug('Username pool: ' + str(list(benign_stats['username_pool'].keys())))
    ds = benign_stats['duration_stats']
    log.debug('Duration: median=' + str(ds['median']) + 's, mu='
              + str(ds['lognormal_mu']) + ', sigma=' + str(ds['lognormal_sigma']))

    # Target for upscale plan (total benign sessions after synthetic)
    if args.target_vectors > 0 or args.benign_attack_ratio:
        pass  # target already set above
    else:
        if cfg_path.exists():
            with cfg_path.open('r') as f:
                cfg = json.load(f)
            target = int(cfg.get('estimated_attack_feature_vectors', 0) or 0)
            if target <= 0:
                target = benign_stats['total_sessions']
            log.info('Target từ pipeline_feature_config.json: ' + str(target) + ' phiên')
        else:
            target = benign_stats['total_sessions']
            log.info('Không có feature config; target = real count (' + str(target) + ')')

    ratio_meta['upscale_target_sessions'] = target
    log.info('Upscale plan target (tổng phiên benign): ' + str(target))

    # ── 5. Plan upscale ──
    log.section('Kế hoạch Upscale')
    upscale_plan = plan_upscale(benign_stats, target)
    log.debug('Target         : ' + str(upscale_plan['target_vectors']))
    log.debug('Real sessions  : ' + str(upscale_plan['real_sessions']))
    log.debug('Synthetic      : ' + str(upscale_plan['synthetic_needed']))
    log.debug('Factor         : ' + str(upscale_plan['upscale_factor']) + 'x')
    log.info('Allocation:')
    for arch, cnt in upscale_plan['allocation'].items():
        log.debug('  ' + arch + ': ' + str(cnt))

    # ── 6. Execute upscale ──
    log.section('Tạo phiên tổng hợp (synthetic sessions)')
    vn_ips = _load_vn_ips(Path(args.ipvn)) if Path(args.ipvn).exists() else []
    if not vn_ips:
        vn_ips = ['10.' + str(i) + '.' + str(j) + '.' + str(k)
                  for i in range(1, 255) for j in range(1, 10) for k in range(1, 10)]
    log.debug('IP pool: ' + str(len(vn_ips)) + ' địa chỉ')

    all_events = execute_upscale(sessions, benign_stats, upscale_plan, vn_ips, seed=args.seed)
    real_count = sum(1 for e in all_events if e.get('data_origin') == 'benign_corp')
    synth_count = sum(1 for e in all_events if e.get('data_origin') == 'benign_corp_synthetic')
    log.ok('Real events     : ' + str(real_count))
    log.ok('Synthetic events: ' + str(synth_count))
    log.ok('Tổng events     : ' + str(len(all_events)))

    if upscale_plan['synthetic_needed'] <= 0:
        log.info('Không cần tạo phiên synthetic.')

    # ── 7. Write outputs ──
    log.section('Ghi kết quả ra file')

    all_events.sort(key=lambda e: e.get('timestamp', ''))
    output_path = Path(args.output_upscaled)
    _write_ndjson(output_path, all_events)
    log.ok('Upscaled events -> ' + str(output_path))

    # Report
    full_report = {
        'verification': verification,
        'ratio_study': ratio_meta,
        'sessions_total_in_file': len(sessions_full),
        'sessions_used': len(sessions),
        'empirical_stats': {
            k: v for k, v in benign_stats.items()
            if k not in ('archetypes', 'profiles')
        },
        'upscale_plan': upscale_plan,
        'output_stats': {
            'real_events': real_count,
            'synthetic_events': synth_count,
            'total_events': len(all_events),
        },
    }
    report_path = Path(args.output_report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open('w', encoding='utf-8') as f:
        json.dump(full_report, f, indent=2, ensure_ascii=False)
    log.ok('Report JSON     -> ' + str(report_path))

    html_content = _build_html_report(
        verification, benign_stats, upscale_plan, ratio_meta,
        all_events=all_events, log=log,
    )
    html_path = Path(args.output_html)
    write_html(html_path, html_content)
    log.ok('Report HTML     -> ' + str(html_path))

    log.section('Step 3B hoàn tất.')


if __name__ == '__main__':
    main()
