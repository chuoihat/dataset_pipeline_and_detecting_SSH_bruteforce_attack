"""
Feature Extraction Pipeline for Cowrie Honeypot SSH Brute-Force Detection.

Implements the full thesis pipeline:
  1. Parse Cowrie JSON logs
  2. Extract features per (src_ip, time_window)  — configurable window size
  3. DBSCAN clustering on scaled feature matrix
  4. Rule-based ground-truth labelling (Attack / Benign)
  5. Temporal train / val / test split (60 / 20 / 20)

Feature groups
--------------
Group 1 – Frequency & Account (rule-based ground-truth labelling):
  failed_attempts, num_unique_users, username_entropy, success_ratio, num_failed_ports

Group 2 – Time-based (Random Forest input, NOT used for rule thresholds):
  avg_time_between_attempts, login_interval_variance, time_of_day_avg, num_failed_days

Group 3 – Additional:
  ip_entropy, client_version_category

Metadata columns (drop before training): ip, window_start, cluster_id
"""
from __future__ import annotations

import csv
import json
import math
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
import argparse
from pathlib import Path
from typing import Any

from utils.report_utils import (
    ViLogger, html_header, html_footer, html_toc, html_section, html_cards,
    html_table, html_chart, html_debug_log, html_decision,
    html_verification_section, write_html as _write_report_html,
    make_bar_chart, make_pie_chart, make_histogram, make_heatmap,
    make_confusion_matrix_chart,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Directories and glob patterns to scan for newline-delimited JSON log files.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

LOG_SOURCES: list[tuple[Path, str]] = [
    (_PROJECT_ROOT / 'output' / 'step3c', 'cowrie_merged*.json'),
]

# Time-window granularity in minutes (default 15 min as recommended).
WINDOW_MINUTES: int = 60

# DBSCAN hyperparameters
DBSCAN_EPS: float = 1.0
DBSCAN_MIN_SAMPLES: int = 5

# Temporal split ratios (must sum to 1.0)
TRAIN_RATIO: float = 0.60
VAL_RATIO: float = 0.20
# TEST_RATIO = 1 - TRAIN_RATIO - VAL_RATIO

# Output paths
OUTPUT_DIR = _PROJECT_ROOT / 'output' / 'step4'
OUTPUT_CSV = OUTPUT_DIR / 'ml_features.csv'
OUTPUT_HTML = OUTPUT_DIR / 'ml_features.html'
OUTPUT_JSON = OUTPUT_DIR / 'ml_features.json'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _parse_ts(ts_value: Any) -> datetime | None:
    if not isinstance(ts_value, str) or not ts_value:
        return None
    try:
        return datetime.fromisoformat(ts_value.replace('Z', '+00:00')).astimezone(timezone.utc)
    except Exception:
        return None


def _floor_dt(dt: datetime, minutes: int) -> datetime:
    """Floor a datetime to the nearest *minutes*-aligned boundary."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    minute = (dt.minute // minutes) * minutes
    return dt.replace(minute=minute, second=0, microsecond=0)


def _fmt_ts(dt: datetime | None) -> str:
    if dt is None:
        return 'N/A'
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def _shannon_entropy(values: list[str]) -> float:
    """Shannon entropy (bits) of a list of categorical values."""
    if not values:
        return 0.0
    counter = Counter(values)
    total = len(values)
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 6)


def _ip_entropy(ip: str) -> float:
    """Shannon entropy of the character distribution in an IP address string."""
    return _shannon_entropy(list(ip))


def _seconds_from_midnight(dt: datetime) -> float:
    return dt.hour * 3600 + dt.minute * 60 + dt.second + dt.microsecond / 1_000_000


def _unanimous_origin(records: list[dict], log: ViLogger | None = None) -> str:
    """Return the data_origin if all events agree; warn and fallback to majority if mixed."""
    origins = [r.get('data_origin', '') for r in records if r.get('data_origin')]
    if not origins:
        return ''
    unique = set(origins)
    if len(unique) == 1:
        return unique.pop()
    msg = f'Mixed data_origin trong cùng (ip,window): {Counter(origins)}'
    if log:
        log.warn(msg)
    else:
        print(f'  [WARN] {msg}')
    return Counter(origins).most_common(1)[0][0]


# ---------------------------------------------------------------------------
# SSH client version categorisation
# ---------------------------------------------------------------------------
# Integer encoding for Random Forest (ordinal categories).
CLIENT_CATEGORIES: dict[str, int] = {
    'openssh': 0,
    'libssh': 1,
    'paramiko': 2,
    'go': 3,
    'putty': 4,
    'scanner': 5,   # ZGrab, Nmap, etc.
    'other_lib': 6, # JSCH, phpseclib, makiko, dropbear, etc.
    'unknown': 7,   # non-SSH probes, garbage bytes
}

_CLIENT_RULES: list[tuple[str, str]] = [
    (r'openssh|OpenSSH', 'openssh'),
    (r'paramiko', 'paramiko'),
    (r'libssh', 'libssh'),
    (r'\bGo\b', 'go'),
    (r'PuTTY|putty', 'putty'),
    (r'ZGrab|Nmap|nmap|zgrab|masscan|scanner', 'scanner'),
    (r'JSCH|phpseclib|makiko|dropbear|AsyncSSH|Twisted', 'other_lib'),
]


def _classify_client_version(version: str) -> int:
    """Return an integer category for an SSH version string."""
    if not version or not version.startswith('SSH-'):
        return CLIENT_CATEGORIES['unknown']
    for pattern, label in _CLIENT_RULES:
        if re.search(pattern, version, re.IGNORECASE):
            return CLIENT_CATEGORIES[label]
    return CLIENT_CATEGORIES['unknown']


# Reverse map for display
CLIENT_CATEGORY_NAMES: dict[int, str] = {v: k for k, v in CLIENT_CATEGORIES.items()}


# ---------------------------------------------------------------------------
# I/O – read events
# ---------------------------------------------------------------------------
def read_all_events(
    sources: list[tuple[Path, str]] | None = None,
) -> list[dict[str, Any]]:
    """Read newline-delimited JSON events from all configured log sources."""
    events: list[dict[str, Any]] = []
    use_sources = sources if sources is not None else LOG_SOURCES
    for log_dir, pattern in use_sources:
        if not log_dir.exists():
            continue
        for log_file in sorted(log_dir.glob(pattern)):
            with log_file.open('r', encoding='utf-8', errors='replace') as f:
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


# ---------------------------------------------------------------------------
# Core – feature extraction (time-window based)
# ---------------------------------------------------------------------------
def extract_features(
    events: list[dict[str, Any]],
    window_minutes: int = WINDOW_MINUTES,
) -> list[dict[str, Any]]:
    """
    Build one feature row per (src_ip, time_window).

    Returns a list of dicts ready for CSV/JSON serialisation.
    """
    # --- Pre-pass: build session lookup tables ---
    session_dst_port: dict[str, int] = {}
    session_client_version: dict[str, str] = {}
    session_connect_ts: dict[str, datetime] = {}
    session_duration_s: dict[str, float] = {}

    for ev in events:
        eid = ev.get('eventid', '')
        session = str(ev.get('session') or '')
        if not session:
            continue
        if eid == 'cowrie.session.connect':
            dst_port = ev.get('dst_port')
            if dst_port is not None:
                session_dst_port[session] = int(dst_port)
            ts = _parse_ts(ev.get('timestamp'))
            if ts and session not in session_connect_ts:
                session_connect_ts[session] = ts
        elif eid == 'cowrie.client.version':
            version = str(ev.get('version') or '')
            if version:
                session_client_version[session] = version
        elif eid == 'cowrie.session.closed':
            d = ev.get('duration')
            if isinstance(d, (int, float)):
                session_duration_s[session] = float(d)

    # --- Bucket login events by (src_ip, window_start) ---
    ip_win_failed: dict[tuple[str, str], list[dict]] = defaultdict(list)
    ip_win_success: dict[tuple[str, str], list[dict]] = defaultdict(list)

    for ev in events:
        eventid = ev.get('eventid', '')
        if eventid not in ('cowrie.login.failed', 'cowrie.login.success'):
            continue

        src_ip = str(ev.get('src_ip') or '')
        if not src_ip:
            continue

        ts = _parse_ts(ev.get('timestamp'))
        if ts is None:
            continue

        win_start = _fmt_ts(_floor_dt(ts, window_minutes))
        session = str(ev.get('session') or '')
        username = str(ev.get('username') or '')
        dst_port = session_dst_port.get(session)
        client_ver = session_client_version.get(session, '')

        record = {
            'timestamp': ts,
            'username': username,
            'session': session,
            'dst_port': dst_port,
            'client_version': client_ver,
            'data_origin': ev.get('data_origin', ''),
        }

        if eventid == 'cowrie.login.failed':
            ip_win_failed[(src_ip, win_start)].append(record)
        else:
            ip_win_success[(src_ip, win_start)].append(record)

    all_keys = sorted(set(ip_win_failed.keys()) | set(ip_win_success.keys()))

    # --- Pre-compute cross-window features ---
    # num_failed_days per IP (across ALL windows)
    ip_failed_days: dict[str, set[str]] = defaultdict(set)
    for (ip, _win), recs in ip_win_failed.items():
        for r in recs:
            ip_failed_days[ip].add(r['timestamp'].strftime('%Y-%m-%d'))

    # --- Build feature rows ---
    rows: list[dict[str, Any]] = []
    for src_ip, win_start in all_keys:
        failed_events = ip_win_failed.get((src_ip, win_start), [])
        success_events = ip_win_success.get((src_ip, win_start), [])

        failed_count = len(failed_events)
        success_count = len(success_events)
        total_attempts = failed_count + success_count

        # -- Group 1: Frequency & Account ----------------------------------
        failed_attempts = failed_count

        failed_usernames = [e['username'] for e in failed_events]
        num_unique_users = len(set(failed_usernames))

        username_entropy = _shannon_entropy(failed_usernames)

        success_ratio = round(success_count / total_attempts, 6) if total_attempts > 0 else 0.0

        failed_ports: set[int] = set()
        for e in failed_events:
            if e['dst_port'] is not None:
                failed_ports.add(e['dst_port'])
        num_failed_ports = len(failed_ports)

        # -- Group 2: Time-based -------------------------------------------
        failed_timestamps = sorted(e['timestamp'] for e in failed_events)

        intervals: list[float] = []
        for i in range(1, len(failed_timestamps)):
            delta = (failed_timestamps[i] - failed_timestamps[i - 1]).total_seconds()
            intervals.append(delta)

        avg_time_between_attempts = round(statistics.mean(intervals), 6) if intervals else 0.0
        login_interval_variance = round(statistics.variance(intervals), 6) if len(intervals) >= 2 else 0.0

        all_timestamps = [e['timestamp'] for e in failed_events] + [e['timestamp'] for e in success_events]
        if all_timestamps:
            time_of_day_avg = round(
                statistics.mean(_seconds_from_midnight(ts) for ts in all_timestamps), 6
            )
        else:
            time_of_day_avg = 0.0

        num_failed_days = len(ip_failed_days.get(src_ip, set()))

        # -- Group 3: Additional -------------------------------------------
        ip_entropy_val = _ip_entropy(src_ip)

        # client_version_category: dominant category across sessions in this window
        all_versions = [e['client_version'] for e in failed_events + success_events if e['client_version']]
        if all_versions:
            cat_counts: Counter[int] = Counter(_classify_client_version(v) for v in all_versions)
            client_version_category = cat_counts.most_common(1)[0][0]
        else:
            client_version_category = CLIENT_CATEGORIES['unknown']

        # -- Group 4: New MICRO time features --------------------------------
        all_login = failed_events + success_events
        window_sessions = {e['session'] for e in all_login if e['session']}

        # time_to_auth: mean time from connect → first login per session
        tta_vals: list[float] = []
        for sid in window_sessions:
            conn_ts = session_connect_ts.get(sid)
            if conn_ts is None:
                continue
            first_login = None
            for e in all_login:
                if e['session'] == sid:
                    if first_login is None or e['timestamp'] < first_login:
                        first_login = e['timestamp']
            if first_login and first_login > conn_ts:
                tta_vals.append((first_login - conn_ts).total_seconds())
        time_to_auth = round(statistics.mean(tta_vals), 6) if tta_vals else 0.0

        # session_duration: mean session duration across sessions in window
        sdur_vals: list[float] = []
        for sid in window_sessions:
            d = session_duration_s.get(sid)
            if d is not None and d > 0:
                sdur_vals.append(d)
        session_duration_feat = round(statistics.mean(sdur_vals), 6) if sdur_vals else 0.0

        # min/max inter-arrival time from existing intervals
        min_inter = round(min(intervals), 6) if intervals else 0.0
        max_inter = round(max(intervals), 6) if intervals else 0.0

        # hour_sin, hour_cos: cyclic encoding of window start hour
        win_dt = _parse_ts(win_start)
        win_hour = win_dt.hour if win_dt else 12
        hour_sin = round(math.sin(2 * math.pi * win_hour / 24), 6)
        hour_cos = round(math.cos(2 * math.pi * win_hour / 24), 6)

        rows.append({
            # Metadata (drop before training)
            'ip': src_ip,
            'window_start': win_start,
            # Group 1 – Frequency & Account
            'failed_attempts': failed_attempts,
            'num_unique_users': num_unique_users,
            'username_entropy': round(username_entropy, 6),
            'success_ratio': success_ratio,
            'num_failed_ports': num_failed_ports,
            # Group 2 – Time-based
            'avg_time_between_attempts': avg_time_between_attempts,
            'login_interval_variance': login_interval_variance,
            'time_of_day_avg': round(time_of_day_avg, 6),
            'num_failed_days': num_failed_days,
            # Group 3 – Additional
            'ip_entropy': round(ip_entropy_val, 6),
            'client_version_category': client_version_category,
            # Group 4 – MICRO time features
            'time_to_auth': time_to_auth,
            'session_duration': session_duration_feat,
            'min_inter_arrival': min_inter,
            'max_inter_arrival': max_inter,
            'hour_sin': hour_sin,
            'hour_cos': hour_cos,
            # Origin tracking (for final_label)
            'data_origin': _unanimous_origin(failed_events + success_events),
            # Session tracking (for integrity audit)
            'session_ids': sorted({e['session'] for e in failed_events + success_events if e['session']}),
        })

    return rows


# ---------------------------------------------------------------------------
# DBSCAN Clustering
# ---------------------------------------------------------------------------
CLUSTER_FEATURES = [
    'failed_attempts',
    'num_unique_users',
    'username_entropy',
    'success_ratio',
    'num_failed_ports',
    'avg_time_between_attempts',
    'login_interval_variance',
    'time_of_day_avg',
    'num_failed_days',
    'ip_entropy',
    'client_version_category',
    'time_to_auth',
    'session_duration',
    'min_inter_arrival',
    'max_inter_arrival',
    'hour_sin',
    'hour_cos',
]


def apply_dbscan(
    rows: list[dict[str, Any]],
    eps: float = DBSCAN_EPS,
    min_samples: int = DBSCAN_MIN_SAMPLES,
    train_indices: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Apply DBSCAN clustering and add 'cluster_id' to each row.

    If *train_indices* is provided, the scaler is fit only on those rows
    (train split) to avoid information leakage from val/test.

    Requires scikit-learn.  Falls back gracefully if not installed.
    """
    if not rows:
        return rows

    try:
        import numpy as np
        from sklearn.cluster import DBSCAN
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        print('[WARN] scikit-learn not installed — skipping DBSCAN clustering.')
        for r in rows:
            r['cluster_id'] = -1
        return rows

    X = np.array([[float(r.get(f, 0) or 0) for f in CLUSTER_FEATURES] for r in rows])

    scaler = StandardScaler()
    if train_indices is not None and len(train_indices) > 0:
        scaler.fit(X[train_indices])
    else:
        scaler.fit(X)
    X_scaled = scaler.transform(X)

    labels = DBSCAN(eps=eps, min_samples=min_samples).fit_predict(X_scaled)
    for r, lbl in zip(rows, labels):
        r['cluster_id'] = int(lbl)
    return rows


# ---------------------------------------------------------------------------
# Source-based labelling (final_label — no leakage)
# ---------------------------------------------------------------------------
def label_by_origin(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Assign 'final_label' based on data_origin field.

    final_label = 1  if data_origin == 'attack_cowrie'
    final_label = 0  if data_origin == 'benign_corp'
    """
    for r in rows:
        origin = r.get('data_origin', '')
        if origin == 'attack_cowrie':
            r['final_label'] = 1
        elif origin == 'benign_corp':
            r['final_label'] = 0
        else:
            # Fallback: unknown origin -> mark benign (conservative)
            r['final_label'] = 0
    return rows


# ---------------------------------------------------------------------------
# Rule-Based Attack Labelling (weak_label — reference only, train-split thresholds)
# ---------------------------------------------------------------------------
RULE_FEATURES = [
    'failed_attempts',
    'num_unique_users',
    'username_entropy',
    'success_ratio',
    'num_failed_ports',
]


def label_attacks(rows: list[dict[str, Any]], train_only_rows: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Assign 'weak_label' (1=Attack, 0=Benign) per cluster using quantile thresholds.

    If train_only_rows is provided, thresholds are computed on that subset only
    (avoids peeking at val/test). Otherwise falls back to all rows.
    """
    if not rows:
        return rows

    ref = train_only_rows if train_only_rows else rows

    def _quantile(values: list[float], q: float) -> float:
        s = sorted(values)
        idx = q * (len(s) - 1)
        lo = int(idx)
        hi = min(lo + 1, len(s) - 1)
        frac = idx - lo
        return s[lo] * (1 - frac) + s[hi] * frac

    thresholds = {
        'failed_attempts': _quantile([r['failed_attempts'] for r in ref], 0.65),
        'num_unique_users': _quantile([r['num_unique_users'] for r in ref], 0.65),
        'username_entropy': _quantile([r['username_entropy'] for r in ref], 0.70),
        'success_ratio': _quantile([r['success_ratio'] for r in ref], 0.30),
        'num_failed_ports': _quantile([r['num_failed_ports'] for r in ref], 0.65),
    }

    # Group rows by cluster_id
    clusters: dict[int, list[dict]] = defaultdict(list)
    for r in rows:
        clusters[r.get('cluster_id', -1)].append(r)

    def _is_attack(cluster_rows: list[dict]) -> bool:
        n = len(cluster_rows)
        if n == 0:
            return False
        avg = {f: sum(r[f] for r in cluster_rows) / n for f in RULE_FEATURES}
        return (
            avg['failed_attempts'] > thresholds['failed_attempts']
            or avg['num_unique_users'] > thresholds['num_unique_users']
            or avg['username_entropy'] > thresholds['username_entropy']
            or avg['num_failed_ports'] > thresholds['num_failed_ports']
            or avg['success_ratio'] < thresholds['success_ratio']
        )

    attack_clusters = {cid for cid, crows in clusters.items() if _is_attack(crows)}

    for r in rows:
        r['weak_label'] = 1 if r.get('cluster_id', -1) in attack_clusters else 0

    return rows, thresholds


# ---------------------------------------------------------------------------
# Temporal Split
# ---------------------------------------------------------------------------
def temporal_split(
    rows: list[dict[str, Any]],
    train_ratio: float = TRAIN_RATIO,
    val_ratio: float = VAL_RATIO,
) -> list[dict[str, Any]]:
    """Assign 'split' column (train / val / test) based on temporal ordering, stratified by data_origin."""
    if not rows:
        return rows

    # Group rows by data_origin to perform stratified temporal split
    origins = {r.get('data_origin', '') for r in rows}
    
    for origin in origins:
        origin_rows = [r for r in rows if r.get('data_origin', '') == origin]
        # Split by unique time windows for this origin
        unique_windows = sorted({r['window_start'] for r in origin_rows})
        n_windows = len(unique_windows)
        
        train_end = int(n_windows * train_ratio)
        val_end = int(n_windows * (train_ratio + val_ratio))

        window_to_split: dict[str, str] = {}
        for i, w in enumerate(unique_windows):
            if i < train_end:
                window_to_split[w] = 'train'
            elif i < val_end:
                window_to_split[w] = 'val'
            else:
                window_to_split[w] = 'test'

        for r in origin_rows:
            r['split'] = window_to_split.get(r['window_start'], 'test')

    return rows  # original list is mutated (same dicts)


# ---------------------------------------------------------------------------
# Output columns
# ---------------------------------------------------------------------------
FEATURE_COLUMNS = [
    'ip',
    'window_start',
    'failed_attempts',
    'num_unique_users',
    'username_entropy',
    'success_ratio',
    'num_failed_ports',
    'avg_time_between_attempts',
    'login_interval_variance',
    'time_of_day_avg',
    'num_failed_days',
    'ip_entropy',
    'client_version_category',
    'time_to_auth',
    'session_duration',
    'min_inter_arrival',
    'max_inter_arrival',
    'hour_sin',
    'hour_cos',
    'cluster_id',
    'data_origin',
    'final_label',
    'weak_label',
    'split',
]

# Columns that MUST be dropped before calling .fit()
METADATA_COLUMNS = ['ip', 'window_start', 'cluster_id', 'data_origin',
                    'final_label', 'weak_label', 'split']

# ML training columns (numeric features only)
# Default set — drops time_of_day_avg and num_failed_days which are artifacts
# of timestamp expansion (Owezarski 2015; Hofstede et al. 2014).
# Dynamically overridden by logs/pipeline_feature_config.json if present.
_ALL_ML_FEATURES = [
    'failed_attempts',
    'num_unique_users',
    'username_entropy',
    'success_ratio',
    'num_failed_ports',
    'avg_time_between_attempts',
    'login_interval_variance',
    'time_to_auth',
    'session_duration',
    'min_inter_arrival',
    'max_inter_arrival',
    'hour_sin',
    'hour_cos',
    'time_of_day_avg',
    'num_failed_days',
    'ip_entropy',
    'client_version_category',
]

_DEFAULT_DROP = {'time_of_day_avg', 'num_failed_days'}


def _load_feature_config() -> list[str]:
    """Read pipeline_feature_config.json (from attack_expert.py) if available."""
    cfg_path = _PROJECT_ROOT / 'output' / 'step3a' / 'pipeline_feature_config.json'
    if cfg_path.exists():
        try:
            import json as _json
            with cfg_path.open('r', encoding='utf-8') as f:
                cfg = _json.load(f)
            active = cfg.get('active_features')
            if isinstance(active, list) and active:
                print(f'[CONFIG] Loaded feature config from {cfg_path}')
                print(f'         Active features ({len(active)}): {active}')
                return active
        except Exception:
            pass
    return [f for f in _ALL_ML_FEATURES if f not in _DEFAULT_DROP]


ML_FEATURE_COLUMNS = _load_feature_config()


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------
def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def _write_json(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    out = [{k: r.get(k) for k in FEATURE_COLUMNS} for r in rows]
    path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')


def _html_table_legacy(headers: list[str], rows: list[list[Any]]) -> str:
    parts = ['<table class="dataframe">']
    parts.append('<thead><tr>')
    for h in headers:
        parts.append(f'<th>{html_escape(str(h))}</th>')
    parts.append('</tr></thead><tbody>')
    for row in rows:
        parts.append('<tr>')
        for cell in row:
            parts.append(f'<td>{html_escape("" if cell is None else str(cell))}</td>')
        parts.append('</tr>')
    parts.append('</tbody></table>')
    return ''.join(parts)


def _write_html(path: Path, rows: list[dict[str, Any]], total_events: int, thresholds_info: str) -> None:
    """Legacy HTML report — kept for backward compatibility."""
    path.parent.mkdir(parents=True, exist_ok=True)

    table_rows = [[r.get(c) for c in FEATURE_COLUMNS] for r in rows]

    total_ips = len({r['ip'] for r in rows})
    total_windows = len({r['window_start'] for r in rows})
    total_rows = len(rows)
    n_attack = sum(1 for r in rows if r.get('final_label') == 1)
    n_benign = total_rows - n_attack
    n_clusters = len({r.get('cluster_id', -1) for r in rows})
    split_counts = Counter(r.get('split', '?') for r in rows)
    client_cat_counts = Counter(CLIENT_CATEGORY_NAMES.get(r.get('client_version_category', 7), 'unknown') for r in rows)

    html = [
        '<!doctype html>',
        '<html lang="en">',
        '<head>',
        '<meta charset="utf-8"/>',
        '<meta name="viewport" content="width=device-width,initial-scale=1"/>',
        '<title>ML Feature Extraction Pipeline Report</title>',
        '<style>',
        'body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:24px;color:#111}',
        'h1{margin:0 0 4px} h2{margin:24px 0 8px}',
        '.muted{color:#666;font-size:13px}',
        '.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:14px 0 20px}',
        '.card{border:1px solid #e5e7eb;border-radius:10px;padding:10px 12px;background:#fff}',
        '.card .k{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.04em}',
        '.card .v{font-size:15px;font-weight:600;margin-top:3px}',
        'details{border:1px solid #e5e7eb;border-radius:10px;padding:10px 12px;margin:10px 0;background:#fff}',
        'summary{cursor:pointer;font-weight:700}',
        'table.dataframe{border-collapse:collapse;width:100%;margin-top:8px}',
        'table.dataframe th,table.dataframe td{border:1px solid #e5e7eb;padding:5px 7px;font-size:11px}',
        'table.dataframe thead th{position:sticky;top:0;background:#f9fafb}',
        '.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;margin:2px}',
        '.tag-rule{background:#dbeafe;color:#1e40af}',
        '.tag-time{background:#fef3c7;color:#92400e}',
        '.tag-id{background:#d1fae5;color:#065f46}',
        '.tag-meta{background:#f3f4f6;color:#6b7280}',
        '.tag-attack{background:#fee2e2;color:#991b1b}',
        '.tag-benign{background:#d1fae5;color:#065f46}',
        '.tag-train{background:#dbeafe;color:#1e40af}',
        '.tag-val{background:#fef3c7;color:#92400e}',
        '.tag-test{background:#fce7f3;color:#9d174d}',
        'pre{background:#0b1020;color:#e5e7eb;padding:12px;border-radius:10px;overflow-x:auto;font-size:12px}',
        '</style>',
        '</head>',
        '<body>',
        '<h1>ML Feature Extraction Pipeline Report</h1>',
        f'<div class="muted">Cowrie Honeypot · Time Window = {WINDOW_MINUTES} min · DBSCAN eps={DBSCAN_EPS} min_samples={DBSCAN_MIN_SAMPLES}</div>',
        '<div class="grid">',
        f'<div class="card"><div class="k">Total Events</div><div class="v">{total_events:,}</div></div>',
        f'<div class="card"><div class="k">Distinct IPs</div><div class="v">{total_ips}</div></div>',
        f'<div class="card"><div class="k">Distinct Windows</div><div class="v">{total_windows}</div></div>',
        f'<div class="card"><div class="k">Feature Rows</div><div class="v">{total_rows}</div></div>',
        f'<div class="card"><div class="k">DBSCAN Clusters</div><div class="v">{n_clusters}</div></div>',
        f'<div class="card"><div class="k">Attack / Benign</div><div class="v">'
        f'<span class="tag tag-attack">{n_attack}</span> <span class="tag tag-benign">{n_benign}</span></div></div>',
        f'<div class="card"><div class="k">Temporal Split</div><div class="v">'
        f'<span class="tag tag-train">train {split_counts.get("train",0)}</span> '
        f'<span class="tag tag-val">val {split_counts.get("val",0)}</span> '
        f'<span class="tag tag-test">test {split_counts.get("test",0)}</span></div></div>',
        '</div>',
        '<details open><summary>Feature Legend</summary>',
        f'<p><b>Aggregation unit:</b> one row per (src_ip, {WINDOW_MINUTES}-minute window). '
        '<span class="tag tag-meta">metadata</span> columns must be dropped before <code>.fit()</code>.</p>',
        '<p><span class="tag tag-rule">G1 — Frequency &amp; Account</span> Rule-based labelling · '
        '<span class="tag tag-time">G2 — Time-based</span> RF input only · '
        '<span class="tag tag-id">G3 — Additional</span></p>',
        '<ul>',
        '<li><b>failed_attempts</b> <span class="tag tag-rule">G1</span></li>',
        '<li><b>num_unique_users</b> <span class="tag tag-rule">G1</span></li>',
        '<li><b>username_entropy</b> <span class="tag tag-rule">G1</span></li>',
        '<li><b>success_ratio</b> <span class="tag tag-rule">G1</span></li>',
        '<li><b>num_failed_ports</b> <span class="tag tag-rule">G1</span></li>',
        '<li><b>avg_time_between_attempts</b> <span class="tag tag-time">G2</span></li>',
        '<li><b>login_interval_variance</b> <span class="tag tag-time">G2</span></li>',
        '<li><b>time_of_day_avg</b> <span class="tag tag-time">G2</span></li>',
        '<li><b>num_failed_days</b> <span class="tag tag-time">G2</span> (cross-window, per IP)</li>',
        '<li><b>ip_entropy</b> <span class="tag tag-id">G3</span></li>',
        '<li><b>client_version_category</b> <span class="tag tag-id">G3</span> — SSH client: '
        + ', '.join(f'{k}={v}' for k, v in sorted(CLIENT_CATEGORIES.items(), key=lambda x: x[1]))
        + '</li>',
        '</ul>',
        '</details>',
        '<details><summary>Rule-Based Labelling Thresholds (quantile)</summary>',
        f'<pre>{html_escape(thresholds_info)}</pre>',
        '</details>',
        '<details><summary>Client Version Distribution</summary>',
        _html_table_legacy(
            ['category', 'count'],
            [[cat, cnt] for cat, cnt in client_cat_counts.most_common()],
        ),
        '</details>',
        '<details><summary>Feature Table (all rows)</summary>',
        _html_table_legacy(FEATURE_COLUMNS, table_rows),
        '</details>',
        '</body></html>',
    ]

    path.write_text('\n'.join(html), encoding='utf-8')


# ---------------------------------------------------------------------------
# Comprehensive HTML report (new — uses report_utils)
# ---------------------------------------------------------------------------
def _write_comprehensive_html(
    path: Path,
    rows: list[dict[str, Any]],
    total_events: int,
    thresholds: dict[str, float],
    log: ViLogger,
    session_to_windows: dict[str, set[str]],
    session_to_splits: dict[str, set[str]],
) -> None:
    """Write a full HTML report with embedded charts and verification tests."""
    path.parent.mkdir(parents=True, exist_ok=True)

    total_rows = len(rows)
    total_ips = len({r['ip'] for r in rows})
    total_windows = len({r['window_start'] for r in rows})
    n_attack = sum(1 for r in rows if r.get('final_label') == 1)
    n_benign = total_rows - n_attack
    n_attack_weak = sum(1 for r in rows if r.get('weak_label') == 1)
    n_benign_weak = total_rows - n_attack_weak
    split_counts = Counter(r.get('split', '?') for r in rows)
    cluster_counts = Counter(r.get('cluster_id', -1) for r in rows)
    n_clusters = len(cluster_counts)
    client_cat_counts = Counter(
        CLIENT_CATEGORY_NAMES.get(r.get('client_version_category', 7), 'unknown')
        for r in rows
    )

    # ── Build HTML ─────────────────────────────────────────────────────────
    parts: list[str] = []

    parts.append(html_header(
        'Step 4 — Trích xuất Feature & Gán nhãn',
        'Step4: Feature Extraction',
        f'Cowrie Honeypot · Cửa sổ = {WINDOW_MINUTES} phút · DBSCAN eps={DBSCAN_EPS} min_samples={DBSCAN_MIN_SAMPLES}',
    ))

    # ── Table of contents ──────────────────────────────────────────────────
    toc_items = [
        ('s1', '1. Tổng quan dữ liệu đầu vào'),
        ('s2', '2. Trích xuất Feature'),
        ('s3', '3. Phân chia dữ liệu theo thời gian (Temporal Split)'),
        ('s4', '4. Phân cụm DBSCAN'),
        ('s5', '5. Gán nhãn (Labeling)'),
        ('s6', '6. Phân phối Feature theo nhãn'),
        ('s7', '7. Client Version Distribution'),
        ('s8', '8. Kiểm tra & Xác minh (Verification)'),
        ('s9', '9. Cơ sở khoa học cho các quyết định'),
        ('s10', '10. Debug Log'),
    ]
    parts.append(html_toc(toc_items))

    # ── Section 1: Tổng quan dữ liệu đầu vào ─────────────────────────────
    parts.append(html_section('s1', '1. Tổng quan dữ liệu đầu vào'))
    parts.append(html_cards([
        ('Tổng sự kiện (events)', total_events),
        ('Distinct IPs', total_ips),
        ('Distinct Windows', total_windows),
        ('Dòng feature', total_rows),
        ('Attack (final_label=1)', n_attack),
        ('Benign (final_label=0)', n_benign),
    ]))
    parts.append(
        '<details open><summary><b>Giải thích các chỉ số</b></summary>'
        '<table><tr><th>Chỉ số</th><th>Ý nghĩa</th><th>Cách xác định</th></tr>'
        '<tr><td><b>Tổng sự kiện (events)</b></td>'
        '<td>Tổng event thô từ file merged đầu vào</td>'
        '<td>Đếm dòng trong <code>output/step3c/cowrie_merged.json</code> — '
        'bao gồm cả attack và benign đã ghép và neutralize</td></tr>'
        '<tr><td><b>Distinct IPs</b></td>'
        '<td>Số địa chỉ IP nguồn khác nhau trong toàn bộ dataset</td>'
        '<td><code>len(set(row[\'ip\']))</code> — bao gồm IP tấn công + IP benign đã ánh xạ</td></tr>'
        '<tr><td><b>Distinct Windows</b></td>'
        '<td>Số cửa sổ thời gian ' + str(WINDOW_MINUTES) + ' phút khác nhau xuất hiện trong dữ liệu</td>'
        '<td><code>len(set(row[\'window_start\']))</code> — mỗi window là 1 khoảng thời gian cố định '
        'mà event được gom vào (VD: 14:00-15:00, 15:00-16:00)</td></tr>'
        '<tr><td><b>Dòng feature</b></td>'
        '<td>Số feature vector = số mẫu cho model ML</td>'
        '<td>Mỗi dòng = 1 cặp <code>(src_ip, window ' + str(WINDOW_MINUTES) + ' phút)</code> duy nhất. '
        'VD: IP A hoạt động trong 3 window → 3 dòng feature. '
        'Đây chính là đơn vị train/predict của model</td></tr>'
        '<tr><td><b>Attack (final_label=1)</b></td>'
        '<td>Số dòng feature được gán nhãn tấn công</td>'
        '<td>Dòng có <code>data_origin = attack_cowrie</code> → <code>final_label = 1</code>. '
        'Nhãn dựa trên nguồn gốc dữ liệu (honeypot = 100% attack), không dựa vào feature</td></tr>'
        '<tr><td><b>Benign (final_label=0)</b></td>'
        '<td>Số dòng feature được gán nhãn lành tính</td>'
        '<td>Dòng có <code>data_origin = benign_corp / benign_corp_synthetic</code> → <code>final_label = 0</code>. '
        'Nhãn dựa trên nguồn gốc: RHEL production server = 100% benign</td></tr>'
        '</table></details>'
    )

    # ── Section 2: Trích xuất Feature ──────────────────────────────────────
    parts.append(html_section('s2', '2. Trích xuất Feature'))
    parts.append(
        f'<p>Mỗi dòng feature tương ứng với một cặp <code>(src_ip, cửa sổ {WINDOW_MINUTES} phút)</code>. '
        f'Tổng cộng <b>{total_rows:,}</b> dòng từ <b>{total_ips:,}</b> IP và <b>{total_windows:,}</b> cửa sổ thời gian.</p>'
    )

    key_features_hist = [
        ('failed_attempts', 'Phân phối failed_attempts'),
        ('success_ratio', 'Phân phối success_ratio'),
        ('avg_time_between_attempts', 'Phân phối avg_time_between_attempts'),
        ('username_entropy', 'Phân phối username_entropy'),
    ]
    for feat, title in key_features_hist:
        vals = [float(r.get(feat, 0)) for r in rows]
        parts.append(html_chart(
            make_histogram(vals, title=title, xlabel=feat, log_scale=True),
            caption=f'Histogram của {feat} (log scale) — {total_rows} mẫu',
        ))

    # ── Section 3: Temporal Split ──────────────────────────────────────────
    parts.append(html_section('s3', '3. Phân chia dữ liệu theo thời gian (Temporal Split)'))
    parts.append(html_cards([
        ('Train', split_counts.get('train', 0)),
        ('Validation', split_counts.get('val', 0)),
        ('Test', split_counts.get('test', 0)),
    ]))

    split_labels = ['train', 'val', 'test']
    split_vals = [split_counts.get(s, 0) for s in split_labels]
    parts.append(html_chart(
        make_pie_chart(split_labels, split_vals, title='Tỉ lệ phân chia dữ liệu'),
        caption='Pie chart: train / val / test',
    ))

    atk_per_split = []
    ben_per_split = []
    for sp in split_labels:
        sp_rows = [r for r in rows if r.get('split') == sp]
        atk_per_split.append(sum(1 for r in sp_rows if r.get('final_label') == 1))
        ben_per_split.append(sum(1 for r in sp_rows if r.get('final_label') == 0))

    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        from utils.report_utils import fig_to_base64, img_tag

        fig, ax = plt.subplots(figsize=(8, 4))
        x = range(len(split_labels))
        w = 0.35
        ax.bar([i - w / 2 for i in x], atk_per_split, w, label='Attack', color='#e53e3e')
        ax.bar([i + w / 2 for i in x], ben_per_split, w, label='Benign', color='#38a169')
        ax.set_xticks(list(x))
        ax.set_xticklabels(split_labels)
        ax.set_ylabel('Số lượng')
        ax.set_title('Attack vs Benign theo từng split', fontsize=12, fontweight='bold')
        ax.legend()
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        fig.tight_layout()
        parts.append(html_chart(img_tag(fig_to_base64(fig), 'Attack vs Benign per split')))
    except ImportError:
        pass

    # ── Section 4: DBSCAN ──────────────────────────────────────────────────
    parts.append(html_section('s4', '4. Phân cụm DBSCAN'))
    parts.append(html_cards([
        ('Số cụm (clusters)', n_clusters),
        ('eps', DBSCAN_EPS),
        ('min_samples', DBSCAN_MIN_SAMPLES),
    ]))

    cluster_labels = [str(c) for c in sorted(cluster_counts.keys())]
    cluster_vals = [cluster_counts[int(c)] for c in cluster_labels]
    parts.append(html_chart(
        make_pie_chart(cluster_labels, cluster_vals, title='Kích thước các cụm DBSCAN'),
        caption='Pie chart: phân bố kích thước cụm',
    ))

    cluster_label_dist: dict[int, Counter] = defaultdict(Counter)
    for r in rows:
        cid = r.get('cluster_id', -1)
        lbl = 'Attack' if r.get('final_label') == 1 else 'Benign'
        cluster_label_dist[cid][lbl] += 1

    cl_table_headers = ['Cluster', 'Attack', 'Benign', 'Tổng']
    cl_table_rows = []
    for cid in sorted(cluster_label_dist.keys()):
        dist = cluster_label_dist[cid]
        cl_table_rows.append([
            str(cid), dist.get('Attack', 0), dist.get('Benign', 0),
            dist.get('Attack', 0) + dist.get('Benign', 0),
        ])
    parts.append(html_table(cl_table_headers, cl_table_rows))

    parts.append(html_chart(
        make_bar_chart(
            cluster_labels, cluster_vals,
            title='Số lượng mẫu theo cụm', xlabel='Cluster ID', ylabel='Số lượng',
        ),
        caption='Bar chart: phân bố nhãn theo cluster',
    ))

    # ── Section 5: Labeling ────────────────────────────────────────────────
    parts.append(html_section('s5', '5. Gán nhãn (Labeling)'))
    parts.append(
        '<p><b>final_label</b>: Dựa trên <code>data_origin</code> — <code>attack_cowrie → 1</code>, '
        '<code>benign_corp → 0</code>. Không dựa vào feature nên không có label leakage.</p>'
        '<p><b>weak_label</b>: Rule-based trên cluster averages, chỉ dùng để tham khảo. '
        'Thresholds tính trên train split.</p>'
    )

    parts.append(html_chart(
        make_pie_chart(
            ['Attack', 'Benign'], [n_attack, n_benign],
            title='final_label Distribution',
            colors=['#e53e3e', '#38a169'],
        ),
        caption='Pie chart: final_label (dựa trên data_origin)',
    ))

    parts.append(html_chart(
        make_pie_chart(
            ['Attack', 'Benign'], [n_attack_weak, n_benign_weak],
            title='weak_label Distribution',
            colors=['#e53e3e', '#38a169'],
        ),
        caption='Pie chart: weak_label (rule-based, tham khảo)',
    ))

    # Confusion matrix: final_label vs weak_label
    tp = sum(1 for r in rows if r.get('final_label') == 1 and r.get('weak_label') == 1)
    fp = sum(1 for r in rows if r.get('final_label') == 0 and r.get('weak_label') == 1)
    fn = sum(1 for r in rows if r.get('final_label') == 1 and r.get('weak_label') == 0)
    tn = sum(1 for r in rows if r.get('final_label') == 0 and r.get('weak_label') == 0)
    cm = [[tp, fn], [fp, tn]]
    agree = tp + tn
    parts.append(html_chart(
        make_confusion_matrix_chart(cm, ['Attack (1)', 'Benign (0)'],
                                    title='final_label vs weak_label'),
        caption=f'Đồng thuận: {agree}/{total_rows} ({agree / max(1, total_rows) * 100:.1f}%)',
    ))

    thresholds_table = [
        [feat, f'{thr:.4f}',
         'train-only Q30 (thấp = nghi ngờ)' if feat == 'success_ratio' else 'train-only quantile']
        for feat, thr in thresholds.items()
    ]
    parts.append('<h3>Ngưỡng rule-based (quantile, train-only)</h3>')
    parts.append(html_table(['Feature', 'Threshold', 'Ghi chú'], thresholds_table))

    # ── Section 6: Feature distributions by label ──────────────────────────
    parts.append(html_section('s6', '6. Phân phối Feature theo nhãn'))
    parts.append('<p>So sánh phân phối các feature chính giữa Attack và Benign (final_label).</p>')

    key_feats = ['failed_attempts', 'success_ratio', 'num_unique_users',
                 'username_entropy', 'avg_time_between_attempts']

    attack_rows = [r for r in rows if r.get('final_label') == 1]
    benign_rows = [r for r in rows if r.get('final_label') == 0]

    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        from utils.report_utils import fig_to_base64, img_tag, HAS_MPL

        if HAS_MPL:
            for feat in key_feats:
                atk_vals = [float(r.get(feat, 0)) for r in attack_rows]
                ben_vals = [float(r.get(feat, 0)) for r in benign_rows]
                fig, axes = plt.subplots(1, 2, figsize=(12, 4))
                axes[0].hist(atk_vals, bins=30, color='#e53e3e', alpha=0.85, edgecolor='white')
                axes[0].set_title(f'Attack (n={len(atk_vals)})', fontsize=11)
                axes[0].set_xlabel(feat)
                axes[0].set_ylabel('Số lượng')
                axes[0].spines['top'].set_visible(False)
                axes[0].spines['right'].set_visible(False)
                axes[1].hist(ben_vals, bins=30, color='#38a169', alpha=0.85, edgecolor='white')
                axes[1].set_title(f'Benign (n={len(ben_vals)})', fontsize=11)
                axes[1].set_xlabel(feat)
                axes[1].set_ylabel('Số lượng')
                axes[1].spines['top'].set_visible(False)
                axes[1].spines['right'].set_visible(False)
                fig.suptitle(f'Phân phối {feat} — Attack vs Benign', fontsize=13, fontweight='bold')
                fig.tight_layout()
                parts.append(html_chart(img_tag(fig_to_base64(fig), f'{feat} by label')))
    except ImportError:
        pass

    # ── Section 7: Client Version Distribution ─────────────────────────────
    parts.append(html_section('s7', '7. Client Version Distribution'))
    cv_labels = [cat for cat, _ in client_cat_counts.most_common()]
    cv_vals = [cnt for _, cnt in client_cat_counts.most_common()]
    parts.append(html_chart(
        make_pie_chart(cv_labels, cv_vals, title='Phân bố Client Version Category'),
        caption='SSH client fingerprint categories',
    ))
    parts.append(html_table(
        ['Category', 'Count', 'Tỉ lệ'],
        [[cat, cnt, f'{cnt / max(1, total_rows) * 100:.1f}%']
         for cat, cnt in client_cat_counts.most_common()],
    ))

    # ── Section 8: Verification ────────────────────────────────────────────
    parts.append(html_section('s8', '8. Kiểm tra & Xác minh (Verification)'))

    n_multi_split = sum(1 for sps in session_to_splits.values() if len(sps) > 1)
    n_sessions = len(session_to_windows)
    n_multi_window = sum(1 for wins in session_to_windows.values() if len(wins) > 1)

    ip_win_origins: dict[tuple, set] = defaultdict(set)
    for r in rows:
        ip_win_origins[(r['ip'], r['window_start'])].add(r.get('data_origin', ''))
    n_mixed_origin = sum(1 for v in ip_win_origins.values() if len(v) > 1)

    critical_features = ['failed_attempts', 'success_ratio', 'num_unique_users',
                         'username_entropy', 'avg_time_between_attempts',
                         'num_failed_ports', 'ip_entropy', 'client_version_category']
    nan_count = 0
    for r in rows:
        for cf in critical_features:
            v = r.get(cf)
            if v is None or (isinstance(v, float) and math.isnan(v)):
                nan_count += 1

    split_label_ok = True
    split_label_detail_parts = []
    for sp in ['train', 'val', 'test']:
        sp_rows = [r for r in rows if r.get('split') == sp]
        if not sp_rows:
            continue
        n_atk_sp = sum(1 for r in sp_rows if r.get('final_label') == 1)
        n_ben_sp = len(sp_rows) - n_atk_sp
        has_both = n_atk_sp > 0 and n_ben_sp > 0
        pct = n_atk_sp / len(sp_rows) * 100
        split_label_detail_parts.append(f'{sp}: Atk={n_atk_sp}({pct:.1f}%) Ben={n_ben_sp}')
        if not has_both:
            split_label_ok = False

    all_expected_cols = set(FEATURE_COLUMNS)
    present_cols = set()
    if rows:
        present_cols = set(rows[0].keys())
    missing_cols = all_expected_cols - present_cols

    tests = [
        ('Tổng dòng feature > 0',
         total_rows > 0,
         f'{total_rows} dòng feature'),
        ('Attack + Benign = Tổng dòng feature',
         n_attack + n_benign == total_rows,
         f'Attack({n_attack}) + Benign({n_benign}) = {n_attack + n_benign} vs Total({total_rows})'),
        ('Train + Val + Test = Tổng dòng feature',
         sum(split_vals) == total_rows,
         f'Train({split_vals[0]}) + Val({split_vals[1]}) + Test({split_vals[2]}) = {sum(split_vals)} vs Total({total_rows})'),
        ('Không có NaN/None trong feature quan trọng',
         nan_count == 0,
         f'{nan_count} giá trị NaN/None trong {len(critical_features)} feature × {total_rows} dòng'),
        ('Tính toàn vẹn session (session spanning >1 split)',
         n_multi_split == 0,
         f'{n_multi_split}/{n_sessions} session nằm trong nhiều hơn 1 split'),
        ('Mixed-origin IP-Window pairs',
         n_mixed_origin == 0,
         f'{n_mixed_origin}/{len(ip_win_origins)} cặp (IP,Window) có mixed data_origin'),
        ('Phân bố nhãn hợp lý (mỗi split có cả 2 lớp)',
         split_label_ok,
         '; '.join(split_label_detail_parts)),
        ('Tất cả metadata columns có mặt',
         len(missing_cols) == 0,
         f'Thiếu: {missing_cols}' if missing_cols else 'Đủ tất cả cột FEATURE_COLUMNS'),
    ]
    parts.append(html_verification_section(tests))

    # ── Section 9: Decisions ───────────────────────────────────────────────
    parts.append(html_section('s9', '9. Cơ sở khoa học cho các quyết định'))

    parts.append(html_decision(
        'Temporal Split (không dùng Random Split)',
        '<p>Chia dữ liệu theo thời gian đảm bảo mô hình được đánh giá trên dữ liệu <em>tương lai</em>, '
        'mô phỏng triển khai thực tế. Random split có thể gây data leakage nếu cùng IP/session xuất hiện '
        'ở cả train và test.</p>',
        'Arp et al. (2022) "Dos and Don\'ts of ML in Computer Security"; '
        'Pendlebury et al. (2019) "TESSERACT: Eliminating Experimental Bias in Malware Classification".',
    ))

    parts.append(html_decision(
        'DBSCAN Clustering (tại sao phân cụm?)',
        '<p>DBSCAN giúp phát hiện nhóm hành vi tương tự mà không cần biết trước số cụm. '
        'Noise points (cluster=-1) thường là outlier — có thể là attack đơn lẻ hoặc benign bất thường. '
        'Cluster info được dùng cho weak_label (rule-based) nhưng KHÔNG phải cho final_label.</p>',
        'Ester et al. (1996) "A Density-Based Algorithm for Discovering Clusters"; '
        'Owezarski (2015) "Unsupervised classification and characterization of honeypot attacks".',
    ))

    parts.append(html_decision(
        'final_label dựa trên data_origin (không leak)',
        '<p>Nhãn chính thức (final_label) được gán hoàn toàn từ trường <code>data_origin</code> — '
        'attack_cowrie (honeypot) → 1, benign_corp (corporate) → 0. Vì data_origin là metadata nguồn, '
        'không phải feature hành vi, nên không có label leakage.</p>',
        'Bảo đảm ground truth chất lượng cao nhờ tách biệt nguồn dữ liệu honeypot vs corporate.',
    ))

    parts.append(html_decision(
        'weak_label chỉ để tham khảo',
        '<p>weak_label sử dụng quantile thresholds trên train split để gán nhãn theo cluster. '
        'Nó giúp kiểm tra xem rule-based có tương đồng với final_label hay không, '
        'nhưng <b>không bao giờ</b> được dùng làm target trong training.</p>',
        'So sánh weak_label vs final_label giúp validate giả thuyết rằng các feature '
        'hành vi có tương quan với ground truth.',
    ))

    # ── Section 10: Debug Log ──────────────────────────────────────────────
    parts.append(html_section('s10', '10. Debug Log'))
    parts.append(html_debug_log(log))

    # ── Feature Table (collapsible) ────────────────────────────────────────
    parts.append('<details><summary>Bảng Feature đầy đủ (tất cả dòng)</summary>')
    table_rows = [[r.get(c) for c in FEATURE_COLUMNS] for r in rows]
    parts.append(html_table(FEATURE_COLUMNS, table_rows))
    parts.append('</details>')

    parts.append(html_footer())

    _write_report_html(path, '\n'.join(parts))


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description='Step 4: Feature extraction from merged Cowrie logs')
    parser.add_argument(
        '--log-dir',
        default=None,
        help='Directory containing merged NDJSON (overrides default output/step3c)',
    )
    parser.add_argument(
        '--log-glob',
        default='cowrie_merged*.json',
        help='Glob pattern under --log-dir (default: cowrie_merged*.json)',
    )
    parser.add_argument(
        '--output-dir',
        default=None,
        help='Write ml_features.* here (default: output/step4)',
    )
    args = parser.parse_args()

    log = ViLogger('Step4')

    log_sources = LOG_SOURCES
    if args.log_dir:
        log_sources = [(Path(args.log_dir), args.log_glob)]

    out_dir = Path(args.output_dir) if args.output_dir else OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_csv = out_dir / 'ml_features.csv'
    out_json = out_dir / 'ml_features.json'
    out_html = out_dir / 'ml_features.html'

    # ── 1. Read events ─────────────────────────────────────────────────────
    log.section('Bước 1/7: Đọc sự kiện Cowrie JSON')
    log.info(f'Nguồn dữ liệu: {", ".join(f"{d}/{p}" for d, p in log_sources)}')
    log.info(f'Thư mục đầu ra: {out_dir}')

    events = read_all_events(sources=log_sources)
    total_events = len(events)
    log.ok(f'Đã đọc {total_events:,} events')

    sensor_counts = Counter(str(e.get('sensor') or 'N/A') for e in events)
    log.debug(f'Số sensor: {len(sensor_counts)}')
    for s, c in sensor_counts.most_common(6):
        log.debug(f'  sensor={s}: {c:,} event')

    if total_events == 0:
        log.fail('Không tìm thấy event nào! Hãy kiểm tra LOG_SOURCES.')
        return

    # ── 2. Extract features ────────────────────────────────────────────────
    log.section(f'Bước 2/7: Trích xuất feature theo (src_ip, cửa sổ {WINDOW_MINUTES} phút)')
    rows = extract_features(events, window_minutes=WINDOW_MINUTES)
    log.ok(f'Tạo được {len(rows):,} dòng feature')
    if not rows:
        log.fail('Không có event login, không tạo được output.')
        return

    distinct_ips = len({r['ip'] for r in rows})
    distinct_windows = len({r['window_start'] for r in rows})
    log.debug(f'Distinct IPs: {distinct_ips}, Distinct windows: {distinct_windows}')

    # ── 3. Temporal split ──────────────────────────────────────────────────
    log.section(f'Bước 3/7: Chia tập theo thời gian (train {TRAIN_RATIO:.0%} / val {VAL_RATIO:.0%} / test {1-TRAIN_RATIO-VAL_RATIO:.0%})')
    rows = temporal_split(rows, train_ratio=TRAIN_RATIO, val_ratio=VAL_RATIO)
    split_counts = Counter(r.get('split') for r in rows)
    log.ok(f'train={split_counts.get("train",0)}  val={split_counts.get("val",0)}  test={split_counts.get("test",0)}')
    log.debug('Ý nghĩa split: train để học, val để chỉnh, test để báo cáo cuối.')

    train_indices = [i for i, r in enumerate(rows) if r.get('split') == 'train']

    # Session integrity check
    session_to_windows: dict[str, set[str]] = defaultdict(set)
    session_to_splits: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        for sid in r.get('session_ids', []):
            session_to_windows[sid].add(r['window_start'])
            session_to_splits[sid].add(r.get('split', ''))

    n_multi_window = sum(1 for wins in session_to_windows.values() if len(wins) > 1)
    n_multi_split = sum(1 for sps in session_to_splits.values() if len(sps) > 1)
    log.info(f'Session integrity: {n_multi_window}/{len(session_to_windows)} session nằm trong >1 window')
    log.info(f'Session integrity: {n_multi_split}/{len(session_to_windows)} session nằm trong >1 split')
    if n_multi_split > 0:
        log.warn('Một số session xuất hiện trong nhiều split — có nguy cơ rò rỉ thông tin (information leakage).')

    # ── 4. DBSCAN ──────────────────────────────────────────────────────────
    log.section(f'Bước 4/7: Phân cụm DBSCAN (eps={DBSCAN_EPS}, min_samples={DBSCAN_MIN_SAMPLES}, scaler fit train-only)')
    rows = apply_dbscan(rows, eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMPLES, train_indices=train_indices)
    n_clusters = len({r.get('cluster_id', -1) for r in rows})
    log.ok(f'Tìm thấy {n_clusters} cụm (clusters)')

    cluster_dist = Counter(r.get('cluster_id', -1) for r in rows)
    for cid, cnt in cluster_dist.most_common(10):
        log.debug(f'  cluster_id={cid}: {cnt:,} mẫu')

    # ── 5. final_label ─────────────────────────────────────────────────────
    log.section('Bước 5/7: Gán final_label theo data_origin (không leak)')
    rows = label_by_origin(rows)
    n_attack_final = sum(1 for r in rows if r.get('final_label') == 1)
    n_benign_final = len(rows) - n_attack_final
    log.ok(f'final_label: Attack={n_attack_final}  Benign={n_benign_final}')

    origin_dist = Counter(r.get('data_origin', 'N/A') for r in rows)
    for orig, cnt in origin_dist.most_common():
        log.debug(f'  data_origin={orig}: {cnt}')

    log.debug('final_label = 1 nếu data_origin == attack_cowrie, 0 nếu benign_corp.')
    log.debug('Không dựa vào feature → không có label leakage.')

    # Mixed-origin diagnostic
    ip_win_origins: dict[tuple, set] = defaultdict(set)
    for r in rows:
        ip_win_origins[(r['ip'], r['window_start'])].add(r.get('data_origin', ''))
    n_mixed_ip_win = sum(1 for v in ip_win_origins.values() if len(v) > 1)
    log.info(f'IP-Window pairs với mixed origin: {n_mixed_ip_win}/{len(ip_win_origins)}')
    if n_mixed_ip_win > 0:
        log.warn('Có IP-Window pairs mix cả attack và benign! final_label có thể bị noisy.')

    # Label distribution per split
    for sp in ['train', 'val', 'test']:
        sp_rows = [r for r in rows if r.get('split') == sp]
        n_atk = sum(1 for r in sp_rows if r.get('final_label') == 1)
        n_ben = len(sp_rows) - n_atk
        pct_atk = n_atk / max(1, len(sp_rows)) * 100
        log.debug(f'  {sp:6s}: Attack={n_atk} ({pct_atk:.1f}%)  Benign={n_ben} ({100-pct_atk:.1f}%)')

    # ── 6. weak_label ──────────────────────────────────────────────────────
    log.section('Bước 6/7: Gán weak_label (rule-based, chỉ để tham khảo, threshold trên train)')
    train_rows_only = [r for r in rows if r.get('split') == 'train']
    rows, thresholds = label_attacks(rows, train_only_rows=train_rows_only)
    n_attack_weak = sum(1 for r in rows if r.get('weak_label') == 1)
    n_benign_weak = len(rows) - n_attack_weak
    log.ok(f'weak_label: Attack={n_attack_weak}  Benign={n_benign_weak}')

    agree = sum(1 for r in rows if r.get('final_label') == r.get('weak_label'))
    log.info(f'Đồng thuận final vs weak: {agree}/{len(rows)} ({agree/len(rows)*100:.1f}%)')

    for feat, thr in thresholds.items():
        direction = '<' if feat == 'success_ratio' else '>'
        log.debug(f'  Ngưỡng {feat}: {direction} {thr:.4f}')

    # ── 7. Write outputs ───────────────────────────────────────────────────
    log.section('Bước 7/7: Ghi các file kết quả')

    _write_csv(out_csv, rows)
    log.ok(f'CSV: {out_csv}')

    _write_json(out_json, rows)
    log.ok(f'JSON: {out_json}')

    _write_comprehensive_html(
        out_html, rows, total_events, thresholds, log,
        session_to_windows, session_to_splits,
    )
    log.ok(f'HTML (comprehensive): {out_html}')

    # ── Summary ────────────────────────────────────────────────────────────
    log.section('Tóm tắt')
    log.info(f'ML features: {len(ML_FEATURE_COLUMNS)} cột')
    log.debug(f'  {ML_FEATURE_COLUMNS}')
    log.info(f'Metadata phải DROP trước .fit(): {METADATA_COLUMNS}')
    log.info(f'Target column: final_label  (1=Attack, 0=Benign, theo data_origin)')
    log.info(f'Weak label (tham khảo): weak_label  (rule-based, threshold train-only)')
    log.debug('Giải thích nhanh feature chính:')
    log.debug('  - failed_attempts: số lần đăng nhập thất bại trong cửa sổ thời gian')
    log.debug('  - success_ratio: tỉ lệ thành công / tổng số lần đăng nhập')
    log.debug('  - num_unique_users: số username khác nhau bị thử')
    log.debug('  - num_failed_ports: số cổng đích bị fail (attack scan thường cao hơn benign)')
    log.debug('  - client_version_category: loại fingerprint SSH client')


if __name__ == '__main__':
    main()
