"""
Model Training, Evaluation & Near Real-Time Demo for Cowrie Honeypot
SSH Brute-Force Detection.

Pipeline:
  Step 4 — Train Random Forest on ml_features.json (temporal split)
  Step 5 — Near real-time demo: simulate streaming Cowrie logs → predict
  Evaluation — Confusion Matrix, Precision/Recall/F1, ROC-AUC,
               Feature Importance, Robustness scenarios, Latency

Usage:
  pixi run python train_and_demo.py              # full pipeline
  pixi run python train_and_demo.py --train      # train + evaluate only
  pixi run python train_and_demo.py --demo       # demo only (requires saved model)
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import os
import pickle
import re
import statistics
import subprocess as _subprocess_mod
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

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
    write_html as _write_report_html,
    make_bar_chart,
    make_pie_chart,
    make_confusion_matrix_chart,
    verify_card,
    fig_to_base64,
    img_tag,
)


EASY_FEATURES = ['success_ratio', 'failed_attempts', 'num_unique_users', 'num_failed_ports',
                  'time_to_auth', 'session_duration']

# ---------------------------------------------------------------------------
# Feature configuration — reads from pipeline_feature_config.json (Step 3A)
#
# The attack_expert.py (Step 3A) produces a config file that specifies:
#   - active_features: features to use for training
#   - shortcut_features: features to exclude (leakage risk)
#   - drop_features: features dropped due to data constraints
#   - success_ratio_enabled: whether bias correction was applied
#
# Falls back to legacy detection (bias_correction_meta.json) if the new
# config is not available, for backward compatibility.
# ---------------------------------------------------------------------------
_ALL_FEATURE_COLUMNS = [
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

_DEFAULT_DROP = {'time_of_day_avg', 'num_failed_days'}
_DEFAULT_SHORTCUT_FEATURES = ['num_failed_ports', 'ip_entropy']


def _load_pipeline_config(base_dir: Path) -> tuple[list[str], list[str]]:
    """Load feature config from Step 3A output or fall back to defaults."""
    cfg_path = base_dir / 'output' / 'step3a' / 'pipeline_feature_config.json'
    if cfg_path.exists():
        try:
            with cfg_path.open('r') as f:
                cfg = json.load(f)
            active = cfg.get('active_features', [])
            shortcuts = cfg.get('shortcut_features', _DEFAULT_SHORTCUT_FEATURES)
            if isinstance(active, list) and active:
                print(f'[CONFIG] Loaded pipeline_feature_config.json (Step 3A)')
                print(f'         Active features ({len(active)}): {active}')
                print(f'         Shortcut features: {shortcuts}')
                return active, shortcuts
        except Exception:
            pass

    # Legacy fallback: check bias_correction_meta.json (old Step 3.5)
    meta_path = base_dir / 'output' / 'step3a' / 'bias_correction_meta.json'
    bias_corrected = False
    if meta_path.exists():
        try:
            with meta_path.open('r') as f:
                meta = json.load(f)
            bias_corrected = bool(meta.get('success_ratio_enabled', False))
        except Exception:
            pass

    shortcuts = list(_DEFAULT_SHORTCUT_FEATURES)
    if not bias_corrected:
        shortcuts.append('success_ratio')

    active = [f for f in _ALL_FEATURE_COLUMNS if f not in _DEFAULT_DROP and f not in shortcuts]
    print(f'[CONFIG] Using default feature config (no pipeline_feature_config.json)')
    print(f'         Active features ({len(active)}): {active}')
    return active, shortcuts


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
ML_FEATURE_COLUMNS, SHORTCUT_FEATURES = _load_pipeline_config(_PROJECT_ROOT)

TARGET_COLUMN = 'final_label'

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
FEATURES_JSON = _PROJECT_ROOT / 'output' / 'step4' / 'ml_features.json'
MODEL_PATH = _PROJECT_ROOT / 'output' / 'step5' / 'models' / 'random_forest.pkl'
REPORT_DIR = _PROJECT_ROOT / 'output' / 'step5' / 'reports'
DEMO_LOG_DIR = _PROJECT_ROOT / 'output' / 'step3c'
DEBUG_VIETNAMESE = True

# Alert threshold for demo
ALERT_THRESHOLD = 0.8

# Time-window for demo (must match feature_extraction.py)
WINDOW_MINUTES = 60


# ═══════════════════════════════════════════════════════════════════════════
# STEP 4 — MODEL TRAINING
# ═══════════════════════════════════════════════════════════════════════════

def load_features(path: Path) -> pd.DataFrame:
    """Load the feature JSON produced by feature_extraction.py."""
    with path.open('r', encoding='utf-8') as f:
        data = json.load(f)
    return pd.DataFrame(data)


def train_model(df: pd.DataFrame) -> dict[str, Any]:
    """
    Train a Random Forest on the temporal train split,
    tune on val, and evaluate on test.

    Returns dict with model, metrics, and dataframes for plotting.
    """
    train_df = df[df['split'] == 'train'].copy()
    val_df = df[df['split'] == 'val'].copy()
    test_df = df[df['split'] == 'test'].copy()

    X_train = train_df[ML_FEATURE_COLUMNS].values
    y_train = train_df[TARGET_COLUMN].values
    X_val = val_df[ML_FEATURE_COLUMNS].values
    y_val = val_df[TARGET_COLUMN].values
    X_test = test_df[ML_FEATURE_COLUMNS].values
    y_test = test_df[TARGET_COLUMN].values

    print(f'  Train: {len(X_train)} rows  (Attack={int(y_train.sum())}, Benign={int(len(y_train)-y_train.sum())})')
    print(f'  Val:   {len(X_val)} rows  (Attack={int(y_val.sum())}, Benign={int(len(y_val)-y_val.sum())})')
    print(f'  Test:  {len(X_test)} rows  (Attack={int(y_test.sum())}, Benign={int(len(y_test)-y_test.sum())})')
    if DEBUG_VIETNAMESE:
        print('  [DEBUG-VI] Y nghia:')
        print('    - Train: du lieu hoc model')
        print('    - Val: du lieu dieu chinh/kiem soat overfit')
        print('    - Test: du lieu bao cao hieu nang cuoi cung')

    # --- Train ---
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        min_samples_split=5,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)

    # --- Validation metrics (for tuning info) ---
    y_val_pred = rf.predict(X_val)
    y_val_proba = rf.predict_proba(X_val)[:, 1]
    val_f1 = f1_score(y_val, y_val_pred)
    val_macro_f1 = (
        f1_score(y_val, y_val_pred, average='macro', zero_division=0)
        if len(set(y_val)) > 1
        else float('nan')
    )
    val_auc = roc_auc_score(y_val, y_val_proba) if len(set(y_val)) > 1 else 0.0
    print(f'  Val F1={val_f1:.4f}  macro-F1={val_macro_f1:.4f}  AUC={val_auc:.4f}')

    # --- Test metrics (final report) ---
    y_test_pred = rf.predict(X_test)
    y_test_proba = rf.predict_proba(X_test)[:, 1]

    test_acc = accuracy_score(y_test, y_test_pred)
    test_prec = precision_score(y_test, y_test_pred, zero_division=0)
    test_rec = recall_score(y_test, y_test_pred, zero_division=0)
    test_f1 = f1_score(y_test, y_test_pred, zero_division=0)
    test_macro_f1 = (
        f1_score(y_test, y_test_pred, average='macro', zero_division=0)
        if len(set(y_test)) > 1
        else float('nan')
    )
    y_train_pred = rf.predict(X_train)
    train_macro_f1 = (
        f1_score(y_train, y_train_pred, average='macro', zero_division=0)
        if len(set(y_train)) > 1
        else float('nan')
    )
    test_auc = roc_auc_score(y_test, y_test_proba) if len(set(y_test)) > 1 else 0.0
    cm = confusion_matrix(y_test, y_test_pred, labels=[0, 1])
    test_labels = sorted(set(y_test) | set(y_test_pred))
    test_target_names = ['Benign', 'Attack'] if len(test_labels) == 2 else (
        ['Attack'] if 1 in test_labels else ['Benign'])
    cls_report = classification_report(
        y_test, y_test_pred, labels=test_labels, target_names=test_target_names,
        zero_division=0)

    if len(set(y_test)) > 1:
        fpr, tpr, _ = roc_curve(y_test, y_test_proba)
        pr_auc = average_precision_score(y_test, y_test_proba)
        pr_precision, pr_recall, _ = precision_recall_curve(y_test, y_test_proba)
    else:
        fpr, tpr = np.array([0.0, 1.0]), np.array([0.0, 1.0])
        pr_auc = 0.0
        pr_precision, pr_recall = np.array([1.0, 0.0]), np.array([0.0, 1.0])

    # FPR @ fixed TPR levels
    fpr_at_tpr: dict[str, float] = {}
    for target_tpr in [0.90, 0.95, 0.99]:
        idx = np.where(tpr >= target_tpr)[0]
        fpr_at_tpr[f'FPR@TPR={target_tpr:.2f}'] = float(fpr[idx[0]]) if len(idx) > 0 else 1.0

    # Feature importance
    importances = rf.feature_importances_
    feat_imp = sorted(
        zip(ML_FEATURE_COLUMNS, importances),
        key=lambda x: x[1],
        reverse=True,
    )

    return {
        'model': rf,
        'accuracy': test_acc,
        'precision': test_prec,
        'recall': test_rec,
        'f1': test_f1,
        'auc': test_auc,
        'pr_auc': pr_auc,
        'fpr_at_tpr': fpr_at_tpr,
        'pr_precision': pr_precision,
        'pr_recall': pr_recall,
        'confusion_matrix': cm,
        'classification_report': cls_report,
        'roc_fpr': fpr,
        'roc_tpr': tpr,
        'feature_importance': feat_imp,
        'val_f1': val_f1,
        'val_macro_f1': val_macro_f1,
        'val_auc': val_auc,
        'test_macro_f1': test_macro_f1,
        'train_macro_f1': train_macro_f1,
        'y_test': y_test,
        'y_test_pred': y_test_pred,
        'y_test_proba': y_test_proba,
        'X_train': X_train,
        'y_train': y_train,
        'split_sizes': {
            'train': len(X_train),
            'val': len(X_val),
            'test': len(X_test),
        },
    }


def _best_single_feature_threshold(x_train: np.ndarray, y_train: np.ndarray, prefer_low: bool) -> tuple[float, bool, float]:
    """Find best threshold rule on train for one feature.

    Returns (threshold, is_low_attack, best_f1).
    """
    uniq = np.unique(x_train)
    if len(uniq) == 0:
        return 0.0, prefer_low, 0.0
    if len(uniq) > 200:
        # Subsample thresholds to keep runtime stable.
        idx = np.linspace(0, len(uniq) - 1, 200).astype(int)
        uniq = uniq[idx]

    best_f1 = -1.0
    best_thr = float(uniq[0])
    best_low_attack = prefer_low

    for thr in uniq:
        y_pred_low = (x_train <= thr).astype(int)
        f1_low = f1_score(y_train, y_pred_low, zero_division=0)
        if f1_low > best_f1:
            best_f1 = f1_low
            best_thr = float(thr)
            best_low_attack = True

        y_pred_high = (x_train >= thr).astype(int)
        f1_high = f1_score(y_train, y_pred_high, zero_division=0)
        if f1_high > best_f1:
            best_f1 = f1_high
            best_thr = float(thr)
            best_low_attack = False

    return best_thr, best_low_attack, float(best_f1)


def _split_overlap_ratio(df: pd.DataFrame, feature_cols: list[str]) -> dict[str, float]:
    """Compute exact feature-row overlap across temporal splits."""
    train_df = df[df['split'] == 'train'][feature_cols].copy()
    val_df = df[df['split'] == 'val'][feature_cols].copy()
    test_df = df[df['split'] == 'test'][feature_cols].copy()

    train_hash = set(pd.util.hash_pandas_object(train_df, index=False).astype(str).tolist())
    val_hash = set(pd.util.hash_pandas_object(val_df, index=False).astype(str).tolist())
    test_hash = set(pd.util.hash_pandas_object(test_df, index=False).astype(str).tolist())

    tv = len(train_hash & val_hash)
    tt = len(train_hash & test_hash)
    vt = len(val_hash & test_hash)

    return {
        'train_val_overlap': tv,
        'train_test_overlap': tt,
        'val_test_overlap': vt,
        'train_test_overlap_ratio': (tt / max(1, len(test_hash))),
    }


def run_leakage_audit(df: pd.DataFrame) -> dict[str, Any]:
    """Run quick leakage/sanity diagnostics requested by checklist A/B/C/D.

    Uses _ALL_FEATURE_COLUMNS (including shortcuts) so the audit evaluates
    the full feature space regardless of what's used for training.
    """
    train_df = df[df['split'] == 'train'].copy()
    test_df = df[df['split'] == 'test'].copy()

    # For audit, use ALL features (including shortcuts)
    available_features = [f for f in _ALL_FEATURE_COLUMNS if f in df.columns]
    X_train_all = train_df[available_features]
    y_train = train_df[TARGET_COLUMN].values
    X_test_all = test_df[available_features]
    y_test = test_df[TARGET_COLUMN].values

    # A) Single-feature baseline (on ALL features, not just training set).
    single_feature_scores: list[dict[str, Any]] = []
    for f in EASY_FEATURES:
        if f not in df.columns:
            continue
        xtr = X_train_all[f].to_numpy()
        xte = X_test_all[f].to_numpy()
        prefer_low = (f == 'success_ratio')
        thr, low_attack, f1_train = _best_single_feature_threshold(xtr, y_train, prefer_low)
        y_pred = (xte <= thr).astype(int) if low_attack else (xte >= thr).astype(int)
        f1_test = f1_score(y_test, y_pred, zero_division=0)
        acc_test = accuracy_score(y_test, y_pred)
        single_feature_scores.append({
            'feature': f,
            'threshold': thr,
            'rule': '<=' if low_attack else '>=',
            'train_f1': float(f1_train),
            'test_f1': float(f1_test),
            'test_acc': float(acc_test),
        })

    # C) Hash overlap between splits (on all features).
    overlap = _split_overlap_ratio(df, available_features)

    # D) Stress test: train ONLY on hard features (time-based + some additional).
    hard_features = [c for c in ML_FEATURE_COLUMNS if c not in EASY_FEATURES]
    rf_hard = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        min_samples_split=5,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )
    rf_hard.fit(train_df[hard_features].values, y_train)
    y_pred_hard = rf_hard.predict(test_df[hard_features].values)
    y_proba_hard = rf_hard.predict_proba(test_df[hard_features].values)[:, 1]
    hard_metrics = {
        'accuracy': float(accuracy_score(y_test, y_pred_hard)),
        'f1': float(f1_score(y_test, y_pred_hard, zero_division=0)),
        'auc': float(roc_auc_score(y_test, y_proba_hard)) if len(set(y_test)) > 1 else 0.0,
    }

    # Risk scoring heuristic.
    best_single = max(single_feature_scores, key=lambda x: x['test_f1'])
    leakage_risk = 'LOW'
    reasons: list[str] = []
    if best_single['test_f1'] >= 0.98:
        leakage_risk = 'HIGH'
        reasons.append('Baseline 1-feature dat F1 rat cao, du lieu co the qua de hoac label leak.')
    if overlap['train_test_overlap'] > 0:
        leakage_risk = 'HIGH'
        reasons.append('Co trung lap feature row giua train/test.')
    if hard_metrics['f1'] >= 0.97:
        reasons.append('Bo feature de van rat cao, can kiem tra them duplicate/labeling.')

    return {
        'single_feature_scores': single_feature_scores,
        'best_single_feature': best_single,
        'overlap': overlap,
        'hard_feature_metrics': hard_metrics,
        'leakage_risk': leakage_risk,
        'reasons': reasons,
    }


# ---------------------------------------------------------------------------
# Univariate AUC / F1 scan for all active ML features
# ---------------------------------------------------------------------------
def run_univariate_scan(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Compute univariate ROC-AUC and best-threshold F1 for each ML feature."""
    train_df = df[df['split'] == 'train']
    test_df = df[df['split'] == 'test']
    y_train = train_df[TARGET_COLUMN].values
    y_test = test_df[TARGET_COLUMN].values

    results: list[dict[str, Any]] = []
    for feat in ML_FEATURE_COLUMNS:
        xtr = train_df[feat].to_numpy().astype(float)
        xte = test_df[feat].to_numpy().astype(float)

        # Univariate AUC
        auc_val = roc_auc_score(y_test, xte) if len(set(y_test)) > 1 else 0.0
        # If AUC < 0.5, flip direction
        if auc_val < 0.5:
            auc_val = 1.0 - auc_val

        # Best single-threshold F1
        prefer_low = (feat in ('success_ratio', 'avg_time_between_attempts'))
        thr, low_atk, _ = _best_single_feature_threshold(xtr, y_train, prefer_low)
        y_pred = (xte <= thr).astype(int) if low_atk else (xte >= thr).astype(int)
        f1_val = f1_score(y_test, y_pred, zero_division=0)

        results.append({
            'feature': feat,
            'univariate_auc': round(float(auc_val), 4),
            'best_threshold_f1': round(float(f1_val), 4),
            'threshold': round(float(thr), 4),
            'rule': '<=' if low_atk else '>=',
        })

    results.sort(key=lambda x: x['univariate_auc'], reverse=True)
    return results


# ---------------------------------------------------------------------------
# SHAP explanation
# ---------------------------------------------------------------------------
def run_shap_analysis(
    model: RandomForestClassifier,
    X_train: np.ndarray,
    report_dir: Path,
) -> dict[str, Any] | None:
    """Run SHAP TreeExplainer on the training set and save summary plot."""
    try:
        import shap
    except ImportError:
        print('  [WARN] shap not installed — skipping SHAP analysis.')
        return None

    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    report_dir.mkdir(parents=True, exist_ok=True)

    explainer = shap.TreeExplainer(model)
    # Use a subsample for speed if training set is large
    n_sample = min(500, len(X_train))
    rng = np.random.RandomState(42)
    idx = rng.choice(len(X_train), n_sample, replace=False)
    X_sample = X_train[idx]
    shap_values = explainer.shap_values(X_sample)

    # For binary classification, shap_values can be:
    #   - list of [class0_2d, class1_2d]  (older shap)
    #   - 3D array (n_samples, n_features, n_classes)  (newer shap)
    #   - 2D array (n_samples, n_features) for single-output
    if isinstance(shap_values, list):
        sv = shap_values[1]  # class=Attack
    elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
        sv = shap_values[:, :, 1]  # class=Attack
    else:
        sv = shap_values

    mean_abs = np.mean(np.abs(sv), axis=0).ravel()
    feature_shap = sorted(
        zip(ML_FEATURE_COLUMNS, mean_abs.tolist()),
        key=lambda x: x[1],
        reverse=True,
    )

    # Save beeswarm plot
    fig, ax = plt.subplots(figsize=(9, 5))
    shap.summary_plot(
        sv,
        X_sample,
        feature_names=ML_FEATURE_COLUMNS,
        show=False,
    )
    fname = 'shap_summary.png'
    plt.tight_layout()
    plt.savefig(report_dir / fname, dpi=150, bbox_inches='tight')
    plt.close('all')

    # Save bar plot
    fig, ax = plt.subplots(figsize=(8, 5))
    names = [f[0] for f in feature_shap]
    vals = [f[1] for f in feature_shap]
    ax.barh(names[::-1], vals[::-1], color='#6366f1')
    ax.set_xlabel('Mean |SHAP value|')
    ax.set_title('SHAP Feature Importance (Attack class)')
    fig.tight_layout()
    fname_bar = 'shap_bar.png'
    fig.savefig(report_dir / fname_bar, dpi=150)
    plt.close(fig)

    return {
        'feature_shap': feature_shap,
        'summary_plot': fname,
        'bar_plot': fname_bar,
    }


# ---------------------------------------------------------------------------
# Rolling (expanding-window) time-series cross-validation
# ---------------------------------------------------------------------------
def run_rolling_cv(df: pd.DataFrame, n_folds: int = 5) -> dict[str, Any]:
    """Time-series expanding-window CV with n_folds.

    Returns per-fold metrics and summary statistics.
    """
    unique_windows = sorted(df['window_start'].unique())
    n_windows = len(unique_windows)

    if n_windows < n_folds + 1:
        print(f'  [WARN] Only {n_windows} windows, need {n_folds + 1} for rolling CV. Reducing folds.')
        n_folds = max(1, n_windows - 1)

    # Each fold: train on windows[:split_idx], test on windows[split_idx:split_idx+test_size]
    # Expanding window: first fold uses minimal train, last fold uses most
    fold_size = max(1, n_windows // (n_folds + 1))
    min_train = max(2, fold_size)  # at least 2 windows for training

    fold_results: list[dict[str, Any]] = []

    for fold in range(n_folds):
        train_end = min_train + fold * fold_size
        test_end = min(train_end + fold_size, n_windows)
        if train_end >= n_windows or test_end <= train_end:
            break

        train_wins = set(unique_windows[:train_end])
        test_wins = set(unique_windows[train_end:test_end])

        train_mask = df['window_start'].isin(train_wins)
        test_mask = df['window_start'].isin(test_wins)

        X_tr = df.loc[train_mask, ML_FEATURE_COLUMNS].values
        y_tr = df.loc[train_mask, TARGET_COLUMN].values
        X_te = df.loc[test_mask, ML_FEATURE_COLUMNS].values
        y_te = df.loc[test_mask, TARGET_COLUMN].values

        if len(set(y_tr)) < 2 or len(set(y_te)) < 2:
            continue

        rf = RandomForestClassifier(
            n_estimators=100, max_depth=None, min_samples_split=5,
            class_weight='balanced', random_state=42, n_jobs=-1,
        )
        rf.fit(X_tr, y_tr)
        y_pred = rf.predict(X_te)
        y_proba = rf.predict_proba(X_te)[:, 1]

        fold_results.append({
            'fold': fold + 1,
            'train_windows': len(train_wins),
            'test_windows': len(test_wins),
            'train_rows': len(X_tr),
            'test_rows': len(X_te),
            'f1': float(f1_score(y_te, y_pred, zero_division=0)),
            'precision': float(precision_score(y_te, y_pred, zero_division=0)),
            'recall': float(recall_score(y_te, y_pred, zero_division=0)),
            'auc': float(roc_auc_score(y_te, y_proba)),
            'pr_auc': float(average_precision_score(y_te, y_proba)),
        })

    if not fold_results:
        return {'folds': [], 'summary': {}}

    # Summary statistics
    metrics = ['f1', 'precision', 'recall', 'auc', 'pr_auc']
    summary: dict[str, dict[str, float]] = {}
    for m in metrics:
        vals = [fr[m] for fr in fold_results]
        summary[m] = {
            'mean': round(float(np.mean(vals)), 4),
            'std': round(float(np.std(vals)), 4),
            'min': round(float(np.min(vals)), 4),
            'max': round(float(np.max(vals)), 4),
        }

    return {'folds': fold_results, 'summary': summary}


def save_model(model: RandomForestClassifier, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('wb') as f:
        pickle.dump(model, f)
    print(f'  Model saved → {path}')


def load_model(path: Path) -> RandomForestClassifier:
    with path.open('rb') as f:
        return pickle.load(f)


# ═══════════════════════════════════════════════════════════════════════════
# EVALUATION — Plots & HTML Report
# ═══════════════════════════════════════════════════════════════════════════

def generate_plots(results: dict[str, Any], report_dir: Path) -> dict[str, str]:
    """Generate matplotlib charts. Returns dict of {name: filename}."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import seaborn as sns

    report_dir.mkdir(parents=True, exist_ok=True)
    plots: dict[str, str] = {}

    # 1. Confusion Matrix
    fig, ax = plt.subplots(figsize=(6, 5))
    cm = results['confusion_matrix']
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Benign', 'Attack'],
                yticklabels=['Benign', 'Attack'], ax=ax)
    ax.set_xlabel('Predicted')
    ax.set_ylabel('Actual')
    ax.set_title('Confusion Matrix (Test Set)')
    fig.tight_layout()
    fname = 'confusion_matrix.png'
    fig.savefig(report_dir / fname, dpi=150)
    plt.close(fig)
    plots['Confusion Matrix'] = fname

    # 2. ROC Curve
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(results['roc_fpr'], results['roc_tpr'],
            color='#2563eb', lw=2,
            label=f'AUC = {results["auc"]:.4f}')
    ax.plot([0, 1], [0, 1], 'k--', lw=1, alpha=0.4)
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    ax.set_title('ROC Curve (Test Set)')
    ax.legend(loc='lower right')
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.02])
    fig.tight_layout()
    fname = 'roc_curve.png'
    fig.savefig(report_dir / fname, dpi=150)
    plt.close(fig)
    plots['ROC Curve'] = fname

    # 2b. Precision-Recall Curve
    if 'pr_precision' in results and 'pr_recall' in results:
        fig, ax = plt.subplots(figsize=(6, 5))
        ax.plot(results['pr_recall'], results['pr_precision'],
                color='#059669', lw=2,
                label=f'PR-AUC = {results.get("pr_auc", 0):.4f}')
        ax.set_xlabel('Recall')
        ax.set_ylabel('Precision')
        ax.set_title('Precision-Recall Curve (Test Set)')
        ax.legend(loc='lower left')
        ax.set_xlim([0, 1])
        ax.set_ylim([0, 1.02])
        fig.tight_layout()
        fname = 'pr_curve.png'
        fig.savefig(report_dir / fname, dpi=150)
        plt.close(fig)
        plots['PR Curve'] = fname

    # 3. Feature Importance
    fig, ax = plt.subplots(figsize=(8, 5))
    feat_names = [f[0] for f in results['feature_importance']]
    feat_vals = [f[1] for f in results['feature_importance']]
    colors = ['#ef4444' if v == max(feat_vals) else '#3b82f6' for v in feat_vals]
    ax.barh(feat_names[::-1], feat_vals[::-1], color=colors[::-1])
    ax.set_xlabel('Importance (Gini)')
    ax.set_title('Feature Importance — Random Forest')
    fig.tight_layout()
    fname = 'feature_importance.png'
    fig.savefig(report_dir / fname, dpi=150)
    plt.close(fig)
    plots['Feature Importance'] = fname

    # 4. Prediction probability distribution
    fig, ax = plt.subplots(figsize=(7, 4))
    y_test = results['y_test']
    y_proba = results['y_test_proba']
    ax.hist(y_proba[y_test == 0], bins=40, alpha=0.6, label='Benign', color='#22c55e')
    ax.hist(y_proba[y_test == 1], bins=40, alpha=0.6, label='Attack', color='#ef4444')
    ax.axvline(x=ALERT_THRESHOLD, color='black', linestyle='--', lw=1.5, label=f'Alert threshold={ALERT_THRESHOLD}')
    ax.set_xlabel('P(Attack)')
    ax.set_ylabel('Count')
    ax.set_title('Prediction Probability Distribution (Test Set)')
    ax.legend()
    fig.tight_layout()
    fname = 'probability_distribution.png'
    fig.savefig(report_dir / fname, dpi=150)
    plt.close(fig)
    plots['Probability Distribution'] = fname

    return plots


def _embed_saved_png(report_dir: Path, fname: str | None) -> str:
    """Read a saved PNG from report_dir and return an embedded img tag."""
    if not fname:
        return ''
    fpath = report_dir / fname
    if not fpath.exists():
        return '<p class="small">Biểu đồ không khả dụng.</p>'
    b64 = base64.b64encode(fpath.read_bytes()).decode()
    return img_tag(b64, fname)


def _safe_metric(v: float, fmt: str = '.4f') -> str:
    """Format a metric value, returning 'N/A' for NaN."""
    if isinstance(v, float) and math.isnan(v):
        return 'N/A'
    return f'{v:{fmt}}'


def _evaluate_dataset_quality(
    df: pd.DataFrame,
    feature_cols: list[str],
    target_col: str = 'final_label',
) -> dict[str, Any]:
    """Compute 6 dataset-quality aspects (Tukey 1977; He & Garcia 2009; etc.).

    Returns a dict with keys for each aspect, containing sub-metrics
    and lists of findings suitable for embedding in an HTML report.
    """
    report: dict[str, Any] = {}

    # ----- Aspect 1: Statistical Validity -----
    stat: dict[str, Any] = {}
    desc = df[feature_cols].describe().to_dict()
    stat['descriptive'] = desc

    impossible: list[str] = []
    for col in feature_cols:
        series = df[col].dropna()
        if col == 'success_ratio' and ((series < -0.001).any() or (series > 1.001).any()):
            impossible.append(f'{col}: giá trị ngoài [0,1] phát hiện')
        if col == 'failed_attempts' and (series < -0.5).any():
            impossible.append(f'{col}: giá trị âm phát hiện')
        if col in ('hour_sin', 'hour_cos') and ((series < -1.1).any() or (series > 1.1).any()):
            impossible.append(f'{col}: giá trị ngoài [-1,1]')
    stat['impossible_values'] = impossible

    missing_counts = df[feature_cols].isnull().sum().to_dict()
    stat['missing'] = {k: int(v) for k, v in missing_counts.items() if v > 0}

    outlier_info: dict[str, dict] = {}
    for col in feature_cols:
        s = df[col].dropna()
        if len(s) < 10:
            continue
        q1, q3 = s.quantile(0.25), s.quantile(0.75)
        iqr = q3 - q1
        n_low = int((s < q1 - 3 * iqr).sum())
        n_high = int((s > q3 + 3 * iqr).sum())
        if n_low + n_high > 0:
            outlier_info[col] = {'low': n_low, 'high': n_high, 'total': n_low + n_high}
    stat['outliers_3iqr'] = outlier_info
    report['statistical_validity'] = stat

    # ----- Aspect 2: Class Balance & Representativeness -----
    balance: dict[str, Any] = {}
    vc = df[target_col].value_counts().to_dict()
    total = len(df)
    attack_n = int(vc.get(1, 0))
    benign_n = int(vc.get(0, 0))
    balance['attack'] = attack_n
    balance['benign'] = benign_n
    balance['ratio'] = f'{benign_n}:{attack_n}' if attack_n else 'N/A'
    balance['imbalance_ratio'] = round(attack_n / max(benign_n, 1), 2)

    diversity: dict[str, dict] = {}
    for label_name, label_val in [('attack', 1), ('benign', 0)]:
        sub = df[df[target_col] == label_val][feature_cols]
        nuniq = sub.nunique().to_dict()
        diversity[label_name] = {k: int(v) for k, v in nuniq.items()}
    balance['intra_class_diversity'] = diversity

    overlap_feats: dict[str, float] = {}
    for col in feature_cols:
        a = df[df[target_col] == 1][col].dropna()
        b = df[df[target_col] == 0][col].dropna()
        if len(a) < 2 or len(b) < 2:
            continue
        lo = max(a.min(), b.min())
        hi = min(a.max(), b.max())
        if hi <= lo:
            overlap_feats[col] = 0.0
        else:
            full = max(a.max(), b.max()) - min(a.min(), b.min())
            overlap_feats[col] = round((hi - lo) / max(full, 1e-12), 4)
    balance['feature_overlap'] = overlap_feats

    if 'split' in df.columns:
        split_dist: dict[str, dict] = {}
        for sp in ('train', 'val', 'test'):
            sub = df[df['split'] == sp]
            split_dist[sp] = {
                'total': int(len(sub)),
                'attack': int((sub[target_col] == 1).sum()),
                'benign': int((sub[target_col] == 0).sum()),
            }
        balance['split_distribution'] = split_dist
    report['class_balance'] = balance

    # ----- Aspect 3: Fisher's Discriminant Ratio (Leakage proxy) -----
    fisher: dict[str, float] = {}
    for col in feature_cols:
        a = df[df[target_col] == 1][col].dropna()
        b = df[df[target_col] == 0][col].dropna()
        if len(a) < 2 or len(b) < 2:
            continue
        mu_a, mu_b = a.mean(), b.mean()
        var_a, var_b = a.var(), b.var()
        denom = var_a + var_b
        if denom < 1e-12:
            fisher[col] = float('inf') if abs(mu_a - mu_b) > 1e-12 else 0.0
        else:
            fisher[col] = round(float((mu_a - mu_b) ** 2 / denom), 4)
    fisher_sorted = dict(sorted(fisher.items(), key=lambda x: x[1], reverse=True))
    report['fisher_ratio'] = fisher_sorted

    # ----- Aspect 4: Label-Feature Consistency -----
    label_consistency: dict[str, Any] = {}
    if 'weak_label' in df.columns:
        agree = (df[target_col] == df['weak_label']).sum()
        label_consistency['agreement_rate'] = round(agree / max(total, 1), 4)
        label_consistency['disagreement_count'] = int(total - agree)
        disagree = df[df[target_col] != df['weak_label']]
        if len(disagree) > 0:
            label_consistency['disagreement_origin'] = (
                disagree['data_origin'].value_counts().to_dict()
                if 'data_origin' in disagree.columns else {}
            )
    report['label_consistency'] = label_consistency

    # ----- Aspect 5: Separability & Difficulty -----
    sep: dict[str, Any] = {}
    corr = df[feature_cols].corr()
    high_corr_pairs: list[tuple[str, str, float]] = []
    for i, c1 in enumerate(feature_cols):
        for c2 in feature_cols[i + 1:]:
            val = abs(corr.loc[c1, c2])
            if val > 0.90:
                high_corr_pairs.append((c1, c2, round(float(val), 4)))
    sep['high_correlation_pairs'] = high_corr_pairs
    sep['n_high_corr'] = len(high_corr_pairs)

    trivial_features = [f for f, r in fisher_sorted.items() if r > 10.0]
    sep['trivially_separable_features'] = trivial_features
    sep['n_trivial'] = len(trivial_features)
    report['separability'] = sep

    # ----- Aspect 6: Temporal Stability -----
    temporal: dict[str, Any] = {}
    if 'window_start' in df.columns:
        try:
            ws = pd.to_datetime(df['window_start'])
            df_tmp = df.copy()
            df_tmp['_day'] = ws.dt.date
            per_day = df_tmp.groupby('_day')[target_col].agg(['count', 'sum'])
            per_day.columns = ['total', 'attack']
            per_day['benign'] = per_day['total'] - per_day['attack']
            per_day['attack_ratio'] = (per_day['attack'] / per_day['total']).round(4)
            temporal['per_day'] = per_day.reset_index().to_dict('records')
            temporal['n_days'] = int(len(per_day))

            all_attack_days = int((per_day['attack_ratio'] >= 0.999).sum())
            all_benign_days = int((per_day['attack_ratio'] <= 0.001).sum())
            temporal['all_attack_days'] = all_attack_days
            temporal['all_benign_days'] = all_benign_days
        except Exception:
            pass

    if 'split' in df.columns:
        drift: dict[str, dict] = {}
        train_sub = df[df['split'] == 'train']
        test_sub = df[df['split'] == 'test']
        for col in feature_cols:
            tr_s = train_sub[col].dropna()
            te_s = test_sub[col].dropna()
            if len(tr_s) < 5 or len(te_s) < 5:
                continue
            tr_mean, te_mean = tr_s.mean(), te_s.mean()
            tr_std, te_std = tr_s.std(), te_s.std()
            pooled = np.sqrt((tr_std ** 2 + te_std ** 2) / 2)
            if pooled > 1e-12:
                drift[col] = {
                    'train_mean': round(float(tr_mean), 4),
                    'test_mean': round(float(te_mean), 4),
                    'shift_score': round(float(abs(tr_mean - te_mean) / pooled), 4),
                }
        large_drift = {k: v for k, v in drift.items() if v['shift_score'] > 1.0}
        temporal['feature_drift'] = large_drift
        temporal['n_large_drift'] = len(large_drift)
    report['temporal_stability'] = temporal

    return report


def _build_dataset_quality_html(
    parts: list[str],
    quality: dict[str, Any],
    feature_cols: list[str],
) -> None:
    """Render dataset quality evaluation into HTML parts."""

    # --- Aspect 1: Statistical Validity ---
    parts.append('<h3>1. Tính hợp lệ thống kê (Statistical Validity)</h3>')
    parts.append(
        '<p><b>Cơ sở:</b> Tukey (1977) — EDA chuẩn; '
        'Sommer & Paxson (2010) — kiểm tra domain constraints cho IDS dataset.</p>')

    sv = quality.get('statistical_validity', {})
    imp_vals = sv.get('impossible_values', [])
    if imp_vals:
        parts.append('<div class="warn-box"><b>Giá trị bất thường:</b><ul>')
        for iv in imp_vals:
            parts.append(f'<li>{iv}</li>')
        parts.append('</ul></div>')
    else:
        parts.append('<p class="good">Không phát hiện giá trị vi phạm domain (success_ratio∈[0,1], '
                      'failed_attempts≥0, sin/cos∈[-1,1]).</p>')

    missing = sv.get('missing', {})
    if missing:
        rows = [[k, v] for k, v in missing.items()]
        parts.append(html_table(['Feature', 'Giá trị thiếu'], rows))
    else:
        parts.append('<p class="good">Không có giá trị thiếu (missing) trong dataset.</p>')

    outliers = sv.get('outliers_3iqr', {})
    if outliers:
        rows = [[k, v['low'], v['high'], v['total']] for k, v in outliers.items()]
        parts.append('<p><b>Outlier (3×IQR):</b> Các feature có giá trị cách xa hơn 3 lần '
                      'khoảng tứ phân vị — có thể do attack bùng nổ hoặc bug pipeline.</p>')
        parts.append(html_table(['Feature', 'Outlier thấp', 'Outlier cao', 'Tổng'], rows))
    else:
        parts.append('<p class="good">Không phát hiện outlier cực đoan (3×IQR).</p>')

    # --- Aspect 2: Class Balance ---
    parts.append('<h3>2. Tính cân bằng & đại diện (Class Balance & Representativeness)</h3>')
    parts.append(
        '<p><b>Cơ sở:</b> He & Garcia (2009) — phân tích tác động class imbalance; '
        'Japkowicz & Stephen (2002) — diversity trong minority class quan trọng hơn số lượng.</p>')

    cb = quality.get('class_balance', {})
    att = cb.get('attack', 0)
    ben = cb.get('benign', 0)
    parts.append(html_cards([
        ('Attack samples', att),
        ('Benign samples', ben),
        ('Tỉ lệ Benign:Attack', cb.get('ratio', 'N/A')),
        ('Imbalance ratio (att/ben)', cb.get('imbalance_ratio', 'N/A')),
    ]))

    if 'split_distribution' in cb:
        sd = cb['split_distribution']
        rows = []
        for sp in ('train', 'val', 'test'):
            d = sd.get(sp, {})
            rows.append([sp.capitalize(), d.get('total', 0), d.get('attack', 0),
                         d.get('benign', 0)])
        parts.append(html_table(['Split', 'Tổng', 'Attack', 'Benign'], rows))

    # Overlap chart
    overlap = cb.get('feature_overlap', {})
    if overlap:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(10, max(4, len(overlap) * 0.35)))
        feats_sorted = sorted(overlap.items(), key=lambda x: x[1])
        names = [f[0] for f in feats_sorted]
        vals = [f[1] for f in feats_sorted]
        colors = ['#e53e3e' if v < 0.05 else '#f6ad55' if v < 0.2 else '#38a169' for v in vals]
        ax.barh(names, vals, color=colors)
        ax.set_xlabel('Overlap ratio (0 = hoàn toàn tách biệt, 1 = chồng chéo hoàn toàn)')
        ax.set_title('Feature Overlap giữa Attack vs Benign')
        ax.axvline(x=0.05, color='red', linestyle='--', linewidth=0.8, label='Ngưỡng trivial (0.05)')
        ax.legend(fontsize=8)
        plt.tight_layout()
        parts.append(html_chart(img_tag(fig_to_base64(fig), 'Feature Overlap'),
                                 'Feature Overlap: đỏ = tách biệt quá dễ (nghi shortcut)'))
        plt.close(fig)

    # --- Aspect 3: Fisher's Discriminant Ratio ---
    parts.append('<h3>3. Tỉ số Fisher & Phát hiện Shortcut (Leakage Proxy)</h3>')
    parts.append(
        '<p><b>Cơ sở:</b> Ho & Basu (2002) — Fisher Discriminant Ratio là complexity measure '
        'chuẩn cho dataset; Kaufman et al. (2012) — framework phát hiện leakage.</p>'
        '<p>Fisher Ratio = (μ₁ − μ₂)² / (σ₁² + σ₂²). Ratio càng cao → feature đó '
        'tách 2 class càng dễ. Ratio > 10 → nghi shortcut feature.</p>')

    fisher = quality.get('fisher_ratio', {})
    if fisher:
        rows = []
        for f, r in list(fisher.items())[:20]:
            risk = '🔴 Shortcut' if r > 10.0 else '🟡 Cao' if r > 2.0 else '🟢 OK'
            rows.append([f, f'{r:.4f}' if r != float('inf') else '∞', risk])
        parts.append(html_table(['Feature', 'Fisher Ratio', 'Đánh giá'], rows))

    # --- Aspect 4: Label Consistency ---
    parts.append('<h3>4. Tính nhất quán nhãn (Label-Feature Consistency)</h3>')
    parts.append(
        '<p><b>Cơ sở:</b> Northcutt et al. (2021) Confident Learning — framework phát hiện label errors; '
        'Frénay & Verleysen (2014) — phân loại label noise.</p>')

    lc = quality.get('label_consistency', {})
    if 'agreement_rate' in lc:
        agree_pct = lc['agreement_rate'] * 100
        parts.append(html_cards([
            ('Final ↔ Weak label agreement', f'{agree_pct:.2f}%'),
            ('Số mẫu bất đồng', lc.get('disagreement_count', 0)),
        ]))
        if agree_pct >= 99.0:
            parts.append('<p class="good">Tỉ lệ đồng thuận rất cao — nhãn nhất quán.</p>')
        elif agree_pct >= 95.0:
            parts.append('<p>Tỉ lệ đồng thuận chấp nhận được. Kiểm tra các mẫu bất đồng.</p>')
        else:
            parts.append('<p class="warn">Tỉ lệ đồng thuận thấp — cần kiểm tra lại pipeline gán nhãn.</p>')
        if lc.get('disagreement_origin'):
            rows = [[k, v] for k, v in lc['disagreement_origin'].items()]
            parts.append('<p><b>Nguồn gốc mẫu bất đồng:</b></p>')
            parts.append(html_table(['Data origin', 'Số mẫu'], rows))
    else:
        parts.append('<p><i>Không có cột weak_label — bỏ qua kiểm tra này.</i></p>')

    # --- Aspect 5: Separability ---
    parts.append('<h3>5. Tính phân tách & Độ khó (Separability & Appropriate Difficulty)</h3>')
    parts.append(
        '<p><b>Cơ sở:</b> Ho & Basu (2002) — 12 complexity measures; '
        'Lorena et al. (2019) — meta-features cho dataset characterization.</p>')

    sep = quality.get('separability', {})
    trivial = sep.get('trivially_separable_features', [])
    if trivial:
        parts.append(
            f'<p class="warn"><b>{len(trivial)} feature có Fisher Ratio > 10</b> '
            f'(trivially separable): {", ".join(trivial)}. '
            f'Model có thể dựa hoàn toàn vào {trivial[0]} mà không cần học hành vi phức tạp.</p>')
    else:
        parts.append('<p class="good">Không có feature nào tách 2 class quá dễ (Fisher < 10). '
                      'Dataset yêu cầu model học pattern phức tạp.</p>')

    hc = sep.get('high_correlation_pairs', [])
    if hc:
        rows = [[c1, c2, f'{v:.4f}'] for c1, c2, v in hc]
        parts.append(f'<p><b>{len(hc)} cặp feature có correlation > 0.90</b> — '
                      'feature redundancy, có thể gây multicollinearity.</p>')
        parts.append(html_table(['Feature 1', 'Feature 2', '|Correlation|'], rows))
    else:
        parts.append('<p class="good">Không có cặp feature nào có correlation > 0.90.</p>')

    # --- Aspect 6: Temporal Stability ---
    parts.append('<h3>6. Tính ổn định qua thời gian (Temporal Stability)</h3>')
    parts.append(
        '<p><b>Cơ sở:</b> Tashman (2000) — out-of-sample tests; '
        'Žliobaitė (2010) — concept drift monitoring.</p>')

    ts = quality.get('temporal_stability', {})
    if 'n_days' in ts:
        parts.append(html_cards([
            ('Số ngày dữ liệu', ts['n_days']),
            ('Ngày 100% attack', ts.get('all_attack_days', 0)),
            ('Ngày 100% benign', ts.get('all_benign_days', 0)),
        ]))
        if ts.get('all_attack_days', 0) > 0 or ts.get('all_benign_days', 0) > 0:
            parts.append(
                '<p class="warn">Có ngày chỉ chứa 1 class — temporal split có thể '
                'tạo ra split chỉ attack hoặc chỉ benign. Đây là hạn chế vốn có của '
                'dataset honeypot + synthetic benign (Arp et al., 2022).</p>')

    drift = ts.get('feature_drift', {})
    if drift:
        parts.append(f'<p><b>{len(drift)} feature có distribution shift lớn giữa Train → Test</b> '
                      '(Cohen\'s d > 1.0):</p>')
        rows = [[f, v['train_mean'], v['test_mean'], v['shift_score']]
                for f, v in sorted(drift.items(), key=lambda x: x[1]['shift_score'], reverse=True)]
        parts.append(html_table(['Feature', 'Train mean', 'Test mean', 'Shift score (Cohen d)'], rows))
    else:
        parts.append('<p class="good">Không phát hiện distribution shift đáng kể giữa train và test.</p>')

    # --- Expert Summary ---
    parts.append('<h3>Tổng kết đánh giá Dataset (ML Expert)</h3>')

    findings: list[str] = []

    n_impossible = len(sv.get('impossible_values', []))
    n_missing = len(sv.get('missing', {}))
    n_outlier_feats = len(sv.get('outliers_3iqr', {}))
    n_trivial = sep.get('n_trivial', 0)
    n_hcorr = sep.get('n_high_corr', 0)
    n_drift = ts.get('n_large_drift', 0)

    if n_impossible == 0 and n_missing == 0:
        findings.append(
            '<li><span class="good"><b>Statistical Validity: ĐẠT</b></span> — '
            'Không vi phạm domain, không missing values.</li>')
    else:
        findings.append(
            f'<li><span class="warn"><b>Statistical Validity: CẦN XEM LẠI</b></span> — '
            f'{n_impossible} vi phạm domain, {n_missing} feature có missing values.</li>')

    ir = cb.get('imbalance_ratio', 1.0)
    if 0.3 <= ir <= 3.0:
        findings.append(
            f'<li><span class="good"><b>Class Balance: ĐẠT</b></span> — '
            f'Tỉ lệ attack/benign = {ir} (trong vùng chấp nhận 0.3–3.0).</li>')
    else:
        findings.append(
            f'<li><span class="warn"><b>Class Balance: MẤT CÂN BẰNG</b></span> — '
            f'Tỉ lệ attack/benign = {ir}.</li>')

    if n_trivial > 0:
        findings.append(
            f'<li><span class="warn"><b>Separability: {n_trivial} shortcut features</b></span> — '
            f'Fisher Ratio > 10 → dataset có thể quá dễ cho model.</li>')
    else:
        findings.append(
            '<li><span class="good"><b>Separability: ĐẠT</b></span> — '
            'Không có shortcut feature rõ ràng.</li>')

    agree = lc.get('agreement_rate', None)
    if agree is not None:
        if agree >= 0.99:
            findings.append(
                f'<li><span class="good"><b>Label Consistency: ĐẠT</b></span> — '
                f'{agree*100:.1f}% agreement.</li>')
        else:
            findings.append(
                f'<li><span class="warn"><b>Label Consistency: {agree*100:.1f}%</b></span></li>')

    if n_drift > 0:
        findings.append(
            f'<li><span class="warn"><b>Temporal Stability: {n_drift} feature bị drift</b></span></li>')
    else:
        findings.append(
            '<li><span class="good"><b>Temporal Stability: ĐẠT</b></span> — '
            'Không có feature drift đáng kể.</li>')

    parts.append('<ul>' + '\n'.join(findings) + '</ul>')

    overall_issues = n_impossible + n_missing + (1 if n_trivial > 0 else 0) + (1 if n_drift > 0 else 0)
    if overall_issues == 0:
        parts.append(
            '<div class="good-box"><b>KẾT LUẬN:</b> Dataset đạt tất cả 6 khía cạnh đánh giá. '
            'Phù hợp để huấn luyện ML model.</div>')
    else:
        parts.append(
            f'<div class="warn-box"><b>KẾT LUẬN:</b> Phát hiện {overall_issues} vấn đề cần lưu ý. '
            'Xem chi tiết từng khía cạnh phía trên.</div>')


def _build_scenario_expert_evaluation(
    parts: list[str],
    rows: list[dict[str, Any]],
    sfmt,
) -> None:
    """Generate dynamic ML expert evaluation based on actual scenario metrics."""
    from utils.report_utils import html_decision

    n = len(rows)
    # Gather key metrics per scenario
    entries = []
    for r in rows:
        sid = r.get('scenario_id', '')
        ratio = r.get('ratio', '')
        tmf = r.get('train_macro_f1')
        vmf = r.get('val_macro_f1')
        tf1 = r.get('test_f1')
        trc = r.get('test_recall')
        tpr = r.get('test_precision')
        ta = r.get('test_auc')
        entries.append({
            'sid': sid, 'ratio': ratio,
            'tmf': float(tmf) if tmf is not None else None,
            'vmf': float(vmf) if vmf is not None else None,
            'tf1': float(tf1) if tf1 is not None else None,
            'trc': float(trc) if trc is not None else None,
            'tpr': float(tpr) if tpr is not None else None,
            'ta': float(ta) if ta is not None else None,
        })

    # Find best/worst on key metrics
    best_vmf = max((e for e in entries if e['vmf'] is not None), key=lambda e: e['vmf'], default=None)
    best_tf1 = max((e for e in entries if e['tf1'] is not None), key=lambda e: e['tf1'], default=None)
    worst_trc = min((e for e in entries if e['trc'] is not None), key=lambda e: e['trc'], default=None)

    # Overfitting detection
    overfit_warnings = []
    for e in entries:
        if e['tmf'] is not None and e['vmf'] is not None:
            gap = e['tmf'] - e['vmf']
            if gap > 0.05:
                overfit_warnings.append(
                    f'<b>{e["sid"]}</b> ({e["ratio"]}): Train−Val gap = {gap:.4f} → '
                    f'dấu hiệu overfitting')

    # Perfect score detection
    perfect_scenarios = [e for e in entries
                         if e['tmf'] is not None and e['tmf'] >= 0.9999
                         and e['vmf'] is not None and e['vmf'] >= 0.9999]

    # Build analysis
    analysis_items = []

    if perfect_scenarios:
        sids = ', '.join(e['sid'] for e in perfect_scenarios)
        analysis_items.append(
            f'<li><span class="warn"><b>Cảnh báo metric hoàn hảo:</b></span> '
            f'Các scenario {sids} đạt Train & Val Macro-F1 ≈ 1.0. '
            f'Điều này thường cho thấy model đang dựa vào shortcut feature hoặc '
            f'dữ liệu attack/benign có phân phối quá khác biệt trên một số feature. '
            f'Cần kiểm tra Feature Importance phía trên — nếu 1-2 feature chiếm >50% importance, '
            f'đó là dấu hiệu model chưa thực sự học hành vi tấn công.</li>')

    if worst_trc and worst_trc['trc'] is not None and worst_trc['trc'] < 0.95:
        analysis_items.append(
            f'<li><b>Recall thấp nhất:</b> {worst_trc["sid"]} ({worst_trc["ratio"]}) '
            f'với Test Recall = {worst_trc["trc"]:.4f}. Khi benign tăng cao, '
            f'model có xu hướng phân loại nhầm attack thành benign — '
            f'đây là trade-off quan trọng trong SOC (miss attack vs false alarm).</li>')

    if best_vmf:
        analysis_items.append(
            f'<li><b>Val Macro-F1 cao nhất:</b> {best_vmf["sid"]} ({best_vmf["ratio"]}) = '
            f'{best_vmf["vmf"]:.4f}. Đây là scenario generalize tốt nhất trên '
            f'temporal validation split.</li>')

    # Stability analysis
    vmf_vals = [e['vmf'] for e in entries if e['vmf'] is not None]
    if vmf_vals and len(vmf_vals) >= 2:
        vmf_range = max(vmf_vals) - min(vmf_vals)
        if vmf_range < 0.01:
            analysis_items.append(
                '<li><span class="good"><b>Ổn định cao:</b></span> '
                f'Val Macro-F1 dao động chỉ {vmf_range:.4f} giữa các scenario. '
                'Model robust với thay đổi tỉ lệ — Random Forest với class_weight="balanced" '
                'tự điều chỉnh tốt.</li>')
        elif vmf_range > 0.05:
            analysis_items.append(
                f'<li><span class="warn"><b>Biến động lớn:</b></span> '
                f'Val Macro-F1 dao động {vmf_range:.4f} giữa các scenario. '
                f'Tỉ lệ benign:attack ảnh hưởng đáng kể đến model performance — '
                f'cần chọn ratio cẩn thận cho production.</li>')

    if overfit_warnings:
        analysis_items.append(
            '<li><b>Overfitting:</b> ' + '; '.join(overfit_warnings) + '</li>')
    else:
        analysis_items.append(
            '<li><span class="good"><b>Không phát hiện overfitting:</b></span> '
            'Tất cả scenario có Train−Val gap < 0.05.</li>')

    # Recommendation
    rec_parts = []
    if best_vmf and best_vmf['vmf'] is not None:
        rec_parts.append(
            f'Dựa trên kết quả thực nghiệm, scenario <b>{best_vmf["sid"]} '
            f'({best_vmf["ratio"]})</b> cho Val Macro-F1 cao nhất ({best_vmf["vmf"]:.4f}). ')
    if worst_trc and worst_trc['trc'] is not None and worst_trc['trc'] < 0.95:
        rec_parts.append(
            f'Tuy nhiên, nếu ưu tiên recall (bắt hết attack), nên tránh '
            f'{worst_trc["sid"]} vì Test Recall chỉ {worst_trc["trc"]:.4f}. ')
    rec_parts.append(
        'Quyết định cuối cùng phụ thuộc vào cost FN/FP của hệ thống triển khai '
        '— SOC ưu tiên recall, production ưu tiên precision.')

    parts.append(html_decision(
        'Đánh giá của ML Expert dựa trên kết quả thực nghiệm',
        '<ul>' + '\n'.join(analysis_items) + '</ul>',
        'He & Garcia (2009): So sánh nhiều tỉ lệ là best practice. '
        'Sommer & Paxson (2010): Metric hoàn hảo trên dữ liệu lab không đảm bảo '
        'hiệu quả thực tế — cần đánh giá generalization qua temporal split.',
    ))
    parts.append(html_decision(
        'Khuyến nghị',
        '<p>' + ''.join(rec_parts) + '</p>',
    ))


def generate_html_report(
    results: dict[str, Any],
    plots: dict[str, str],
    robustness: list[dict] | None,
    demo_results: list[dict] | None,
    report_dir: Path,
    univariate_scan: list[dict] | None = None,
    shap_info: dict[str, Any] | None = None,
    rolling_cv: dict[str, Any] | None = None,
    leakage_audit: dict[str, Any] | None = None,
    log: ViLogger | None = None,
    model_path: Path | None = None,
    train_accuracy: float | None = None,
    scenario_comparison: list[dict[str, Any]] | None = None,
    dataset_quality_df: pd.DataFrame | None = None,
) -> Path:
    """Build a comprehensive HTML evaluation report with embedded charts."""
    report_dir.mkdir(parents=True, exist_ok=True)
    parts: list[str] = []

    # ── Header ──
    parts.append(html_header(
        'Báo cáo Đánh giá ML — Cowrie Honeypot',
        'Step 5',
        'Random Forest SSH Brute-Force Detection (n_estimators=100)',
    ))

    # ── Table of Contents ──
    toc_items = [
        ('sec-overview', 'Tổng quan mô hình'),
        ('sec-training', 'Kết quả huấn luyện'),
        ('sec-features', 'Phân tích Feature Importance'),
    ]
    if dataset_quality_df is not None:
        toc_items.append(('sec-dataset-quality', 'Đánh giá chất lượng Dataset (6 khía cạnh)'))
    if scenario_comparison:
        toc_items.append(('sec-scenarios', 'Thực nghiệm tỉ lệ Benign:Attack (RQ8)'))
    toc_items += [
        ('sec-shap', 'SHAP Analysis'),
        ('sec-cv', 'Rolling Time-Series CV'),
        ('sec-robustness', 'Kiểm tra độ bền (Robustness Tests)'),
        ('sec-verify', 'Kiểm tra & Xác minh tổng hợp (Verification)'),
        ('sec-science', 'Cơ sở khoa học'),
    ]
    if demo_results:
        toc_items.append(('sec-demo', 'Demo gần thời gian thực'))
    toc_items.append(('sec-debug', 'Debug Log'))
    parts.append(html_toc(toc_items))

    # ── Section 1: Tổng quan mô hình ──
    parts.append(html_section('sec-overview', 'Tổng quan mô hình'))
    total_samples = sum(results['split_sizes'].values())
    n_feat = len(ML_FEATURE_COLUMNS)
    rf_model = results['model']
    parts.append(html_cards([
        ('Tổng số mẫu', total_samples),
        ('Số đặc trưng sử dụng', n_feat),
        ('Train', results['split_sizes']['train']),
        ('Val', results['split_sizes']['val']),
        ('Test', results['split_sizes']['test']),
        ('Loại mô hình', 'Random Forest'),
        ('n_estimators', rf_model.n_estimators),
        ('max_depth', str(rf_model.max_depth) if rf_model.max_depth is not None else 'Không giới hạn'),
    ]))
    parts.append(
        '<details open><summary><b>Giải thích các chỉ số</b></summary>'
        '<table><tr><th>Chỉ số</th><th>Ý nghĩa</th><th>Cách xác định</th></tr>'
        '<tr><td><b>Tổng số mẫu</b></td>'
        '<td>Tổng feature vectors (train + val + test)</td>'
        '<td>Từ <code>output/step4/ml_features.json</code> — mỗi mẫu = 1 cặp (IP, 60-phút window)</td></tr>'
        '<tr><td><b>Số đặc trưng sử dụng</b></td>'
        '<td>Số cột feature đưa vào model (không bao gồm metadata/label)</td>'
        '<td>Danh sách từ <code>pipeline_feature_config.json</code> — '
        'chỉ các feature active, đã loại shortcut features</td></tr>'
        '<tr><td><b>Train / Val / Test</b></td>'
        '<td>Số mẫu trong mỗi phần chia dữ liệu</td>'
        '<td>Temporal split 60/20/20: sắp xếp theo <code>window_start</code>, '
        '60% đầu tiên (quá khứ) = train, 20% giữa = val, 20% cuối (tương lai) = test. '
        'Không shuffle → mô phỏng deploy thực tế</td></tr>'
        '<tr><td><b>Loại mô hình</b></td>'
        '<td>Thuật toán ML được sử dụng</td>'
        '<td>Random Forest — ensemble of decision trees, phù hợp tabular data hỗn hợp (Breiman, 2001)</td></tr>'
        '<tr><td><b>n_estimators</b></td>'
        '<td>Số cây quyết định trong ensemble</td>'
        '<td>Hyperparameter: nhiều cây → ổn định hơn nhưng chậm hơn. Mặc định 200</td></tr>'
        '<tr><td><b>max_depth</b></td>'
        '<td>Độ sâu tối đa của mỗi cây</td>'
        '<td>"Không giới hạn" = cây phát triển đến khi thuần nhất hoặc hết mẫu. '
        'Giới hạn depth giúp chống overfitting nhưng có thể giảm accuracy</td></tr>'
        '</table></details>'
    )
    parts.append(html_table(
        ['Đặc trưng'],
        [[f] for f in ML_FEATURE_COLUMNS],
    ))

    # ── Section 2: Kết quả huấn luyện ──
    parts.append(html_section('sec-training', 'Kết quả huấn luyện'))

    test_macro_f1 = results.get('test_macro_f1', float('nan'))
    val_macro_f1 = results.get('val_macro_f1', float('nan'))
    train_macro_f1 = results.get('train_macro_f1', float('nan'))
    train_acc_display = train_accuracy if train_accuracy is not None else 'N/A'

    card_items: list[tuple[str, Any]] = [
        ('Test Accuracy', results['accuracy']),
        ('Test Precision', results['precision']),
        ('Test Recall', results['recall']),
        ('Test F1', results['f1']),
        ('Test Macro F1', _safe_metric(test_macro_f1)),
        ('Test ROC AUC', results['auc']),
        ('Test PR-AUC', results.get('pr_auc', 0)),
        ('Val F1', results['val_f1']),
        ('Val Macro F1', _safe_metric(val_macro_f1)),
        ('Val AUC', results['val_auc']),
    ]
    if train_accuracy is not None:
        card_items.append(('Train Accuracy', train_accuracy))
    parts.append(html_cards(card_items))

    parts.append(
        '<details open><summary><b>Giải thích chi tiết — Kết quả huấn luyện (cho ML Expert)</b></summary>'
        '<p class="small" style="margin:8px 0 12px 0">Bài toán nhị phân: lớp dương thường là <b>Attack (1)</b>, '
        'lớp âm là <b>Benign (0)</b>. Precision/Recall/F1 mặc định theo lớp dương (attack) trừ khi ghi rõ macro.</p>'
        '<table><tr><th>Chỉ số</th><th>Ý nghĩa</th><th>Cách tính / Nguồn</th><th>Đánh giá nhanh (sai ở đâu?)</th></tr>'

        '<tr><td><b>Train Accuracy</b></td>'
        '<td>Tỉ lệ dự đoán đúng trên tập <b>huấn luyện</b> (đã thấy khi fit).</td>'
        '<td><code>(TP+TN) / (TP+TN+FP+FN)</code> trên train.</td>'
        '<td><span class="warn">Cao hơn Test nhiều</span> → nghi overfitting / ghi nhớ mẫu. '
        'So sánh với Val/Test; nếu Train≈1.0 mà Test thấp → cần regularization, ít cây hơn, hoặc kiểm tra leakage.</td></tr>'

        '<tr><td><b>Test Accuracy</b></td>'
        '<td>Tỉ lệ đúng trên tập <b>test</b> (thời gian “tương lai”, chưa thấy khi train).</td>'
        '<td>Cùng công thức accuracy, áp dụng cho <code>y_test</code> vs <code>y_pred</code>.</td>'
        '<td>Dễ <span class="good">ảo tưởng cao</span> nếu lớp lệch mạnh (imbalance): model dự đoán hết benign vẫn accuracy cao. '
        'Luôn xem kèm Recall, PR-AUC, Confusion Matrix.</td></tr>'

        '<tr><td><b>Test Precision</b></td>'
        '<td>Trong số các lần model gọi “Attack”, bao nhiêu % đúng thật là attack.</td>'
        '<td><code>TP / (TP+FP)</code> — tính cho lớp attack (positive).</td>'
        '<td><span class="warn">Thấp</span> → nhiều <b>false alarm</b> (FP): benign bị báo attack. '
        'Ưu tiên giảm FP khi chi phí cảnh báo cao (SOC mệt mỏi).</td></tr>'

        '<tr><td><b>Test Recall</b> (Sensitivity)</td>'
        '<td>Trong số attack thật, model bắt được bao nhiêu %.</td>'
        '<td><code>TP / (TP+FN)</code>.</td>'
        '<td><span class="warn">Thấp</span> → <b>bỏ sót tấn công</b> (FN). Nguy hiểm nếu mục tiêu là phát hiện tối đa attack. '
        'Cân bằng với Precision (điều chỉnh ngưỡng, class_weight, cost-sensitive).</td></tr>'

        '<tr><td><b>Test F1</b></td>'
        '<td>Trung bình điều hòa của Precision và Recall trên lớp attack (thường là macro hoặc binary theo sklearn).</td>'
        '<td><code>2·P·R / (P+R)</code> khi P,R cùng lớp positive.</td>'
        '<td>Một số duy nhất để trade-off P/R. So với <b>Macro F1</b> để biết có lệch lớp không.</td></tr>'

        '<tr><td><b>Test Macro F1</b></td>'
        '<td>Trung bình F1 của <b>từng lớp</b> (Benign & Attack), mỗi lớp coi trọng như nhau.</td>'
        '<td><code>mean(F1_benign, F1_attack)</code> (sklearn <code>average=\'macro\'</code>).</td>'
        '<td><span class="good">Phù hợp imbalance</span> hơn accuracy. '
        '<span class="warn">Thấp trong khi accuracy cao</span> → model thiên một lớp (vd: chỉ khớp benign).</td></tr>'

        '<tr><td><b>Test ROC AUC</b></td>'
        '<td>Diện tích dưới đường ROC: khả năng xếp hạng attack cao hơn benign (score).</td>'
        '<td>Tích phân TPR vs FPR khi đổi ngưỡng; sklearn <code>roc_auc_score</code>.</td>'
        '<td>0.5 = ngẫu nhiên. <span class="warn">Cao bất thường + leakage audit HIGH</span> → nghi shortcut/feature lộ nhãn. '
        'Với cực imbalance, ROC có thể lạc quan; đối chiếu <b>PR-AUC</b>.</td></tr>'

        '<tr><td><b>Test PR-AUC</b></td>'
        '<td>Diện tích dưới đường Precision–Recall; nhạy với lớp thiểu số (attack).</td>'
        '<td><code>average_precision_score</code> hoặc tích phân P–R.</td>'
        '<td><span class="good">Quan trọng khi attack hiếm</span>. Thấp dù ROC cao → model không đủ precision ở vùng recall cần thiết.</td></tr>'

        '<tr><td><b>Val F1 / Val Macro F1 / Val AUC</b></td>'
        '<td>Đo trên tập <b>validation</b> (giữa train và test theo thời gian).</td>'
        '<td>Cùng metric như test, trên <code>split=val</code>.</td>'
        '<td>Dùng để chọn hyperparameter / early stopping. '
        '<span class="warn">Val tốt, Test xấu</span> → drift thời gian hoặc test khó hơn; '
        '<span class="warn">Train & Val tốt, Test xấu</span> → overfit tới phân phối train+val.</td></tr>'

        '</table>'
        '<h4>Bảng tóm tắt Train / Val / Test (Accuracy, Precision, Recall, F1, Macro F1)</h4>'
        '<ul class="small">'
        '<li><b>Train</b>: chỉ có Accuracy + Macro F1 trong bảng — phản ánh mức “khớp” dữ liệu đã học; không có Precision/Recall riêng ở bảng này để tránh trùng với card.</li>'
        '<li><b>Val</b>: F1 + Macro F1 (+ AUC ở card) — theo dõi khớp trong giai đoạn trung gian thời gian.</li>'
        '<li><b>Test</b>: đầy đủ Accuracy, Precision, Recall, F1, Macro F1 — <b>đánh giá cuối cùng</b> báo cáo cho deployment.</li>'
        '</ul>'
        '<p class="small"><b>Tham khảo:</b> Sokolova & Lapalme (2009) — hạn chế của accuracy với imbalance; '
        'Davis & Goadrich (2006) — PR curve vs ROC với rare positives.</p>'
        '</details>'
    )

    # Metrics table
    metrics_rows = [
        ['Train', _safe_metric(train_acc_display) if isinstance(train_acc_display, float) else str(train_acc_display),
         '—', '—', '—', _safe_metric(train_macro_f1)],
        ['Val', '—', '—', '—', _safe_metric(results['val_f1']), _safe_metric(val_macro_f1)],
        ['Test', _safe_metric(results['accuracy']), _safe_metric(results['precision']),
         _safe_metric(results['recall']), _safe_metric(results['f1']), _safe_metric(test_macro_f1)],
    ]
    parts.append(html_table(
        ['Tập', 'Accuracy', 'Precision', 'Recall', 'F1', 'Macro F1'],
        metrics_rows,
    ))

    # Classification Report
    parts.append('<details open><summary>Classification Report chi tiết</summary>')
    parts.append(f'<pre style="background:#0f172a;color:#e2e8f0;padding:14px;border-radius:10px;font-size:12px">'
                 f'{html_escape(results["classification_report"])}</pre>')
    parts.append('</details>')

    # FPR @ TPR table
    if results.get('fpr_at_tpr'):
        parts.append('<details open><summary>FPR tại các mức TPR cố định</summary>')
        fpr_rows = [[k, v] for k, v in results['fpr_at_tpr'].items()]
        parts.append(html_table(['Metric', 'Giá trị'], fpr_rows))
        parts.append('</details>')

    # Embed ROC curve
    roc_html = _embed_saved_png(report_dir, plots.get('ROC Curve'))
    if roc_html:
        parts.append(html_chart(roc_html, 'Đường cong ROC trên tập Test'))

    # Embed PR curve
    pr_html = _embed_saved_png(report_dir, plots.get('PR Curve'))
    if pr_html:
        parts.append(html_chart(pr_html, 'Đường cong Precision-Recall trên tập Test'))

    # Embed confusion matrix (saved png + inline from report_utils)
    cm_html = _embed_saved_png(report_dir, plots.get('Confusion Matrix'))
    if cm_html:
        parts.append(html_chart(cm_html, 'Ma trận nhầm lẫn (Confusion Matrix) trên tập Test'))
    cm_data = results['confusion_matrix']
    if hasattr(cm_data, 'tolist'):
        cm_list = cm_data.tolist()
    else:
        cm_list = [list(row) for row in cm_data]
    inline_cm = make_confusion_matrix_chart(cm_list, ['Benign', 'Attack'])
    if inline_cm:
        parts.append(html_chart(inline_cm, 'Ma trận nhầm lẫn (embedded vector)'))

    # Embed probability distribution
    prob_html = _embed_saved_png(report_dir, plots.get('Probability Distribution'))
    if prob_html:
        parts.append(html_chart(prob_html, 'Phân bố xác suất dự đoán trên tập Test'))

    # ── Section 3: Phân tích Feature Importance ──
    parts.append(html_section('sec-features', 'Phân tích Feature Importance'))

    fi_html = _embed_saved_png(report_dir, plots.get('Feature Importance'))
    if fi_html:
        parts.append(html_chart(fi_html, 'Tầm quan trọng đặc trưng (Gini Impurity)'))

    feat_names = [f[0] for f in results['feature_importance']]
    feat_vals = [f[1] for f in results['feature_importance']]
    inline_fi = make_bar_chart(
        feat_names, feat_vals,
        title='Feature Importance — Random Forest',
        xlabel='', ylabel='Importance',
        color='#3b82f6', horizontal=True,
        value_format='.4f',
    )
    if inline_fi:
        parts.append(html_chart(inline_fi, 'Feature Importance (embedded vector)'))

    parts.append(html_table(
        ['Đặc trưng', 'Importance (Gini)'],
        [[name, imp] for name, imp in results['feature_importance']],
    ))

    # ── Section: Dataset Quality Evaluation (6 aspects) ──
    if dataset_quality_df is not None:
        parts.append(html_section('sec-dataset-quality',
                                  'Đánh giá chất lượng Dataset (6 khía cạnh)'))
        parts.append(html_decision(
            'Tại sao cần đánh giá dataset trước khi train?',
            '<p>Một bộ dataset "tốt" cho ML research cần vượt qua nhiều tiêu chí khắt khe, '
            'không chỉ nhìn vào F1/AUC cuối cùng. Việc đánh giá chất lượng dataset <b>trước khi</b> '
            'đưa vào model là bước riêng biệt, giúp phát hiện sớm bias, leakage, '
            'và các vấn đề cấu trúc dữ liệu.</p>',
            'Tukey (1977): EDA phải kiểm tra domain constraints trước khi fit model. '
            'Sommer & Paxson (2010): IDS dataset rất dễ có artifact — kiểm tra trước khi train. '
            'Ho & Basu (2002): Dataset complexity measures xác định liệu bài toán có "quá dễ" hay không.',
        ))
        quality_report = _evaluate_dataset_quality(
            dataset_quality_df, ML_FEATURE_COLUMNS, TARGET_COLUMN)
        _build_dataset_quality_html(parts, quality_report, ML_FEATURE_COLUMNS)

    # ── Section: Ratio Scenario Comparison (RQ8) ──
    if scenario_comparison:
        parts.append(html_section('sec-scenarios',
                                  'Thực nghiệm tỉ lệ Benign:Attack (RQ8)'))
        parts.append(html_decision(
            'RQ8: Tỉ lệ upscale 1:1 — có phải tối ưu?',
            f'<p>Pipeline đã chạy <b>{len(scenario_comparison)} scenario</b> thực nghiệm '
            'với các tỉ lệ benign:attack khác nhau. Mỗi scenario chạy đầy đủ sub-pipeline '
            '(3B→3C→4→5), giữ nguyên dữ liệu attack, chỉ thay đổi lượng benign synthetic.</p>',
            'He & Garcia (2009): Không có tỉ lệ sampling phổ quát — cần thực nghiệm trên bài toán cụ thể. '
            'Arp et al. (2022): Báo cáo giới hạn đánh giá khi temporal split chỉ có 1 lớp.',
        ))

        def _sfmt(v: Any, f: str = '.4f') -> str:
            if v is None:
                return 'N/A'
            try:
                return format(float(v), f)
            except (TypeError, ValueError):
                return str(v)

        # Data split table
        parts.append('<h4>Phân bố dữ liệu huấn luyện theo scenario</h4>')
        split_rows = []
        for r in scenario_comparison:
            split_rows.append([
                r.get('scenario_id', ''), r.get('ratio', ''),
                r.get('train_rows', 0), r.get('train_attack', 0),
                r.get('train_benign', 0),
                _sfmt(r.get('train_benign_share'), '.1%'),
                r.get('val_rows', 0), r.get('test_rows', 0),
            ])
        parts.append(html_table(
            ['Scenario', 'Ratio', 'Train', 'Attack', 'Benign',
             'Benign %', 'Val', 'Test'],
            split_rows,
        ))

        # Attack vs Benign grouped bar chart (fix: use img_tag)
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            sc_sids = [r.get('scenario_id', '') for r in scenario_comparison]
            t_atk = [r.get('train_attack', 0) for r in scenario_comparison]
            t_ben = [r.get('train_benign', 0) for r in scenario_comparison]
            fig, ax = plt.subplots(figsize=(10, 4))
            x = range(len(sc_sids))
            w = 0.35
            ax.bar([i - w / 2 for i in x], t_atk, w, label='Attack', color='#e53e3e')
            ax.bar([i + w / 2 for i in x], t_ben, w, label='Benign', color='#38a169')
            ax.set_xticks(list(x)); ax.set_xticklabels(sc_sids, rotation=15)
            ax.set_ylabel('Feature vectors')
            ax.set_title('Attack vs Benign trong tập Train')
            ax.legend(); fig.tight_layout()
            parts.append(html_chart(
                img_tag(fig_to_base64(fig), 'Attack vs Benign distribution'),
                'Biểu đồ: phân bố attack/benign theo scenario',
            ))
            plt.close(fig)
        except Exception:
            pass

        # Main metrics comparison table (no Leakage column)
        parts.append('<h4>So sánh metric toàn bộ scenario</h4>')
        metric_keys = [
            ('train_macro_f1', 'Train Macro-F1'),
            ('val_macro_f1', 'Val Macro-F1'),
            ('val_f1', 'Val F1'),
            ('val_auc', 'Val AUC'),
            ('test_macro_f1', 'Test Macro-F1'),
            ('test_f1', 'Test F1'),
            ('test_auc', 'Test AUC'),
            ('test_pr_auc', 'Test PR-AUC'),
            ('test_accuracy', 'Accuracy'),
            ('test_precision', 'Precision'),
            ('test_recall', 'Recall'),
        ]
        m_headers = ['Scenario', 'Ratio'] + [m[1] for m in metric_keys]
        m_rows = []
        for r in scenario_comparison:
            row = [r.get('scenario_id', ''), r.get('ratio', '')]
            for key, _ in metric_keys:
                row.append(_sfmt(r.get(key)))
            m_rows.append(row)
        parts.append(html_table(m_headers, m_rows))

        # Per-metric bar charts
        for key, label, color in [
            ('train_macro_f1', 'Train Macro-F1', '#3182ce'),
            ('val_macro_f1', 'Val Macro-F1', '#805ad5'),
            ('test_f1', 'Test F1 (Attack)', '#e53e3e'),
            ('test_auc', 'Test AUC', '#dd6b20'),
        ]:
            vals, lbls = [], []
            for r in scenario_comparison:
                v = r.get(key)
                if v is not None:
                    try:
                        vals.append(float(v)); lbls.append(r.get('scenario_id', ''))
                    except (TypeError, ValueError):
                        pass
            if vals:
                parts.append(html_chart(
                    make_bar_chart(lbls, vals, title=f'{label} theo Scenario',
                                   ylabel=label, color=color, figsize=(10, 4)),
                    f'So sánh {label} giữa các scenario',
                ))

        # Train vs Val overfitting chart (fix: use img_tag)
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            c_sids, c_train, c_val = [], [], []
            for r in scenario_comparison:
                tf, vf = r.get('train_macro_f1'), r.get('val_macro_f1')
                if tf is not None and vf is not None:
                    c_sids.append(r.get('scenario_id', ''))
                    c_train.append(float(tf)); c_val.append(float(vf))
            if c_sids:
                fig, ax = plt.subplots(figsize=(10, 4))
                x = range(len(c_sids)); w = 0.35
                ax.bar([i - w / 2 for i in x], c_train, w,
                       label='Train Macro-F1', color='#3182ce')
                ax.bar([i + w / 2 for i in x], c_val, w,
                       label='Val Macro-F1', color='#805ad5')
                ax.set_xticks(list(x)); ax.set_xticklabels(c_sids, rotation=15)
                ax.set_ylabel('Macro-F1')
                ax.set_title('Train vs Val Macro-F1 — Phát hiện Overfitting')
                ax.legend(); ax.set_ylim(0, 1.05); fig.tight_layout()
                parts.append(html_chart(
                    img_tag(fig_to_base64(fig), 'Train vs Val overfitting'),
                    'Chênh lệch Train/Val = mức overfitting',
                ))
                plt.close(fig)
        except Exception:
            pass

        # Dataset quality per scenario
        dq_rows_available = any(r.get('dataset_quality') for r in scenario_comparison)
        if dq_rows_available:
            parts.append('<h4>Chất lượng Dataset theo scenario</h4>')
            parts.append(
                '<p>Mỗi scenario tạo ra bộ dataset khác nhau (thay đổi lượng benign synthetic). '
                'Bảng dưới tóm tắt các chỉ số chất lượng cơ bản cho từng scenario.</p>')
            dq_headers = ['Scenario', 'Ratio', 'Tổng mẫu', 'Attack', 'Benign',
                          'Label Agreement', 'Rows với missing']
            dq_rows_data = []
            for r in scenario_comparison:
                dq = r.get('dataset_quality', {})
                dq_rows_data.append([
                    r.get('scenario_id', ''),
                    r.get('ratio', ''),
                    dq.get('total_samples', 'N/A'),
                    dq.get('n_attack', 'N/A'),
                    dq.get('n_benign', 'N/A'),
                    _sfmt(dq.get('label_agreement'), '.4f'),
                    dq.get('n_rows_with_missing', 'N/A'),
                ])
            parts.append(html_table(dq_headers, dq_rows_data))

        # Dynamic expert evaluation based on actual data
        _build_scenario_expert_evaluation(parts, scenario_comparison, _sfmt)

        parts.append(
            '<p><b>Xem báo cáo chi tiết từng scenario:</b> '
            '<code>output/ratio_study/scenario_comparison.html</code></p>'
        )

    # ── Section: SHAP Analysis ──
    parts.append(html_section('sec-shap', 'SHAP Analysis'))

    if shap_info:
        shap_summary_html = _embed_saved_png(report_dir, shap_info.get('summary_plot'))
        if shap_summary_html:
            parts.append(html_chart(shap_summary_html, 'SHAP Summary (Beeswarm) — lớp Attack'))
        shap_bar_html = _embed_saved_png(report_dir, shap_info.get('bar_plot'))
        if shap_bar_html:
            parts.append(html_chart(shap_bar_html, 'SHAP Feature Importance (bar)'))

        parts.append(html_table(
            ['Đặc trưng', 'Mean |SHAP|'],
            [[name, val] for name, val in shap_info['feature_shap']],
        ))
    else:
        parts.append('<p class="small">SHAP analysis không khả dụng (có thể do thiếu thư viện shap).</p>')

    # ── Section 6: Rolling Time-Series CV ──
    parts.append(html_section('sec-cv', 'Rolling Time-Series CV'))

    if rolling_cv and rolling_cv.get('folds'):
        fold_rows = [
            [fr['fold'], fr['train_windows'], fr['test_windows'],
             fr['train_rows'], fr['test_rows'],
             fr['f1'], fr['precision'], fr['recall'], fr['auc'], fr['pr_auc']]
            for fr in rolling_cv['folds']
        ]
        parts.append(html_table(
            ['Fold', 'Train Win', 'Test Win', 'Train Rows', 'Test Rows',
             'F1', 'Precision', 'Recall', 'AUC', 'PR-AUC'],
            fold_rows,
        ))

        # Bar chart of per-fold F1
        fold_labels = [f'Fold {fr["fold"]}' for fr in rolling_cv['folds']]
        fold_f1s = [fr['f1'] for fr in rolling_cv['folds']]
        cv_chart = make_bar_chart(
            fold_labels, fold_f1s,
            title='F1 theo từng fold (Rolling CV)',
            ylabel='F1 Score', color='#059669',
            value_format='.3f',
        )
        if cv_chart:
            parts.append(html_chart(cv_chart, 'F1 Score qua các fold — kiểm tra tính ổn định'))

        summary = rolling_cv.get('summary', {})
        if summary:
            parts.append('<details open><summary>Tổng hợp (mean ± std)</summary>')
            sum_rows = [
                [m, s['mean'], s['std'], s['min'], s['max']]
                for m, s in summary.items()
            ]
            parts.append(html_table(
                ['Metric', 'Mean', 'Std', 'Min', 'Max'],
                sum_rows,
            ))
            parts.append('</details>')
    else:
        parts.append('<p class="small">Rolling CV không tạo được fold (không đủ cửa sổ thời gian).</p>')

    # ── Section 7: Kiểm tra độ bền (Robustness Tests) ──
    parts.append(html_section('sec-robustness', 'Kiểm tra độ bền (Robustness Tests)'))

    if robustness:
        rob_tests = [
            (r['scenario'],
             r['correct'],
             f'P(Attack)={r["probability"]:.4f} → {r["prediction"]} '
             f'(kỳ vọng: {r["expected"]})'
             + (f' | {r["note"]}' if r.get('note') else ''))
            for r in robustness
        ]
        parts.append(html_verification_section(rob_tests))

        rob_rows = [
            [r['scenario'], r['description'], r['prediction'],
             r['probability'], 'PASS' if r['correct'] else 'FAIL',
             r.get('note', '')]
            for r in robustness
        ]
        parts.append(html_table(
            ['Kịch bản', 'Mô tả', 'Dự đoán', 'P(Attack)', 'Kết quả', 'Ghi chú'],
            rob_rows,
        ))
    else:
        parts.append('<p class="small">Không có kết quả kiểm tra độ bền.</p>')

    # ── Section 8: Kiểm tra & Xác minh tổng hợp (Verification) ──
    parts.append(html_section('sec-verify', 'Kiểm tra & Xác minh tổng hợp (Verification)'))

    verification_tests: list[tuple[str, bool, str]] = []

    # 1. Model file exists and loadable
    _mp = model_path or MODEL_PATH
    model_exists = _mp.exists()
    model_loadable = False
    if model_exists:
        try:
            with _mp.open('rb') as _f:
                pickle.load(_f)
            model_loadable = True
        except Exception:
            pass
    verification_tests.append((
        'File mô hình tồn tại và nạp được',
        model_exists and model_loadable,
        f'{_mp} — exists={model_exists}, loadable={model_loadable}',
    ))

    # 2. Test accuracy > 0.5
    test_acc = results['accuracy']
    verification_tests.append((
        'Test accuracy > 0.5 (tốt hơn ngẫu nhiên)',
        test_acc > 0.5,
        f'Accuracy = {test_acc:.4f}',
    ))

    # 3. No single feature AUC > 0.99
    max_uni_auc = 0.0
    if univariate_scan:
        max_uni_auc = max(s['univariate_auc'] for s in univariate_scan)
    verification_tests.append((
        'Không có đặc trưng đơn lẻ nào có AUC > 0.99 (không có shortcut trivial)',
        max_uni_auc < 0.99,
        f'Max univariate AUC = {max_uni_auc:.4f}',
    ))

    # 4. Train/test accuracy gap < 0.15
    t_acc = train_accuracy if train_accuracy is not None else test_acc
    gap = abs(t_acc - test_acc)
    verification_tests.append((
        'Chênh lệch accuracy train/test < 0.15 (không overfitting nghiêm trọng)',
        gap < 0.15,
        f'Train acc = {t_acc:.4f}, Test acc = {test_acc:.4f}, Gap = {gap:.4f}',
    ))

    # 5. Both classes present in test set
    y_test = results['y_test']
    both_classes = len(set(y_test)) >= 2
    verification_tests.append((
        'Cả hai lớp (Benign & Attack) đều có trong tập test',
        both_classes,
        f'Các lớp trong test: {sorted(set(y_test))}',
    ))

    # 6. Feature importance sum ≈ 1.0
    fi_sum = sum(v for _, v in results['feature_importance'])
    verification_tests.append((
        'Tổng feature importance ≈ 1.0',
        abs(fi_sum - 1.0) < 0.01,
        f'Tổng = {fi_sum:.6f}',
    ))

    # 7. Classification report generated successfully
    cls_report_ok = bool(results.get('classification_report', '').strip())
    verification_tests.append((
        'Classification report tạo thành công',
        cls_report_ok,
        'Có' if cls_report_ok else 'Không — report rỗng',
    ))

    parts.append(html_verification_section(verification_tests))

    # ── Section 9: Cơ sở khoa học ──
    parts.append(html_section('sec-science', 'Cơ sở khoa học'))

    parts.append(html_decision(
        'Tại sao dùng Random Forest?',
        '<p>Random Forest là ensemble gồm nhiều cây quyết định (decision trees), '
        'giảm thiểu overfitting bằng cách lấy trung bình từ nhiều cây huấn luyện '
        'trên bootstrap samples. Phù hợp với dữ liệu dạng bảng (tabular), '
        'không cần chuẩn hóa đặc trưng, và cung cấp feature importance tự nhiên.</p>',
        'Breiman, L. (2001). Random Forests. Machine Learning, 45(1), 5–32.',
    ))
    parts.append(html_decision(
        'Tại sao dùng temporal split thay vì random split?',
        '<p>Trong bài toán phát hiện tấn công mạng, dữ liệu test phải đến từ '
        'khoảng thời gian SAU dữ liệu train để mô phỏng điều kiện triển khai thực tế. '
        'Random split có thể gây data leakage do các sự kiện gần nhau trong thời gian '
        'có tương quan cao.</p>',
        'Arp, D., Quiring, E., Pendlebury, F., et al. (2022). '
        'Dos and Don\'ts of Machine Learning in Computer Security. USENIX Security.',
    ))
    parts.append(html_decision(
        'Tại sao cần kiểm tra rò rỉ dữ liệu (Leakage Audit)?',
        '<p>Mô hình có thể đạt độ chính xác cao giả tạo nếu đặc trưng chứa '
        'thông tin trực tiếp từ nhãn (label leakage) hoặc nếu dữ liệu train/test '
        'bị trùng lặp. Leakage audit bao gồm: kiểm tra baseline đơn đặc trưng, '
        'kiểm tra overlap hash, và stress test trên đặc trưng khó.</p>',
        'Kaufman, S., Rosset, S., & Perlich, C. (2012). '
        'Leakage in Data Mining. ACM TKDD, 6(4).',
    ))
    parts.append(html_decision(
        'Tại sao dùng SHAP?',
        '<p>SHAP (SHapley Additive exPlanations) dựa trên lý thuyết trò chơi '
        'để giải thích đóng góp của từng đặc trưng vào dự đoán. Giúp kiểm tra '
        'xem mô hình có học được pattern hợp lý hay dựa vào artifact/shortcut.</p>',
        'Lundberg, S. M. & Lee, S.-I. (2017). '
        'A Unified Approach to Interpreting Model Predictions. NeurIPS.',
    ))

    # ── Demo section (if available) ──
    if demo_results:
        parts.append(html_section('sec-demo', 'Demo gần thời gian thực'))

        alert_rows = [d for d in demo_results if d.get('alert')]
        latencies = [d['latency_ms'] for d in demo_results]
        avg_lat = statistics.mean(latencies) if latencies else 0
        p95_idx = int(len(latencies) * 0.95)
        p95_lat = sorted(latencies)[p95_idx] if latencies else 0

        parts.append(html_cards([
            ('Cửa sổ đã xử lý', len(demo_results)),
            ('Cảnh báo phát hiện', len(alert_rows)),
            ('Ngưỡng cảnh báo', f'P(Attack) > {ALERT_THRESHOLD}'),
            ('Độ trễ trung bình', f'{avg_lat:.2f} ms'),
            ('Độ trễ P95', f'{p95_lat:.2f} ms'),
        ]))

        demo_tbl_rows = [
            [d.get('ip', ''), d.get('window_start', ''),
             d.get('failed_attempts', 0), d.get('probability', 0),
             'ALERT' if d.get('alert') else 'OK',
             f'{d.get("latency_ms", 0):.1f} ms']
            for d in demo_results[:200]
        ]
        parts.append(html_table(
            ['IP', 'Cửa sổ', 'Số lần thất bại', 'P(Attack)', 'Trạng thái', 'Độ trễ'],
            demo_tbl_rows,
        ))

    # ── Section: Debug Log ──
    parts.append(html_section('sec-debug', 'Debug Log'))
    if log:
        parts.append(html_debug_log(log))
    else:
        parts.append('<p class="small">Không có debug log.</p>')

    # ── Footer ──
    parts.append(html_footer())

    # ── Write report ──
    report_path = report_dir / 'evaluation_report.html'
    _write_report_html(report_path, '\n'.join(parts))
    return report_path


# ═══════════════════════════════════════════════════════════════════════════
# ROBUSTNESS TESTS
# ═══════════════════════════════════════════════════════════════════════════

def _shannon_entropy(values: list[str]) -> float:
    if not values:
        return 0.0
    counter = Counter(values)
    total = len(values)
    ent = 0.0
    for count in counter.values():
        if count > 0:
            p = count / total
            ent -= p * math.log2(p)
    return round(ent, 6)


def _ip_entropy(ip: str) -> float:
    return _shannon_entropy(list(ip))


def _hour_cyclic_from_seconds(seconds_from_midnight: float) -> tuple[float, float]:
    """Match step4: hour_sin, hour_cos from window hour (derived from seconds)."""
    hour = (seconds_from_midnight / 3600.0) % 24
    return (
        round(math.sin(2 * math.pi * hour / 24), 6),
        round(math.cos(2 * math.pi * hour / 24), 6),
    )


def _make_feature_dict(
    failed_attempts: int,
    num_unique_users: int,
    username_entropy: float,
    success_ratio: float,
    num_failed_ports: int,
    avg_time_between_attempts: float,
    login_interval_variance: float,
    time_of_day_avg: float,
    num_failed_days: int,
    ip_entropy: float,
    client_version_category: int,
    *,
    time_to_auth: float = 0.0,
    session_duration: float = 0.0,
    min_inter_arrival: float = 0.0,
    max_inter_arrival: float = 0.0,
    hour_sin: float | None = None,
    hour_cos: float | None = None,
) -> dict[str, float]:
    """Return a dict covering all columns in _ALL_FEATURE_COLUMNS for robustness tests."""
    hs, hc = _hour_cyclic_from_seconds(time_of_day_avg)
    if hour_sin is not None:
        hs = hour_sin
    if hour_cos is not None:
        hc = hour_cos
    return {
        'failed_attempts': failed_attempts,
        'num_unique_users': num_unique_users,
        'username_entropy': username_entropy,
        'success_ratio': success_ratio,
        'num_failed_ports': num_failed_ports,
        'avg_time_between_attempts': avg_time_between_attempts,
        'login_interval_variance': login_interval_variance,
        'time_of_day_avg': time_of_day_avg,
        'num_failed_days': num_failed_days,
        'ip_entropy': ip_entropy,
        'client_version_category': client_version_category,
        'time_to_auth': time_to_auth,
        'session_duration': session_duration,
        'min_inter_arrival': min_inter_arrival,
        'max_inter_arrival': max_inter_arrival,
        'hour_sin': hs,
        'hour_cos': hc,
    }


def _feature_dict_to_vector(d: dict[str, float]) -> list[float]:
    """Extract ML_FEATURE_COLUMNS in order; missing keys default to 0.0."""
    return [float(d.get(f, 0.0)) for f in ML_FEATURE_COLUMNS]


def run_robustness_tests(model: RandomForestClassifier) -> list[dict]:
    """
    Create synthetic feature vectors for 3 attack scenarios:
    1. Burst Attack — loud brute-force
    2. Low-and-Slow — slow, spread out
    3. Benign Typo — real user with a few typos
    """
    scenarios = []

    # 1. Burst Attack: 200 failed in 1 hour, 50 unique users, Go client
    burst = _make_feature_dict(
        failed_attempts=200,
        num_unique_users=50,
        username_entropy=_shannon_entropy(['user' + str(i) for i in range(50)]),
        success_ratio=0.0,
        num_failed_ports=2,
        avg_time_between_attempts=0.5,
        login_interval_variance=0.1,
        time_of_day_avg=14400.0,   # 4 AM
        num_failed_days=1,
        ip_entropy=_ip_entropy('185.220.101.42'),
        client_version_category=3,  # go
        time_to_auth=0.05,
        session_duration=120.0,
        min_inter_arrival=0.001,
        max_inter_arrival=2.0,
    )
    X_burst = np.array([_feature_dict_to_vector(burst)])
    p_burst = model.predict_proba(X_burst)[0][1]
    scenarios.append({
        'scenario': 'Burst Attack',
        'description': '200 failed logins/hour, 50 unique usernames, Go SSH client, 0% success',
        'prediction': 'Attack' if p_burst > 0.5 else 'Benign',
        'probability': p_burst,
        'expected': 'Attack',
        'correct': p_burst > 0.5,
    })

    # 2. Low-and-Slow: 6 failed per hour, 6 unique users, high entropy
    slow_users = ['admin', 'root', 'test', 'operator', 'guest', 'ftpuser']
    slow = _make_feature_dict(
        failed_attempts=6,
        num_unique_users=6,
        username_entropy=_shannon_entropy(slow_users),
        success_ratio=0.0,
        num_failed_ports=1,
        avg_time_between_attempts=600.0,  # 10 min apart
        login_interval_variance=100.0,
        time_of_day_avg=10800.0,  # 3 AM
        num_failed_days=5,
        ip_entropy=_ip_entropy('45.33.32.156'),
        client_version_category=1,  # libssh
        time_to_auth=45.0,
        session_duration=7200.0,
        min_inter_arrival=300.0,
        max_inter_arrival=900.0,
    )
    X_slow = np.array([_feature_dict_to_vector(slow)])
    p_slow = model.predict_proba(X_slow)[0][1]
    scenarios.append({
        'scenario': 'Low-and-Slow Attack',
        'description': '6 failed/hour, 6 unique users, 10min intervals, 5 days persistent, libssh',
        'prediction': 'Attack' if p_slow > 0.5 else 'Benign',
        'probability': p_slow,
        'expected': 'Attack',
        'correct': p_slow > 0.5,
    })

    # 3. Benign Typo: 3 failures then 1 success, 1 username, OpenSSH
    benign = _make_feature_dict(
        failed_attempts=3,
        num_unique_users=1,
        username_entropy=0.0,  # same username
        success_ratio=0.25,    # 1 success / 4 total
        num_failed_ports=1,
        avg_time_between_attempts=5.0,  # 5s between typos
        login_interval_variance=2.0,
        time_of_day_avg=36000.0,  # 10 AM (working hours)
        num_failed_days=1,
        ip_entropy=_ip_entropy('192.168.1.100'),
        client_version_category=0,  # openssh
        time_to_auth=12.0,
        session_duration=900.0,
        min_inter_arrival=3.0,
        max_inter_arrival=20.0,
    )
    X_benign = np.array([_feature_dict_to_vector(benign)])
    p_benign = model.predict_proba(X_benign)[0][1]
    scenarios.append({
        'scenario': 'Benign Typo',
        'description': '3 typos then success, 1 username, OpenSSH, working hours, 25% success ratio',
        'prediction': 'Attack' if p_benign > 0.5 else 'Benign',
        'probability': p_benign,
        'expected': 'Benign',
        'correct': p_benign <= 0.5,
        'note': 'Expected FAIL on honeypot data — no legitimate users exist in training set.',
    })

    return scenarios


# ═══════════════════════════════════════════════════════════════════════════
# STEP 5 — NEAR REAL-TIME DEMO
# ═══════════════════════════════════════════════════════════════════════════

# SSH client categorisation (duplicate from feature_extraction for standalone use)
_CLIENT_RULES = [
    (r'openssh|OpenSSH', 0),
    (r'paramiko', 2),
    (r'libssh', 1),
    (r'\bGo\b', 3),
    (r'PuTTY|putty', 4),
    (r'ZGrab|Nmap|nmap|zgrab|masscan|scanner', 5),
    (r'JSCH|phpseclib|makiko|dropbear|AsyncSSH|Twisted', 6),
]


def _classify_client(version: str) -> int:
    if not version or 'SSH-' not in version:
        return 7
    for pattern, cat in _CLIENT_RULES:
        if re.search(pattern, version, re.IGNORECASE):
            return cat
    return 7


def _parse_ts(ts: Any) -> datetime | None:
    if not isinstance(ts, str) or not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00')).astimezone(timezone.utc)
    except Exception:
        return None


def _floor_dt(dt: datetime, minutes: int) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    minute = (dt.minute // minutes) * minutes
    return dt.replace(minute=minute, second=0, microsecond=0)


def _seconds_from_midnight(dt: datetime) -> float:
    return dt.hour * 3600 + dt.minute * 60 + dt.second + dt.microsecond / 1_000_000


def run_near_realtime_demo(
    model: RandomForestClassifier,
    log_dir: Path,
    window_minutes: int = WINDOW_MINUTES,
    max_files: int = 5,
) -> list[dict]:
    """
    Simulate near real-time detection by streaming Cowrie JSON logs
    from numbered files (cowrie.json.1, .2, ...).

    For each completed time-window of events, extracts features and
    runs prediction. Measures latency per window.
    """
    # Prefer merged files first (same domain as training), fallback to old cowrie.json.N stream files.
    merged_files = sorted(log_dir.glob('cowrie_merged_*.json'))
    if merged_files:
        numbered_files = merged_files[:max_files]
    else:
        numbered_files = sorted(
            [f for f in log_dir.glob('cowrie.json.[0-9]*')
             if f.suffix.lstrip('.').isdigit() or f.name.split('.')[-1].isdigit()],
            key=lambda f: int(f.name.split('.')[-1]),
        )[:max_files]

    if not numbered_files:
        print('  [WARN] No demo log files found in', log_dir)
        return []

    print(f'  Streaming {len(numbered_files)} log files: {[f.name for f in numbered_files]}')
    if DEBUG_VIETNAMESE and merged_files:
        print('  [DEBUG-VI] Demo dang dung merged dataset (khop voi pipeline train/evaluate).')
    elif DEBUG_VIETNAMESE:
        print('  [DEBUG-VI] Demo dang fallback sang cowrie.json.N (nguon stream cu).')

    # --- Pass 1: Read all events, build session lookup, bucket by (ip, window) ---
    all_events: list[dict] = []
    for logfile in numbered_files:
        with logfile.open('r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        all_events.append(obj)
                except json.JSONDecodeError:
                    continue

    if not all_events:
        print('  [WARN] No events parsed.')
        return []

    print(f'  Total events streamed: {len(all_events):,}')

    # Build session lookup
    session_dst_port: dict[str, int] = {}
    session_client_ver: dict[str, str] = {}
    session_connect_ts: dict[str, datetime] = {}
    session_duration_s: dict[str, float] = {}
    for ev in all_events:
        eid = ev.get('eventid', '')
        sess = str(ev.get('session') or '')
        if eid == 'cowrie.session.connect' and ev.get('dst_port') is not None:
            session_dst_port[sess] = int(ev['dst_port'])
            ts_c = _parse_ts(ev.get('timestamp'))
            if ts_c and sess not in session_connect_ts:
                session_connect_ts[sess] = ts_c
        elif eid == 'cowrie.client.version':
            session_client_ver[sess] = str(ev.get('version') or '')
        elif eid == 'cowrie.session.closed':
            d = ev.get('duration')
            if isinstance(d, (int, float)):
                session_duration_s[sess] = float(d)

    # Bucket login events
    ip_win_failed: dict[tuple[str, str], list[dict]] = defaultdict(list)
    ip_win_success: dict[tuple[str, str], list[dict]] = defaultdict(list)

    for ev in all_events:
        eid = ev.get('eventid', '')
        if eid not in ('cowrie.login.failed', 'cowrie.login.success'):
            continue
        src_ip = str(ev.get('src_ip') or '')
        if not src_ip:
            continue
        ts = _parse_ts(ev.get('timestamp'))
        if ts is None:
            continue
        win_key = _floor_dt(ts, window_minutes).isoformat().replace('+00:00', 'Z')
        sess = str(ev.get('session') or '')
        rec = {
            'timestamp': ts,
            'username': str(ev.get('username') or ''),
            'session': sess,
            'dst_port': session_dst_port.get(sess),
            'client_version': session_client_ver.get(sess, ''),
        }
        if eid == 'cowrie.login.failed':
            ip_win_failed[(src_ip, win_key)].append(rec)
        else:
            ip_win_success[(src_ip, win_key)].append(rec)

    all_keys = sorted(set(ip_win_failed.keys()) | set(ip_win_success.keys()),
                      key=lambda k: (k[1], k[0]))

    # Pre-compute cross-window: num_failed_days per IP
    ip_failed_days: dict[str, set[str]] = defaultdict(set)
    for (ip, _), recs in ip_win_failed.items():
        for r in recs:
            ip_failed_days[ip].add(r['timestamp'].strftime('%Y-%m-%d'))

    # --- Pass 2: Extract features per window & predict ---
    results: list[dict] = []
    for src_ip, win_key in all_keys:
        t_start = time.perf_counter()

        failed = ip_win_failed.get((src_ip, win_key), [])
        success = ip_win_success.get((src_ip, win_key), [])
        failed_count = len(failed)
        success_count = len(success)
        total = failed_count + success_count

        usernames = [r['username'] for r in failed]
        num_unique = len(set(usernames))
        u_entropy = _shannon_entropy(usernames)
        s_ratio = round(success_count / total, 6) if total > 0 else 0.0

        ports = {r['dst_port'] for r in failed if r['dst_port'] is not None}
        n_ports = len(ports)

        failed_ts = sorted(r['timestamp'] for r in failed)
        intervals = []
        for i in range(1, len(failed_ts)):
            intervals.append((failed_ts[i] - failed_ts[i - 1]).total_seconds())
        avg_interval = round(statistics.mean(intervals), 6) if intervals else 0.0
        var_interval = round(statistics.variance(intervals), 6) if len(intervals) >= 2 else 0.0

        all_ts = [r['timestamp'] for r in failed] + [r['timestamp'] for r in success]
        tod_avg = round(statistics.mean(_seconds_from_midnight(t) for t in all_ts), 6) if all_ts else 0.0

        n_fail_days = len(ip_failed_days.get(src_ip, set()))

        versions = [r['client_version'] for r in failed + success if r['client_version']]
        if versions:
            cats = Counter(_classify_client(v) for v in versions)
            client_cat = cats.most_common(1)[0][0]
        else:
            client_cat = 7

        all_login = failed + success
        window_sessions = {r['session'] for r in all_login if r.get('session')}
        tta_vals: list[float] = []
        for sid in window_sessions:
            conn_ts = session_connect_ts.get(sid)
            if conn_ts is None:
                continue
            first_login = None
            for e in all_login:
                if e.get('session') == sid:
                    if first_login is None or e['timestamp'] < first_login:
                        first_login = e['timestamp']
            if first_login and first_login > conn_ts:
                tta_vals.append((first_login - conn_ts).total_seconds())
        time_to_auth = round(statistics.mean(tta_vals), 6) if tta_vals else 0.0

        sdur_vals = [session_duration_s[sid] for sid in window_sessions
                     if sid in session_duration_s and session_duration_s[sid] > 0]
        session_duration_feat = round(statistics.mean(sdur_vals), 6) if sdur_vals else 0.0

        min_inter = round(min(intervals), 6) if intervals else 0.0
        max_inter = round(max(intervals), 6) if intervals else 0.0

        if all_ts:
            wh = all_ts[0].hour
        else:
            wh = 12
        hour_sin = round(math.sin(2 * math.pi * wh / 24), 6)
        hour_cos = round(math.cos(2 * math.pi * wh / 24), 6)

        feature_dict = {
            'failed_attempts': failed_count,
            'num_unique_users': num_unique,
            'username_entropy': u_entropy,
            'success_ratio': s_ratio,
            'num_failed_ports': n_ports,
            'avg_time_between_attempts': avg_interval,
            'login_interval_variance': var_interval,
            'time_of_day_avg': tod_avg,
            'num_failed_days': n_fail_days,
            'ip_entropy': _ip_entropy(src_ip),
            'client_version_category': client_cat,
            'time_to_auth': time_to_auth,
            'session_duration': session_duration_feat,
            'min_inter_arrival': min_inter,
            'max_inter_arrival': max_inter,
            'hour_sin': hour_sin,
            'hour_cos': hour_cos,
        }
        feature_vec = np.array([_feature_dict_to_vector(feature_dict)])

        proba = model.predict_proba(feature_vec)[0][1]
        alert = proba > ALERT_THRESHOLD

        t_end = time.perf_counter()
        latency_ms = (t_end - t_start) * 1000

        results.append({
            'ip': src_ip,
            'window_start': win_key,
            'failed_attempts': failed_count,
            'probability': proba,
            'alert': alert,
            'latency_ms': latency_ms,
        })

    n_alerts = sum(1 for r in results if r['alert'])
    latencies = [r['latency_ms'] for r in results]
    avg_lat = statistics.mean(latencies) if latencies else 0
    p95_lat = sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0

    print(f'  So cua so da xu ly: {len(results)}')
    print(f'  So canh bao:        {n_alerts}  (nguong P > {ALERT_THRESHOLD})')
    print(f'  Do tre trung binh:  {avg_lat:.2f} ms')
    print(f'  Do tre P95:         {p95_lat:.2f} ms')
    if DEBUG_VIETNAMESE:
        print('  [DEBUG-VI] Y nghia thong so demo:')
        print('    - Windows processed: so cua so thoi gian da duoc suy luan')
        print('    - Alerts issued: so cua so co xac suat Attack vuot nguong canh bao')
        print('    - Avg/P95 latency: do tre du doan trung binh va phan vi 95%')

    return results


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(description='Train, evaluate & demo Cowrie ML pipeline')
    parser.add_argument('--train', action='store_true', help='Train + evaluate only')
    parser.add_argument('--demo', action='store_true', help='Demo only (requires saved model)')
    parser.add_argument('--features-json', default=None, help='Override path to ml_features.json')
    parser.add_argument('--model-path', default=None, help='Override path to save/load .pkl model')
    parser.add_argument('--report-dir', default=None, help='Override reports output directory')
    parser.add_argument('--demo-log-dir', default=None, help='Override directory for near-real-time demo')
    parser.add_argument(
        '--metrics-json',
        default=None,
        help='Write compact train/val/test metrics JSON (for ratio ablation / automation)',
    )
    parser.add_argument('--skip-demo', action='store_true', help='Skip near-real-time demo step')
    parser.add_argument('--skip-shap', action='store_true', help='Skip SHAP (faster batch runs)')
    parser.add_argument('--skip-scenarios', action='store_true',
                        help='Skip ratio scenario ablation study (RQ8)')
    parser.add_argument('--scenario-ids', default='',
                        help='Comma-separated scenario ids (default: all 5)')
    args = parser.parse_args()

    features_json = Path(args.features_json) if args.features_json else FEATURES_JSON
    model_path = Path(args.model_path) if args.model_path else MODEL_PATH
    report_dir = Path(args.report_dir) if args.report_dir else REPORT_DIR
    demo_log_dir = Path(args.demo_log_dir) if args.demo_log_dir else DEMO_LOG_DIR

    run_train = not args.demo or args.train  # default: run both
    run_demo = (not args.train or args.demo) and not args.skip_demo

    log = ViLogger('Step5')

    results = None
    model = None
    audit = None
    univariate_scan = None
    shap_info = None
    rolling_cv = None
    robustness = None
    plots: dict[str, str] = {}
    train_accuracy: float | None = None
    df: pd.DataFrame | None = None

    if run_train:
        log.section('BƯỚC 4: HUẤN LUYỆN MÔ HÌNH')

        log.info(f'[4.1] Nạp đặc trưng từ {features_json} ...')
        df = load_features(features_json)
        log.ok(f'Đã nạp {len(df)} dòng dữ liệu.')
        log.debug(f'Kiểm tra nguồn đặc trưng: file này phải được tạo từ feature_extraction.py trên merged logs.')
        log.debug(f'TARGET_COLUMN = {TARGET_COLUMN}  (nhãn theo data_origin, không rò rỉ)')
        log.debug(f'ML_FEATURE_COLUMNS ({len(ML_FEATURE_COLUMNS)}): {ML_FEATURE_COLUMNS}')
        log.debug(f'SHORTCUT_FEATURES (đã loại bỏ): {SHORTCUT_FEATURES}')

        log.info('[4.2] Huấn luyện Random Forest (n_estimators=100) ...')
        results = train_model(df)

        # Compute train accuracy for verification
        y_train_pred = results['model'].predict(results['X_train'])
        train_accuracy = float(accuracy_score(results['y_train'], y_train_pred))

        log.ok('Huấn luyện hoàn tất. Kết quả trên tập Test:')
        log.info(f'  Accuracy:  {results["accuracy"]:.4f}')
        log.info(f'  Precision: {results["precision"]:.4f}')
        log.info(f'  Recall:    {results["recall"]:.4f}')
        log.info(f'  F1-Score:  {results["f1"]:.4f}')
        log.info(f'  ROC AUC:   {results["auc"]:.4f}')
        log.info(f'  PR-AUC:    {results["pr_auc"]:.4f}')
        log.info(f'  Train Acc: {train_accuracy:.4f}')

        log.debug('Giải thích nhanh metric:')
        log.debug('  - Accuracy: tỉ lệ dự đoán đúng tổng thể')
        log.debug('  - Precision: trong các điểm model báo Attack, bao nhiêu điểm đúng')
        log.debug('  - Recall: model bắt được bao nhiêu Attack thật')
        log.debug('  - F1: cân bằng giữa Precision và Recall')
        log.debug('  - ROC AUC: khả năng tách 2 lớp trên nhiều ngưỡng')

        for tpr_label, fpr_val in results.get('fpr_at_tpr', {}).items():
            log.info(f'  {tpr_label}: {fpr_val:.4f}')

        log.info('[4.2b] Kiểm tra nguy cơ rò rỉ dữ liệu (Leakage Audit A/B/C/D) ...')
        audit = run_leakage_audit(df)
        risk = audit['leakage_risk']
        if risk == 'HIGH':
            log.warn(f'Mức độ rủi ro rò rỉ: {risk}')
        else:
            log.ok(f'Mức độ rủi ro rò rỉ: {risk}')
        best = audit['best_single_feature']
        log.info(
            f'  Baseline 1-feature tốt nhất: {best["feature"]} {best["rule"]} '
            f'{best["threshold"]:.6f} | Test F1={best["test_f1"]:.4f}, '
            f'Test Acc={best["test_acc"]:.4f}'
        )
        ov = audit['overlap']
        log.info(
            f'  Overlap hash train/test: {ov["train_test_overlap"]} dòng '
            f'({ov["train_test_overlap_ratio"]*100:.2f}% tập test)'
        )
        hm = audit['hard_feature_metrics']
        log.info(
            f'  Stress test (bỏ đặc trưng dễ): '
            f'Acc={hm["accuracy"]:.4f}, F1={hm["f1"]:.4f}, AUC={hm["auc"]:.4f}'
        )
        if audit['reasons']:
            log.warn('Nhận xét:')
            for reason in audit['reasons']:
                log.warn(f'  - {reason}')
        else:
            log.ok('Nhận xét: chưa thấy dấu hiệu rò rỉ rõ ràng theo bộ test nhanh.')

        log.info('[4.2c] Quét đơn biến AUC/F1 (Univariate scan) ...')
        univariate_scan = run_univariate_scan(df)
        for s in univariate_scan:
            log.debug(
                f'  {s["feature"]:35s}  AUC={s["univariate_auc"]:.4f}  '
                f'F1={s["best_threshold_f1"]:.4f}  ({s["rule"]} {s["threshold"]:.4f})'
            )

        log.info('[4.3] Lưu mô hình ...')
        model = results['model']
        model_path.parent.mkdir(parents=True, exist_ok=True)
        save_model(model, model_path)
        log.ok(f'Mô hình đã lưu tại {model_path}')

        log.info('[4.4] Tạo các biểu đồ ...')
        plots = generate_plots(results, report_dir)
        for name, fname in plots.items():
            log.ok(f'  Biểu đồ: {name} → {fname}')

        log.info('[4.5] Kiểm thử độ bền (Robustness) ...')
        robustness = run_robustness_tests(model)
        for r in robustness:
            status = 'PASS' if r['correct'] else 'FAIL'
            if r['correct']:
                log.ok(f'  [{status}] {r["scenario"]}: P(Attack)={r["probability"]:.4f} → {r["prediction"]}')
            else:
                log.warn(f'  [{status}] {r["scenario"]}: P(Attack)={r["probability"]:.4f} → {r["prediction"]}')
        log.debug('Nếu kịch bản Benign Typo bị FAIL thì model đang nhạy cảm với lỗi nhẹ của user thật.')

        log.info('[4.6] Phân tích SHAP ...')
        shap_info = None
        if not args.skip_shap:
            shap_info = run_shap_analysis(results['model'], results['X_train'], report_dir)
        if shap_info:
            for name, val in shap_info['feature_shap']:
                log.debug(f'  {name:35s}  mean|SHAP|={val:.6f}')
            log.ok('Phân tích SHAP hoàn tất.')
        else:
            if args.skip_shap:
                log.info('  [BỎ QUA] --skip-shap được chỉ định.')
            else:
                log.warn('  SHAP không khả dụng (thiếu thư viện shap).')

        log.info('[4.7] Cross-validation chuỗi thời gian (Rolling CV) ...')
        rolling_cv = run_rolling_cv(df)
        if rolling_cv.get('folds'):
            for fr in rolling_cv['folds']:
                log.debug(
                    f'  Fold {fr["fold"]}: F1={fr["f1"]:.4f}  AUC={fr["auc"]:.4f}  '
                    f'PR-AUC={fr["pr_auc"]:.4f}  (train={fr["train_rows"]}, test={fr["test_rows"]})'
                )
            sm = rolling_cv.get('summary', {})
            if 'f1' in sm:
                log.ok(
                    f'  Tổng hợp: F1={sm["f1"]["mean"]:.4f}±{sm["f1"]["std"]:.4f}  '
                    f'AUC={sm["auc"]["mean"]:.4f}±{sm["auc"]["std"]:.4f}'
                )
        else:
            log.warn('Không tạo được fold — không đủ cửa sổ thời gian.')

        if args.metrics_json:
            train_df = df[df['split'] == 'train']
            val_df = df[df['split'] == 'val']
            test_df = df[df['split'] == 'test']
            n_tr_a = int(train_df[TARGET_COLUMN].sum())
            n_tr_b = len(train_df) - n_tr_a
            n_va_a = int(val_df[TARGET_COLUMN].sum())
            n_va_b = len(val_df) - n_va_a
            n_te_a = int(test_df[TARGET_COLUMN].sum())
            n_te_b = len(test_df) - n_te_a
            metrics_payload: dict[str, Any] = {
                'features_json': str(features_json),
                'train_rows': len(train_df),
                'train_attack': n_tr_a,
                'train_benign': n_tr_b,
                'train_benign_share': round(n_tr_b / max(len(train_df), 1), 6),
                'val_rows': len(val_df),
                'val_attack': n_va_a,
                'val_benign': n_va_b,
                'test_rows': len(test_df),
                'test_attack': n_te_a,
                'test_benign': n_te_b,
                'val_f1': float(results['val_f1']),
                'val_macro_f1': float(results['val_macro_f1'])
                if not math.isnan(results['val_macro_f1'])
                else None,
                'val_auc': float(results['val_auc']),
                'test_accuracy': float(results['accuracy']),
                'test_precision': float(results['precision']),
                'test_recall': float(results['recall']),
                'test_f1': float(results['f1']),
                'test_macro_f1': float(results['test_macro_f1'])
                if not math.isnan(results['test_macro_f1'])
                else None,
                'train_macro_f1': float(results['train_macro_f1'])
                if not math.isnan(results['train_macro_f1'])
                else None,
                'test_auc': float(results['auc']),
                'test_pr_auc': float(results['pr_auc']),
                'leakage_risk': audit.get('leakage_risk'),
            }
            mp = Path(args.metrics_json)
            mp.parent.mkdir(parents=True, exist_ok=True)
            with mp.open('w', encoding='utf-8') as mf:
                json.dump(metrics_payload, mf, indent=2, ensure_ascii=False)
            log.ok(f'[4.8] Metrics JSON đã ghi → {mp}')

    # ── Ratio scenario ablation (RQ8) ──
    scenario_rows: list[dict[str, Any]] | None = None
    if run_train and not args.skip_scenarios:
        log.section('BƯỚC 4.9: THỰC NGHIỆM TỈ LỆ (RQ8)')
        log.info('Chạy ablation study: 5 scenario benign:attack ratio ...')
        scenario_script = _PROJECT_ROOT / 'src' / 'run_ratio_scenarios.py'
        scenario_out = _PROJECT_ROOT / 'output' / 'ratio_study'
        scenario_cmd = [sys.executable, str(scenario_script), '--out-root', str(scenario_out)]
        if args.scenario_ids:
            scenario_cmd.extend(['--scenarios', args.scenario_ids])
        try:
            _subprocess_mod.run(scenario_cmd, cwd=str(_PROJECT_ROOT), check=True)
            comparison_json = scenario_out / 'scenario_comparison.json'
            if comparison_json.exists():
                with comparison_json.open('r', encoding='utf-8') as _sf:
                    scenario_rows = json.load(_sf)
                log.ok(f'Đã tải kết quả {len(scenario_rows)} scenario từ {comparison_json.name}')
            else:
                log.warn('Không tìm thấy scenario_comparison.json sau khi chạy.')
        except Exception as exc:
            log.warn(f'Thực nghiệm scenario thất bại: {exc}')
            scenario_rows = None
    elif run_train:
        log.info('Bỏ qua thực nghiệm scenario (--skip-scenarios).')

    else:
        log.info(f'Nạp mô hình đã lưu từ {model_path} ...')
        model = load_model(model_path)
        log.ok('Đã nạp mô hình.')

    demo_results = None
    if run_demo:
        log.section('BƯỚC 5: DEMO GẦN THỜI GIAN THỰC')

        if model is None:
            model = load_model(model_path)

        log.info(f'[5.1] Mô phỏng luồng dữ liệu từ {demo_log_dir} ...')
        demo_results = run_near_realtime_demo(
            model, demo_log_dir,
            window_minutes=WINDOW_MINUTES,
            max_files=30,
        )
        if demo_results:
            n_alerts = sum(1 for d in demo_results if d.get('alert'))
            log.ok(f'Demo hoàn tất: {len(demo_results)} cửa sổ, {n_alerts} cảnh báo.')
        else:
            log.warn('Demo không tạo ra kết quả (có thể thiếu file log).')

    # --- Generate final HTML report ---
    log.section('TẠO BÁO CÁO ĐÁNH GIÁ')

    if results is None:
        log.warn('Không có metric huấn luyện, báo cáo chỉ gồm kết quả demo.')
        report_path = report_dir / 'evaluation_report.html'
        report_dir.mkdir(parents=True, exist_ok=True)
        if demo_results:
            n_alerts = sum(1 for d in demo_results if d.get('alert'))
            report_path.write_text(
                f'<html><body><h1>Demo Results</h1><p>Windows: {len(demo_results)}, Alerts: {n_alerts}</p></body></html>',
                encoding='utf-8',
            )
            log.ok(f'Báo cáo demo → {report_path}')
    else:
        report_path = generate_html_report(
            results, plots, robustness, demo_results, report_dir,
            univariate_scan=univariate_scan,
            shap_info=shap_info,
            rolling_cv=rolling_cv,
            leakage_audit=audit,
            log=log,
            model_path=model_path,
            train_accuracy=train_accuracy,
            scenario_comparison=scenario_rows,
            dataset_quality_df=df,
        )
        log.ok(f'Báo cáo đánh giá → {report_path}')

    log.ok('Hoàn tất pipeline Step 5.')
    log.debug('Nếu metric quá đẹp, hãy xem lại nguy cơ label leakage ở feature_extraction.py.')


if __name__ == '__main__':
    main()
