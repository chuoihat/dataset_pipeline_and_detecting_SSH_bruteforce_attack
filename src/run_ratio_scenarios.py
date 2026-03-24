#!/usr/bin/env python3
"""
Step 6: Ratio Scenario Ablation Study (RQ8)
============================================

Runs the full sub-pipeline (Step 3B → 3C → 4 → 5) for each benign:attack
ratio scenario.  Produces:

  * Per-scenario artefacts under ``output/ratio_study/<scenario_id>/``
    (each contains its own Step 5 HTML report, model, and metrics).
  * A **unified HTML comparison report** with embedded charts that lets
    an ML / security expert compare all scenarios at a glance.

Scientific basis (design of scenario count):
  - He & Garcia (2009): class imbalance handling; compare multiple
    training priors.
  - Cochran (1977): stratified bootstrap — proportional archetypes.
  - Arp et al. (2022): report evaluation limits (e.g. temporal test
    with one class).

Usage (from repository root)::

    python3 src/run_ratio_scenarios.py
    python3 src/run_ratio_scenarios.py --scenarios S0_natural,S2_1to1
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from utils.report_utils import (        # noqa: E402
    ViLogger, html_header, html_footer, html_toc, html_section,
    html_cards, html_table, html_chart, html_decision,
    html_verification_section, html_debug_log, write_html,
    make_bar_chart, make_pie_chart,
)


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Scenario:
    id: str
    ratio: str          # 'natural' or 'A:B'
    title_vi: str
    intent_vi: str


DEFAULT_SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        'S0_natural', 'natural',
        'S0 — Tự nhiên (không upscale)',
        'Baseline: chỉ 893 phiên benign thật, không synthetic — đo stress mất cân bằng.',
    ),
    Scenario(
        'S1_1to2', '1:2',
        'S1 — Benign:Attack = 1:2',
        'Attack-heavy: ít benign hơn — kiểm tra false positive khi benign hiếm.',
    ),
    Scenario(
        'S2_1to1', '1:1',
        'S2 — Benign:Attack ≈ 1:1 (mặc định)',
        'Cân bằng mục tiêu session vs tham chiếu attack (He & Garcia, 2009).',
    ),
    Scenario(
        'S3_2to1', '2:1',
        'S3 — Benign:Attack = 2:1',
        'Benign gấp đôi attack — giảm thiên attack, tăng nhạy benign.',
    ),
    Scenario(
        'S4_3to1', '3:1',
        'S4 — Benign:Attack = 3:1',
        'Stress test over-sampling: rủi ro overfit benign synthetic pattern.',
    ),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _run(cmd: list[str], cwd: Path, log: ViLogger) -> None:
    short = ' '.join(cmd[1:3]) + ' ...'
    log.debug(f'Chạy: {short}')
    result = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if result.returncode != 0:
        log.fail(f'Lệnh thất bại (exit {result.returncode})')
        if result.stderr:
            for line in result.stderr.strip().split('\n')[-10:]:
                log.warn(f'  stderr: {line}')
        raise subprocess.CalledProcessError(result.returncode, cmd)


def _safe(v: Any, fmt: str = '.4f') -> str:
    if v is None:
        return 'N/A'
    try:
        return format(float(v), fmt)
    except (TypeError, ValueError):
        return str(v)


# ---------------------------------------------------------------------------
# HTML comparison report
# ---------------------------------------------------------------------------
def _build_comparison_html(
    scenarios: list[Scenario],
    rows: list[dict[str, Any]],
    out_root: Path,
    log: ViLogger,
) -> str:
    """Build a comprehensive standalone HTML report comparing all scenarios."""

    toc = [
        ('overview', '1. Tổng quan thiết kế thực nghiệm'),
        ('data-split', '2. Phân bố dữ liệu huấn luyện'),
        ('metrics-table', '3. Bảng so sánh metric'),
        ('charts', '4. Biểu đồ so sánh'),
        ('leakage', '5. Kiểm tra rò rỉ dữ liệu'),
        ('expert', '6. Đánh giá chuyên gia'),
        ('links', '7. Liên kết báo cáo chi tiết'),
        ('debug', '8. Nhật ký debug'),
    ]

    parts: list[str] = []
    parts.append(html_header(
        'Step 6 — So sánh Scenario Tỉ lệ Benign:Attack (RQ8)',
        'RQ8', f'{len(rows)} scenario | Ablation study',
    ))
    parts.append(html_toc(toc))

    # ── 1. Overview ──
    parts.append(html_section('overview', '1. Tổng quan thiết kế thực nghiệm'))
    parts.append(html_decision(
        'RQ8: Tỉ lệ upscale 1:1 — có phải tối ưu?',
        '<p>Thay vì chỉ chọn một tỉ lệ duy nhất, chúng ta thiết kế <b>5 scenario</b> '
        'thực nghiệm với các tỉ lệ benign:attack khác nhau, giữ nguyên '
        'dữ liệu attack và chỉ thay đổi lượng benign synthetic. '
        'Mỗi scenario chạy đầy đủ sub-pipeline: Step 3B → 3C → 4 → 5.</p>'
        '<p>Mục tiêu: cung cấp bằng chứng thực nghiệm cho việc chọn tỉ lệ, '
        'thay vì dựa hoàn toàn vào lý thuyết.</p>',
        'He & Garcia (2009): Không có tỉ lệ sampling nào là tối ưu phổ quát — '
        'cần thực nghiệm trên từng bài toán cụ thể. '
        'Arp et al. (2022): Báo cáo giới hạn đánh giá khi temporal split chỉ có 1 lớp.',
    ))

    scenario_rows = []
    for sc in scenarios:
        scenario_rows.append([sc.id, sc.ratio, sc.title_vi, sc.intent_vi])
    parts.append(html_table(
        ['ID', 'Tỉ lệ', 'Tên', 'Mục đích'],
        scenario_rows,
    ))

    # ── 2. Data split ──
    parts.append(html_section('data-split', '2. Phân bố dữ liệu huấn luyện'))

    split_rows = []
    for r in rows:
        sid = r.get('scenario_id', '')
        split_rows.append([
            sid, r.get('ratio', ''),
            r.get('train_rows', 0),
            r.get('train_attack', 0),
            r.get('train_benign', 0),
            _safe(r.get('train_benign_share'), '.2%'),
            r.get('val_rows', 0),
            r.get('test_rows', 0),
        ])
    parts.append(html_table(
        ['Scenario', 'Ratio', 'Train rows', 'Train attack',
         'Train benign', 'Benign share', 'Val rows', 'Test rows'],
        split_rows,
    ))

    sids = [r.get('scenario_id', '') for r in rows]
    train_attack = [r.get('train_attack', 0) for r in rows]
    train_benign = [r.get('train_benign', 0) for r in rows]
    if any(train_attack) or any(train_benign):
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            fig, ax = plt.subplots(figsize=(10, 5))
            x = range(len(sids))
            w = 0.35
            ax.bar([i - w / 2 for i in x], train_attack, w, label='Attack', color='#e53e3e')
            ax.bar([i + w / 2 for i in x], train_benign, w, label='Benign', color='#38a169')
            ax.set_xticks(list(x))
            ax.set_xticklabels(sids, rotation=15)
            ax.set_ylabel('Số feature vectors')
            ax.set_title('Phân bố Attack vs Benign trong tập Train')
            ax.legend()
            fig.tight_layout()
            from utils.report_utils import fig_to_base64, img_tag
            parts.append(html_chart(fig_to_base64(fig), 'Biểu đồ cột: attack vs benign per scenario'))
            plt.close(fig)
        except ImportError:
            log.warn('matplotlib không khả dụng — bỏ qua biểu đồ phân bố.')

    # ── 3. Metrics table ──
    parts.append(html_section('metrics-table', '3. Bảng so sánh metric'))

    main_metrics = [
        ('train_macro_f1', 'Train Macro-F1'),
        ('val_macro_f1', 'Val Macro-F1'),
        ('val_f1', 'Val F1 (Attack)'),
        ('val_auc', 'Val AUC'),
        ('test_macro_f1', 'Test Macro-F1'),
        ('test_f1', 'Test F1 (Attack)'),
        ('test_auc', 'Test AUC'),
        ('test_pr_auc', 'Test PR-AUC'),
        ('test_accuracy', 'Test Accuracy'),
        ('test_precision', 'Test Precision'),
        ('test_recall', 'Test Recall'),
    ]

    metric_headers = ['Scenario', 'Ratio'] + [m[1] for m in main_metrics]
    metric_rows = []
    for r in rows:
        row = [r.get('scenario_id', ''), r.get('ratio', '')]
        for key, _ in main_metrics:
            row.append(_safe(r.get(key)))
        metric_rows.append(row)
    parts.append(html_table(metric_headers, metric_rows))

    parts.append(
        '<details><summary><b>Giải thích cách đọc bảng</b></summary>'
        '<table><tr><th>Metric</th><th>Ý nghĩa</th><th>Đọc kết quả</th></tr>'
        '<tr><td><b>Train Macro-F1</b></td>'
        '<td>Trung bình F1 của cả 2 lớp trên tập train</td>'
        '<td>Phản ánh khả năng học tương đối công bằng giữa attack và benign. '
        'So sánh giữa các scenario để thấy tỉ lệ nào giúp model học cân bằng nhất.</td></tr>'
        '<tr><td><b>Val Macro-F1</b></td>'
        '<td>Macro-F1 trên tập validation (temporal split)</td>'
        '<td>Đánh giá generalization tốt hơn train. '
        'Nếu chênh lệch lớn so với Train → overfitting.</td></tr>'
        '<tr><td><b>Test Macro-F1</b></td>'
        '<td>Macro-F1 trên tập test (temporal split cuối)</td>'
        '<td><b>Chỉ tin cậy khi test có đủ 2 lớp.</b> '
        'N/A = chỉ có 1 lớp trong test set → Arp et al. (2022).</td></tr>'
        '<tr><td><b>Test AUC</b></td>'
        '<td>Area Under ROC Curve — khả năng phân tách 2 lớp</td>'
        '<td>Gần 1.0 = tốt. Nếu gần 0.5 = random. '
        'So sánh giữa scenario: AUC ổn định = model robust.</td></tr>'
        '<tr><td><b>Test PR-AUC</b></td>'
        '<td>Area Under Precision-Recall Curve</td>'
        '<td>Phù hợp hơn AUC khi dữ liệu mất cân bằng. '
        'Cao = model giữ precision tốt ở mọi mức recall.</td></tr>'
        '<tr><td><b>Leakage risk</b></td>'
        '<td>Kết quả kiểm tra rò rỉ dữ liệu nhanh</td>'
        '<td>Phải ổn định qua tất cả scenario. Nếu đột biến → kiểm tra merge/neutralization.</td></tr>'
        '</table></details>'
    )

    # ── 4. Charts ──
    parts.append(html_section('charts', '4. Biểu đồ so sánh'))

    chart_metrics = [
        ('train_macro_f1', 'Train Macro-F1', '#3182ce'),
        ('val_macro_f1', 'Val Macro-F1', '#805ad5'),
        ('test_f1', 'Test F1 (Attack)', '#e53e3e'),
        ('test_auc', 'Test AUC', '#dd6b20'),
        ('test_pr_auc', 'Test PR-AUC', '#38a169'),
    ]

    for key, label, color in chart_metrics:
        values = []
        labels = []
        for r in rows:
            v = r.get(key)
            if v is not None:
                try:
                    values.append(float(v))
                    labels.append(r.get('scenario_id', ''))
                except (TypeError, ValueError):
                    pass
        if values:
            parts.append(html_chart(
                make_bar_chart(
                    labels, values,
                    title=f'{label} theo Scenario',
                    ylabel=label,
                    color=color,
                    figsize=(10, 4),
                ),
                f'So sánh {label} giữa các scenario thực nghiệm',
            ))

    # Grouped bar: Train vs Val Macro-F1
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        train_f1s = []
        val_f1s = []
        chart_sids = []
        for r in rows:
            tf = r.get('train_macro_f1')
            vf = r.get('val_macro_f1')
            if tf is not None and vf is not None:
                train_f1s.append(float(tf))
                val_f1s.append(float(vf))
                chart_sids.append(r.get('scenario_id', ''))
        if train_f1s:
            fig, ax = plt.subplots(figsize=(10, 5))
            x = range(len(chart_sids))
            w = 0.35
            ax.bar([i - w / 2 for i in x], train_f1s, w, label='Train Macro-F1', color='#3182ce')
            ax.bar([i + w / 2 for i in x], val_f1s, w, label='Val Macro-F1', color='#805ad5')
            ax.set_xticks(list(x))
            ax.set_xticklabels(chart_sids, rotation=15)
            ax.set_ylabel('Macro-F1')
            ax.set_title('Train vs Val Macro-F1 — Phát hiện Overfitting')
            ax.legend()
            ax.set_ylim(0, 1.05)
            fig.tight_layout()
            from utils.report_utils import fig_to_base64
            parts.append(html_chart(
                fig_to_base64(fig),
                'So sánh Train vs Val Macro-F1: chênh lệch lớn = overfitting',
            ))
            plt.close(fig)
    except ImportError:
        pass

    # ── 5. Leakage comparison ──
    parts.append(html_section('leakage', '5. Kiểm tra rò rỉ dữ liệu'))
    leak_rows = []
    for r in rows:
        leak_rows.append([
            r.get('scenario_id', ''),
            r.get('leakage_risk', 'N/A'),
        ])
    parts.append(html_table(['Scenario', 'Leakage Risk'], leak_rows))

    leak_values = set(r.get('leakage_risk', '') for r in rows)
    if len(leak_values) == 1:
        parts.append(html_decision(
            'Leakage ổn định',
            f'<p class="good">Tất cả scenario có cùng mức leakage risk: '
            f'<b>{leak_values.pop()}</b>. Merge/neutralization hoạt động nhất quán.</p>',
        ))
    else:
        parts.append(html_decision(
            'Cảnh báo: Leakage không nhất quán',
            f'<p class="warn">Các scenario có mức leakage khác nhau: '
            f'{leak_values}. Cần kiểm tra lại merge/neutralization.</p>',
            'Arp et al. (2022): inconsistent leakage across experiments '
            'suggests data assembly artifacts.',
        ))

    # ── 6. Expert commentary ──
    parts.append(html_section('expert', '6. Đánh giá chuyên gia'))
    parts.append(html_decision(
        'Góc nhìn An ninh thông tin (SOC / Blue Team)',
        '<ul>'
        '<li><b>S0 (natural)</b>: Baseline mất cân bằng thật. '
        'Model có thể thiên về lớp đa số — cần đọc recall/precision theo lớp.</li>'
        '<li><b>S1 (1:2)</b>: Attack-heavy, benign ít hơn. '
        'Có thể <span class="good">tăng nhạy với attack</span> nhưng '
        '<span class="warn">tăng báo động giả</span> nếu synthetic benign chưa đủ đa dạng.</li>'
        '<li><b>S2 (1:1)</b>: Điểm làm việc cân bằng. '
        'Dễ so sánh công bằng giữa các thí nghiệm feature/neutralization.</li>'
        '<li><b>S3 (2:1) / S4 (3:1)</b>: Tăng trọng benign → giảm false alarm '
        'nhưng tăng rủi ro <span class="warn">học artifact synthetic</span> '
        '(Sommer & Paxson, 2010: domain shift).</li>'
        '</ul>',
        'Owezarski (2015): SOC ưu tiên recall cao (bắt hết attack) khi '
        'false alarm cost thấp. Ngược lại, môi trường production '
        'ưu tiên precision (giảm alert fatigue).',
    ))
    parts.append(html_decision(
        'Góc nhìn Học máy (Generalization / Evaluation)',
        '<ul>'
        '<li><b>Random Forest</b> đã dùng <code>class_weight="balanced"</code> '
        '— khác biệt giữa scenario đến từ <b>phân phối mẫu + tổng hợp</b> '
        'chứ không chỉ từ trọng số lớp.</li>'
        '<li><b>Macro-F1 trên train</b> giúp so sánh học tương đối công bằng '
        'giữa lớp; <b>test temporal</b> có thể chỉ chứa 1 lớp — khi đó '
        'test metric phải đọc kèm cảnh báo.</li>'
        '<li><b>Leakage audit</b> phải <b>ổn định</b> qua các scenario; '
        'nếu đột biến → kiểm tra lại merge/neutralization và tỉ lệ synthetic.</li>'
        '<li>Scenario có <b>Val Macro-F1 gần Train Macro-F1</b> nhất = '
        'generalize tốt nhất (ít overfitting).</li>'
        '</ul>',
        'He & Garcia (2009): Không có tỉ lệ sampling phổ quát. '
        'Arp et al. (2022): Temporal split yếu khi test chỉ có 1 lớp.',
    ))

    # Auto-pick best scenario
    best_sid, best_val = None, -1.0
    for r in rows:
        v = r.get('val_macro_f1')
        if v is not None:
            try:
                vf = float(v)
                if vf > best_val:
                    best_val = vf
                    best_sid = r.get('scenario_id')
            except (TypeError, ValueError):
                pass
    if best_sid:
        parts.append(html_decision(
            'Khuyến nghị tự động (heuristic)',
            f'<p>Scenario có <b>Val Macro-F1 cao nhất</b>: '
            f'<code>{best_sid}</code> ({best_val:.4f}). '
            f'Đây chỉ là heuristic — chọn scenario production cần xét '
            f'cost FN/FP và dữ liệu triển khai thật.</p>',
        ))

    # ── 7. Links ──
    parts.append(html_section('links', '7. Liên kết báo cáo chi tiết'))
    link_rows = []
    for sc in scenarios:
        sdir = out_root / sc.id
        step5_html = sdir / 'step5' / 'reports' / 'evaluation_report.html'
        step3b_html = sdir / 'step3b' / 'benign_expert_report.html'
        rel5 = step5_html.relative_to(out_root) if step5_html.exists() else 'N/A'
        rel3b = step3b_html.relative_to(out_root) if step3b_html.exists() else 'N/A'
        link_rows.append([
            sc.id, sc.ratio,
            f'<a href="{rel5}">{rel5}</a>' if step5_html.exists() else 'N/A',
            f'<a href="{rel3b}">{rel3b}</a>' if step3b_html.exists() else 'N/A',
        ])
    parts.append(html_table(
        ['Scenario', 'Ratio', 'Step 5 Report', 'Step 3B Report'],
        link_rows,
    ))

    # ── 8. Debug log ──
    parts.append(html_section('debug', '8. Nhật ký debug'))
    parts.append(html_debug_log(log))

    parts.append(html_footer())
    return '\n'.join(parts)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    root = Path(__file__).resolve().parent.parent
    py = sys.executable
    parser = argparse.ArgumentParser(
        description='Step 6: Ratio Scenario Ablation Study (RQ8)')
    parser.add_argument(
        '--scenarios', default='',
        help='Comma-separated scenario ids (default: all). '
             'Example: S0_natural,S2_1to1',
    )
    parser.add_argument(
        '--out-root', default=str(root / 'output' / 'ratio_study'),
        help='Root directory for all scenario outputs',
    )
    args = parser.parse_args()

    log = ViLogger('Step6')
    log.section('Step 6 — Ablation Study: Tỉ lệ Benign:Attack (RQ8)')

    want = {s.strip() for s in args.scenarios.split(',') if s.strip()}
    scenarios = [s for s in DEFAULT_SCENARIOS if not want or s.id in want]
    if not scenarios:
        log.fail('Không có scenario nào khớp --scenarios filter.')
        raise SystemExit(1)

    out_root = Path(args.out_root)
    attack_selected = root / 'output' / 'step3a' / 'attack_selected.json'
    if not attack_selected.exists():
        log.fail(f'Thiếu {attack_selected}. Chạy Step 3A trước.')
        raise SystemExit(1)

    log.info(f'Scenarios: {[s.id for s in scenarios]}')
    log.info(f'Output root: {out_root}')
    log.info(f'Attack selected: {attack_selected}')

    summary_rows: list[dict[str, Any]] = []

    for idx, sc in enumerate(scenarios, 1):
        log.section(f'[{idx}/{len(scenarios)}] Scenario {sc.id} — {sc.title_vi}')
        log.info(f'Tỉ lệ: {sc.ratio}')
        log.info(f'Mục đích: {sc.intent_vi}')

        sdir = out_root / sc.id
        s3b = sdir / 'step3b'
        s3c = sdir / 'step3c'
        s4 = sdir / 'step4'
        s5 = sdir / 'step5'
        for d in (s3b, s3c, s4, s5 / 'models', s5 / 'reports'):
            d.mkdir(parents=True, exist_ok=True)

        benign_out = s3b / 'benign_upscaled.json'
        report_3b = s3b / 'benign_expert_report.json'
        merged = s3c / 'cowrie_merged.json'
        features_json = s4 / 'ml_features.json'
        metrics_json = s5 / 'metrics.json'

        # Step 3B: Benign Expert
        log.info(f'  [3B] Upscale benign (ratio={sc.ratio}) ...')
        _run([
            py, str(root / 'src' / 'step3b_benign_expert.py'),
            '--benign-attack-ratio', sc.ratio,
            '--output-upscaled', str(benign_out),
            '--output-report', str(report_3b),
            '--output-html', str(s3b / 'benign_expert_report.html'),
        ], cwd=root, log=log)
        log.ok(f'  [3B] Hoàn tất → {benign_out.name}')

        # Step 3C: Merge
        log.info(f'  [3C] Merge attack + benign ...')
        _run([
            py, str(root / 'src' / 'step3c_merge.py'),
            '--attack', str(attack_selected),
            '--benign', str(benign_out),
            '--output', str(merged),
        ], cwd=root, log=log)
        log.ok(f'  [3C] Hoàn tất → {merged.name}')

        # Step 4: Feature extraction
        log.info(f'  [4] Feature extraction ...')
        _run([
            py, str(root / 'src' / 'step4_feature_extraction.py'),
            '--log-dir', str(s3c),
            '--log-glob', 'cowrie_merged*.json',
            '--output-dir', str(s4),
        ], cwd=root, log=log)
        log.ok(f'  [4] Hoàn tất → {s4.name}/')

        # Step 5: Train & evaluate
        log.info(f'  [5] Train + evaluate ...')
        _run([
            py, str(root / 'src' / 'step5_train.py'),
            '--train', '--skip-demo', '--skip-shap', '--skip-scenarios',
            '--features-json', str(features_json),
            '--model-path', str(s5 / 'models' / 'random_forest.pkl'),
            '--report-dir', str(s5 / 'reports'),
            '--demo-log-dir', str(s3c),
            '--metrics-json', str(metrics_json),
        ], cwd=root, log=log)
        log.ok(f'  [5] Hoàn tất → {s5.name}/reports/evaluation_report.html')

        # Collect metrics
        try:
            with metrics_json.open('r', encoding='utf-8') as mf:
                m = json.load(mf)
        except Exception as exc:
            log.warn(f'  Không đọc được metrics: {exc}')
            m = {}

        # Dataset quality summary per scenario
        dq: dict[str, Any] = {}
        if features_json.exists():
            try:
                import pandas as _pd
                _fdf = _pd.DataFrame(json.loads(features_json.read_text('utf-8')))
                dq['total_samples'] = int(len(_fdf))
                if 'final_label' in _fdf.columns:
                    dq['n_attack'] = int((_fdf['final_label'] == 1).sum())
                    dq['n_benign'] = int((_fdf['final_label'] == 0).sum())
                if 'weak_label' in _fdf.columns and 'final_label' in _fdf.columns:
                    dq['label_agreement'] = round(
                        float((_fdf['final_label'] == _fdf['weak_label']).mean()), 4)
                n_missing = int(_fdf.isnull().any(axis=1).sum())
                dq['n_rows_with_missing'] = n_missing
            except Exception as _exc:
                log.warn(f'  Không tính được dataset quality: {_exc}')
        m['dataset_quality'] = dq

        row = {
            'scenario_id': sc.id,
            'ratio': sc.ratio,
            'title_vi': sc.title_vi,
            'intent_vi': sc.intent_vi,
            **m,
        }
        summary_rows.append(row)

        meta_path = sdir / 'scenario_meta.json'
        with meta_path.open('w', encoding='utf-8') as f:
            json.dump({
                'scenario_id': sc.id, 'ratio': sc.ratio,
                'title_vi': sc.title_vi, 'intent_vi': sc.intent_vi,
                'paths': {
                    'step3b': str(s3b), 'step3c': str(s3c),
                    'step4': str(s4), 'step5': str(s5),
                },
            }, f, indent=2, ensure_ascii=False)

        log.ok(f'Scenario {sc.id} hoàn tất.')

    # ── Write comparison outputs ──
    log.section('Tổng hợp kết quả tất cả scenario')

    summary_json = out_root / 'scenario_comparison.json'
    with summary_json.open('w', encoding='utf-8') as f:
        json.dump(summary_rows, f, indent=2, ensure_ascii=False)
    log.ok(f'JSON tổng hợp → {summary_json}')

    # HTML comparison report
    html_content = _build_comparison_html(scenarios, summary_rows, out_root, log)
    comparison_html = out_root / 'scenario_comparison.html'
    write_html(comparison_html, html_content)
    log.ok(f'Báo cáo HTML so sánh → {comparison_html}')

    # Markdown comparison (backward compat)
    md_lines = [
        '# So sánh scenario tỉ lệ Benign:Attack (RQ8)',
        '',
        '| Scenario | Ratio | Train rows | Benign share '
        '| Train Macro-F1 | Val Macro-F1 | Test F1 | Test AUC '
        '| PR-AUC | Leakage |',
        '|----------|-------|------------|------------- '
        '|----------------|--------------|---------|--------- '
        '|--------|---------|',
    ]
    for r in summary_rows:
        md_lines.append(
            '| {sid} | {ratio} | {tr} | {tbs} | {tmf} | {vmf} | {tf1} '
            '| {ta} | {pa} | {lr} |'.format(
                sid=r.get('scenario_id', ''),
                ratio=r.get('ratio', ''),
                tr=r.get('train_rows', ''),
                tbs=_safe(r.get('train_benign_share'), '.2%'),
                tmf=_safe(r.get('train_macro_f1')),
                vmf=_safe(r.get('val_macro_f1')),
                tf1=_safe(r.get('test_f1')),
                ta=_safe(r.get('test_auc')),
                pa=_safe(r.get('test_pr_auc')),
                lr=r.get('leakage_risk', 'N/A'),
            ))
    summary_md = out_root / 'EXPERT_SCENARIO_COMPARISON.md'
    summary_md.write_text('\n'.join(md_lines), encoding='utf-8')
    log.ok(f'Markdown tổng hợp → {summary_md}')

    log.section('Step 6 hoàn tất')
    log.info(f'Tổng cộng {len(summary_rows)} scenario đã được đánh giá.')
    log.info(f'Xem báo cáo tổng hợp: {comparison_html}')


if __name__ == '__main__':
    main()
