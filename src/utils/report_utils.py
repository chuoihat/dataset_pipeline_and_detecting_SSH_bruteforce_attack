"""
Shared utilities for HTML report generation with embedded charts
and Vietnamese debug logging across all pipeline steps.
"""
from __future__ import annotations

import base64
import io
import sys
import time
from collections import Counter
from datetime import datetime
from html import escape as html_escape
from pathlib import Path
from typing import Any

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
    HAS_MPL = True
except ImportError:
    HAS_MPL = False


# ── Vietnamese debug logger ────────────────────────────────────────────────

class ViLogger:
    """Collects Vietnamese debug lines for both console and HTML embedding."""

    def __init__(self, step_name: str):
        self.step_name = step_name
        self.lines: list[tuple[str, str, str]] = []  # (level, timestamp, msg)
        self._start = time.time()

    def _ts(self) -> str:
        elapsed = time.time() - self._start
        return f'+{elapsed:07.2f}s'

    def info(self, msg: str) -> None:
        ts = self._ts()
        self.lines.append(('INFO', ts, msg))
        print(f'[{self.step_name}] ℹ  {msg}')

    def debug(self, msg: str) -> None:
        ts = self._ts()
        self.lines.append(('DEBUG', ts, msg))
        print(f'[{self.step_name}]    {msg}')

    def warn(self, msg: str) -> None:
        ts = self._ts()
        self.lines.append(('WARN', ts, msg))
        print(f'[{self.step_name}] ⚠  {msg}')

    def ok(self, msg: str) -> None:
        ts = self._ts()
        self.lines.append(('OK', ts, msg))
        print(f'[{self.step_name}] ✓  {msg}')

    def fail(self, msg: str) -> None:
        ts = self._ts()
        self.lines.append(('FAIL', ts, msg))
        print(f'[{self.step_name}] ✗  {msg}')

    def section(self, msg: str) -> None:
        ts = self._ts()
        self.lines.append(('SECTION', ts, msg))
        print(f'\n{"═"*60}')
        print(f'  {msg}')
        print(f'{"═"*60}')

    def to_html(self) -> str:
        level_cls = {
            'INFO': 'log-info', 'DEBUG': 'log-debug', 'WARN': 'log-warn',
            'OK': 'log-ok', 'FAIL': 'log-fail', 'SECTION': 'log-section',
        }
        rows = []
        for level, ts, msg in self.lines:
            cls = level_cls.get(level, 'log-debug')
            rows.append(f'<div class="{cls}"><span class="log-ts">{ts}</span>'
                        f'<span class="log-lvl">[{level:7s}]</span> {html_escape(msg)}</div>')
        return '\n'.join(rows)


# ── Chart helpers ──────────────────────────────────────────────────────────

def fig_to_base64(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=120, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def img_tag(b64: str, alt: str = '', width: str = '100%') -> str:
    return f'<img src="data:image/png;base64,{b64}" alt="{html_escape(alt)}" style="max-width:{width};height:auto;">'


def make_bar_chart(
    labels: list[str],
    values: list[float],
    title: str = '',
    xlabel: str = '',
    ylabel: str = '',
    color: str = '#3182ce',
    horizontal: bool = False,
    figsize: tuple[float, float] = (8, 4),
    top_n: int = 0,
    value_format: str = ',',
) -> str:
    if not HAS_MPL or not labels:
        return ''
    if top_n > 0:
        pairs = sorted(zip(values, labels), reverse=True)[:top_n]
        values, labels = [p[0] for p in pairs], [p[1] for p in pairs]
    fig, ax = plt.subplots(figsize=figsize)
    if horizontal:
        labels, values = labels[::-1], values[::-1]
        bars = ax.barh(range(len(labels)), values, color=color, edgecolor='white')
        ax.set_yticks(range(len(labels)))
        ax.set_yticklabels(labels, fontsize=9)
        ax.set_xlabel(xlabel)
        for bar, v in zip(bars, values):
            ax.text(bar.get_width() + max(values)*0.01, bar.get_y() + bar.get_height()/2,
                    f'{v:{value_format}}', va='center', fontsize=8)
    else:
        bars = ax.bar(range(len(labels)), values, color=color, edgecolor='white')
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=9)
        ax.set_ylabel(ylabel)
        for bar, v in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
                    f'{v:{value_format}}', ha='center', va='bottom', fontsize=8)
    if title:
        ax.set_title(title, fontsize=12, fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    fig.tight_layout()
    return img_tag(fig_to_base64(fig), title)


def make_pie_chart(
    labels: list[str],
    values: list[float],
    title: str = '',
    figsize: tuple[float, float] = (6, 5),
    colors: list[str] | None = None,
) -> str:
    if not HAS_MPL or not labels:
        return ''
    fig, ax = plt.subplots(figsize=figsize)
    default_colors = ['#3182ce', '#e53e3e', '#38a169', '#d69e2e', '#805ad5',
                      '#dd6b20', '#319795', '#d53f8c', '#718096', '#2b6cb0']
    _colors = colors or default_colors[:len(labels)]
    wedges, texts, autotexts = ax.pie(
        values, labels=None, autopct='%1.1f%%', colors=_colors,
        pctdistance=0.8, startangle=90,
    )
    for t in autotexts:
        t.set_fontsize(9)
    ax.legend(labels, loc='center left', bbox_to_anchor=(1, 0.5), fontsize=9)
    if title:
        ax.set_title(title, fontsize=12, fontweight='bold')
    fig.tight_layout()
    return img_tag(fig_to_base64(fig), title)


def make_histogram(
    values: list[float],
    title: str = '',
    xlabel: str = '',
    ylabel: str = 'Số lượng',
    bins: int = 30,
    color: str = '#3182ce',
    figsize: tuple[float, float] = (8, 4),
    log_scale: bool = False,
) -> str:
    if not HAS_MPL or not values:
        return ''
    fig, ax = plt.subplots(figsize=figsize)
    ax.hist(values, bins=bins, color=color, edgecolor='white', alpha=0.85)
    if xlabel:
        ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    if log_scale:
        ax.set_yscale('log')
    if title:
        ax.set_title(title, fontsize=12, fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    fig.tight_layout()
    return img_tag(fig_to_base64(fig), title)


def make_timeline_chart(
    timestamps: list[str],
    counts: list[int],
    title: str = '',
    ylabel: str = 'Events',
    color: str = '#3182ce',
    figsize: tuple[float, float] = (10, 3),
) -> str:
    if not HAS_MPL or not timestamps:
        return ''
    fig, ax = plt.subplots(figsize=figsize)
    ax.fill_between(range(len(timestamps)), counts, color=color, alpha=0.3)
    ax.plot(range(len(timestamps)), counts, color=color, linewidth=1.5)
    n = len(timestamps)
    step = max(1, n // 10)
    ax.set_xticks(range(0, n, step))
    ax.set_xticklabels([timestamps[i][:16] for i in range(0, n, step)], rotation=30, fontsize=8)
    ax.set_ylabel(ylabel)
    if title:
        ax.set_title(title, fontsize=12, fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    fig.tight_layout()
    return img_tag(fig_to_base64(fig), title)


def make_heatmap(
    matrix: list[list[float]],
    xlabels: list[str],
    ylabels: list[str],
    title: str = '',
    figsize: tuple[float, float] = (8, 5),
    cmap: str = 'Blues',
    fmt: str = '.0f',
) -> str:
    if not HAS_MPL or not matrix:
        return ''
    import numpy as np
    fig, ax = plt.subplots(figsize=figsize)
    data = np.array(matrix)
    im = ax.imshow(data, cmap=cmap, aspect='auto')
    ax.set_xticks(range(len(xlabels)))
    ax.set_xticklabels(xlabels, rotation=45, ha='right', fontsize=9)
    ax.set_yticks(range(len(ylabels)))
    ax.set_yticklabels(ylabels, fontsize=9)
    for i in range(len(ylabels)):
        for j in range(len(xlabels)):
            ax.text(j, i, f'{data[i, j]:{fmt}}', ha='center', va='center', fontsize=8)
    fig.colorbar(im, ax=ax, shrink=0.8)
    if title:
        ax.set_title(title, fontsize=12, fontweight='bold')
    fig.tight_layout()
    return img_tag(fig_to_base64(fig), title)


def make_confusion_matrix_chart(
    cm: list[list[int]],
    labels: list[str],
    title: str = 'Ma trận nhầm lẫn (Confusion Matrix)',
    figsize: tuple[float, float] = (5, 4),
) -> str:
    if not HAS_MPL:
        return ''
    return make_heatmap(cm, labels, labels, title=title, figsize=figsize, cmap='Blues')


# ── Verification card helpers ──────────────────────────────────────────────

def verify_card(test_name: str, passed: bool, detail: str) -> str:
    status = '✓ PASS' if passed else '✗ FAIL'
    cls = 'verify-pass' if passed else 'verify-fail'
    return (f'<div class="{cls}"><b>{status}</b> — {html_escape(test_name)}'
            f'<div class="verify-detail">{html_escape(detail)}</div></div>')


# ── HTML template ──────────────────────────────────────────────────────────

CSS = """
body{font-family:'Segoe UI',system-ui,sans-serif;max-width:1300px;margin:2em auto;padding:0 1.5em;line-height:1.65;color:#1a202c;background:#f7fafc}
h1{border-bottom:3px solid #2c5282;padding-bottom:.3em;color:#1a365d}
h2{color:#2c5282;margin-top:2.5em;border-bottom:1px solid #e2e8f0;padding-bottom:.2em}
h3{color:#4a5568;margin-top:1.5em}
table{border-collapse:collapse;width:100%;margin:1em 0;font-size:13px}
th,td{border:1px solid #e2e8f0;padding:7px 10px;text-align:left}
th{background:#edf2f7;font-weight:600;color:#2d3748}
tr:nth-child(even){background:#f7fafc}
.num{text-align:right;font-family:'SF Mono',Consolas,monospace;font-size:12px}
.mono{font-family:'SF Mono',Consolas,monospace;font-size:11px}
.small{font-size:11px;color:#718096}
.warn{color:#c05621;font-weight:bold}
.good{color:#276749;font-weight:bold}
.warn-box{background:#fffaf0;border-left:4px solid #dd6b20;padding:.8em 1em;margin:.8em 0;border-radius:6px;color:#c05621}
.good-box{background:#f0fff4;border-left:4px solid #38a169;padding:.8em 1em;margin:.8em 0;border-radius:6px;color:#276749}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:16px 0}
.card{border:1px solid #e2e8f0;border-radius:10px;padding:12px 16px;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.card .k{font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:.04em}
.card .v{font-size:18px;font-weight:700;margin-top:4px;color:#2d3748}
.decision{background:#ebf8ff;border-left:4px solid #3182ce;padding:1em 1.2em;margin:1em 0;border-radius:6px}
.decision h3{color:#2c5282;margin-top:0}
.reason{background:#f0fff4;border-left:4px solid #38a169;padding:.8em 1em;margin:.5em 0;border-radius:6px}
.chart-container{margin:1.5em 0;text-align:center}
.chart-container img{border:1px solid #e2e8f0;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.06)}
details{border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;margin:12px 0;background:#fff}
summary{cursor:pointer;font-weight:700;padding:4px;color:#2c5282}
.verify-pass{background:#f0fff4;border-left:4px solid #38a169;padding:.6em 1em;margin:.4em 0;border-radius:4px}
.verify-fail{background:#fff5f5;border-left:4px solid #e53e3e;padding:.6em 1em;margin:.4em 0;border-radius:4px}
.verify-detail{font-size:12px;color:#4a5568;margin-top:2px}
.log-section{font-weight:bold;margin-top:8px;padding:4px 0;color:#2c5282;font-size:13px;border-bottom:1px dashed #cbd5e0}
.log-info{font-size:12px;color:#2d3748;padding:1px 0}
.log-debug{font-size:11px;color:#718096;padding:1px 0;padding-left:16px}
.log-warn{font-size:12px;color:#c05621;font-weight:600;padding:1px 0}
.log-ok{font-size:12px;color:#276749;font-weight:600;padding:1px 0}
.log-fail{font-size:12px;color:#c53030;font-weight:600;padding:1px 0}
.log-ts{display:inline-block;width:80px;color:#a0aec0;font-size:10px;font-family:monospace}
.log-lvl{display:inline-block;width:70px;font-family:monospace;font-size:10px}
.debug-log{background:#1a202c;color:#e2e8f0;padding:16px;border-radius:8px;max-height:500px;overflow-y:auto;font-family:monospace;font-size:11px;line-height:1.7}
.debug-log .log-info{color:#90cdf4} .debug-log .log-debug{color:#a0aec0}
.debug-log .log-warn{color:#fbd38d} .debug-log .log-ok{color:#9ae6b4}
.debug-log .log-fail{color:#feb2b2} .debug-log .log-section{color:#63b3ed;border-color:#4a5568}
.toc{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:1em 1.5em;margin:1em 0}
.toc a{text-decoration:none;color:#2c5282} .toc a:hover{text-decoration:underline}
.toc ol{margin:0;padding-left:1.5em}
.toc li{margin:4px 0;font-size:14px}
"""


def html_header(title: str, step_name: str, subtitle: str = '') -> str:
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    parts = [
        '<!DOCTYPE html><html lang="vi"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f'<title>{html_escape(title)}</title>',
        f'<style>{CSS}</style>',
        '</head><body>',
        f'<h1>{html_escape(title)}</h1>',
        f'<p class="small">Pipeline step: <b>{html_escape(step_name)}</b> | '
        f'Thời gian tạo: {now}</p>',
    ]
    if subtitle:
        parts.append(f'<p class="small">{html_escape(subtitle)}</p>')
    return '\n'.join(parts)


def html_footer() -> str:
    return '</body></html>'


def html_toc(sections: list[tuple[str, str]]) -> str:
    items = ''.join(f'<li><a href="#{sid}">{html_escape(label)}</a></li>'
                    for sid, label in sections)
    return f'<div class="toc"><b>Mục lục</b><ol>{items}</ol></div>'


def html_section(section_id: str, title: str) -> str:
    return f'<h2 id="{section_id}">{html_escape(title)}</h2>'


def html_cards(items: list[tuple[str, str | int | float]]) -> str:
    cards = []
    for label, value in items:
        if isinstance(value, float):
            vstr = f'{value:,.2f}'
        elif isinstance(value, int):
            vstr = f'{value:,}'
        else:
            vstr = str(value)
        cards.append(f'<div class="card"><div class="k">{html_escape(label)}</div>'
                     f'<div class="v">{html_escape(vstr)}</div></div>')
    return '<div class="grid">' + ''.join(cards) + '</div>'


def html_table(headers: list[str], rows: list[list[Any]], max_rows: int = 500) -> str:
    parts = ['<table><thead><tr>']
    for h in headers:
        parts.append(f'<th>{html_escape(str(h))}</th>')
    parts.append('</tr></thead><tbody>')
    for row in rows[:max_rows]:
        parts.append('<tr>')
        for cell in row:
            if cell is None:
                parts.append('<td></td>')
            elif isinstance(cell, float):
                parts.append(f'<td class="num">{cell:,.4f}</td>')
            elif isinstance(cell, int):
                parts.append(f'<td class="num">{cell:,}</td>')
            else:
                parts.append(f'<td>{html_escape(str(cell))}</td>')
        parts.append('</tr>')
    parts.append('</tbody></table>')
    if len(rows) > max_rows:
        parts.append(f'<p class="small">(Hiển thị {max_rows}/{len(rows)} dòng)</p>')
    return ''.join(parts)


def html_chart(chart_html: str, caption: str = '') -> str:
    if not chart_html:
        return ''
    parts = [f'<div class="chart-container">{chart_html}']
    if caption:
        parts.append(f'<p class="small"><i>{html_escape(caption)}</i></p>')
    parts.append('</div>')
    return ''.join(parts)


def html_debug_log(logger: ViLogger) -> str:
    return (f'<details><summary>📋 Debug Log ({len(logger.lines)} dòng)</summary>'
            f'<div class="debug-log">{logger.to_html()}</div></details>')


def html_decision(title: str, content: str, rationale: str = '') -> str:
    parts = [f'<div class="decision"><h3>{html_escape(title)}</h3>{content}']
    if rationale:
        parts.append(f'<div class="reason"><b>Cơ sở khoa học:</b> {html_escape(rationale)}</div>')
    parts.append('</div>')
    return ''.join(parts)


def html_verification_section(tests: list[tuple[str, bool, str]]) -> str:
    parts = ['<div class="verify-section">']
    n_pass = sum(1 for _, p, _ in tests if p)
    n_total = len(tests)
    parts.append(f'<p><b>Kết quả kiểm tra:</b> {n_pass}/{n_total} PASS</p>')
    for name, passed, detail in tests:
        parts.append(verify_card(name, passed, detail))
    parts.append('</div>')
    return ''.join(parts)


def write_html(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')
