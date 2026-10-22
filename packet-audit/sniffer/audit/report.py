"""Audit report generator — Markdown and HTML output from JSONL trail.

Reads the audit trail JSONL, groups events by severity, and produces a
structured report with statistics, per-rule summaries, and findings table.

PRIVACY: No raw payloads or credential values appear in reports.
"""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
}

_SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#2563eb",
    "INFO": "#6b7280",
}


def _load_events(trail_path: Path) -> list[dict[str, Any]]:
    """Parse JSONL trail and return only ``type == "event"`` entries."""
    events: list[dict[str, Any]] = []
    with trail_path.open("r", encoding="utf-8") as fh:
        for raw_line in fh:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                entry = json.loads(raw_line)
                if entry.get("type") == "event":
                    events.append(entry.get("payload", {}))
            except json.JSONDecodeError:
                continue
    return events


def generate_report(
    trail_path: str | Path,
    out_dir: str | Path,
    fmt: str = "markdown",
    operator: str = "",
) -> Path:
    """Generate an audit report from *trail_path*.

    Args:
        trail_path: Path to the JSONL audit trail.
        out_dir:    Output directory for the report file.
        fmt:        "markdown" or "html".
        operator:   Operator ID to include in the report header.

    Returns:
        Path to the generated report file.
    """
    trail_path = Path(trail_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    events = _load_events(trail_path)

    ts_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = ".html" if fmt == "html" else ".md"
    out_path = out_dir / f"audit_report_{stamp}{suffix}"

    if fmt == "html":
        content = _render_html(events, ts_now, operator, trail_path)
    else:
        content = _render_markdown(events, ts_now, operator, trail_path)

    out_path.write_text(content, encoding="utf-8")
    log.info("Report written to %s", out_path)
    return out_path


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def _render_markdown(
    events: list[dict[str, Any]],
    ts_now: str,
    operator: str,
    trail_path: Path,
) -> str:
    sev_counts: Counter[str] = Counter(e.get("severity", "INFO") for e in events)
    rule_counts: Counter[str] = Counter(e.get("rule", "unknown") for e in events)
    sorted_events = sorted(events, key=lambda e: _SEVERITY_ORDER.get(e.get("severity", "INFO"), 99))
    rule_msgs: dict[str, list[str]] = defaultdict(list)
    for e in events:
        rule_msgs[e.get("rule", "unknown")].append(
            f"[{e.get('severity', '?')}] {e.get('src', '?')} -> {e.get('dst', '?')}: {e.get('message', '')}"
        )

    lines: list[str] = [
        "# Network Traffic Audit Report",
        "",
        f"**Generated:** {ts_now}",
        f"**Operator:** {operator or '_not set_'}",
        f"**Trail file:** `{trail_path}`",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"Total events: **{len(events)}**",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev_counts.get(sev, 0):
            lines.append(f"| {sev} | {sev_counts[sev]} |")

    lines += [
        "",
        "## Events by Rule",
        "",
        "| Rule | Count |",
        "|------|-------|",
    ]
    for rule, cnt in rule_counts.most_common():
        lines.append(f"| `{rule}` | {cnt} |")

    lines += ["", "## Findings", ""]

    lines += [
        "| # | Severity | Rule | Source | Destination | Proto | Message |",
        "|---|----------|------|--------|-------------|-------|---------|",
    ]
    for i, ev in enumerate(sorted_events, start=1):
        sport = f":{ev.get('sport')}" if ev.get("sport") else ""
        dport = f":{ev.get('dport')}" if ev.get("dport") else ""
        lines.append(
            f"| {i} | **{ev.get('severity', '?')}** | `{ev.get('rule', '?')}` "
            f"| {ev.get('src', '?')}{sport} "
            f"| {ev.get('dst', '?')}{dport} "
            f"| {ev.get('proto', '?')} "
            f"| {ev.get('message', '')[:120]} |"
        )

    lines += [
        "",
        "---",
        "",
        "## Per-Rule Details",
        "",
    ]
    for rule, msgs in sorted(rule_msgs.items()):
        lines.append(f"### `{rule}`")
        lines.append("")
        for msg in msgs[:50]:  # cap per rule to keep report readable
            lines.append(f"- {msg}")
        if len(msgs) > 50:
            lines.append(f"- _... and {len(msgs) - 50} more_")
        lines.append("")

    lines += [
        "---",
        "_This report was generated automatically. Review on authorized infrastructure only._",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

def _render_html(
    events: list[dict[str, Any]],
    ts_now: str,
    operator: str,
    trail_path: Path,
) -> str:
    sev_counts: Counter[str] = Counter(e.get("severity", "INFO") for e in events)
    sorted_events = sorted(events, key=lambda e: _SEVERITY_ORDER.get(e.get("severity", "INFO"), 99))
    rule_counts: Counter[str] = Counter(e.get("rule", "unknown") for e in events)

    def _badge(sev: str) -> str:
        color = _SEVERITY_COLORS.get(sev, "#6b7280")
        return (
            f'<span style="background:{color};color:#fff;padding:1px 7px;'
            f'border-radius:4px;font-size:0.78em;font-weight:bold">{sev}</span>'
        )

    summary_rows = "".join(
        f"<tr><td>{_badge(sev)}</td><td style='text-align:right'>{sev_counts.get(sev, 0)}</td></tr>"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        if sev_counts.get(sev, 0)
    )

    rule_rows = "".join(
        f"<tr><td><code>{rule}</code></td><td style='text-align:right'>{cnt}</td></tr>"
        for rule, cnt in rule_counts.most_common()
    )

    def _ev_row(i: int, ev: dict[str, Any]) -> str:
        sport = f":{ev.get('sport')}" if ev.get("sport") else ""
        dport = f":{ev.get('dport')}" if ev.get("dport") else ""
        msg = str(ev.get("message", ""))[:160]
        return (
            f"<tr><td>{i}</td>"
            f"<td>{_badge(ev.get('severity', '?'))}</td>"
            f"<td><code>{ev.get('rule', '?')}</code></td>"
            f"<td>{ev.get('src', '?')}{sport}</td>"
            f"<td>{ev.get('dst', '?')}{dport}</td>"
            f"<td>{ev.get('proto', '?')}</td>"
            f"<td>{msg}</td></tr>"
        )

    finding_rows = "".join(_ev_row(i, ev) for i, ev in enumerate(sorted_events, 1))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Traffic Audit Report</title>
<style>
  body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; margin: 0; background:#f8fafc; color:#1e293b }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem }}
  h1 {{ color:#0f172a; border-bottom: 3px solid #3b82f6; padding-bottom:.5rem }}
  h2 {{ color:#1e3a5f; margin-top:2rem }}
  table {{ border-collapse:collapse; width:100%; margin:1rem 0; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.1) }}
  th {{ background:#1e3a5f; color:#fff; padding:.7rem 1rem; text-align:left; font-size:.85em }}
  td {{ padding:.6rem 1rem; border-bottom:1px solid #e2e8f0; font-size:.85em }}
  tr:last-child td {{ border-bottom:none }}
  tr:hover {{ background:#f1f5f9 }}
  code {{ background:#e2e8f0; padding:1px 5px; border-radius:3px; font-size:.85em }}
  .meta {{ background:#fff; border-left:4px solid #3b82f6; padding:1rem; margin:1rem 0; border-radius:4px }}
  footer {{ margin-top:3rem; color:#94a3b8; font-size:.8em; text-align:center }}
</style>
</head>
<body>
<div class="container">
<h1>🔍 Network Traffic Audit Report</h1>
<div class="meta">
  <strong>Generated:</strong> {ts_now} &nbsp;|&nbsp;
  <strong>Operator:</strong> {operator or '<em>not set</em>'} &nbsp;|&nbsp;
  <strong>Trail:</strong> <code>{trail_path}</code>
</div>
<h2>Executive Summary</h2>
<p>Total events recorded: <strong>{len(events)}</strong></p>
<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>{summary_rows}</tbody></table>
<h2>Events by Rule</h2>
<table><thead><tr><th>Rule</th><th>Count</th></tr></thead><tbody>{rule_rows}</tbody></table>
<h2>Findings</h2>
<table>
<thead><tr><th>#</th><th>Severity</th><th>Rule</th><th>Source</th><th>Destination</th><th>Proto</th><th>Message</th></tr></thead>
<tbody>{finding_rows}</tbody>
</table>
<footer>This report was generated automatically. Review on authorized infrastructure only.</footer>
</div>
</body>
</html>"""
