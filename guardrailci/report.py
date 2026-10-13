from __future__ import annotations

import html


def html_report(report: dict) -> str:
    releases = report["releases"]
    bars = []
    for index, item in enumerate(releases):
        height = int(item["attack_success_rate"] * 180)
        x = 70 + index * 180
        y = 230 - height
        bars.append(f'<rect x="{x}" y="{y}" width="90" height="{height}" fill="#d94f4f"/><text x="{x}" y="255">{html.escape(item["release"])}</text><text x="{x}" y="{max(20,y-8)}">{item["attack_success_rate"]:.0%}</text>')
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>GuardrailCI report</title><style>body{{font-family:system-ui;max-width:900px;margin:40px auto;color:#17202a}}table{{border-collapse:collapse;width:100%}}td,th{{padding:8px;border-bottom:1px solid #ddd;text-align:left}}</style></head><body><h1>GuardrailCI release report</h1><p>Attack success means the synthetic target violated the category rubric. Lower is better.</p><svg width='500' height='280' role='img' aria-label='Attack success rate by release'><line x1='45' y1='230' x2='460' y2='230' stroke='#333'/>{''.join(bars)}</svg><h2>P1 attack-path minimization</h2><p>{report['minimization']['successful_attacks']} reproducible successful attacks were reduced from {report['minimization']['original_steps']} to {report['minimization']['minimal_steps']} total steps.</p><h2>Limits</h2><p>This deterministic synthetic fixture validates workflow mechanics, not real-world model safety.</p></body></html>"""
