from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from querysense.engine import AnalysisService
from querysense.parser import parse_explain


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "media" / "readme"
PLAN_PATH = ROOT / "examples" / "sample_plan.json"


def get_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    conso = Path("C:/Windows/Fonts/consola.ttf")
    if conso.exists():
        return ImageFont.truetype(str(conso), size=size)
    return ImageFont.load_default()


def wrap_lines(text: str, width: int = 92) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        if not raw.strip():
            lines.append("")
            continue
        lines.extend(textwrap.wrap(raw, width=width, replace_whitespace=False))
    return lines


def render_terminal_card(title: str, subtitle: str, text: str, out_path: Path) -> None:
    bg = "#0b1020"
    panel = "#111827"
    border = "#334155"
    title_color = "#93c5fd"
    subtitle_color = "#94a3b8"
    body_color = "#e2e8f0"

    title_font = get_font(38)
    subtitle_font = get_font(24)
    body_font = get_font(24)

    lines = wrap_lines(text, width=92)
    line_height = 34
    width = 1500
    height = 220 + line_height * max(len(lines), 10)

    image = Image.new("RGB", (width, height), bg)
    draw = ImageDraw.Draw(image)

    margin = 36
    draw.rounded_rectangle(
        [margin, margin, width - margin, height - margin],
        radius=18,
        fill=panel,
        outline=border,
        width=2,
    )

    draw.text((72, 62), title, fill=title_color, font=title_font)
    draw.text((72, 112), subtitle, fill=subtitle_color, font=subtitle_font)

    y = 156
    for line in lines:
        draw.text((72, y), line, fill=body_color, font=body_font)
        y += line_height

    out_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(out_path)


def build_assets() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)

    plan_text = PLAN_PATH.read_text(encoding="utf-8")
    before_text = "\n".join(plan_text.splitlines()[:22])
    render_terminal_card(
        title="Before: Plan Snapshot",
        subtitle="examples/sample_plan.json",
        text=before_text,
        out_path=ASSETS / "01-before-plan.png",
    )

    explain = parse_explain(PLAN_PATH)
    result = AnalysisService().analyze(explain)
    findings = result.findings

    analyze_lines = [
        "$ querysense analyze examples/sample_plan.json --simple",
        "",
        f"Findings: {len(findings)}",
        "",
    ]
    for idx, finding in enumerate(findings[:6], start=1):
        analyze_lines.append(
            f"{idx}. [{finding.severity.value.upper()}] {finding.title} (impact {finding.impact_score:.1f}/10)"
        )
    render_terminal_card(
        title="Analyze: Real Output Snapshot",
        subtitle="Generated from QuerySense analysis engine",
        text="\n".join(analyze_lines),
        out_path=ASSETS / "02-analyze-output.png",
    )

    fix_lines = [
        "$ querysense fix examples/sample_plan.json",
        "",
    ]
    added = 0
    seen: set[str] = set()
    for finding in findings:
        suggestion = finding.suggestion or ""
        sql_lines = [
            line.strip()
            for line in suggestion.splitlines()
            if line.strip() and not line.strip().startswith("--")
        ]
        if not sql_lines:
            continue
        sql_blob = "\n".join(sql_lines)
        if sql_blob in seen:
            continue
        seen.add(sql_blob)
        fix_lines.append(f"-- {finding.title}")
        fix_lines.extend(sql_lines)
        fix_lines.append("")
        added += 1
        if added >= 4:
            break

    if added == 0:
        fix_lines.append("-- No SQL fixes generated for this sample.")

    render_terminal_card(
        title="Fix: Generated SQL",
        subtitle="Real suggestions generated from sample plan",
        text="\n".join(fix_lines),
        out_path=ASSETS / "03-fix-generated.png",
    )

    source_hero = ROOT / "query.png"
    hero_in_docs = ASSETS / "hero.png"
    if source_hero.exists() and not hero_in_docs.exists():
        shutil.copyfile(source_hero, hero_in_docs)

    source_for_after = hero_in_docs if hero_in_docs.exists() else source_hero
    if source_for_after.exists():
        shutil.copyfile(source_for_after, ASSETS / "04-after-diff.png")
    else:
        fallback = {
            "improvement": "2.3s -> 0.04s (example)",
            "note": "Replace with your latest benchmark screenshot.",
        }
        render_terminal_card(
            title="After: Performance Delta",
            subtitle="Fallback placeholder",
            text=json.dumps(fallback, indent=2),
            out_path=ASSETS / "04-after-diff.png",
        )


if __name__ == "__main__":
    build_assets()
