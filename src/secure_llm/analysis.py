from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .metrics import summarize_security, summarize_utility


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _svg_bars(path: Path, title: str, labels: list[str], values: list[float]) -> None:
    colors = ["#4c78a8", "#f58518", "#54a24b", "#e45756"]
    bars = []
    for index, (label, value) in enumerate(zip(labels, values)):
        x = 90 + index * 170
        height = 300 * value
        bars.append(f'<rect x="{x}" y="{370-height:.1f}" width="100" height="{height:.1f}" fill="{colors[index%len(colors)]}"/><text x="{x+50}" y="395" text-anchor="middle">{label}</text><text x="{x+50}" y="{360-height:.1f}" text-anchor="middle">{value:.2f}</text>')
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="700" height="440"><rect width="100%" height="100%" fill="white"/><text x="350" y="30" text-anchor="middle" font-size="20">{title}</text><line x1="65" y1="70" x2="65" y2="370" stroke="black"/><line x1="65" y1="370" x2="670" y2="370" stroke="black"/><text x="25" y="220" transform="rotate(-90 25 220)" text-anchor="middle">Rate</text>{''.join(bars)}</svg>'
    path.write_text(svg, encoding="utf-8")


def _svg_pareto(path: Path, security: list[dict[str, Any]], utility: list[dict[str, Any]]) -> None:
    util = {r["architecture"]: r["attack_utility"] for r in utility}
    points = []
    for row in security:
        x, y = 70 + util[row["architecture"]] * 560, 370 - row["Security"] * 300
        points.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="7" fill="#4c78a8"/><text x="{x+10:.1f}" y="{y-8:.1f}">{row["architecture"]}</text>')
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="700" height="440"><rect width="100%" height="100%" fill="white"/><text x="350" y="30" text-anchor="middle" font-size="20">Security–Utility Pareto (Mock Pilot)</text><line x1="70" y1="70" x2="70" y2="370" stroke="black"/><line x1="70" y1="370" x2="630" y2="370" stroke="black"/><text x="350" y="420" text-anchor="middle">Attack Utility</text><text x="25" y="220" transform="rotate(-90 25 220)" text-anchor="middle">Security (1-ASR)</text>{''.join(points)}</svg>'
    path.write_text(svg, encoding="utf-8")


def analyze(run_dir: Path) -> dict[str, Any]:
    config = json.loads((run_dir / "config.yaml").read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in (run_dir / "runs.jsonl").read_text(encoding="utf-8").splitlines()]
    failures = [r for r in rows if r.get("error")]
    valid = [r for r in rows if not r.get("error")]
    security = summarize_security(valid, float(config["analysis"]["alpha"]), int(config["analysis"]["bootstrap_samples"]), int(config["experiment"]["seed"]))
    utility = summarize_utility(valid)
    write_csv(run_dir / "results.csv", valid)
    write_csv(run_dir / "security_summary.csv", security)
    write_csv(run_dir / "utility_summary.csv", utility)
    plots = run_dir / "plots"
    plots.mkdir(exist_ok=True)
    _svg_bars(plots / "asr_by_attack.svg", "Attack Success Rate (Mock Pilot)", [r["architecture"] for r in security], [r["ASR"] for r in security])
    _svg_pareto(plots / "pareto.svg", security, utility)
    metrics = {"warning":"MOCKED RESULTS — INFRASTRUCTURE VALIDATION ONLY; REAL-MODEL EXPERIMENTS NOT RUN","valid_runs":len(valid),"failed_runs":len(failures),"security":security,"utility":utility}
    (run_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics
