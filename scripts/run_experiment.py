from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from secure_llm.runner import execute, load_json, planned_runs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", type=Path)
    args = parser.parse_args()
    config_path = args.config if args.config.is_absolute() else ROOT / args.config
    config = load_json(config_path)
    cases = load_json(ROOT / config["dataset"])
    estimate = {"planned_calls":planned_runs(config, len(cases)),"estimated_input_tokens":planned_runs(config,len(cases))*180,"estimated_output_tokens":planned_runs(config,len(cases))*60,"projected_cost_usd":0.0,"backend":"mock","warning":"MOCK ONLY; NOT SCIENTIFIC EVIDENCE"}
    print(json.dumps(estimate, indent=2))
    if not args.dry_run:
        print(execute(config_path, ROOT, args.limit, args.resume).resolve())


if __name__ == "__main__":
    main()
