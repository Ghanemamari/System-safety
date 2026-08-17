from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path("/workspace/NeurIPS")
OUT = ROOT / "results/iteration4c_phi4mini_capability"
sys.path.insert(0, str(ROOT / "src"))

from secure_llm.utility_v2 import _argument_equal


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


def write_csv(path, rows):
    fields = list(rows[0]) if rows else []
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def frac(numerator, denominator):
    return numerator / denominator if denominator else None


tasks = json.loads((ROOT / "data/iteration2a/capability_tasks.json").read_text(encoding="utf-8"))
by_task = {task["task_id"]: task for task in tasks}

phi_runs = read_jsonl(OUT / "raw_runs.jsonl")
phi_metrics = json.loads((OUT / "metrics.json").read_text(encoding="utf-8"))
mistral_runs = read_jsonl(ROOT / "results/iteration4a_mistral7b_capability/raw_runs.jsonl")
mistral_metrics = json.loads((ROOT / "results/iteration4a_mistral7b_capability/metrics.json").read_text(encoding="utf-8"))
qwen_metrics = json.loads((ROOT / "results/iteration3a_qwen25_7b_runpod/metrics.json").read_text(encoding="utf-8"))
smol_runs = read_jsonl(ROOT / "results/20260812T104118.870114Z_iteration2a_legitimate_capability/runs_evaluator_corrected.jsonl")
smol_metrics = json.loads((ROOT / "results/20260812T104118.870114Z_iteration2a_legitimate_capability/metrics.json").read_text(encoding="utf-8"))


def prior_row(name, parameters, runs, metrics):
    json_n = sum(row.get("parse_status") != "PARSE_FAILURE" for row in runs)
    schema_n = sum(row.get("parse_status") == "PARSE_SUCCESS" for row in runs)
    action_n = sum(row.get("actual_action") == row.get("expected_action") for row in runs)
    arguments_ok = 0
    arguments_total = 0
    for row in runs:
        required = by_task[row["task_id"]]["utility_criteria"].get("required_arguments", {})
        actual = (row.get("proposed_action") or {}).get("arguments", {})
        arguments_total += len(required)
        arguments_ok += sum(_argument_equal(key, actual.get(key, ""), value) for key, value in required.items())
    coverage = metrics["minimum_coverage"]
    return {
        "model": name,
        "parameter_count": parameters,
        "JSON_numerator": json_n,
        "JSON_denominator": 25,
        "JSON_rate": json_n / 25,
        "Schema_numerator": schema_n,
        "Schema_denominator": 25,
        "Schema_rate": schema_n / 25,
        "Action_numerator": action_n,
        "Action_denominator": 25,
        "Action_rate": action_n / 25,
        "Argument_numerator": arguments_ok,
        "Argument_denominator": arguments_total,
        "Argument_rate": frac(arguments_ok, arguments_total),
        "General_Utility_numerator": metrics["overall"]["general_utility"] * 25,
        "General_Utility_denominator": 25,
        "General_Utility_rate": metrics["overall"]["general_utility"],
        "Security_eligible_numerator": metrics["overall"]["security_eligible_n"],
        "Security_eligible_denominator": 25,
        "LAC_read_numerator": coverage["read"]["eligible"],
        "LAC_read_denominator": 5,
        "LAC_read_rate": coverage["read"]["eligible"] / 5,
        "LAC_write_numerator": coverage["write"]["eligible"],
        "LAC_write_denominator": 5,
        "LAC_write_rate": coverage["write"]["eligible"] / 5,
        "LAC_overall_numerator": coverage["read"]["eligible"] + coverage["write"]["eligible"],
        "LAC_overall_denominator": 10,
        "LAC_overall_rate": (coverage["read"]["eligible"] + coverage["write"]["eligible"]) / 10,
    }


def metric_row(name, parameters, metrics):
    overall = metrics["overall"]
    lac = metrics["lac"]
    return {
        "model": name,
        "parameter_count": parameters,
        "JSON_numerator": overall["json_extraction"]["numerator"],
        "JSON_denominator": overall["json_extraction"]["denominator"],
        "JSON_rate": overall["json_extraction"]["rate"],
        "Schema_numerator": overall["schema_validity"]["numerator"],
        "Schema_denominator": overall["schema_validity"]["denominator"],
        "Schema_rate": overall["schema_validity"]["rate"],
        "Action_numerator": overall["action_accuracy"]["numerator"],
        "Action_denominator": overall["action_accuracy"]["denominator"],
        "Action_rate": overall["action_accuracy"]["rate"],
        "Argument_numerator": overall["argument_accuracy"]["numerator"],
        "Argument_denominator": overall["argument_accuracy"]["denominator"],
        "Argument_rate": overall["argument_accuracy"]["rate"],
        "General_Utility_numerator": overall["general_utility"]["numerator"],
        "General_Utility_denominator": overall["general_utility"]["denominator"],
        "General_Utility_rate": overall["general_utility"]["rate"],
        "Security_eligible_numerator": overall["security_eligible"]["numerator"],
        "Security_eligible_denominator": overall["security_eligible"]["denominator"],
        "LAC_read_numerator": lac["read"]["numerator"],
        "LAC_read_denominator": lac["read"]["denominator"],
        "LAC_read_rate": lac["read"]["rate"],
        "LAC_write_numerator": lac["write"]["numerator"],
        "LAC_write_denominator": lac["write"]["denominator"],
        "LAC_write_rate": lac["write"]["rate"],
        "LAC_overall_numerator": lac["overall"]["numerator"],
        "LAC_overall_denominator": lac["overall"]["denominator"],
        "LAC_overall_rate": lac["overall"]["rate"],
    }


cross = [
    prior_row("HuggingFaceTB/SmolLM2-1.7B-Instruct", 1711376384, smol_runs, smol_metrics),
    metric_row("Qwen/Qwen2.5-7B-Instruct", 7615616512, qwen_metrics),
    metric_row("mistralai/Mistral-7B-Instruct-v0.3", 7248023552, mistral_metrics),
    metric_row("microsoft/Phi-4-mini-instruct", 3836021760, phi_metrics),
]
write_csv(OUT / "cross_model_capability.csv", cross)

smol = {row["task_id"] for row in smol_runs if row["security_eligible"]}
qwen = {
    row["task_id"]
    for row in read_jsonl(ROOT / "results/iteration3a_qwen25_7b_runpod/security_eligibility.jsonl")
    if row["security_eligible"]
}
mistral = {row["task_id"] for row in mistral_runs if row["security_eligible"]}
phi = {row["task_id"] for row in phi_runs if row["security_eligible"]}


def section(task_ids):
    ids = sorted(task_ids)
    return {
        "count": len(ids),
        "task_ids": ids,
        "composition": {
            "read": sum(by_task[item]["utility_criteria"]["action"] == "read_email" for item in ids),
            "write": sum(by_task[item]["utility_criteria"]["action"] == "send_email" for item in ids),
            "no_action": sum(by_task[item]["utility_criteria"]["action"] == "none" for item in ids),
        },
    }


common = {
    "smollm2_intersection_phi": section(smol & phi),
    "qwen_intersection_phi": section(qwen & phi),
    "mistral_intersection_phi": section(mistral & phi),
    "smollm2_qwen_phi_intersection": section(smol & qwen & phi),
    "four_model_intersection": section(smol & qwen & mistral & phi),
}
(OUT / "common_eligibility.json").write_text(json.dumps(common, indent=2) + "\n", encoding="utf-8")


def failure_classes(row, task):
    labels = []
    if row["parse_status"] == "PARSE_FAILURE":
        labels.append("parsing")
    elif row["parse_status"] != "PARSE_SUCCESS":
        labels.append("schema")
    if row["actual_action"] != row["expected_action"]:
        labels.append("wrong action")
    required = task["utility_criteria"].get("required_arguments", {})
    actual = (row.get("proposed_action") or {}).get("arguments", {})
    wrong_keys = [key for key, expected in required.items() if not _argument_equal(key, actual.get(key, ""), expected)]
    if wrong_keys:
        labels.append("recipient error" if "to" in wrong_keys else "wrong argument")
    if row["expected_action"] == "none" and row.get("answer_utility") != 1:
        labels.append(f"{task['task_cluster'].replace('_', ' ')} failure")
    return labels or ["full-task evaluator failure"]


failures = []
for row in phi_runs:
    if row["security_eligible"]:
        continue
    task = by_task[row["task_id"]]
    failures.append(
        {
            "task_id": row["task_id"],
            "task_family": task["task_cluster"],
            "expected_action": row["expected_action"],
            "proposed_action": row["actual_action"],
            "expected_arguments": json.dumps(task["utility_criteria"].get("required_arguments", {}), sort_keys=True),
            "proposed_arguments": json.dumps((row.get("proposed_action") or {}).get("arguments", {}), sort_keys=True),
            "parser_status": row["parse_status"],
            "evaluator_status": "PASS" if row.get("task_success") else "FAIL",
            "failure_labels": ";".join(failure_classes(row, task)),
            "raw_model_output": row["raw_model_output"],
        }
    )
write_csv(OUT / "ineligible_tasks.csv", failures)

post_text = (OUT / "post_regression_tests.txt").read_text(encoding="utf-8")
match = re.search(r"Ran 63 tests in ([0-9.]+)s", post_text)
assert match and "OK" in post_text
phi_metrics["cross_model_capability"] = cross
phi_metrics["common_eligibility"] = common
phi_metrics["post_regression_tests"] = {
    "tests": 63,
    "status": "PASS",
    "duration_seconds": float(match.group(1)),
    "offline_mode": True,
}
(OUT / "metrics.json").write_text(json.dumps(phi_metrics, indent=2) + "\n", encoding="utf-8")

report = OUT / "ITERATION4C_PHI4MINI_CAPABILITY_REPORT.md"
text = report.read_text(encoding="utf-8")
assert "## Cross-model capability comparison" not in text
pct = lambda value: f"{100 * value:.1f}%"
lines = [
    "",
    "## Cross-model capability comparison",
    "",
    "Descriptive only; prior models were not rerun.",
    "",
    "| Model | Parameters | JSON | Schema | Action | Arguments | General Utility | Eligible | LAC read | LAC write | LAC overall |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
]
for item in cross:
    lines.append(
        f"| {item['model']} | {item['parameter_count']:,} | "
        f"{item['JSON_numerator']}/{item['JSON_denominator']} ({pct(item['JSON_rate'])}) | "
        f"{item['Schema_numerator']}/{item['Schema_denominator']} ({pct(item['Schema_rate'])}) | "
        f"{item['Action_numerator']}/{item['Action_denominator']} ({pct(item['Action_rate'])}) | "
        f"{item['Argument_numerator']}/{item['Argument_denominator']} ({pct(item['Argument_rate'])}) | "
        f"{item['General_Utility_numerator']:.3f}/{item['General_Utility_denominator']} ({pct(item['General_Utility_rate'])}) | "
        f"{item['Security_eligible_numerator']}/{item['Security_eligible_denominator']} | "
        f"{item['LAC_read_numerator']}/{item['LAC_read_denominator']} | "
        f"{item['LAC_write_numerator']}/{item['LAC_write_denominator']} | "
        f"{item['LAC_overall_numerator']}/{item['LAC_overall_denominator']} |"
    )
lines += [
    "",
    "## Common eligibility preparation",
    "",
    "| Intersection | Tasks | Read | Write | No-action |",
    "|---|---:|---:|---:|---:|",
]
for label, key in [
    ("SmolLM2 ∩ Phi", "smollm2_intersection_phi"),
    ("Qwen ∩ Phi", "qwen_intersection_phi"),
    ("Mistral ∩ Phi", "mistral_intersection_phi"),
    ("SmolLM2 ∩ Qwen ∩ Phi", "smollm2_qwen_phi_intersection"),
    ("SmolLM2 ∩ Qwen ∩ Mistral ∩ Phi", "four_model_intersection"),
]:
    item = common[key]
    composition = item["composition"]
    lines.append(
        f"| {label} | {item['count']} | {composition['read']} | {composition['write']} | {composition['no_action']} |"
    )
failure_counts = Counter(label for row in failures for label in row["failure_labels"].split(";"))
lines += [
    "",
    "Exact task IDs are preserved in `common_eligibility.json`. No attacks were run.",
    "",
    "## Failure analysis",
    "",
    f"{len(failures)} tasks were ineligible. Descriptive failure-label counts: "
    + ", ".join(f"{name}={count}" for name, count in sorted(failure_counts.items()))
    + ". Exact expected/proposed actions and arguments, parser/evaluator status, and raw outputs are preserved in `ineligible_tasks.csv` and `raw_runs.jsonl`.",
    "",
    "## Regression integrity",
    "",
    "- Pre-experiment: 63/63 PASS.",
    "- Post-experiment: 63/63 PASS.",
    "- Frozen tasks, P4, parser, evaluator, simulator, and eligibility rules were not modified.",
    "",
]
report.write_text(text + "\n".join(lines), encoding="utf-8")
print(json.dumps({"decision": phi_metrics["decision"], "cross": cross, "common": common, "failures": len(failures)}, indent=2))
