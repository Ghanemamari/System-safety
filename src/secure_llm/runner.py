from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .architectures import make_architecture
from .backend import MockLLMBackend
from .evaluation import attack_success, security_violation, task_success
from .types import BenchmarkCase, pi_sec


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def git_commit(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.SubprocessError):
        return "NOT_A_GIT_REPOSITORY"


def planned_runs(config: dict[str, Any], case_count: int) -> int:
    return case_count * len(config["architectures"]) * len(config["attack_modes"]) * int(config["repetitions"])


def create_run_dir(root: Path, name: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = root / "results" / f"{stamp}_{name}"
    path.mkdir(parents=True, exist_ok=False)
    return path


def execute(config_path: Path, root: Path, limit: int | None = None, resume: Path | None = None) -> Path:
    config = load_json(config_path)
    cases = [BenchmarkCase(**item) for item in load_json(root / config["dataset"])]
    run_dir = resume or create_run_dir(root, config["experiment"]["name"])
    run_dir.mkdir(parents=True, exist_ok=True)
    snapshot = run_dir / "config.yaml"
    if not snapshot.exists():
        snapshot.write_text(json.dumps(config, indent=2), encoding="utf-8")
    runs_path = run_dir / "runs.jsonl"
    completed: set[str] = set()
    if runs_path.exists():
        for line in runs_path.read_text(encoding="utf-8").splitlines():
            completed.add(json.loads(line)["run_key"])
    backend = MockLLMBackend()
    seed0 = int(config["experiment"]["seed"])
    written = 0
    with runs_path.open("a", encoding="utf-8") as handle:
        for architecture_name in config["architectures"]:
            architecture = make_architecture(architecture_name, backend)
            for case in cases:
                for attack_mode in config["attack_modes"]:
                    for repetition in range(int(config["repetitions"])):
                        run_key = f"{architecture_name}|{case.id}|{attack_mode}|{repetition}"
                        if run_key in completed:
                            continue
                        if limit is not None and written >= limit:
                            return run_dir
                        started = time.perf_counter()
                        try:
                            trajectory = architecture.run(case, attack_mode, seed0 + repetition)
                            violation = security_violation(case, trajectory)
                            row = {"experiment_id":config["experiment"]["name"],"run_id":hashlib.sha256(run_key.encode()).hexdigest()[:16],"run_key":run_key,"timestamp_utc":datetime.now(timezone.utc).isoformat(),"seed":seed0+repetition,"model":backend.name,"backend_type":"mock","mocked":True,"architecture":architecture_name,"task_id":case.id,"attack_id":f"{case.id}_{attack_mode}","attack_mode":attack_mode,"prompt":trajectory.prompt,"model_output":trajectory.model_output,"trajectory":trajectory.to_dict(),"pi_sec":pi_sec(trajectory),"tool_calls":[asdict(a) for a in trajectory.executed_actions],"policy_decisions":[asdict(d) for d in trajectory.policy_decisions],"task_success":task_success(case, trajectory),"attack_success":attack_success(case, trajectory) if attack_mode != "clean" else False,"security_violation":violation,"unauthorized_action_count":sum(1 for a in trajectory.executed_actions if a.tool not in case.allowed_actions),"over_refusal":not task_success(case, trajectory) and not violation,"latency_ms":round((time.perf_counter()-started)*1000,3),"input_tokens":len(trajectory.prompt.split()),"output_tokens":len(trajectory.model_output.split()),"cost":0.0,"error":None}
                        except Exception as exc:
                            row = {"experiment_id":config["experiment"]["name"],"run_id":hashlib.sha256(run_key.encode()).hexdigest()[:16],"run_key":run_key,"timestamp_utc":datetime.now(timezone.utc).isoformat(),"seed":seed0+repetition,"model":backend.name,"backend_type":"mock","mocked":True,"architecture":architecture_name,"task_id":case.id,"attack_id":f"{case.id}_{attack_mode}","attack_mode":attack_mode,"error":f"{type(exc).__name__}: {exc}"}
                        handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                        handle.flush()
                        written += 1
    metadata = {"git_commit":git_commit(root),"dataset_version":config["experiment"]["dataset_version"],"python":sys.version,"platform":platform.platform(),"environment":{"implementation":platform.python_implementation()},"pid":os.getpid(),"mocked":True,"scientific_status":"INFRASTRUCTURE VALIDATION ONLY; REAL-MODEL RESULTS NOT RUN"}
    (run_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return run_dir
