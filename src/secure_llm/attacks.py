from __future__ import annotations

from .types import BenchmarkCase


def materialize_content(case: BenchmarkCase, attack_mode: str) -> str:
    if attack_mode == "clean":
        return case.clean_content
    if attack_mode == "direct":
        return f"{case.clean_content}\n\n{case.direct_attack}"
    if attack_mode == "contextual":
        return f"{case.clean_content}\n\n{case.contextual_attack}"
    raise ValueError(f"Unsupported attack mode: {attack_mode}")
