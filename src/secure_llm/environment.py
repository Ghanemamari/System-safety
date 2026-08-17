"""Local environment loading and secret-safe preflight checks."""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class EnvironmentReport:
    api_key_configured: bool
    base_url: str
    model: str
    env_ignored: bool
    git_repository: bool
    potential_secret_files: tuple[str, ...]

    @property
    def safe_for_real_requests(self) -> bool:
        return self.api_key_configured and self.env_ignored and not self.potential_secret_files


def load_project_environment(root: Path) -> None:
    """Load local values without overriding an existing process environment."""
    load_dotenv(dotenv_path=root / ".env", override=False)


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=False)


def _ignore_rules_are_safe(root: Path) -> bool:
    path = root / ".gitignore"
    if not path.exists():
        return False
    rules = {line.strip() for line in path.read_text(encoding="utf-8").splitlines()}
    required = {".env", ".env.*", "!.env.example"}
    if not required.issubset(rules):
        return False
    probe = _git(root, "check-ignore", "-q", ".env")
    inside = _git(root, "rev-parse", "--is-inside-work-tree").returncode == 0
    return probe.returncode == 0 if inside else True


def _candidate_files(root: Path, git_repository: bool) -> list[Path]:
    if git_repository:
        result = _git(root, "ls-files")
        return [root / line for line in result.stdout.splitlines() if line]
    candidates: list[Path] = []
    excluded = {".env", ".git", ".venv", "results", "articles", "__pycache__"}
    for path in root.rglob("*"):
        if path.is_file() and not any(part in excluded for part in path.relative_to(root).parts):
            candidates.append(path)
    return candidates


def _secret_files(root: Path, git_repository: bool) -> tuple[str, ...]:
    # Construct the marker so this safety checker does not flag its own source.
    marker = b"nvapi" + b"-"
    hits: list[str] = []
    for path in _candidate_files(root, git_repository):
        if path.name == ".env":
            continue
        try:
            if marker in path.read_bytes():
                hits.append(path.relative_to(root).as_posix())
        except OSError:
            continue
    return tuple(sorted(hits))


def inspect_environment(root: Path) -> EnvironmentReport:
    git_repository = _git(root, "rev-parse", "--is-inside-work-tree").returncode == 0
    return EnvironmentReport(
        api_key_configured=bool(os.getenv("NVIDIA_API_KEY") or os.getenv("LLM_API_KEY")),
        base_url=os.getenv("NVIDIA_BASE_URL") or os.getenv("LLM_BASE_URL") or "https://integrate.api.nvidia.com/v1",
        model=os.getenv("NVIDIA_MODEL") or os.getenv("LLM_MODEL") or "nvidia/nemotron-3-super-120b-a12b",
        env_ignored=_ignore_rules_are_safe(root),
        git_repository=git_repository,
        potential_secret_files=_secret_files(root, git_repository),
    )


def require_safe_real_environment(root: Path) -> EnvironmentReport:
    load_project_environment(root)
    report = inspect_environment(root)
    problems = []
    if not report.api_key_configured:
        problems.append("NVIDIA_API_KEY is not configured")
    if not report.env_ignored:
        problems.append(".env is not safely ignored")
    if report.potential_secret_files:
        problems.append("potential NVIDIA credentials occur in project files: " + ", ".join(report.potential_secret_files))
    if problems:
        raise RuntimeError("Real-request security preflight failed: " + "; ".join(problems))
    return report
