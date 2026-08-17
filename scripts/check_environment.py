from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from secure_llm.environment import inspect_environment, load_project_environment


def main() -> int:
    load_project_environment(ROOT)
    report = inspect_environment(ROOT)
    print(f"NVIDIA_API_KEY: {'configured' if report.api_key_configured else 'not configured'}")
    print(f"NVIDIA_BASE_URL: {report.base_url}")
    print(f"NVIDIA_MODEL: {report.model}")
    print(f".env ignored by git: {'YES' if report.env_ignored else 'NO'}")
    print(f"Git repository detected: {'YES' if report.git_repository else 'NO'}")
    print(f"Potential committed NVIDIA secrets: {len(report.potential_secret_files)}")
    if report.potential_secret_files:
        print("WARNING: potential secret markers found in: " + ", ".join(report.potential_secret_files))
    if not report.env_ignored or report.potential_secret_files:
        print("SECURITY WARNING: real model execution is disabled until these issues are resolved.")
        return 2
    return 0 if report.api_key_configured else 1


if __name__ == "__main__":
    raise SystemExit(main())
