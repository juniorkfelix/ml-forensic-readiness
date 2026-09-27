"""Verify the ML-FREF execution environment (Phase 1).

Checks:
  * Python interpreter version
  * required third-party packages are importable (and their versions)
  * CUDA / GPU availability, including a small tensor operation on the GPU
  * the expected project directory structure exists
  * the working tree is a Git repository

Writes a machine-readable report to results/environment/environment_check.json
and exits non-zero if a REQUIRED check fails.

Usage:
    python scripts/setup_environment.py
"""

from __future__ import annotations

import argparse
import importlib
import json
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# import name -> distribution name (for reporting)
REQUIRED_PACKAGES = {
    "torch": "torch",
    "torchvision": "torchvision",
    "mlflow": "mlflow",
    "numpy": "numpy",
    "pandas": "pandas",
    "scipy": "scipy",
    "statsmodels": "statsmodels",
    "sklearn": "scikit-learn",
    "matplotlib": "matplotlib",
    "yaml": "PyYAML",
    "psutil": "psutil",
    "pytest": "pytest",
}
OPTIONAL_PACKAGES = {"networkx": "networkx", "ruff": "ruff", "black": "black"}

REQUIRED_DIRS = [
    "config",
    "data/raw",
    "data/clean",
    "data/poisoned",
    "data/manifests",
    "models/checkpoints",
    "models/deployed",
    "evidence/conventional",
    "evidence/provenance",
    "evidence/forensic",
    "ground_truth",
    "mlruns",
    "experiments/pilot",
    "experiments/main",
    "results/raw",
    "results/environment",
    "logs",
    "scripts",
    "src/mlfref",
    "tests",
    "docs",
]

PREFERRED_PYTHON = (3, 11)


def check_packages(packages: dict[str, str]) -> dict[str, dict]:
    results = {}
    for module_name, dist_name in packages.items():
        try:
            module = importlib.import_module(module_name)
            version = getattr(module, "__version__", "unknown")
            results[dist_name] = {"available": True, "version": str(version)}
        except Exception as exc:  # noqa: BLE001 - report any import failure
            results[dist_name] = {"available": False, "error": f"{type(exc).__name__}: {exc}"}
    return results


def check_cuda() -> dict:
    try:
        import torch
    except Exception as exc:  # noqa: BLE001
        return {"checked": False, "error": f"torch not importable: {exc}"}

    info = {
        "checked": True,
        "torch_cuda_build": torch.version.cuda,
        "cuda_available": torch.cuda.is_available(),
        "cudnn_version": torch.backends.cudnn.version() if torch.cuda.is_available() else None,
    }
    if info["cuda_available"]:
        props = torch.cuda.get_device_properties(0)
        info.update(
            {
                "device_count": torch.cuda.device_count(),
                "gpu_name": props.name,
                "gpu_total_memory_mb": round(props.total_memory / 1024**2),
                "compute_capability": f"{props.major}.{props.minor}",
            }
        )
        # Smoke test: a real computation on the GPU, checked against the CPU.
        try:
            a = torch.arange(12, dtype=torch.float32).reshape(3, 4)
            gpu_result = (a.cuda() @ a.cuda().T).cpu()
            info["gpu_smoke_test_passed"] = bool(torch.equal(gpu_result, a @ a.T))
        except Exception as exc:  # noqa: BLE001
            info["gpu_smoke_test_passed"] = False
            info["gpu_smoke_test_error"] = str(exc)
    return info


def check_dirs() -> dict[str, bool]:
    return {d: (PROJECT_ROOT / d).is_dir() for d in REQUIRED_DIRS}


def check_git() -> dict:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        is_project_repo = Path(out).resolve() == PROJECT_ROOT
        head = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )
        return {
            "is_repo": True,
            "repo_root_is_project_root": is_project_repo,
            "head_commit": head.stdout.strip() if head.returncode == 0 else None,
        }
    except Exception as exc:  # noqa: BLE001
        return {"is_repo": False, "error": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--output",
        default=str(PROJECT_ROOT / "results" / "environment" / "environment_check.json"),
    )
    args = parser.parse_args()

    py = sys.version_info
    report = {
        "checked_at_utc": datetime.now(UTC).isoformat(timespec="microseconds"),
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable_in_project_venv": ".venv" in Path(sys.executable).parts,
            "preferred_version": ".".join(map(str, PREFERRED_PYTHON)),
            "matches_preferred": (py.major, py.minor) == PREFERRED_PYTHON,
        },
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "required_packages": check_packages(REQUIRED_PACKAGES),
        "optional_packages": check_packages(OPTIONAL_PACKAGES),
        "cuda": check_cuda(),
        "directories": check_dirs(),
        "git": check_git(),
    }

    failures = []
    if py < (3, 11):
        failures.append(f"Python >= 3.11 required, found {platform.python_version()}")
    failures += [
        f"missing package: {n}"
        for n, r in report["required_packages"].items()
        if not r["available"]
    ]
    failures += [f"missing directory: {d}" for d, ok in report["directories"].items() if not ok]
    if not report["git"].get("is_repo"):
        failures.append("project is not a Git repository")

    warnings = []
    if not report["python"]["matches_preferred"]:
        warnings.append(
            f"Python {platform.python_version()} differs from preferred "
            f"{report['python']['preferred_version']} (documented deviation)"
        )
    if not report["cuda"].get("cuda_available"):
        warnings.append("CUDA not available: training will run on CPU (much slower)")
    elif not report["cuda"].get("gpu_smoke_test_passed"):
        failures.append("CUDA reported available but GPU smoke test failed")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Full environment manifest via the reproducibility module (Phase 2), if importable.
    manifest_path = out.parent / "environment_manifest.json"
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "src"))
        from mlfref.config import load_config
        from mlfref.reproducibility import collect_environment, save_environment_manifest

        cfg = load_config(PROJECT_ROOT / "config" / "experiment.yaml")
        save_environment_manifest(collect_environment(cfg), manifest_path)
    except Exception as exc:  # noqa: BLE001 - optional step; report and continue
        warnings.append(f"environment manifest not written: {type(exc).__name__}: {exc}")
        manifest_path = None

    report["warnings"] = warnings
    report["failures"] = failures
    report["status"] = "PASS" if not failures else "FAIL"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Human-readable summary (this is a CLI utility, so stdout output is intended).
    print(
        f"Python      : {report['python']['version']} "
        f"(venv: {report['python']['executable_in_project_venv']})"
    )
    for name, r in {**report["required_packages"], **report["optional_packages"]}.items():
        print(f"  {name:<13}: {r['version'] if r['available'] else 'MISSING'}")
    c = report["cuda"]
    print(
        f"CUDA        : available={c.get('cuda_available')} torch_build={c.get('torch_cuda_build')}"
        f" gpu={c.get('gpu_name')} smoke_test={c.get('gpu_smoke_test_passed')}"
    )
    print(f"Git         : {report['git']}")
    for w in warnings:
        print(f"WARNING     : {w}")
    for f in failures:
        print(f"FAILURE     : {f}")
    if manifest_path is not None:
        print(f"Manifest    : {manifest_path.relative_to(PROJECT_ROOT)}")
    print(f"STATUS      : {report['status']}  (report: {out.relative_to(PROJECT_ROOT)})")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
