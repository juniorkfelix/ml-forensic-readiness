"""Reproducibility controls and environment manifests.

* ``seed_everything`` seeds Python ``random``, NumPy, PyTorch (CPU) and all CUDA devices.
* ``configure_determinism`` turns on deterministic algorithms where PyTorch supports them
  and records exactly what was configured. PyTorch cannot guarantee bitwise determinism for
  every CUDA operation. With ``warn_only=True``, an op that has no deterministic kernel emits
  a warning instead of raising. Those warnings reach the run log through
  ``logging.captureWarnings`` (see mlfref.logging_utils), so any non-determinism is
  recorded rather than hidden.
* ``collect_environment`` / ``save_environment_manifest`` record the software and hardware
  context of every run.

Privacy: the raw hostname is never stored. ``machine_id`` is a truncated SHA-256 of the
hostname (a pseudonymous identifier that tells machines apart without naming them).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import socket
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import torch

from mlfref.config import config_hash
from mlfref.logging_utils import get_logger

log = get_logger("reproducibility")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CUBLAS_WORKSPACE_CONFIG = ":4096:8"


# --------------------------------------------------------------------------- seeding


def seed_everything(seed: int) -> None:
    """Seed Python, NumPy, PyTorch and CUDA RNGs."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)  # also seeds all CUDA devices
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    log.info("seeded python/numpy/torch/cuda RNGs with seed=%d", seed)


def make_generator(seed: int) -> torch.Generator:
    """Dedicated torch.Generator (e.g. for DataLoader shuffling), independent of global state."""
    g = torch.Generator()
    g.manual_seed(seed)
    return g


def seed_worker(worker_id: int) -> None:  # pragma: no cover - runs inside DataLoader workers
    """DataLoader ``worker_init_fn``: derive NumPy/random seeds from the torch worker seed."""
    worker_seed = torch.initial_seed() % 2**32
    np.random.seed(worker_seed)
    random.seed(worker_seed)


# --------------------------------------------------------------------------- determinism


def configure_determinism(
    deterministic: bool = True,
    cudnn_benchmark: bool = False,
    warn_only: bool = True,
) -> dict[str, Any]:
    """Configure deterministic execution; returns a record of the settings in effect."""
    notes: list[str] = []
    if deterministic:
        # Required by cuBLAS for deterministic behaviour; must be set before the first cuBLAS call.
        if os.environ.get("CUBLAS_WORKSPACE_CONFIG") is None:
            os.environ["CUBLAS_WORKSPACE_CONFIG"] = CUBLAS_WORKSPACE_CONFIG
        torch.use_deterministic_algorithms(True, warn_only=warn_only)
        torch.backends.cudnn.deterministic = True
        if warn_only:
            notes.append(
                "warn_only=True: operations without a deterministic implementation emit a "
                "warning (captured in the run log) instead of raising an error"
            )
    else:
        torch.use_deterministic_algorithms(False)
        torch.backends.cudnn.deterministic = False
        notes.append("deterministic algorithms DISABLED by configuration")
    torch.backends.cudnn.benchmark = cudnn_benchmark
    if cudnn_benchmark:
        notes.append("cudnn.benchmark=True may select non-deterministic kernels")

    record = {
        "deterministic_algorithms_enabled": torch.are_deterministic_algorithms_enabled(),
        "deterministic_warn_only": torch.is_deterministic_algorithms_warn_only_enabled(),
        "cudnn_deterministic": torch.backends.cudnn.deterministic,
        "cudnn_benchmark": torch.backends.cudnn.benchmark,
        "cublas_workspace_config": os.environ.get("CUBLAS_WORKSPACE_CONFIG"),
        "notes": notes,
    }
    for note in notes:
        log.warning("determinism: %s", note)
    return record


def resolve_device(preference: str = "auto") -> torch.device:
    if preference == "cuda":
        if not torch.cuda.is_available():
            raise RuntimeError("training.device='cuda' requested but CUDA is not available")
        return torch.device("cuda")
    if preference == "cpu":
        return torch.device("cpu")
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


# --------------------------------------------------------------------------- environment


def _run_git(args: list[str], cwd: Path) -> str | None:
    try:
        result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def get_git_info(repo: Path = PROJECT_ROOT) -> dict[str, Any]:
    """Current commit, branch and whether the working tree has uncommitted changes."""
    commit = _run_git(["rev-parse", "--verify", "HEAD"], repo)
    status = _run_git(["status", "--porcelain"], repo)
    return {
        "commit": commit,
        "branch": _run_git(["rev-parse", "--abbrev-ref", "HEAD"], repo) if commit else None,
        "dirty": bool(status) if status is not None else None,
        "available": commit is not None,
    }


def machine_id() -> str:
    return hashlib.sha256(socket.gethostname().encode("utf-8")).hexdigest()[:16]


def cpu_model() -> str:
    """Human-readable CPU model (platform.processor() is uninformative on Windows)."""
    system = platform.system()
    try:
        if system == "Windows":
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            )
            return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
        if system == "Linux":
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
        if system == "Darwin":
            out = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True
            )
            if out.returncode == 0:
                return out.stdout.strip()
    except Exception:  # noqa: BLE001 - fall back to platform.processor()
        pass
    return platform.processor() or "unknown"


def collect_environment(
    config: Mapping[str, Any] | None = None,
    identity: Mapping[str, str] | None = None,
    device: torch.device | None = None,
    determinism: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect the environment manifest for a run."""
    import psutil
    import torchvision

    cuda_available = torch.cuda.is_available()
    gpu = None
    if cuda_available:
        props = torch.cuda.get_device_properties(0)
        gpu = {
            "name": props.name,
            "total_memory_mb": round(props.total_memory / 1024**2),
            "compute_capability": f"{props.major}.{props.minor}",
            "device_count": torch.cuda.device_count(),
        }

    manifest: dict[str, Any] = {
        "manifest_created_utc": datetime.now(UTC).isoformat(timespec="microseconds"),
        "experiment": dict(identity) if identity else None,
        "seed": config["experiment"]["seed"] if config else None,
        "config_sha256": config_hash(config) if config else None,
        "software": {
            "python": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "torch": torch.__version__,
            "torchvision": torchvision.__version__,
            "numpy": np.__version__,
            "cuda_build": torch.version.cuda,
            "cudnn": torch.backends.cudnn.version() if cuda_available else None,
        },
        "hardware": {
            "cpu": cpu_model(),
            "cpu_physical_cores": psutil.cpu_count(logical=False),
            "cpu_logical_cores": psutil.cpu_count(logical=True),
            "ram_total_gb": round(psutil.virtual_memory().total / 1024**3, 1),
            "cuda_available": cuda_available,
            "gpu": gpu,
        },
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "machine_id": machine_id(),
        "device": str(device) if device is not None else None,
        "determinism": dict(determinism) if determinism else None,
        "git": get_git_info(),
        "command_line": [Path(sys.argv[0]).name, *sys.argv[1:]] if sys.argv else [],
    }
    return manifest


def save_environment_manifest(manifest: Mapping[str, Any], path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=False), encoding="utf-8")
    log.info("environment manifest written to %s", path)
    return path


def initialise_run(
    config: Mapping[str, Any], identity: Mapping[str, str] | None = None
) -> tuple[torch.device, dict[str, Any]]:
    """Standard run preamble: determinism -> seeding -> device -> environment manifest dict."""
    repro = config.get("reproducibility", {})
    determinism = configure_determinism(
        deterministic=repro.get("deterministic", True),
        cudnn_benchmark=repro.get("cudnn_benchmark", False),
        warn_only=repro.get("warn_only", True),
    )
    seed_everything(config["experiment"]["seed"])
    device = resolve_device(config["training"]["device"])
    manifest = collect_environment(config, identity, device, determinism)
    if manifest["git"]["dirty"]:
        log.warning("git working tree has uncommitted changes; commit before recorded runs")
    return device, manifest
