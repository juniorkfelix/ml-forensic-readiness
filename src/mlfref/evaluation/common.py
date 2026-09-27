"""Shared evaluation helpers: schema loading, time consistency and artefact resolution.

The evaluator is the ONLY component that sees both a reconstruction and ground truth,
and it reads ground truth only after the reconstruction has been written.
"""

from __future__ import annotations

from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from mlfref.data.cifar import read_store
from mlfref.data.manifest import build_manifest
from mlfref.forensic.hashing import manifest_hash, sha256_file

SCHEMA_PATH = Path(__file__).resolve().parents[3] / "config" / "evaluation_schema.yaml"

# Strongest-first reference priority per reconstructed event class (D-048).
REF_PRIORITY = {
    "DATASET_REGISTERED": ("dataset_manifest_sha256", "mlflow_digest", "store"),
    "DATASET_MODIFIED": ("dataset_manifest_sha256", "mlflow_digest", "store"),
    "TRAINING_STARTED": ("run_id", "dataset_manifest_sha256", "mlflow_digest", "store"),
    "TRAINING_COMPLETED": ("run_id", "dataset_manifest_sha256", "mlflow_digest", "store"),
    "MODEL_CREATED": ("model_sha256", "registry_version", "model_path"),
    "MODEL_DEPLOYED": (
        "model_sha256",
        "deployment_id",
        "registry_version",
        "deployed_path",
        "model_path",
    ),
    "INPUT_SUBMITTED": ("request_id",),
    "INCIDENT_PREDICTION": ("request_id",),
}

# reconstructed reference key -> canonical identifier kind
CANONICAL_KIND = {
    "dataset_manifest_sha256": "dataset_manifest",
    "store": "dataset_manifest",
    "mlflow_digest": "mlflow_digest",
    "model_sha256": "model_sha256",
    "model_path": "model_sha256",
    "deployed_path": "model_sha256",
    "registry_version": "registry_version",
    "run_id": "run_id",
    "deployment_id": "deployment_id",
    "request_id": "request_id",
    "input_sha256": "input_sha256",
}


def load_schema(path: str | Path = SCHEMA_PATH) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def ts(value: str | None) -> float | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def time_consistent(event: dict[str, Any], gt_time: str, tolerance: float) -> bool:
    t = ts(gt_time)
    basis = event.get("time_basis")
    if basis == "bounded":
        lo, hi = ts(event.get("time_lower")), ts(event.get("time_upper"))
        return lo is not None and hi is not None and lo - tolerance <= t <= hi + tolerance
    if basis in ("exact", "inferred") and event.get("time"):
        return abs(ts(event["time"]) - t) <= tolerance
    return False


class ArtifactResolver:
    """Resolves reconstructed artefact references to canonical identifiers.

    Path references are resolved by hashing the file's CURRENT content: a manifest
    hash for data stores, SHA-256 for model files (D-048).
    """

    def __init__(self, workspace_root: str | Path | None) -> None:
        self.root = Path(workspace_root) if workspace_root else None

    @lru_cache(maxsize=64)  # noqa: B019 - resolver instances are short-lived
    def _current(self, rel: str, kind: str) -> str | None:
        if self.root is None:
            return None
        path = self.root / rel
        if not path.exists():
            return None
        if kind == "dataset_manifest":
            return manifest_hash(build_manifest(read_store(path)))
        return sha256_file(path)

    def resolve(self, key: str, value: Any) -> tuple[str, Any] | None:
        kind = CANONICAL_KIND.get(key)
        if kind is None or value in (None, ""):
            return None
        if key in ("store", "model_path", "deployed_path"):
            current = self._current(str(value), kind)
            return (kind, current) if current else None
        return kind, str(value)

    def strongest(self, event: dict[str, Any]) -> tuple[str, tuple[str, Any] | None]:
        refs = event.get("artifact_refs", {})
        for key in REF_PRIORITY.get(event["event_class"], ()):
            if refs.get(key) not in (None, ""):
                return key, self.resolve(key, refs[key])
        return "none", None


def gt_identifiers(gt_event: dict[str, Any]) -> dict[str, str]:
    """Canonical identifiers of the artefact a ground-truth event concerns."""
    md = gt_event.get("metadata") or {}
    action = gt_event["action"]
    ids: dict[str, Any] = {}
    if action in ("CLEAN_DATASET_CREATED", "POISONED_DATASET_CREATED"):
        ids = {
            "dataset_manifest": gt_event.get("result_artifact")
            or gt_event.get("affected_artifact"),
            "mlflow_digest": md.get("mlflow_digest"),
        }
    elif action in ("TRAINING_STARTED", "TRAINING_COMPLETED"):
        ids = {
            "run_id": md.get("mlflow_run_id"),
            "dataset_manifest": gt_event.get("affected_artifact"),
            "mlflow_digest": md.get("mlflow_digest"),
        }
    elif action in ("COMPROMISED_MODEL_CREATED", "MODEL_CREATED"):
        ids = {
            "model_sha256": gt_event.get("affected_artifact"),
            "registry_version": md.get("registry_version"),
            "run_id": md.get("mlflow_run_id"),
        }
    elif action == "MODEL_DEPLOYED":
        ids = {
            "model_sha256": gt_event.get("affected_artifact"),
            "deployment_id": md.get("deployment_id"),
            "registry_version": md.get("registry_version"),
        }
    elif action in ("TRIGGER_SUBMITTED", "MALICIOUS_PREDICTION"):
        ids = {"request_id": md.get("request_id"), "input_sha256": md.get("input_sha256")}
    return {k: str(v) for k, v in ids.items() if v not in (None, "")}
