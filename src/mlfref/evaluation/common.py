"""Shared evaluation helpers: schema loading, time consistency and artefact resolution.

The evaluator is the ONLY component that sees both a reconstruction and ground truth,
and it reads ground truth only after the reconstruction has been written.

Artefact references are compared with the canonical identifiers of the ground-truth
event, always using the STRONGEST reference present (hash > ID/digest > path).

Path-only references use "content at event time" semantics (researcher decision,
D-054): a path is correct if, at the time of the event it refers to, that file held
the ground-truth artefact. The harness records each event's artefact hash and the
file path that held it, so the comparison is path equality against the ground-truth
event's recorded path. Consequence: one path can correctly refer to different
content at different events (e.g. a store tampered in place).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

SCHEMA_PATH = Path(__file__).resolve().parents[3] / "config" / "evaluation_schema.yaml"

# Strongest-first reference priority per reconstructed event class.
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

# reconstructed reference key -> canonical identifier kind in ground truth
CANONICAL_KIND = {
    "dataset_manifest_sha256": "dataset_manifest",
    "mlflow_digest": "mlflow_digest",
    "store": "store_path",
    "model_sha256": "model_sha256",
    "model_path": "model_path",
    "deployed_path": "deployed_path",
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
    """Maps reconstructed references to canonical identifier kinds (no file access)."""

    def __init__(self, workspace_root: str | Path | None = None) -> None:
        self.root = Path(workspace_root) if workspace_root else None

    def resolve(self, key: str, value: Any) -> tuple[str, str] | None:
        kind = CANONICAL_KIND.get(key)
        if kind is None or value in (None, ""):
            return None
        return kind, str(value)

    def strongest(self, event: dict[str, Any]) -> tuple[str, tuple[str, str] | None]:
        refs = event.get("artifact_refs", {})
        for key in REF_PRIORITY.get(event["event_class"], ()):
            if refs.get(key) not in (None, ""):
                return key, self.resolve(key, refs[key])
        return "none", None

    def matches(self, key: str, value: Any, gt_event: dict[str, Any] | None) -> bool:
        """Does reconstructed reference ``key=value`` identify this GT event's artefact?"""
        if gt_event is None:
            return False
        res = self.resolve(key, value)
        return res is not None and gt_identifiers(gt_event).get(res[0]) == res[1]


def gt_identifiers(gt_event: dict[str, Any]) -> dict[str, str]:
    """Canonical identifiers of the artefact a ground-truth event concerns (at that time)."""
    md = gt_event.get("metadata") or {}
    action = gt_event["action"]
    ids: dict[str, Any] = {}
    if action in ("CLEAN_DATASET_CREATED", "POISONED_DATASET_CREATED"):
        ids = {
            "dataset_manifest": gt_event.get("result_artifact")
            or gt_event.get("affected_artifact"),
            "mlflow_digest": md.get("mlflow_digest"),
            "store_path": md.get("store_path"),
        }
    elif action in ("TRAINING_STARTED", "TRAINING_COMPLETED"):
        ids = {
            "run_id": md.get("mlflow_run_id"),
            "dataset_manifest": gt_event.get("affected_artifact"),
            "mlflow_digest": md.get("mlflow_digest"),
            "store_path": md.get("store_path"),
        }
    elif action in ("COMPROMISED_MODEL_CREATED", "MODEL_CREATED"):
        ids = {
            "model_sha256": gt_event.get("affected_artifact"),
            "registry_version": md.get("registry_version"),
            "run_id": md.get("mlflow_run_id"),
            "model_path": md.get("model_path"),
        }
    elif action == "MODEL_DEPLOYED":
        ids = {
            "model_sha256": gt_event.get("affected_artifact"),
            "deployment_id": md.get("deployment_id"),
            "registry_version": md.get("registry_version"),
            "deployed_path": md.get("deployed_path"),
            "model_path": md.get("model_path"),
        }
    elif action in ("TRIGGER_SUBMITTED", "MALICIOUS_PREDICTION"):
        ids = {"request_id": md.get("request_id"), "input_sha256": md.get("input_sha256")}
    return {k: str(v) for k, v in ids.items() if v not in (None, "")}
