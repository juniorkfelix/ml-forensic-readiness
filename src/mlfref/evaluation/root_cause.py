"""D. Root cause identification (component score) and clean-control false attribution.

Components (config/evaluation_schema.yaml):
  dataset           identified training dataset resolves to the GT poisoned dataset
  training_run      identified run is the run that produced the deployed model
                    (MLflow run ID; or, without an ID, start and end times within tolerance)
  model             identified model resolves to the GT model SHA-256
  poisoning_source  changed-sample set vs GT poisoned sample IDs, F1 >= threshold
RCI score = correct components / 4. Precision, recall and F1 are always reported.
"""

from __future__ import annotations

import re
from typing import Any

from mlfref.evaluation.common import ArtifactResolver, ts

MODIFICATION_FINDINGS = (
    "LABEL_MODIFICATION",
    "CONTENT_AND_LABEL_MODIFICATION",
    "CONTENT_MODIFICATION",
    "MIXED_MODIFICATION",
    "DATASET_MODIFIED_UNSPECIFIED",
)


def set_scores(predicted: list[int] | None, truth: list[int]) -> dict[str, float | None]:
    if predicted is None:
        return {"precision": None, "recall": 0.0 if truth else None, "f1": 0.0, "n_predicted": 0}
    p, t = set(predicted), set(truth)
    tp = len(p & t)
    precision = tp / len(p) if p else 0.0
    recall = tp / len(t) if t else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "n_predicted": len(p)}


def _threshold(schema: dict[str, Any]) -> float:
    crit = schema["root_cause_components"]["poisoning_source"]["criterion"]
    return float(re.search(r"([\d.]+)", crit).group(1))


def _gt(gt_events: list[dict[str, Any]], *actions: str) -> dict[str, Any] | None:
    return next((e for e in gt_events if e["action"] in actions), None)


def dataset_correct(recon: dict[str, Any], gt_events, resolver: ArtifactResolver) -> bool:
    tds = recon["hops"]["training_dataset"]
    if tds["status"] != "IDENTIFIED":
        return False
    gt = _gt(gt_events, "POISONED_DATASET_CREATED") or _gt(gt_events, "CLEAN_DATASET_CREATED")
    v = tds["value"]
    for key in ("manifest_sha256", "mlflow_digest", "store"):
        if v.get(key):
            ref_key = "dataset_manifest_sha256" if key == "manifest_sha256" else key
            res = resolver.resolve(ref_key, v[key])
            want = (
                gt.get("result_artifact")
                if res and res[0] == "dataset_manifest"
                else (gt.get("metadata") or {}).get("mlflow_digest")
            )
            return res is not None and res[1] == want
    return False


def training_run_correct(recon: dict[str, Any], gt_events, tolerance: float) -> bool:
    tr = recon["hops"]["training_run"]
    if tr["status"] != "IDENTIFIED":
        return False
    start, end = _gt(gt_events, "TRAINING_STARTED"), _gt(gt_events, "TRAINING_COMPLETED")
    run_id = (start.get("metadata") or {}).get("mlflow_run_id") if start else None
    if tr["value"].get("run_id"):
        return tr["value"]["run_id"] == run_id
    s, e = tr["value"].get("start_time"), tr["value"].get("end_time")
    return bool(
        s
        and e
        and start
        and end
        and abs(ts(s) - ts(start["timestamp_utc"])) <= tolerance
        and abs(ts(e) - ts(end["timestamp_utc"])) <= tolerance
    )


def model_correct(recon: dict[str, Any], gt_events, resolver: ArtifactResolver) -> bool:
    mod = recon["hops"]["model"]
    gt = _gt(gt_events, "COMPROMISED_MODEL_CREATED", "MODEL_CREATED")
    if mod["status"] != "IDENTIFIED" or gt is None:
        return False
    v = mod["value"]
    if v.get("model_sha256"):
        return v["model_sha256"] == gt["affected_artifact"]
    if v.get("registry_version"):
        return str(v["registry_version"]) == str((gt.get("metadata") or {}).get("registry_version"))
    if v.get("path"):
        res = resolver.resolve("model_path", v["path"])
        return res is not None and res[1] == gt["affected_artifact"]
    return False


def root_cause_score(
    recon: dict[str, Any],
    gt_events: list[dict[str, Any]],
    gt_attack: dict[str, Any] | None,
    schema: dict[str, Any],
    resolver: ArtifactResolver,
) -> dict[str, Any]:
    tol = float(schema["event_matching"]["time_tolerance_seconds"])
    truth = gt_attack["poisoned_sample_ids"] if gt_attack else []
    scores = set_scores(recon["root_cause"].get("changed_sample_ids"), truth)
    components = {
        "dataset": dataset_correct(recon, gt_events, resolver),
        "training_run": training_run_correct(recon, gt_events, tol),
        "model": model_correct(recon, gt_events, resolver),
        "poisoning_source": bool(scores["f1"] is not None and scores["f1"] >= _threshold(schema)),
    }
    correct = sum(components.values())
    return {
        "components": components,
        "rci_score": correct / len(components),
        "rci_all_correct": correct == len(components),
        "poisoning_source_scores": scores,
        "finding": recon["root_cause"]["finding"],
    }


def clean_control(recon: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    finding = recon["root_cause"]["finding"]
    return {
        "finding": finding,
        "correct": finding == schema["clean_control"]["correct_finding"],
        "false_attribution": finding in MODIFICATION_FINDINGS,
    }
