"""Evaluate one reconstruction against ground truth (spec §23).

Order of operations (enforced by the caller, scripts/evaluate_reconstruction.py):
the reconstruction JSON already exists, and its SHA-256 is recorded in the evaluation
record before ground truth is read.
"""

from __future__ import annotations

from typing import Any

from mlfref.evaluation.common import ArtifactResolver
from mlfref.evaluation.event_recovery import event_recovery_rate, match_events, required_gt_events
from mlfref.evaluation.evidence_completeness import evidence_completeness
from mlfref.evaluation.root_cause import clean_control, root_cause_score
from mlfref.evaluation.timeline_accuracy import timeline_accuracy


def evaluate_run(
    recon: dict[str, Any],
    gt_events: list[dict[str, Any]],
    gt_attack: dict[str, Any] | None,
    attack_type: str,
    schema: dict[str, Any],
    workspace_root,
) -> dict[str, Any]:
    resolver = ArtifactResolver(workspace_root)
    required = required_gt_events(gt_events, attack_type, schema, recon["incident"]["request_id"])
    matches = match_events(recon["events"], required, schema, resolver)
    result = {
        "schema_version": schema.get("schema_version"),
        "schema_status": schema.get("status"),
        "attack_type": attack_type,
        "event_recovery": {**event_recovery_rate(matches), "matches": matches},
        "timeline": timeline_accuracy(matches, recon["events"], schema),
        "evidence_completeness": evidence_completeness(
            recon, gt_events, gt_attack, schema, resolver
        ),
        "reconstruction_runtime_seconds": recon.get("runtime_seconds"),
    }
    if attack_type == "none":
        result["clean_control"] = clean_control(recon, schema)
        result["root_cause"] = None
    else:
        result["root_cause"] = root_cause_score(recon, gt_events, gt_attack, schema, resolver)
    return result
