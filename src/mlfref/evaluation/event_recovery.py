"""B. Event Recovery Rate (ERR) = correctly recovered GT events / required GT events.

A reconstructed event correctly recovers a GT event iff (config/evaluation_schema.yaml):
  1. its event_class maps to the GT action;
  2. its strongest artefact reference resolves to the same canonical artefact as the GT
     event (no reference = mismatch);
  3. its time is consistent with the GT timestamp (tolerance; bounded windows allowed).
Matching is one-to-one. For inference actions only the TICKETED request is required.
"""

from __future__ import annotations

from typing import Any

from mlfref.evaluation.common import ArtifactResolver, gt_identifiers, time_consistent

INFERENCE_ACTIONS = ("TRIGGER_SUBMITTED", "MALICIOUS_PREDICTION")


def required_gt_events(
    gt_events: list[dict[str, Any]], attack_type: str, schema: dict[str, Any], request_id: str
) -> list[dict[str, Any]]:
    required = schema["required_gt_events"][attack_type]
    out = []
    for action in required:
        cands = [e for e in gt_events if e["action"] == action]
        if action in INFERENCE_ACTIONS:
            cands = [e for e in cands if (e.get("metadata") or {}).get("request_id") == request_id]
        if action == "COMPROMISED_MODEL_CREATED" and not cands:
            cands = [e for e in gt_events if e["action"] == "MODEL_CREATED"]
        out.append(cands[0] if cands else {"action": action, "missing_in_gt": True})
    return out


def _class_for(action: str, schema: dict[str, Any]) -> list[str]:
    return [c for c, spec in schema["event_classes"].items() if action in spec["gt_actions"]]


def match_events(
    recon_events: list[dict[str, Any]],
    required: list[dict[str, Any]],
    schema: dict[str, Any],
    resolver: ArtifactResolver,
) -> list[dict[str, Any]]:
    tol = float(schema["event_matching"]["time_tolerance_seconds"])
    used: set[int] = set()
    results = []
    for gt in required:
        row: dict[str, Any] = {
            "gt_action": gt["action"],
            "gt_sequence": gt.get("sequence_number"),
            "gt_time": gt.get("timestamp_utc"),
            "recovered": False,
            "reason": None,
            "recon_index": None,
        }
        if gt.get("missing_in_gt"):
            row["reason"] = "event absent from ground truth (not applicable)"
            row["applicable"] = False
            results.append(row)
            continue
        row["applicable"] = True
        ids = gt_identifiers(gt)
        classes = _class_for(gt["action"], schema)
        reasons = []
        for i, ev in enumerate(recon_events):
            if i in used or ev["event_class"] not in classes:
                continue
            key, resolved = resolver.strongest(ev)
            if resolved is None or ids.get(resolved[0]) != resolved[1]:
                reasons.append(f"artefact mismatch via {key}")
                continue
            if not time_consistent(ev, gt["timestamp_utc"], tol):
                reasons.append("time inconsistent")
                continue
            used.add(i)
            row.update(
                recovered=True, recon_index=i, matched_via=key, recon_event_class=ev["event_class"]
            )
            break
        if not row["recovered"]:
            row["reason"] = "; ".join(reasons) or "no reconstructed event of a matching class"
        results.append(row)
    return results


def event_recovery_rate(matches: list[dict[str, Any]]) -> dict[str, Any]:
    applicable = [m for m in matches if m.get("applicable", True)]
    recovered = sum(m["recovered"] for m in applicable)
    return {
        "recovered": recovered,
        "required": len(applicable),
        "err": recovered / len(applicable) if applicable else float("nan"),
    }
