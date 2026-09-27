"""Reconstructed events and chronology.

The event vocabulary is neutral: it names what the evidence shows, not what the
investigator suspects.

    DATASET_REGISTERED   the prior dataset state was registered
    DATASET_MODIFIED     the dataset used for training differs from the registered state
                         (time bounded by registration and training-data load)
    TRAINING_STARTED / TRAINING_COMPLETED
    MODEL_CREATED
    MODEL_DEPLOYED
    INPUT_SUBMITTED      the ticketed input was submitted to the service
    INCIDENT_PREDICTION  the ticketed prediction was served

``time_basis``: exact | bounded (time_lower..time_upper) | inferred | unknown. An event
is emitted only when an identified hop supports it. Nothing is invented.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


def _ts(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _event(
    event_class: str,
    time: str | None,
    basis: str,
    refs: dict[str, Any],
    evidence: list[str],
    confidence: str,
    lower: str | None = None,
    upper: str | None = None,
) -> dict[str, Any]:
    return {
        "event_class": event_class,
        "time": time,
        "time_basis": basis if (time or lower) else "unknown",
        "time_lower": lower,
        "time_upper": upper,
        "artifact_refs": {k: v for k, v in refs.items() if v is not None},
        "evidence_basis": evidence,
        "confidence": confidence,
    }


def build_events(findings: dict[str, Any]) -> list[dict[str, Any]]:
    h = findings["hops"]
    change = findings["dataset_change"]
    events: list[dict[str, Any]] = []

    pri, tds = h["prior_dataset"], h["training_dataset"]
    if pri["status"] == "IDENTIFIED":
        v = pri["value"]
        events.append(
            _event(
                "DATASET_REGISTERED",
                v.get("time"),
                "exact",
                {
                    "dataset_manifest_sha256": v.get("manifest_sha256"),
                    "mlflow_digest": v.get("mlflow_digest"),
                    "store": v.get("store"),
                    "dataset_id": v.get("dataset_id"),
                },
                pri["basis"],
                pri["confidence"],
            )
        )
    if change.get("changed") is True:
        window = change.get("modification_window") or [None, None]
        v = tds["value"]
        events.append(
            _event(
                "DATASET_MODIFIED",
                None,
                "bounded",
                {
                    "dataset_manifest_sha256": v.get("manifest_sha256"),
                    "mlflow_digest": v.get("mlflow_digest"),
                    "store": v.get("store"),
                    "dataset_id": v.get("dataset_id"),
                    "parent_dataset_manifest_sha256": pri["value"].get("manifest_sha256"),
                },
                [change["basis"]],
                tds["confidence"],
                window[0],
                window[1],
            )
        )

    tr = h["training_run"]
    if tr["status"] == "IDENTIFIED":
        v = tr["value"]
        refs = {
            "run_id": v.get("run_id"),
            "dataset_manifest_sha256": tds["value"].get("manifest_sha256"),
            "mlflow_digest": tds["value"].get("mlflow_digest"),
            "store": tds["value"].get("store"),
        }
        if v.get("start_time"):
            events.append(
                _event(
                    "TRAINING_STARTED",
                    v["start_time"],
                    "exact",
                    refs,
                    tr["basis"],
                    tr["confidence"],
                )
            )
        if v.get("end_time"):
            events.append(
                _event(
                    "TRAINING_COMPLETED",
                    v["end_time"],
                    "exact",
                    refs,
                    tr["basis"],
                    tr["confidence"],
                )
            )

    mod = h["model"]
    model_refs = {}
    if mod["status"] == "IDENTIFIED":
        v = mod["value"]
        model_refs = {
            "model_sha256": v.get("model_sha256"),
            "model_path": v.get("path"),
            "registry_version": v.get("registry_version"),
            "model_id": v.get("model_id"),
        }
        events.append(
            _event(
                "MODEL_CREATED", v.get("time"), "exact", model_refs, mod["basis"], mod["confidence"]
            )
        )

    dep = h["deployment"]
    if dep["status"] == "IDENTIFIED":
        v = dep["value"]
        events.append(
            _event(
                "MODEL_DEPLOYED",
                v.get("time"),
                "exact",
                {
                    **model_refs,
                    "deployment_id": v.get("deployment_id"),
                    "deployed_path": v.get("deployed_path"),
                },
                dep["basis"],
                dep["confidence"],
            )
        )

    inf = h["inference"]
    if inf["status"] == "IDENTIFIED":
        v = inf["value"]
        refs = {"request_id": v.get("request_id"), "input_sha256": v.get("input_sha256")}
        if v.get("request_time"):
            events.append(
                _event(
                    "INPUT_SUBMITTED",
                    v["request_time"],
                    "exact",
                    refs,
                    ["request recorded on arrival"],
                    inf["confidence"],
                )
            )
        else:
            events.append(
                _event(
                    "INPUT_SUBMITTED",
                    v.get("time"),
                    "inferred",
                    refs,
                    ["only the served result is recorded; submission time taken " "as result time"],
                    inf["confidence"],
                )
            )
        events.append(
            _event(
                "INCIDENT_PREDICTION",
                v.get("time"),
                "exact",
                {**refs, "predicted_label": v.get("predicted_label")},
                inf["basis"],
                inf["confidence"],
            )
        )
    return order_events(events)


def sort_key(event: dict[str, Any]) -> float | None:
    if event["time_basis"] == "bounded" and event["time_lower"] and event["time_upper"]:
        return (_ts(event["time_lower"]) + _ts(event["time_upper"])) / 2
    if event["time"]:
        return _ts(event["time"])
    return None


def order_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timed = [e for e in events if sort_key(e) is not None]
    untimed = [e for e in events if sort_key(e) is None]
    timed.sort(key=sort_key)
    for i, e in enumerate(timed, start=1):
        e["order"] = i
    for e in untimed:
        e["order"] = None
    return timed + untimed
