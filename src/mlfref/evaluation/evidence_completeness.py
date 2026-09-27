"""A. Evidence Completeness (EC) = required evidence items recovered / applicable items.

Items are pre-defined in config/evaluation_schema.yaml (DS1..IG3). An item counts as
recovered iff the reconstruction reports it with a value AND, where ground truth can
verify it, the value is correct. Each item's rule below is fixed; the reconstruction
engine does not know these rules (it reports findings, the evaluator maps them).

Items DS3 and DS5 apply only to attacked runs (there is no change to describe in a
clean run).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mlfref.evaluation.common import ArtifactResolver, ts
from mlfref.evaluation.root_cause import (
    _gt,
    dataset_correct,
    model_correct,
    set_scores,
    strongest_dataset_ref_matches,
    training_run_correct,
)

ATTACK_ONLY_ITEMS = ("DS3", "DS5")


class Ctx:
    def __init__(self, recon, gt_events, gt_attack, schema, resolver: ArtifactResolver):
        self.recon, self.gt, self.attack, self.schema, self.resolver = (
            recon,
            gt_events,
            gt_attack,
            schema,
            resolver,
        )
        self.tol = float(schema["event_matching"]["time_tolerance_seconds"])
        self.hops = recon["hops"]

    def hop(self, name):
        return self.hops[name]

    def ok(self, name):
        return self.hops[name]["status"] == "IDENTIFIED"


def _near(a: str | None, b: str | None, tol: float) -> bool:
    return bool(a and b and abs(ts(a) - ts(b)) <= tol)


def _registered_correct(c: Ctx) -> bool:
    if not c.ok("prior_dataset"):
        return False
    # Strongest reference; a path counts if it held the registered data at registration (D-054).
    return strongest_dataset_ref_matches(
        c.hop("prior_dataset")["value"], _gt(c.gt, "CLEAN_DATASET_CREATED"), c.resolver
    )


def _profile_correct(c: Ctx) -> bool:
    prof = c.hop("training_dataset")["value"].get("profile")
    gt = _gt(c.gt, "POISONED_DATASET_CREATED") or _gt(c.gt, "CLEAN_DATASET_CREATED")
    return bool(prof) and prof == (gt.get("metadata") or {}).get("class_distribution")


def _lineage_correct(c: Ctx) -> bool:
    rels = {(r["from"], r["relation"], r["to"]) for r in c.recon["graph"]["relations"]}
    return (
        ("training_dataset", "WAS_DERIVED_FROM", "registered_dataset") in rels
        and dataset_correct(c.recon, c.gt, c.resolver)
        and _registered_correct(c)
    )


def _samples_correct(c: Ctx) -> bool:
    import re

    thr = float(
        re.search(
            r"([\d.]+)", c.schema["root_cause_components"]["poisoning_source"]["criterion"]
        ).group(1)
    )
    s = set_scores(
        c.recon["root_cause"].get("changed_sample_ids"),
        c.attack["poisoned_sample_ids"] if c.attack else [],
    )
    return s["f1"] is not None and s["f1"] >= thr


def _run_id_correct(c: Ctx) -> bool:
    start = _gt(c.gt, "TRAINING_STARTED")
    rid = c.hop("training_run")["value"].get("run_id")
    return bool(rid) and rid == (start.get("metadata") or {}).get("mlflow_run_id")


def _times_correct(c: Ctx) -> bool:
    v = c.hop("training_run")["value"]
    return _near(
        v.get("start_time"), _gt(c.gt, "TRAINING_STARTED")["timestamp_utc"], c.tol
    ) and _near(v.get("end_time"), _gt(c.gt, "TRAINING_COMPLETED")["timestamp_utc"], c.tol)


def _params_correct(c: Ctx) -> bool:
    params = c.hop("training_run")["value"].get("parameters") or {}
    hp = (_gt(c.gt, "TRAINING_STARTED").get("metadata") or {}).get("hyperparameters") or {}
    if not params or not hp:
        return False
    keys = [("epochs", "epochs"), ("batch_size", "batch_size")]
    return all(str(params.get(k)) == str(hp.get(g)) for k, g in keys)


def _code_correct(c: Ctx) -> bool:
    code = c.hop("training_run")["value"].get("code_version")
    want = (_gt(c.gt, "TRAINING_STARTED").get("metadata") or {}).get("git_commit")
    return bool(code) and code == want


def _model_hash_recorded(c: Ctx) -> bool:
    v = c.hop("model")["value"]
    gt = _gt(c.gt, "COMPROMISED_MODEL_CREATED", "MODEL_CREATED")
    return bool(v.get("model_sha256")) and v["model_sha256"] == gt["affected_artifact"]


def _model_run_link(c: Ctx) -> bool:
    return (
        c.ok("model")
        and model_correct(c.recon, c.gt, c.resolver)
        and training_run_correct(c.recon, c.gt, c.tol)
    )


def _deployment_record(c: Ctx) -> bool:
    if not c.ok("deployment"):
        return False
    v = c.hop("deployment")["value"]
    gt = _gt(c.gt, "MODEL_DEPLOYED")
    if not _near(v.get("time"), gt["timestamp_utc"], c.tol):
        return False
    # Strongest deployed-model reference present (hash > ID/version > path).
    for key, ref_key in (
        ("model_sha256", "model_sha256"),
        ("deployment_id", "deployment_id"),
        ("registry_version", "registry_version"),
        ("deployed_path", "deployed_path"),
        ("source_path", "model_path"),
    ):
        if v.get(key):
            return c.resolver.matches(ref_key, v[key], gt)
    return False


def _ticket_gt(c: Ctx) -> dict[str, Any] | None:
    rid = c.recon["incident"]["request_id"]
    return next(
        (
            e
            for e in c.gt
            if e["action"] == "MALICIOUS_PREDICTION"
            and (e.get("metadata") or {}).get("request_id") == rid
        ),
        None,
    )


def _inference_record(c: Ctx) -> bool:
    if not c.ok("inference"):
        return False
    gt = _ticket_gt(c)
    v = c.hop("inference")["value"]
    if gt is None:  # clean control: the ticket describes a served prediction
        return v.get("prediction_matches_ticket") is True
    from mlfref.config import CIFAR10_CLASSES

    return v.get("predicted_label") == CIFAR10_CLASSES[int(gt["metadata"]["predicted_class"])]


def _inference_model_link(c: Ctx) -> bool:
    v = c.hop("inference")["value"]
    gt = _gt(c.gt, "MODEL_DEPLOYED")
    if v.get("model_sha256"):
        return v["model_sha256"] == gt["affected_artifact"]
    if v.get("deployment_id"):
        return v["deployment_id"] == (gt.get("metadata") or {}).get("deployment_id")
    return False


def _input_hash(c: Ctx) -> bool:
    v = c.hop("inference")["value"]
    return bool(v.get("input_sha256")) and v["input_sha256"] == c.recon["incident"].get(
        "input_sha256"
    )


def _dataset_check(c: Ctx) -> bool:
    chk = c.recon["integrity"].get("dataset_check", {})
    if chk.get("status") != "RECORDED":
        return False
    attacked = c.attack is not None
    return chk.get("result") == ("MISMATCH" if attacked else "MATCH")


def _model_check(c: Ctx) -> bool:
    chk = c.recon["integrity"].get("deployed_model_check", {})
    return chk.get("status") in ("RECORDED", "POST_HOC") and chk.get("result") == "MATCH"


def _chain(c: Ctx) -> bool:
    return c.recon["integrity"].get("evidence_chain", {}).get("valid") is True


ITEM_RULES: dict[str, Callable[[Ctx], bool]] = {
    "DS1": lambda c: dataset_correct(c.recon, c.gt, c.resolver),
    "DS2": _registered_correct,
    "DS3": _lineage_correct,
    "DS4": _profile_correct,
    "DS5": _samples_correct,
    "TR1": _run_id_correct,
    "TR2": _times_correct,
    "TR3": lambda c: c.ok("training_run") and dataset_correct(c.recon, c.gt, c.resolver),
    "TR4": _params_correct,
    "TR5": _code_correct,
    "MO1": lambda c: model_correct(c.recon, c.gt, c.resolver),
    "MO2": _model_hash_recorded,
    "MO3": _model_run_link,
    "DE1": _deployment_record,
    "IN1": _inference_record,
    "IN2": _inference_model_link,
    "IN3": _input_hash,
    "IG1": _dataset_check,
    "IG2": _model_check,
    "IG3": _chain,
}


def evidence_completeness(recon, gt_events, gt_attack, schema, resolver) -> dict[str, Any]:
    ctx = Ctx(recon, gt_events, gt_attack, schema, resolver)
    items = []
    for spec in schema["required_evidence_items"]:
        applicable = gt_attack is not None or spec["id"] not in ATTACK_ONLY_ITEMS
        rule = ITEM_RULES.get(spec["id"])
        if rule is None:
            raise KeyError(f"no rule for evidence item {spec['id']}")
        recovered = bool(rule(ctx)) if applicable else None
        items.append(
            {
                "id": spec["id"],
                "stage": spec["stage"],
                "applicable": applicable,
                "recovered": recovered,
            }
        )
    app = [i for i in items if i["applicable"]]
    by_stage: dict[str, dict[str, int]] = {}
    for i in app:
        s = by_stage.setdefault(i["stage"], {"recovered": 0, "applicable": 0})
        s["applicable"] += 1
        s["recovered"] += int(i["recovered"])
    return {
        "items": items,
        "recovered": sum(i["recovered"] for i in app),
        "applicable": len(app),
        "ec": sum(i["recovered"] for i in app) / len(app) if app else float("nan"),
        "by_stage": {
            k: {**v, "fraction": v["recovered"] / v["applicable"]} for k, v in by_stage.items()
        },
    }
