"""Phase 15: evaluation metrics with hand-built reconstructions and ground truth."""

from __future__ import annotations

import copy
import math

import pandas as pd
import pytest

from mlfref.evaluation.common import ArtifactResolver, load_schema, time_consistent
from mlfref.evaluation.evaluate import evaluate_run
from mlfref.evaluation.event_recovery import match_events, required_gt_events
from mlfref.evaluation.evidence_completeness import evidence_completeness
from mlfref.evaluation.overhead import relative_overhead
from mlfref.evaluation.root_cause import clean_control, root_cause_score, set_scores
from mlfref.evaluation.statistics import describe
from mlfref.evaluation.timeline_accuracy import timeline_accuracy

SCHEMA = load_schema()
T = "2026-09-28T10:00:{:02d}.000000Z".format
CLEAN, POISONED, MODEL = "c" * 64, "p" * 64, "m" * 64
POISONED_IDS = [3, 7, 11, 19]
STORE = "data/stores/RUN-x/cifar10_train.npz"
MPATH = "models/checkpoints/RUN-x/model_final.pt"
DPATH = "models/deployed/RUN-x/model.pt"


def gt_events(attack=True):
    ev = [
        (
            "CLEAN_DATASET_CREATED",
            T(0),
            {"result_artifact": CLEAN},
            {"mlflow_digest": "d-clean", "class_distribution": {"a": 5}, "store_path": STORE},
        )
    ]
    if attack:
        ev.append(
            (
                "POISONED_DATASET_CREATED",
                T(5),
                {"result_artifact": POISONED},
                {"mlflow_digest": "d-pois", "class_distribution": {"a": 1}, "store_path": STORE},
            )
        )
    ev += [
        (
            "TRAINING_STARTED",
            T(10),
            {"affected_artifact": POISONED if attack else CLEAN},
            {
                "mlflow_run_id": "run-1",
                "hyperparameters": {"epochs": 30, "batch_size": 128},
                "git_commit": "abc",
            },
        ),
        (
            "TRAINING_COMPLETED",
            T(20),
            {"affected_artifact": POISONED if attack else CLEAN},
            {"mlflow_run_id": "run-1"},
        ),
        (
            "COMPROMISED_MODEL_CREATED" if attack else "MODEL_CREATED",
            T(22),
            {"affected_artifact": MODEL},
            {"registry_version": "4", "mlflow_run_id": "run-1", "model_path": MPATH},
        ),
        (
            "MODEL_DEPLOYED",
            T(25),
            {"affected_artifact": MODEL},
            {"deployment_id": "DEP-1", "deployed_path": DPATH, "model_path": MPATH},
        ),
    ]
    if attack:
        ev += [
            ("TRIGGER_SUBMITTED", T(30), {}, {"request_id": "REQ-00007", "input_sha256": "i" * 64}),
            ("MALICIOUS_PREDICTION", T(31), {}, {"request_id": "REQ-00007", "predicted_class": 0}),
        ]
    return [
        {"action": a, "timestamp_utc": t, "sequence_number": i + 1, "metadata": md, **art}
        for i, (a, t, art, md) in enumerate(ev)
    ]


def ev(cls, time, refs, basis="exact", lo=None, hi=None, order=None):
    return {
        "event_class": cls,
        "time": time,
        "time_basis": basis,
        "time_lower": lo,
        "time_upper": hi,
        "artifact_refs": refs,
        "order": order,
    }


def forensic_like_events():
    evs = [
        ev("DATASET_REGISTERED", T(0), {"dataset_manifest_sha256": CLEAN}),
        ev("DATASET_MODIFIED", None, {"dataset_manifest_sha256": POISONED}, "bounded", T(0), T(9)),
        ev("TRAINING_STARTED", T(11), {"run_id": "run-1"}),
        ev("TRAINING_COMPLETED", T(20), {"run_id": "run-1"}),
        ev("MODEL_CREATED", T(22), {"model_sha256": MODEL}),
        ev("MODEL_DEPLOYED", T(25), {"model_sha256": MODEL, "deployment_id": "DEP-1"}),
        ev("INPUT_SUBMITTED", T(30), {"request_id": "REQ-00007"}),
        ev("INCIDENT_PREDICTION", T(31), {"request_id": "REQ-00007"}),
    ]
    for i, e in enumerate(evs, 1):
        e["order"] = i
    return evs


def recon(events=None, **over):
    hop = lambda status="IDENTIFIED", conf="STRONG", **v: {  # noqa: E731
        "name": "",
        "status": status,
        "confidence": conf,
        "basis": [],
        "value": v,
    }
    r = {
        "incident": {"request_id": "REQ-00007", "input_sha256": "i" * 64},
        "events": events if events is not None else forensic_like_events(),
        "hops": {
            "inference": hop(
                request_id="REQ-00007",
                predicted_label="airplane",
                prediction_matches_ticket=True,
                input_sha256="i" * 64,
                model_sha256=MODEL,
                deployment_id="DEP-1",
            ),
            "deployment": hop(time=T(25), model_sha256=MODEL, deployment_id="DEP-1"),
            "model": hop(model_sha256=MODEL, run_id="run-1", time=T(22)),
            "training_run": hop(
                run_id="run-1",
                start_time=T(10),
                end_time=T(20),
                parameters={"epochs": "30", "batch_size": "128"},
                code_version="abc",
            ),
            "training_dataset": hop(manifest_sha256=POISONED, profile={"a": 1}),
            "prior_dataset": hop(manifest_sha256=CLEAN, time=T(0)),
        },
        "graph": {
            "relations": [
                {
                    "from": "training_dataset",
                    "relation": "WAS_DERIVED_FROM",
                    "to": "registered_dataset",
                }
            ]
        },
        "integrity": {
            "evidence_chain": {"valid": True},
            "dataset_check": {"status": "RECORDED", "result": "MISMATCH"},
            "deployed_model_check": {"status": "RECORDED", "result": "MATCH"},
        },
        "root_cause": {
            "finding": "LABEL_MODIFICATION",
            "changed_sample_ids": POISONED_IDS,
            "change_type": "LABEL_MODIFICATION",
        },
        "runtime_seconds": 0.1,
    }
    r.update(over)
    return r


def _matches(events, attack="label_flip", gts=None):
    gts = gts or gt_events()
    req = required_gt_events(gts, attack, SCHEMA, "REQ-00007")
    return match_events(events, req, SCHEMA, ArtifactResolver(None))


# ------------------------------------------------------------------ B. event recovery


def test_event_recovery_metric():
    m = _matches(forensic_like_events())
    assert all(x["recovered"] for x in m) and len(m) == 7  # label_flip requires 7


def test_event_recovery_artifact_time_and_one_to_one():
    evs = forensic_like_events()
    evs[4]["artifact_refs"] = {"model_sha256": "x" * 64}  # wrong model
    evs[5]["time"] = T(59)  # deployment 34 s late
    evs[0]["artifact_refs"] = {}  # no reference
    m = {x["gt_action"]: x for x in _matches(evs)}
    assert not m["COMPROMISED_MODEL_CREATED"]["recovered"]
    assert "artefact mismatch" in m["COMPROMISED_MODEL_CREATED"]["reason"]
    assert not m["MODEL_DEPLOYED"]["recovered"] and "time" in m["MODEL_DEPLOYED"]["reason"]
    assert not m["CLEAN_DATASET_CREATED"]["recovered"]
    # one reconstructed event can match only one GT event
    dup = forensic_like_events()[:1] * 1
    m2 = _matches(dup, gts=gt_events()[:1] + gt_events()[:1])
    assert sum(x["recovered"] for x in m2 if x["gt_action"] == "CLEAN_DATASET_CREATED") <= 1


def test_bounded_time_window():
    e = ev("DATASET_MODIFIED", None, {}, "bounded", T(0), T(9))
    assert time_consistent(e, T(5), 5) and not time_consistent(e, T(20), 5)
    assert time_consistent(e, T(13), 5)  # within tolerance of the upper bound


def test_strongest_reference_is_used():
    """C's DATASET_REGISTERED carries a hash AND a path; the hash (strongest) decides."""
    e = ev(
        "DATASET_REGISTERED", T(0), {"dataset_manifest_sha256": CLEAN, "store": "data/stores/x.npz"}
    )
    assert ArtifactResolver(None).strongest(e)[0] == "dataset_manifest_sha256"


# ------------------------------------------------------------------ C. timeline


def test_timeline_metric():
    evs = forensic_like_events()
    m = _matches(evs)
    t = timeline_accuracy(m, evs, SCHEMA)
    assert t["coverage"] == 1.0 and t["kendall_tau_b"] == pytest.approx(1.0)
    assert t["pairwise_order_accuracy"] == 1.0 and t["tau_status"] == "COMPUTED"


def test_timeline_reversed_and_insufficient():
    evs = forensic_like_events()
    for e in evs:
        e["order"] = 9 - e["order"]
    t = timeline_accuracy(_matches(evs), evs, SCHEMA)
    assert t["kendall_tau_b"] == pytest.approx(-1.0) and t["pairwise_order_accuracy"] == 0.0
    few = forensic_like_events()[:3]
    t2 = timeline_accuracy(_matches(few), few, SCHEMA)
    assert t2["kendall_tau_b"] is None and t2["tau_status"].startswith("NA")
    # REGISTERED, MODIFIED and TRAINING_STARTED recovered: 3 of 7, too few (<4) for tau
    assert t2["coverage"] == pytest.approx(3 / 7) and t2["n_ordered_events"] == 3


# ------------------------------------------------------------------ D. root cause


def test_root_cause_metric():
    gts = gt_events()
    attack = {"poisoned_sample_ids": POISONED_IDS}
    full = root_cause_score(recon(), gts, attack, SCHEMA, ArtifactResolver(None))
    assert full["rci_score"] == 1.0 and full["rci_all_correct"]
    partial = copy.deepcopy(recon())
    partial["root_cause"]["changed_sample_ids"] = None  # B-like: change detected, samples unknown
    partial["hops"]["model"]["value"] = {"registry_version": "4", "run_id": "run-1"}
    r = root_cause_score(partial, gts, attack, SCHEMA, ArtifactResolver(None))
    assert r["components"] == {
        "dataset": True,
        "training_run": True,
        "model": True,
        "poisoning_source": False,
    }
    assert r["rci_score"] == 0.75


def test_set_scores():
    s = set_scores([1, 2, 3, 4], [3, 4, 5, 6])
    assert s["precision"] == 0.5 and s["recall"] == 0.5 and s["f1"] == 0.5
    assert set_scores(None, [1])["f1"] == 0.0


def test_training_run_by_time_when_no_run_id():
    r = copy.deepcopy(recon())
    r["hops"]["training_run"]["value"] = {"start_time": T(11), "end_time": T(21)}
    res = root_cause_score(
        r, gt_events(), {"poisoned_sample_ids": POISONED_IDS}, SCHEMA, ArtifactResolver(None)
    )
    assert res["components"]["training_run"] is True
    r["hops"]["training_run"]["value"] = {"start_time": T(40), "end_time": T(50)}
    res = root_cause_score(
        r, gt_events(), {"poisoned_sample_ids": POISONED_IDS}, SCHEMA, ArtifactResolver(None)
    )
    assert res["components"]["training_run"] is False


def test_clean_control():
    ok = recon(root_cause={"finding": "NO_DATASET_MODIFICATION_FOUND"})
    bad = recon(root_cause={"finding": "DATASET_MODIFIED_UNSPECIFIED"})
    assert (
        clean_control(ok, SCHEMA)["correct"] and not clean_control(ok, SCHEMA)["false_attribution"]
    )
    assert clean_control(bad, SCHEMA)["false_attribution"]


# ------------------------------------------------------------------ A. evidence completeness


def test_evidence_completeness_metric():
    attack = {"poisoned_sample_ids": POISONED_IDS}
    res = evidence_completeness(recon(), gt_events(), attack, SCHEMA, ArtifactResolver(None))
    assert res["applicable"] == len(SCHEMA["required_evidence_items"])
    assert res["ec"] == 1.0, [i for i in res["items"] if not i["recovered"]]
    assert set(res["by_stage"]) == {
        "dataset",
        "training",
        "model",
        "deployment",
        "inference",
        "integrity",
    }


def test_evidence_completeness_degrades_with_missing_evidence():
    attack = {"poisoned_sample_ids": POISONED_IDS}
    r = copy.deepcopy(recon())
    r["integrity"] = {
        "evidence_chain": {"status": "NOT_OBSERVABLE"},
        "dataset_check": {"status": "NOT_OBSERVABLE"},
        "deployed_model_check": {"status": "NOT_OBSERVABLE"},
    }
    r["root_cause"]["changed_sample_ids"] = None
    res = evidence_completeness(r, gt_events(), attack, SCHEMA, ArtifactResolver(None))
    missing = {i["id"] for i in res["items"] if not i["recovered"]}
    assert missing == {"IG1", "IG2", "IG3", "DS5"}
    assert res["by_stage"]["integrity"]["fraction"] == 0.0


def test_attack_only_items_not_applicable_for_clean_runs():
    r = recon(root_cause={"finding": "NO_DATASET_MODIFICATION_FOUND", "changed_sample_ids": None})
    r["integrity"]["dataset_check"]["result"] = "MATCH"
    r["hops"]["training_dataset"]["value"]["manifest_sha256"] = CLEAN
    r["hops"]["training_dataset"]["value"]["profile"] = {"a": 5}
    res = evidence_completeness(r, gt_events(attack=False), None, SCHEMA, ArtifactResolver(None))
    na = {i["id"] for i in res["items"] if not i["applicable"]}
    assert na == {"DS3", "DS5"}
    assert res["applicable"] == len(SCHEMA["required_evidence_items"]) - 2


def test_evaluate_run_end_to_end():
    out = evaluate_run(
        recon(), gt_events(), {"poisoned_sample_ids": POISONED_IDS}, "label_flip", SCHEMA, None
    )
    assert out["event_recovery"]["err"] == 1.0
    assert out["root_cause"]["rci_score"] == 1.0
    assert out["evidence_completeness"]["ec"] == 1.0
    clean = evaluate_run(
        recon(events=forensic_like_events()[2:6]),
        gt_events(attack=False),
        None,
        "none",
        SCHEMA,
        None,
    )
    assert clean["root_cause"] is None and "clean_control" in clean


# ------------------------------------------------------------------ statistics / overhead


def test_describe():
    d = describe([1.0, 2.0, 3.0, 4.0])
    assert d["n"] == 4 and d["mean"] == 2.5 and d["median"] == 2.5
    assert d["iqr"] == pytest.approx(1.5) and d["ci_low"] < 2.5 < d["ci_high"]
    assert describe([5.0])["ci_method"].startswith("n/a")
    assert describe([])["n"] == 0
    assert describe([2.0, 2.0])["ci_method"].startswith("degenerate")


def test_relative_overhead():
    df = pd.DataFrame({"pipeline": ["A", "A", "B", "C"], "bytes": [100, 100, 150, 300]})
    out = relative_overhead(df, "bytes")
    assert out.loc["B", "overhead_pct"] == pytest.approx(50.0)
    assert out.loc["C", "overhead_pct"] == pytest.approx(200.0)
    assert math.isclose(out.loc["A", "overhead_pct"], 0.0)


def test_path_references_use_content_at_event_time():
    """D-054: a path is correct if it held the GT artefact at the event's time. A's single
    store path therefore correctly denotes BOTH the registered and the training dataset."""
    r = copy.deepcopy(recon())
    r["hops"]["prior_dataset"]["value"] = {"store": STORE, "time": T(0)}
    r["hops"]["training_dataset"]["value"] = {"store": STORE}
    r["hops"]["model"]["value"] = {"path": MPATH, "time": T(22)}
    r["hops"]["deployment"]["value"] = {"time": T(25), "deployed_path": DPATH, "source_path": MPATH}
    res = evidence_completeness(
        r, gt_events(), {"poisoned_sample_ids": POISONED_IDS}, SCHEMA, ArtifactResolver(None)
    )
    got = {i["id"]: i["recovered"] for i in res["items"]}
    assert got["DS1"] and got["DS2"] and got["MO1"] and got["DE1"]
    assert not got["MO2"]  # no hash recorded at creation
    wrong = copy.deepcopy(r)
    wrong["hops"]["training_dataset"]["value"] = {"store": "data/stores/OTHER/x.npz"}
    res2 = evidence_completeness(
        wrong, gt_events(), {"poisoned_sample_ids": POISONED_IDS}, SCHEMA, ArtifactResolver(None)
    )
    assert not {i["id"]: i["recovered"] for i in res2["items"]}["DS1"]
    events = [ev("DATASET_REGISTERED", T(0), {"store": STORE}, order=1)]
    m = {x["gt_action"]: x for x in _matches(events)}
    assert m["CLEAN_DATASET_CREATED"]["recovered"]
