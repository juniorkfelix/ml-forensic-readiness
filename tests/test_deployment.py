"""Phase 13: deployment, inference service, traffic simulation and incident tickets."""

from __future__ import annotations

import hashlib
import json
import re

import numpy as np
import pytest

from mlfref.attacks.backdoor import BackdoorAttack
from mlfref.attacks.label_flip import LabelFlipAttack
from mlfref.data.cifar import CifarArrays
from mlfref.forensic.evidence_store import ForensicEvidenceStore
from mlfref.forensic.hashing import sha256_file
from mlfref.forensic.integrity import verify_store
from mlfref.forensic.logger import ForensicLogger
from mlfref.ground_truth.recorder import GroundTruthReader, GroundTruthRecorder
from mlfref.instrumentation import Instrumentation
from mlfref.logging_utils import attach_evidence_log, detach_evidence_log, get_logger
from mlfref.models.artifacts import save_model
from mlfref.models.deployment import InferenceService, deploy_model, model_id_for
from mlfref.models.resnet import build_model
from mlfref.provenance.mlflow_tracker import (
    PRODUCTION_ALIAS,
    REGISTERED_MODEL_NAME,
    MlflowTracker,
)
from mlfref.reproducibility import seed_everything
from mlfref.simulation import (
    build_request_schedule,
    make_incident_ticket,
    run_traffic,
    select_incident,
)

MODEL_CFG = {"architecture": "resnet18", "num_classes": 10, "cifar_stem": True}
UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
RUN_REF = f"RUN-{UUID}"
ATTACK_PATTERNS = (r"attack", r"poison", r"label_flip", r"backdoor", r"trigger", r"EXP-")


def _test_set(n=60, seed=0) -> CifarArrays:
    rng = np.random.default_rng(seed)
    return CifarArrays(
        rng.integers(0, 256, (n, 32, 32, 3), dtype=np.uint8),
        np.tile(np.arange(10), n // 10).astype(np.int64),
        np.arange(n, dtype=np.int64),
    )


@pytest.fixture(scope="module")
def model_file(tmp_path_factory):
    seed_everything(0)
    path = tmp_path_factory.mktemp("ckpt") / "model_final.pt"
    save_model(build_model(MODEL_CFG), path)
    return path


def _run_mode(mode, tmp_path, model_file, requests):
    evidence = tmp_path / mode / RUN_REF
    handler = attach_evidence_log(evidence / "app.log", RUN_REF)
    tracker = forensic = store = None
    registry_version = None
    if mode in ("provenance", "forensic"):
        tracker = MlflowTracker(
            f"sqlite:///{(tmp_path / mode / 'mlflow.db').as_posix()}",
            "t",
            tmp_path / mode / "artifacts",
            RUN_REF,
            mode,
        )
        tracker.client.create_registered_model(REGISTERED_MODEL_NAME)
        registry_version = str(
            tracker.client.create_model_version(
                REGISTERED_MODEL_NAME, source=model_file.as_uri()
            ).version
        )
    if mode == "forensic":
        store = ForensicEvidenceStore(evidence / "forensic_evidence.sqlite")
        forensic = ForensicLogger(store, UUID)
    instr = Instrumentation(mode, RUN_REF, tracker, forensic)
    sha = sha256_file(model_file)
    gt = GroundTruthRecorder(tmp_path / f"gt_{mode}.sqlite", "EXP-BD-X-05-S001", UUID, "backdoor")
    get_logger("harness").info("harness-only message: applying backdoor attack")
    dep = deploy_model(
        model_file,
        tmp_path / mode / "deployed",
        instr,
        model_sha256=sha,
        training_run_id="run-123",
        registry_version=registry_version,
    )
    gt.record("MODEL_DEPLOYED", affected_artifact=sha)
    service = InferenceService(dep, MODEL_CFG, "cpu", instr, training_run_id="run-123")
    served = run_traffic(
        service, requests, gt, "backdoor", BackdoorAttack("airplane", 0.05, 1), model_sha256=sha
    )
    detach_evidence_log(handler)
    gt.close()
    return {
        "evidence": evidence,
        "served": served,
        "tracker": tracker,
        "store": store,
        "sha": sha,
        "dep": dep,
        "registry_version": registry_version,
    }


@pytest.fixture(scope="module")
def runs(tmp_path_factory, model_file):
    tmp = tmp_path_factory.mktemp("modes")
    requests = build_request_schedule(
        _test_set(), 20, seed=1, backdoor=BackdoorAttack("airplane", 0.05, 1), n_triggered=5
    )
    out = {
        m: _run_mode(m, tmp, model_file, requests)
        for m in ("conventional", "provenance", "forensic")
    }
    yield out, tmp
    out["forensic"]["store"].close()


def test_schedule_deterministic_and_adversarial_requests():
    bd = BackdoorAttack("airplane", 0.05, 1)
    a = build_request_schedule(_test_set(), 20, seed=3, backdoor=bd, n_triggered=5)
    b = build_request_schedule(_test_set(), 20, seed=3, backdoor=bd, n_triggered=5)
    assert [r.test_sample_id for r in a] == [r.test_sample_id for r in b]
    adv = [r for r in a if r.adversarial]
    assert len(adv) == 5 and all(r.true_label != 0 for r in adv)
    assert all((r.image[28:31, 28:31, 0] == bd.pattern).all() for r in adv)
    assert len({r.test_sample_id for r in a}) == 20  # no duplicate images
    c = build_request_schedule(_test_set(), 20, seed=4, backdoor=bd, n_triggered=5)
    assert [r.test_sample_id for r in a] != [r.test_sample_id for r in c]
    assert not any(r.adversarial for r in build_request_schedule(_test_set(), 20, seed=3))


def test_predictions_identical_across_pipelines(runs):
    out, _ = runs
    preds = {m: [rec.predicted_class for _, rec in r["served"]] for m, r in out.items()}
    assert preds["conventional"] == preds["provenance"] == preds["forensic"]


def test_conventional_evidence_is_app_log_only(runs):
    out, _ = runs
    evidence = out["conventional"]["evidence"]
    assert sorted(p.name for p in evidence.iterdir()) == ["app.log"]
    log = (evidence / "app.log").read_text(encoding="utf-8")
    assert "serving model file" in log
    assert len(re.findall(r"request_id=REQ-\d{5} predicted=\w+", log)) == 20
    assert not re.search(r"\b[0-9a-f]{64}\b", log)  # no hashes in A (spec §14)
    assert RUN_REF in log


@pytest.mark.parametrize("mode", ["conventional", "provenance", "forensic"])
def test_app_log_has_no_attack_or_harness_information(runs, mode):
    log = (runs[0][mode]["evidence"] / "app.log").read_text(encoding="utf-8")
    assert "harness-only message" not in log
    for pattern in ATTACK_PATTERNS:
        assert not re.search(pattern, log, re.IGNORECASE), pattern


def test_provenance_records_registry_deployment(runs):
    r = runs[0]["provenance"]
    mv = r["tracker"].client.get_model_version_by_alias(REGISTERED_MODEL_NAME, PRODUCTION_ALIAS)
    assert str(mv.version) == r["registry_version"]
    log = (r["evidence"] / "app.log").read_text(encoding="utf-8")
    assert f"@production (version {r['registry_version']})" in log


def test_forensic_deployment_and_inference_events(runs):
    r = runs[0]["forensic"]
    events = r["store"].events()
    types = [e.event_type for e in events]
    assert types[:2] == ["MODEL_DEPLOYED", "ARTIFACT_INTEGRITY_CHECK"]
    assert types.count("INFERENCE_REQUEST") == 20 and types.count("INFERENCE_RESULT") == 20
    dep = events[0]
    assert dep.artifact_hash == r["sha"] and dep.parent_artifact_id == model_id_for(r["sha"])
    assert dep.run_id == "run-123" and dep.deployment_id == r["dep"].deployment_id
    assert json.loads(events[1].metadata_json)["result"] == "MATCH"
    reqs = [e for e in events if e.event_type == "INFERENCE_REQUEST"]
    served = r["served"]
    assert reqs[0].artifact_hash == hashlib.sha256(served[0][0].image.tobytes()).hexdigest()
    results = [json.loads(e.metadata_json) for e in events if e.event_type == "INFERENCE_RESULT"]
    assert [m["predicted_class"] for m in results] == [rec.predicted_class for _, rec in served]
    assert all(m["model_sha256"] == r["sha"] for m in results)
    assert verify_store(r["store"].db_path).valid


def test_ground_truth_records_trigger_submissions(runs):
    _, tmp = runs
    with GroundTruthReader(tmp / "gt_forensic.sqlite") as reader:
        actions = [e["action"] for e in reader.events(UUID)]
    assert actions[0] == "MODEL_DEPLOYED"
    assert actions.count("TRIGGER_SUBMITTED") == 5


def test_incident_ticket_contains_observables_only():
    test = _test_set()
    lf = LabelFlipAttack("automobile", "truck", 0.05, 1)
    reqs = build_request_schedule(test, 20, seed=1)
    from mlfref.models.deployment import InferenceRecord

    # Fabricated service output for the unit test: every request predicted "truck".
    served = [
        (r, InferenceRecord(r.request_id, "2026-01-01T00:00:00.000000Z", 9, 0.9, 1.0)) for r in reqs
    ]
    req, rec = select_incident(served, "label_flip", lf)
    assert req.true_label == 1  # first automobile predicted as truck
    ticket = make_incident_ticket(req, rec, "INC-0001")
    assert ticket["observed_prediction"] == "truck" and ticket["expected_label"] == "automobile"
    assert ticket["input_sha256"] == hashlib.sha256(req.image.tobytes()).hexdigest()
    assert set(ticket) == {
        "ticket_id",
        "reported_issue",
        "request_id",
        "request_time_utc",
        "observed_prediction",
        "observed_confidence",
        "expected_label",
        "input_sha256",
        "input_image_uint8",
    }
    text = json.dumps({k: v for k, v in ticket.items() if k != "input_image_uint8"}).lower()
    for pattern in ATTACK_PATTERNS:
        assert not re.search(pattern, text, re.IGNORECASE)


def test_select_incident_none_when_no_malicious_prediction():
    reqs = build_request_schedule(_test_set(), 10, seed=1)
    from mlfref.models.deployment import InferenceRecord

    served = [(r, InferenceRecord(r.request_id, "t", r.true_label, 0.9, 1.0)) for r in reqs]
    assert select_incident(served, "label_flip", LabelFlipAttack(1, 9, 0.05, 1)) is None
    assert select_incident(served, "none") is None
