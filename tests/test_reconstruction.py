"""Phase 14: reconstruction engine on evidence produced by the real pipeline (tiny data).

The harness role (tampering with the data store between registration and training)
is played by the test; the pipeline and the reconstruction engine are the real code.
"""

from __future__ import annotations

import builtins
import io
import json
import re
import uuid
from pathlib import Path

import numpy as np
import pytest
import torch

from mlfref.attacks.label_flip import LabelFlipAttack
from mlfref.config import compose_run_config
from mlfref.data import cifar
from mlfref.pipeline import Pipeline, PipelinePaths
from mlfref.reconstruction import reconstruct
from mlfref.reconstruction.report import write_json, write_markdown
from mlfref.reproducibility import make_generator, seed_everything
from mlfref.simulation import build_request_schedule, make_incident_ticket

ROOT = Path(__file__).resolve().parents[1]
RECON_DIR = ROOT / "src" / "mlfref" / "reconstruction"


def _balanced(per_class, seed):
    rng = np.random.default_rng(seed)
    n = per_class * 10
    return cifar.CifarArrays(
        rng.integers(0, 256, (n, 32, 32, 3), dtype=np.uint8),
        np.repeat(np.arange(10), per_class).astype(np.int64)[rng.permutation(n)],
        np.arange(n, dtype=np.int64),
    )


def _run(root: Path, mode: str, tamper: bool):
    cfg = compose_run_config(
        ROOT / "config",
        mode,
        overrides=[
            "training.epochs=1",
            "training.batch_size=16",
            "training.device=cpu",
            "training.amp=false",
            f"mlflow.tracking_uri=sqlite:///{(root / 'mlflow.db').as_posix()}",
            f"mlflow.artifact_location={(root / 'mlartifacts').as_posix()}",
        ],
    )
    run_uuid = str(uuid.uuid4())
    base = PipelinePaths.for_run(root, mode, f"RUN-{run_uuid}")
    test = _balanced(3, seed=9)
    test_store = cifar.write_store(root / "data" / "clean" / "test.npz", test)
    paths = PipelinePaths(
        root, base.evidence_dir, base.store_path, test_store, base.checkpoint_dir, base.deployed_dir
    )
    seed_everything(0)
    pipe = Pipeline(cfg, run_uuid, paths, torch.device("cpu"), git_commit="abc123")
    pipe.register_training_data(_balanced(6, seed=1))
    attack_ids = None
    if tamper:  # the adversary modifies the store outside the pipeline
        res = LabelFlipAttack("automobile", "truck", 0.05, seed=1).apply(
            cifar.read_store(paths.store_path)
        )
        cifar.write_store(paths.store_path, res.poisoned)
        attack_ids = res.poisoned_sample_ids.tolist()
    arrays = pipe.load_training_data()
    model, _ = pipe.train(arrays, test, make_generator(0))
    pipe.evaluate(model, test)
    pipe.save_model(model)
    pipe.deploy()
    svc = pipe.service()
    served = [
        (r, svc.predict(r.request_id, r.image)) for r in build_request_schedule(test, 8, seed=1)
    ]
    pipe.finalize()
    ticket = make_incident_ticket(*served[3], "INC-0001")
    return {
        "evidence": paths.evidence_dir,
        "ticket": ticket,
        "attack_ids": attack_ids,
        "pipe": pipe,
        "root": root,
        "served": served,
    }


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    root = tmp_path_factory.mktemp("ws")
    out = {
        "A": _run(root, "A", tamper=True),
        "B": _run(root, "B", tamper=True),
        "C": _run(root, "C", tamper=True),
        "C_clean": _run(root, "C", tamper=False),
    }
    for r in out.values():
        r["recon"] = reconstruct(r["evidence"], r["ticket"], r["root"])
    return out


def _hop(r, name):
    return r["recon"]["hops"][name]


def test_conventional_reconstruction_limits(runs):
    r = runs["A"]
    rec = r["recon"]
    assert rec["evidence_sources"]["app_log"] and not rec["evidence_sources"]["forensic"]
    assert not rec["evidence_sources"]["mlflow"]
    assert _hop(r, "inference")["confidence"] == "MODERATE"
    assert _hop(r, "deployment")["confidence"] == "WEAK"
    assert _hop(r, "model")["status"] == "IDENTIFIED"
    assert _hop(r, "model")["value"]["path"].endswith("model_final.pt")
    assert _hop(r, "training_run")["confidence"] == "WEAK"
    assert _hop(r, "training_dataset")["confidence"] == "WEAK"
    change = rec["dataset_change"]
    assert change["changed"] == "UNKNOWN" and change["finding"] == "INSUFFICIENT_EVIDENCE"
    assert not any(e["event_class"] == "DATASET_MODIFIED" for e in rec["events"])
    assert any("NOT_OBSERVABLE" in m for m in rec["missing_evidence"])


def test_provenance_reconstruction(runs):
    r = runs["B"]
    rec = r["recon"]
    assert _hop(r, "model")["confidence"] == "MODERATE"
    assert _hop(r, "training_run")["value"]["run_id"] == r["pipe"].state.training_run_id
    assert _hop(r, "training_dataset")["value"]["mlflow_digest"]
    change = rec["dataset_change"]
    assert change["changed"] is True
    assert change["finding"] == "DATASET_MODIFIED_UNSPECIFIED"
    assert change["profile_delta"] == {"automobile": -3, "truck": 3}
    assert change["changed_sample_ids"] is None  # B cannot say which samples


def test_forensic_reconstruction_recovers_full_chain(runs):
    r = runs["C"]
    rec = r["recon"]
    for hop in (
        "inference",
        "deployment",
        "model",
        "training_run",
        "training_dataset",
        "prior_dataset",
    ):
        assert _hop(r, hop)["confidence"] == "STRONG", hop
    change = rec["dataset_change"]
    assert change["finding"] == "LABEL_MODIFICATION"
    assert change["changed_sample_ids"] == r["attack_ids"]
    assert change["label_transitions"] == {"1->9": 3}
    assert rec["integrity"]["evidence_chain"]["valid"] is True
    assert rec["integrity"]["deployed_model_check"]["result"] == "MATCH"
    assert rec["integrity"]["dataset_check"]["result"] == "MISMATCH"


def test_forensic_clean_control_finds_no_modification(runs):
    rec = runs["C_clean"]["recon"]
    assert rec["dataset_change"]["changed"] is False
    assert rec["dataset_change"]["finding"] == "NO_DATASET_MODIFICATION_FOUND"
    assert not any(e["event_class"] == "DATASET_MODIFIED" for e in rec["events"])


def test_event_chronology(runs):
    events = runs["C"]["recon"]["events"]
    classes = [e["event_class"] for e in events if e["order"] is not None]
    assert classes == [
        "DATASET_REGISTERED",
        "DATASET_MODIFIED",
        "TRAINING_STARTED",
        "TRAINING_COMPLETED",
        "MODEL_CREATED",
        "MODEL_DEPLOYED",
        "INPUT_SUBMITTED",
        "INCIDENT_PREDICTION",
    ]
    modified = next(e for e in events if e["event_class"] == "DATASET_MODIFIED")
    assert modified["time_basis"] == "bounded" and modified["time_lower"] < modified["time_upper"]


def test_event_correlation(runs):
    """Links recovered in C connect incident -> deployment -> model -> run -> dataset."""
    r = runs["C"]
    rels = {(x["from"], x["relation"], x["to"]) for x in r["recon"]["graph"]["relations"]}
    for rel in [
        ("inference", "USED", "model"),
        ("deployment", "USED", "model"),
        ("model", "WAS_GENERATED_BY", "training"),
        ("training", "USED", "training_dataset"),
        ("training_dataset", "WAS_DERIVED_FROM", "registered_dataset"),
    ]:
        assert rel in rels, rel
    model = _hop(r, "model")["value"]
    assert model["model_sha256"] == r["pipe"].state.model.sha256
    assert _hop(r, "inference")["value"]["input_sha256"] == r["ticket"]["input_sha256"]


def test_more_evidence_never_reduces_identified_hops(runs):
    rank = {"NONE": 0, "WEAK": 1, "MODERATE": 2, "STRONG": 3}
    for hop in runs["A"]["recon"]["hops"]:
        a, b, c = (rank[_hop(runs[m], hop)["confidence"]] for m in ("A", "B", "C"))
        assert a <= b <= c or hop == "inference", hop


def test_reports_written(runs, tmp_path):
    rec = runs["C"]["recon"]
    j = write_json(rec, tmp_path / "EXP.json")
    md = write_markdown(rec, tmp_path / "EXP.md", "RUN-test").read_text(encoding="utf-8")
    assert json.loads(j.read_text())["root_cause"]["finding"] == "LABEL_MODIFICATION"
    for section in (
        "## Incident",
        "## Evidence sources",
        "## Event chronology",
        "## Artefact relationships",
        "## Integrity findings",
        "## Root-cause finding",
        "## Missing evidence",
        "## Limitations",
    ):
        assert section in md


def test_evidence_files_have_no_personal_paths(runs):
    """Every text file in each evidence directory is free of absolute user paths."""
    for r in runs.values():
        for f in r["evidence"].rglob("*"):
            if f.suffix in (".log", ".json", ".jsonl"):
                text = f.read_text(encoding="utf-8")
                assert not re.search(r"[A-Za-z]:[\\/]{1,2}Users", text), f.name
                assert "/tmp/" not in text and "pytest-of-" not in text, f.name


def test_reconstruction_output_has_no_personal_paths(runs):
    for r in runs.values():
        text = json.dumps(r["recon"], default=str)
        assert str(r["root"].resolve()).replace("\\", "/") not in text.replace("\\\\", "/")
        assert not re.search(r"[A-Za-z]:[\\/]{1,2}Users", text)


def test_reconstruction_cannot_access_ground_truth(runs, monkeypatch):
    """Dynamic check: reconstruction opens no file under a ground_truth directory."""
    r = runs["C"]
    opened = []
    real_open, real_io_open = builtins.open, io.open

    def guard(real):
        def _open(file, *a, **k):
            opened.append(str(file))
            if "ground_truth" in str(file).replace("\\", "/"):
                raise AssertionError(f"reconstruction opened ground truth: {file}")
            return real(file, *a, **k)

        return _open

    monkeypatch.setattr(builtins, "open", guard(real_open))
    monkeypatch.setattr(io, "open", guard(real_io_open))
    reconstruct(r["evidence"], r["ticket"], r["root"])
    assert opened  # the guard really saw file access


def test_single_code_path_no_mode_branching():
    """Fairness (spec §45): no reconstruction module branches on the pipeline mode."""
    for path in RECON_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for word in (
            "pipeline_mode",
            "'conventional'",
            '"conventional"',
            "'provenance'",
            '"provenance"',
            "reconstruct_conventional",
            "reconstruct_forensic",
        ):
            assert word not in text, f"{path.name}: {word}"
