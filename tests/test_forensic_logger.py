"""Phase 11: forensic evidence store and logger (pipeline C)."""

from __future__ import annotations

import json
import re
import sqlite3
import uuid

import numpy as np
import pytest

from mlfref.data.cifar import CifarArrays, TensorBatches
from mlfref.forensic.evidence_store import ForensicEvidenceStore
from mlfref.forensic.logger import CompositeHooks, ForensicLogger, ForensicTrainingHooks
from mlfref.forensic.schema import HEADER_FIELDS
from mlfref.models.resnet import build_model
from mlfref.models.train import TrainingHooks, train_model
from mlfref.reproducibility import make_generator, seed_everything

UUID = "0f0e0d0c-0b0a-4908-8706-050403020100"
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


@pytest.fixture()
def store(tmp_path):
    s = ForensicEvidenceStore(tmp_path / "forensic_evidence.sqlite")
    yield s
    s.close()


def _log_some(logger, n=3):
    return [
        logger.log(
            "DATASET_REGISTERED",
            actor="svc-data",
            source_component="test",
            artifact_type="dataset",
            artifact_id=f"CIFAR10-TRAIN-{i:012x}",
            artifact_hash=f"{i:064x}",
            metadata={"num_samples": 100 + i},
        )
        for i in range(n)
    ]


def test_forensic_event_schema(store):
    ev = _log_some(ForensicLogger(store, UUID), 1)[0]
    row = ev.as_dict()
    assert tuple(row) == HEADER_FIELDS
    assert uuid.UUID(row["event_id"]).version == 4
    assert TS.match(row["timestamp_utc"])
    assert row["experiment_id"] == f"RUN-{UUID}"  # opaque run reference (D-021)
    assert row["experiment_uuid"] == UUID and row["pipeline_mode"] == "forensic"
    assert row["sequence_number"] == 1 and row["previous_event_id"] is None
    assert json.loads(row["metadata_json"]) == {"num_samples": 100}
    assert re.fullmatch(r"[0-9a-f]{64}", row["event_hash"])


def test_events_linked_and_sequenced(store):
    events = _log_some(ForensicLogger(store, UUID), 4)
    stored = store.events()
    assert [e.sequence_number for e in stored] == [1, 2, 3, 4]
    for prev, cur in zip(stored, stored[1:], strict=False):
        assert cur.previous_event_id == prev.event_id
        assert cur.previous_event_hash == prev.event_hash
    assert stored == events


def test_logger_resumes_chain_from_existing_store(store):
    _log_some(ForensicLogger(store, UUID), 2)
    resumed = ForensicLogger(store, UUID)
    ev = _log_some(resumed, 1)[0]
    assert ev.sequence_number == 3 and ev.previous_event_id == store.events()[1].event_id


def test_unknown_event_and_artifact_types_rejected(store):
    logger = ForensicLogger(store, UUID)
    with pytest.raises(ValueError):
        logger.log("ROOT_CAUSE_IDENTIFIED", actor="x", source_component="x")
    with pytest.raises(ValueError):
        logger.log("MODEL_CREATED", actor="x", source_component="x", artifact_type="weights")


@pytest.mark.parametrize(
    "metadata",
    [
        {"attack_type": "label_flip"},
        {"poisoned_sample_ids": [1, 2]},
        {"details": {"root_cause": "sample 42"}},
        {"items": [{"trigger": "3x3"}]},
    ],
)
def test_answer_leaking_metadata_rejected(store, metadata):
    """Spec §46: the forensic system must not log the answer."""
    with pytest.raises(ValueError, match="§46"):
        ForensicLogger(store, UUID).log(
            "DATASET_REGISTERED", actor="x", source_component="x", metadata=metadata
        )
    assert store.count() == 0


def test_store_is_append_only(store):
    _log_some(ForensicLogger(store, UUID), 2)
    conn = sqlite3.connect(store.db_path)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE forensic_events SET actor = 'mallory'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM forensic_events")
    conn.close()


def test_jsonl_export_matches_store(store, tmp_path):
    _log_some(ForensicLogger(store, UUID), 3)
    path = store.export_jsonl(tmp_path / "evidence_export.jsonl")
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [line["event_id"] for line in lines] == [e.event_id for e in store.events()]
    assert lines[0]["metadata"] == {"num_samples": 100}


def test_chain_hashing_can_be_disabled_but_links_remain(store):
    events = _log_some(ForensicLogger(store, UUID, chain_hashing=False), 2)
    assert events[1].event_hash is None and events[1].previous_event_hash is None
    assert events[1].previous_event_id == events[0].event_id


def test_logging_time_and_counts_measured(store):
    logger = ForensicLogger(store, UUID)
    _log_some(logger, 3)
    assert logger.events_written == 3 and logger.logging_seconds > 0
    assert store.size_bytes() > 0


def test_training_hooks_emit_start_and_completion_only(store):
    rng = np.random.default_rng(0)
    arrays = CifarArrays(
        rng.integers(0, 256, (32, 32, 32, 3), dtype=np.uint8),
        rng.integers(0, 10, 32).astype(np.int64),
        np.arange(32, dtype=np.int64),
    )
    logger = ForensicLogger(store, UUID)
    hooks = ForensicTrainingHooks(
        logger,
        dataset_id="CIFAR10-TRAIN-abc",
        dataset_hash="f" * 64,
        run_id="mlflow-run-1",
        hyperparameters={"epochs": 2, "lr": 0.05},
    )

    class Counting(TrainingHooks):
        epochs = 0

        def on_epoch_end(self, record):
            Counting.epochs += 1

    seed_everything(0)
    model = build_model({"architecture": "resnet18", "num_classes": 10})
    cfg = {
        "epochs": 2,
        "batch_size": 16,
        "optimizer": "sgd",
        "learning_rate": 0.01,
        "lr_scheduler": "none",
        "loss": "cross_entropy",
    }
    train_model(
        model,
        TensorBatches(arrays),
        cfg,
        make_generator(0),
        hooks=CompositeHooks(hooks, Counting()),
    )
    types = [e.event_type for e in store.events()]
    assert types == ["TRAINING_STARTED", "TRAINING_COMPLETED"]
    assert Counting.epochs == 2
    done = store.events("TRAINING_COMPLETED")[0]
    assert done.run_id == "mlflow-run-1" and done.artifact_hash == "f" * 64
    assert json.loads(done.metadata_json)["epochs_completed"] == 2
