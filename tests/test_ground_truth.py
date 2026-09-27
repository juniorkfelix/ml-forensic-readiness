"""Phase 7: ground-truth recorder and reader."""

from __future__ import annotations

from pathlib import Path

import pytest

from mlfref.ground_truth.recorder import GroundTruthReader, GroundTruthRecorder

ROOT = Path(__file__).resolve().parents[1]


def _rec(db, uuid="u-1", attack="label_flip"):
    return GroundTruthRecorder(db, f"EXP-LF-C-05-S00{uuid[-1]}", uuid, attack)


def test_events_sequenced_and_round_trip(tmp_path):
    db = tmp_path / "gt.sqlite"
    with _rec(db) as gt:
        gt.record("CLEAN_DATASET_CREATED", result_artifact="clean-hash")
        gt.record("POISONING_STARTED", source_artifact="clean-hash")
        gt.record(
            "POISONED_DATASET_CREATED",
            source_artifact="clean-hash",
            result_artifact="poisoned-hash",
            poisoned_sample_ids=[5, 2, 9],
            expected_relationship="DERIVED_FROM",
            metadata={"note": "x"},
        )
    with GroundTruthReader(db) as reader:
        events = reader.events("u-1")
    assert [e["sequence_number"] for e in events] == [1, 2, 3]
    assert [e["action"] for e in events] == [
        "CLEAN_DATASET_CREATED",
        "POISONING_STARTED",
        "POISONED_DATASET_CREATED",
    ]
    assert events[2]["poisoned_sample_ids"] == [5, 2, 9]
    assert events[2]["metadata"] == {"note": "x"}
    assert all(e["timestamp_utc"].endswith("Z") for e in events)
    assert events[0]["timestamp_utc"] <= events[2]["timestamp_utc"]


def test_runs_are_separated_by_uuid(tmp_path):
    db = tmp_path / "gt.sqlite"
    with _rec(db, "u-1") as a, _rec(db, "u-2") as b:
        a.record("TRAINING_STARTED")
        b.record("TRAINING_STARTED")
        b.record("TRAINING_COMPLETED")
    with GroundTruthReader(db) as reader:
        assert len(reader.events("u-1")) == 1
        assert [e["sequence_number"] for e in reader.events("u-2")] == [1, 2]


def test_attack_record_round_trip(tmp_path):
    db = tmp_path / "gt.sqlite"
    with _rec(db) as gt:
        gt.record_attack(
            poison_rate=0.05,
            poisoned_sample_ids=[1, 4],
            original_labels=[1, 1],
            new_labels=[9, 9],
            seed=3,
            source_dataset="a",
            result_dataset="b",
            source_class=1,
            target_class=9,
        )
    with GroundTruthReader(db) as reader:
        attack = reader.attack("u-1")
        assert reader.attack("missing") is None
    assert attack["number_poisoned"] == 2
    assert attack["poisoned_sample_ids"] == [1, 4]
    assert attack["new_labels"] == [9, 9] and attack["trigger"] is None


def test_misaligned_attack_record_rejected(tmp_path):
    with _rec(tmp_path / "gt.sqlite") as gt, pytest.raises(ValueError):
        gt.record_attack(
            poison_rate=0.05,
            poisoned_sample_ids=[1, 2],
            original_labels=[1],
            new_labels=[9, 9],
            seed=1,
            source_dataset="a",
            result_dataset="b",
        )


def test_unknown_action_rejected(tmp_path):
    with _rec(tmp_path / "gt.sqlite") as gt, pytest.raises(ValueError):
        gt.record("ROOT_CAUSE_FOUND")


@pytest.mark.parametrize("folder", ["evidence/forensic", "mlruns", "experiments/pilot", "models"])
def test_recorder_refuses_investigator_visible_locations(folder):
    with pytest.raises(ValueError, match="investigator-visible"):
        GroundTruthRecorder(ROOT / folder / "gt.sqlite", "E", "u", "none", project_root=ROOT)


def test_recorder_accepts_ground_truth_directory(tmp_path):
    root = tmp_path / "proj"
    gt = GroundTruthRecorder(
        root / "ground_truth" / "gt.sqlite", "E", "u", "none", project_root=root
    )
    gt.close()
    assert (root / "ground_truth" / "gt.sqlite").exists()
