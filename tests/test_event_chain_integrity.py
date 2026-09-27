"""Phase 12: hash-chain verification and artefact integrity (tamper EVIDENCE only)."""

from __future__ import annotations

import sqlite3

import numpy as np
import pytest

from mlfref.data.cifar import CifarArrays
from mlfref.data.manifest import build_manifest
from mlfref.forensic.evidence_store import ForensicEvidenceStore
from mlfref.forensic.hashing import manifest_hash, sha256_file
from mlfref.forensic.integrity import (
    log_integrity_check,
    verify_dataset,
    verify_file,
    verify_store,
)
from mlfref.forensic.logger import ForensicLogger, compute_event_hash

UUID = "11111111-2222-4333-8444-555555555555"


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "forensic_evidence.sqlite"
    with ForensicEvidenceStore(path) as store:
        logger = ForensicLogger(store, UUID)
        for i in range(5):
            logger.log(
                "MODEL_HASHED",
                actor="svc",
                source_component="t",
                artifact_type="model",
                artifact_id=f"MODEL-{i}",
                artifact_hash=f"{i:064x}",
                metadata={"i": i},
            )
    return path


def _tamper(db, *sql):
    """Bypass the append-only triggers as an attacker with file access could."""
    conn = sqlite3.connect(db)
    conn.execute("DROP TRIGGER fe_no_update")
    conn.execute("DROP TRIGGER fe_no_delete")
    for stmt in sql:
        conn.execute(stmt)
    conn.commit()
    conn.close()


def test_event_chain_integrity(db):
    report = verify_store(db)
    assert report.valid and report.hash_chained and report.n_events == 5
    assert report.head_hash is not None


def test_verification_is_read_only(db):
    before = sha256_file(db)
    verify_store(db)
    assert sha256_file(db) == before


@pytest.mark.parametrize(
    "sql, kind, seq",
    [
        (
            "UPDATE forensic_events SET metadata_json='{\"i\":99}' WHERE sequence_number=3",
            "HASH_MISMATCH",
            3,
        ),
        (
            "UPDATE forensic_events SET timestamp_utc='2020-01-01T00:00:00.000000Z' "
            "WHERE sequence_number=2",
            "HASH_MISMATCH",
            2,
        ),
        (
            "UPDATE forensic_events SET artifact_hash='deadbeef' WHERE sequence_number=4",
            "HASH_MISMATCH",
            4,
        ),
        ("DELETE FROM forensic_events WHERE sequence_number=3", "SEQUENCE_GAP", 4),
    ],
)
def test_tampering_detected(db, sql, kind, seq):
    _tamper(db, sql)
    report = verify_store(db)
    assert not report.valid
    assert any(p["problem"] == kind and p["sequence_number"] == seq for p in report.problems)
    assert report.first_bad_sequence <= seq


def test_reordering_detected(db):
    _tamper(
        db,
        "UPDATE forensic_events SET sequence_number=-1 WHERE sequence_number=2",
        "UPDATE forensic_events SET sequence_number=2 WHERE sequence_number=3",
        "UPDATE forensic_events SET sequence_number=3 WHERE sequence_number=-1",
    )
    report = verify_store(db)
    assert not report.valid
    assert {p["problem"] for p in report.problems} & {"BROKEN_LINK", "BROKEN_HASH_LINK"}


def test_forged_event_with_valid_own_hash_detected_at_successor(db):
    """Replacing one event and recomputing ITS hash still breaks the successor's link."""
    events = verify_store(db)
    assert events.valid
    from mlfref.forensic.integrity import read_events_readonly

    ev3 = read_events_readonly(db)[2]
    forged = ev3.__class__(**{**ev3.as_dict(), "metadata_json": '{"i":42}', "event_hash": None})
    new_hash = compute_event_hash(forged, forged.previous_event_hash)
    _tamper(
        db,
        f"UPDATE forensic_events SET metadata_json='{{\"i\":42}}', "
        f"event_hash='{new_hash}' WHERE sequence_number=3",
    )
    report = verify_store(db)
    assert not report.valid
    assert [(p["sequence_number"], p["problem"]) for p in report.problems] == [
        (4, "BROKEN_HASH_LINK")
    ]


def test_consistent_full_rewrite_is_not_detectable(db, tmp_path):
    """Documents the limitation: tamper evidence, not tamper prevention. An attacker who
    rewrites every event and recomputes the whole chain yields a store that verifies."""
    from mlfref.forensic.integrity import read_events_readonly

    events = read_events_readonly(db)
    forged_db = tmp_path / "rewritten.sqlite"
    with ForensicEvidenceStore(forged_db) as store:
        logger = ForensicLogger(store, UUID)
        for ev in events:
            logger.log(
                ev.event_type,
                actor=ev.actor,
                source_component=ev.source_component,
                artifact_type=ev.artifact_type,
                artifact_id=ev.artifact_id,
                artifact_hash="0" * 64,
                metadata={"i": -1},
            )
    report = verify_store(forged_db)
    assert report.valid  # undetectable without an externally anchored head hash
    assert report.head_hash != verify_store(db).head_hash  # ...unless the head was anchored


def test_link_only_verification_without_hashing(tmp_path):
    path = tmp_path / "nohash.sqlite"
    with ForensicEvidenceStore(path) as store:
        logger = ForensicLogger(store, UUID, chain_hashing=False)
        for _ in range(3):
            logger.log("INFERENCE_REQUEST", actor="svc", source_component="t")
    report = verify_store(path)
    assert report.valid and not report.hash_chained


def test_verify_file_and_dataset(tmp_path):
    f = tmp_path / "model.pt"
    f.write_bytes(b"weights")
    good = verify_file(f, sha256_file(f))
    assert good.match and good.as_dict()["result"] == "MATCH"
    f.write_bytes(b"weights-tampered")
    assert not verify_file(f, good.expected).match

    rng = np.random.default_rng(0)
    arrays = CifarArrays(
        rng.integers(0, 256, (10, 32, 32, 3), dtype=np.uint8),
        rng.integers(0, 10, 10).astype(np.int64),
        np.arange(10, dtype=np.int64),
    )
    expected = manifest_hash(build_manifest(arrays))
    assert verify_dataset(arrays, expected).match
    labels = arrays.labels.copy()
    labels[0] = (labels[0] + 1) % 10
    changed = CifarArrays(arrays.images, labels, arrays.sample_ids)
    assert not verify_dataset(changed, expected).match


def test_log_integrity_check_records_failure_without_stopping(tmp_path):
    f = tmp_path / "m.pt"
    f.write_bytes(b"a")
    with ForensicEvidenceStore(tmp_path / "e.sqlite") as store:
        logger = ForensicLogger(store, UUID)
        ok = log_integrity_check(
            logger,
            verify_file(f, sha256_file(f)),
            artifact_type="model",
            artifact_id="MODEL-1",
            actor="svc",
            source_component="t",
        )
        bad = log_integrity_check(
            logger,
            verify_file(f, "0" * 64),
            artifact_type="model",
            artifact_id="MODEL-1",
            actor="svc",
            source_component="t",
        )
        types = [e.event_type for e in store.events()]
    assert len(ok) == 1 and len(bad) == 2
    assert types == [
        "ARTIFACT_INTEGRITY_CHECK",
        "ARTIFACT_INTEGRITY_CHECK",
        "ARTIFACT_INTEGRITY_FAILURE",
    ]
