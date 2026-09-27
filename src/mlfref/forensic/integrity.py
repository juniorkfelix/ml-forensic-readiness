"""Integrity verification: event hash chain and artefact hashes (pipeline C).

``verify_chain`` recomputes the hash chain written by mlfref.forensic.logger and
reports every inconsistency:

* sequence numbers not contiguous from 1 (deletion/insertion/reordering)
* ``previous_event_id`` not equal to the preceding event's ID
* ``previous_event_hash`` not equal to the preceding event's hash
* stored ``event_hash`` not equal to the recomputed hash (content modified)

Limitation (tamper EVIDENCE, not prevention): an adversary who can rewrite the
entire store and recompute every hash consistently produces a chain that verifies.
Detecting that would need the latest hash anchored outside the adversary's reach
(e.g. a write-once log or an external timestamping service), which is out of scope.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mlfref.data.cifar import CifarArrays
from mlfref.data.manifest import build_manifest
from mlfref.forensic.hashing import manifest_hash, sha256_file, verify_hash
from mlfref.forensic.logger import ForensicLogger, compute_event_hash
from mlfref.forensic.schema import GENESIS_HASH, ForensicEvent


@dataclass
class ChainReport:
    n_events: int
    hash_chained: bool
    valid: bool
    problems: list[dict[str, Any]] = field(default_factory=list)
    head_hash: str | None = None

    @property
    def first_bad_sequence(self) -> int | None:
        return min((p["sequence_number"] for p in self.problems), default=None)

    def summary(self) -> dict[str, Any]:
        return {
            "n_events": self.n_events,
            "hash_chained": self.hash_chained,
            "valid": self.valid,
            "n_problems": len(self.problems),
            "first_bad_sequence": self.first_bad_sequence,
            "head_hash": self.head_hash,
        }


def verify_chain(events: Sequence[ForensicEvent]) -> ChainReport:
    """Verify linkage and (if present) hashes of events in stored sequence order."""
    events = sorted(events, key=lambda e: e.sequence_number)
    hashed = bool(events) and all(e.event_hash is not None for e in events)
    problems: list[dict[str, Any]] = []

    def problem(ev: ForensicEvent, kind: str, detail: str) -> None:
        problems.append(
            {
                "sequence_number": ev.sequence_number,
                "event_id": ev.event_id,
                "problem": kind,
                "detail": detail,
            }
        )

    prev: ForensicEvent | None = None
    for i, ev in enumerate(events, start=1):
        if ev.sequence_number != i:
            problem(ev, "SEQUENCE_GAP", f"expected sequence {i}, found {ev.sequence_number}")
        expected_prev_id = prev.event_id if prev else None
        if ev.previous_event_id != expected_prev_id:
            problem(
                ev,
                "BROKEN_LINK",
                f"previous_event_id {ev.previous_event_id} != " f"{expected_prev_id}",
            )
        if hashed:
            expected_prev_hash = prev.event_hash if prev else GENESIS_HASH
            if ev.previous_event_hash != expected_prev_hash:
                problem(ev, "BROKEN_HASH_LINK", "previous_event_hash does not match predecessor")
            recomputed = compute_event_hash(ev, ev.previous_event_hash)
            if recomputed != ev.event_hash:
                problem(ev, "HASH_MISMATCH", "stored event_hash does not match recomputed hash")
        prev = ev
    return ChainReport(
        n_events=len(events),
        hash_chained=hashed,
        valid=not problems,
        problems=problems,
        head_hash=events[-1].event_hash if events else None,
    )


def read_events_readonly(db_path: str | Path) -> list[ForensicEvent]:
    """Read events without any possibility of modifying the evidence file."""
    uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM forensic_events ORDER BY sequence_number").fetchall()
    finally:
        conn.close()
    return [ForensicEvent(**dict(r)) for r in rows]


def verify_store(db_path: str | Path) -> ChainReport:
    return verify_chain(read_events_readonly(db_path))


# ----------------------------------------------------------------- artefacts


@dataclass(frozen=True)
class IntegrityResult:
    artifact: str
    expected: str
    observed: str
    method: str

    @property
    def match(self) -> bool:
        return verify_hash(self.expected, self.observed)

    def as_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact,
            "expected": self.expected,
            "observed": self.observed,
            "method": self.method,
            "result": "MATCH" if self.match else "MISMATCH",
        }


def verify_file(path: str | Path, expected_sha256: str) -> IntegrityResult:
    return IntegrityResult(str(path), expected_sha256, sha256_file(path), "SHA-256(file)")


def verify_dataset(
    arrays: CifarArrays, expected_manifest_sha256: str, artifact: str = "dataset"
) -> IntegrityResult:
    return IntegrityResult(
        artifact,
        expected_manifest_sha256,
        manifest_hash(build_manifest(arrays)),
        "SHA-256(canonical manifest)",
    )


def log_integrity_check(
    logger: ForensicLogger,
    result: IntegrityResult,
    *,
    artifact_type: str,
    artifact_id: str,
    actor: str,
    source_component: str,
    event_type: str = "ARTIFACT_INTEGRITY_CHECK",
    run_id: str | None = None,
    deployment_id: str | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> list[ForensicEvent]:
    """Record a check (``ARTIFACT_INTEGRITY_CHECK`` or ``DATASET_INTEGRITY_VERIFIED``) and,
    on mismatch, an additional ``ARTIFACT_INTEGRITY_FAILURE``. Record-only: the caller
    is never stopped (D-016)."""
    meta = {**result.as_dict(), **(extra_metadata or {})}
    common = dict(
        actor=actor,
        source_component=source_component,
        artifact_type=artifact_type,
        artifact_id=artifact_id,
        run_id=run_id,
        deployment_id=deployment_id,
    )
    events = [logger.log(event_type, artifact_hash=result.observed, metadata=meta, **common)]
    if not result.match:
        events.append(
            logger.log(
                "ARTIFACT_INTEGRITY_FAILURE", artifact_hash=result.observed, metadata=meta, **common
            )
        )
    return events
