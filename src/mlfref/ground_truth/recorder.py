"""Ground-truth recorder and reader.

Only the research harness (run orchestration and attack modules) writes ground
truth. Only the evaluator reads it, after reconstruction has finished. Pipeline and
reconstruction code must never import this module (enforced by
tests/test_ground_truth_isolation.py).

Canonical artefact references are content hashes (dataset manifest SHA-256, model
file SHA-256) so that the evaluator can match them against what a reconstruction
points to (D-020).
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mlfref.forensic.hashing import canonical_json
from mlfref.ground_truth.schema import ACTIONS, ATTACK_TYPES, DDL, RELATIONSHIPS

# Top-level directories that are investigator-visible; ground truth must never live there.
FORBIDDEN_TOP_LEVEL = ("evidence", "mlruns", "experiments", "models")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _check_location(db_path: Path, project_root: Path | None) -> None:
    if project_root is None:
        return
    try:
        rel = db_path.resolve().relative_to(project_root.resolve())
    except ValueError:
        return  # outside the project (e.g. a temp dir in tests)
    if rel.parts and rel.parts[0] in FORBIDDEN_TOP_LEVEL:
        raise ValueError(f"ground truth must not be stored in investigator-visible {rel.parts[0]}/")


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(DDL)
    return conn


class GroundTruthRecorder:
    """Append-only recorder for one experiment execution."""

    def __init__(
        self,
        db_path: str | Path,
        experiment_id: str,
        experiment_uuid: str,
        attack_type: str,
        project_root: str | Path | None = None,
    ) -> None:
        if attack_type not in ATTACK_TYPES:
            raise ValueError(f"unknown attack_type {attack_type!r}")
        self.db_path = Path(db_path)
        _check_location(self.db_path, Path(project_root) if project_root else None)
        self.experiment_id = experiment_id
        self.experiment_uuid = experiment_uuid
        self.attack_type = attack_type
        self._conn = _connect(self.db_path)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> GroundTruthRecorder:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _next_sequence(self) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(sequence_number), 0) FROM gt_events WHERE experiment_uuid = ?",
            (self.experiment_uuid,),
        ).fetchone()
        return int(row[0]) + 1

    def record(
        self,
        action: str,
        *,
        affected_artifact: str | None = None,
        source_artifact: str | None = None,
        result_artifact: str | None = None,
        poisoned_sample_ids: Sequence[int] | None = None,
        expected_relationship: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        timestamp_utc: str | None = None,
    ) -> str:
        if action not in ACTIONS:
            raise ValueError(f"unknown ground-truth action {action!r}")
        if expected_relationship not in RELATIONSHIPS:
            raise ValueError(f"unknown relationship {expected_relationship!r}")
        event_id = str(uuid.uuid4())
        with self._conn:
            self._conn.execute(
                "INSERT INTO gt_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event_id,
                    timestamp_utc or _utc_now(),
                    self.experiment_id,
                    self.experiment_uuid,
                    self._next_sequence(),
                    action,
                    self.attack_type,
                    affected_artifact,
                    source_artifact,
                    result_artifact,
                    (
                        canonical_json([int(i) for i in poisoned_sample_ids])
                        if poisoned_sample_ids is not None
                        else None
                    ),
                    expected_relationship,
                    canonical_json(dict(metadata or {})),
                ),
            )
        return event_id

    def record_attack(
        self,
        *,
        poison_rate: float,
        poisoned_sample_ids: Sequence[int],
        original_labels: Sequence[int],
        new_labels: Sequence[int],
        seed: int,
        source_dataset: str,
        result_dataset: str,
        source_class: int | None = None,
        target_class: int | None = None,
        trigger: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        if not (len(poisoned_sample_ids) == len(original_labels) == len(new_labels)):
            raise ValueError("poisoned ids, original labels and new labels must align")
        with self._conn:
            self._conn.execute(
                "INSERT INTO gt_attacks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    self.experiment_uuid,
                    self.experiment_id,
                    _utc_now(),
                    self.attack_type,
                    source_class,
                    target_class,
                    float(poison_rate),
                    len(poisoned_sample_ids),
                    canonical_json([int(i) for i in poisoned_sample_ids]),
                    canonical_json([int(i) for i in original_labels]),
                    canonical_json([int(i) for i in new_labels]),
                    canonical_json(dict(trigger)) if trigger else None,
                    int(seed),
                    source_dataset,
                    result_dataset,
                    canonical_json(dict(metadata or {})),
                ),
            )


class GroundTruthReader:
    """Read access for the evaluator (never for reconstruction)."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        if not self.db_path.exists():
            raise FileNotFoundError(self.db_path)
        self._conn = _connect(self.db_path)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> GroundTruthReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def events(self, experiment_uuid: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM gt_events WHERE experiment_uuid = ? ORDER BY sequence_number",
            (experiment_uuid,),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["poisoned_sample_ids"] = (
                json.loads(d["poisoned_sample_ids"]) if d["poisoned_sample_ids"] else None
            )
            d["metadata"] = json.loads(d.pop("metadata_json"))
            out.append(d)
        return out

    def attack(self, experiment_uuid: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM gt_attacks WHERE experiment_uuid = ?", (experiment_uuid,)
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        for key in ("poisoned_sample_ids", "original_labels", "new_labels"):
            d[key] = json.loads(d[key])
        d["trigger"] = json.loads(d.pop("trigger_json")) if d["trigger_json"] else None
        d["metadata"] = json.loads(d.pop("metadata_json"))
        return d
