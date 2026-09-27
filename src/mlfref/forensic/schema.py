"""Forensic event schema for pipeline C (docs/evidence_schema.md §4).

Every forensic event carries the common header from spec §16. In the ``experiment_id``
field the run is identified as ``RUN-<experiment_uuid>``, never by the human-readable
experiment ID, which encodes the attack (D-021).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

EVENT_TYPES = (
    "EXPERIMENT_STARTED",
    "EXPERIMENT_COMPLETED",
    "CONFIGURATION_LOADED",
    "DATASET_REGISTERED",
    "DATASET_VERSION_CREATED",
    "DATASET_INTEGRITY_VERIFIED",
    "TRAINING_STARTED",
    "TRAINING_COMPLETED",
    "MODEL_CREATED",
    "MODEL_HASHED",
    "MODEL_REGISTERED",
    "MODEL_DEPLOYED",
    "MODEL_REPLACED",
    "INFERENCE_REQUEST",
    "INFERENCE_RESULT",
    "ARTIFACT_INTEGRITY_CHECK",
    "ARTIFACT_INTEGRITY_FAILURE",
)

ARTIFACT_TYPES = ("dataset", "model", "deployment", "inference", "config", "code", "system")

# Metadata keys that would record a conclusion or the attack itself rather than
# preserve evidence (spec §46, D-014, D-019). The logger rejects them.
FORBIDDEN_METADATA_KEYS = frozenset(
    {
        "attack",
        "attack_type",
        "poison_rate",
        "poisoning_rate",
        "poisoned_sample_ids",
        "poisoned",
        "trigger",
        "backdoor",
        "root_cause",
        "source_class",
        "target_class",
        "is_malicious",
    }
)

GENESIS_HASH = "0" * 64

HEADER_FIELDS = (
    "event_id",
    "sequence_number",
    "timestamp_utc",
    "experiment_id",
    "experiment_uuid",
    "pipeline_mode",
    "event_type",
    "actor",
    "source_component",
    "artifact_type",
    "artifact_id",
    "artifact_hash",
    "parent_artifact_id",
    "run_id",
    "deployment_id",
    "previous_event_id",
    "previous_event_hash",
    "event_hash",
    "metadata_json",
)

DDL = """
CREATE TABLE IF NOT EXISTS forensic_events (
    event_id            TEXT PRIMARY KEY,
    sequence_number     INTEGER NOT NULL UNIQUE,
    timestamp_utc       TEXT NOT NULL,
    experiment_id       TEXT NOT NULL,
    experiment_uuid     TEXT NOT NULL,
    pipeline_mode       TEXT NOT NULL,
    event_type          TEXT NOT NULL,
    actor               TEXT NOT NULL,
    source_component    TEXT NOT NULL,
    artifact_type       TEXT,
    artifact_id         TEXT,
    artifact_hash       TEXT,
    parent_artifact_id  TEXT,
    run_id              TEXT,
    deployment_id       TEXT,
    previous_event_id   TEXT,
    previous_event_hash TEXT,
    event_hash          TEXT,
    metadata_json       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_fe_type ON forensic_events (event_type);
CREATE INDEX IF NOT EXISTS ix_fe_artifact ON forensic_events (artifact_id);
CREATE TRIGGER IF NOT EXISTS fe_no_update BEFORE UPDATE ON forensic_events
BEGIN SELECT RAISE(ABORT, 'forensic_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS fe_no_delete BEFORE DELETE ON forensic_events
BEGIN SELECT RAISE(ABORT, 'forensic_events is append-only'); END;
"""


@dataclass(frozen=True)
class ForensicEvent:
    event_id: str
    sequence_number: int
    timestamp_utc: str
    experiment_id: str
    experiment_uuid: str
    pipeline_mode: str
    event_type: str
    actor: str
    source_component: str
    artifact_type: str | None
    artifact_id: str | None
    artifact_hash: str | None
    parent_artifact_id: str | None
    run_id: str | None
    deployment_id: str | None
    previous_event_id: str | None
    previous_event_hash: str | None
    event_hash: str | None
    metadata_json: str

    def as_row(self) -> tuple[Any, ...]:
        return tuple(getattr(self, f) for f in HEADER_FIELDS)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def hash_payload(self) -> dict[str, Any]:
        """Every header field except ``event_hash`` (hashed together with the previous hash)."""
        return {k: v for k, v in self.as_dict().items() if k != "event_hash"}
