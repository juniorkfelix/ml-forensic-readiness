"""Ground-truth schema (docs/ground_truth.md)."""

from __future__ import annotations

ACTIONS = (
    "CLEAN_DATASET_CREATED",
    "POISONING_STARTED",
    "POISONING_COMPLETED",
    "POISONED_DATASET_CREATED",
    "TRAINING_STARTED",
    "TRAINING_COMPLETED",
    "COMPROMISED_MODEL_CREATED",
    "MODEL_CREATED",  # clean runs
    "MODEL_DEPLOYED",
    "TRIGGER_SUBMITTED",
    "MALICIOUS_PREDICTION",
)
ATTACK_TYPES = ("none", "label_flip", "backdoor")
RELATIONSHIPS = ("DERIVED_FROM", "USED", "GENERATED_BY", None)

DDL = """
CREATE TABLE IF NOT EXISTS gt_events (
    gt_event_id           TEXT PRIMARY KEY,
    timestamp_utc         TEXT NOT NULL,
    experiment_id         TEXT NOT NULL,
    experiment_uuid       TEXT NOT NULL,
    sequence_number       INTEGER NOT NULL,
    action                TEXT NOT NULL,
    attack_type           TEXT NOT NULL,
    affected_artifact     TEXT,
    source_artifact       TEXT,
    result_artifact       TEXT,
    poisoned_sample_ids   TEXT,
    expected_relationship TEXT,
    metadata_json         TEXT NOT NULL DEFAULT '{}',
    UNIQUE (experiment_uuid, sequence_number)
);
CREATE INDEX IF NOT EXISTS ix_gt_events_run ON gt_events (experiment_uuid, sequence_number);

CREATE TABLE IF NOT EXISTS gt_attacks (
    experiment_uuid     TEXT PRIMARY KEY,
    experiment_id       TEXT NOT NULL,
    timestamp_utc       TEXT NOT NULL,
    attack_type         TEXT NOT NULL,
    source_class        INTEGER,
    target_class        INTEGER,
    poison_rate         REAL NOT NULL,
    number_poisoned     INTEGER NOT NULL,
    poisoned_sample_ids TEXT NOT NULL,
    original_labels     TEXT NOT NULL,
    new_labels          TEXT NOT NULL,
    trigger_json        TEXT,
    seed                INTEGER NOT NULL,
    source_dataset      TEXT NOT NULL,
    result_dataset      TEXT NOT NULL,
    metadata_json       TEXT NOT NULL DEFAULT '{}'
);
"""
