"""Forensic event logger (pipeline C).

``ForensicLogger.log`` builds the common §16 header, links each event to its
predecessor (``previous_event_id``) and, when chain hashing is enabled, computes

    event_hash = SHA256( canonical_json(payload_without_event_hash) + previous_event_hash )

where the first event's previous hash is ``GENESIS_HASH`` (64 zeros). The chain is
*tamper-evident*: a later modification, deletion, insertion or reordering of stored
events is detectable by recomputing it (mlfref.forensic.integrity). It does not
prevent tampering. Someone able to rewrite the whole store can also recompute every
hash, unless the latest hash has been anchored elsewhere (out of scope).

The logger preserves evidence and does not record conclusions. Metadata keys that
would state the attack or a root cause are rejected (``FORBIDDEN_METADATA_KEYS``,
spec §46).
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from mlfref.forensic.evidence_store import ForensicEvidenceStore
from mlfref.forensic.hashing import canonical_json, sha256_text
from mlfref.forensic.schema import (
    ARTIFACT_TYPES,
    EVENT_TYPES,
    FORBIDDEN_METADATA_KEYS,
    GENESIS_HASH,
    ForensicEvent,
)
from mlfref.models.train import TrainingHooks


def utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def compute_event_hash(event: ForensicEvent, previous_hash: str | None) -> str:
    return sha256_text(canonical_json(event.hash_payload()) + (previous_hash or GENESIS_HASH))


def _check_metadata(metadata: Any, path: str = "metadata") -> None:
    if isinstance(metadata, Mapping):
        for key, value in metadata.items():
            if str(key).lower() in FORBIDDEN_METADATA_KEYS:
                raise ValueError(
                    f"{path}.{key}: forensic evidence must preserve observations, not record "
                    "the attack or conclusions (spec §46)"
                )
            _check_metadata(value, f"{path}.{key}")
    elif isinstance(metadata, (list, tuple)):
        for i, value in enumerate(metadata):
            _check_metadata(value, f"{path}[{i}]")


class ForensicLogger:
    def __init__(
        self,
        store: ForensicEvidenceStore,
        experiment_uuid: str,
        pipeline_mode: str = "forensic",
        chain_hashing: bool = True,
        clock: Callable[[], str] = utc_timestamp,
    ) -> None:
        self.store = store
        self.experiment_uuid = experiment_uuid
        self.run_ref = f"RUN-{experiment_uuid}"
        self.pipeline_mode = pipeline_mode
        self.chain_hashing = chain_hashing
        self.clock = clock
        last = store.last_event()
        self._last_id = last.event_id if last else None
        self._last_hash = last.event_hash if last else None
        self._next_seq = (last.sequence_number + 1) if last else 1
        self.logging_seconds = 0.0  # time spent writing evidence (RQ4)
        self.events_written = 0

    def log(
        self,
        event_type: str,
        *,
        actor: str,
        source_component: str,
        artifact_type: str | None = None,
        artifact_id: str | None = None,
        artifact_hash: str | None = None,
        parent_artifact_id: str | None = None,
        run_id: str | None = None,
        deployment_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ForensicEvent:
        t0 = time.perf_counter()
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown forensic event type {event_type!r}")
        if artifact_type is not None and artifact_type not in ARTIFACT_TYPES:
            raise ValueError(f"unknown artifact type {artifact_type!r}")
        _check_metadata(metadata or {})
        event = ForensicEvent(
            event_id=str(uuid.uuid4()),
            sequence_number=self._next_seq,
            timestamp_utc=self.clock(),
            experiment_id=self.run_ref,
            experiment_uuid=self.experiment_uuid,
            pipeline_mode=self.pipeline_mode,
            event_type=event_type,
            actor=actor,
            source_component=source_component,
            artifact_type=artifact_type,
            artifact_id=artifact_id,
            artifact_hash=artifact_hash,
            parent_artifact_id=parent_artifact_id,
            run_id=run_id,
            deployment_id=deployment_id,
            previous_event_id=self._last_id,
            previous_event_hash=(self._last_hash or GENESIS_HASH) if self.chain_hashing else None,
            event_hash=None,
            metadata_json=canonical_json(dict(metadata or {})),
        )
        if self.chain_hashing:
            event = ForensicEvent(
                **{**event.as_dict(), "event_hash": compute_event_hash(event, self._last_hash)}
            )
        self.store.append(event)
        self._last_id, self._last_hash = event.event_id, event.event_hash
        self._next_seq += 1
        self.events_written += 1
        self.logging_seconds += time.perf_counter() - t0
        return event


class ForensicTrainingHooks(TrainingHooks):
    """Emits TRAINING_STARTED / TRAINING_COMPLETED around the training loop.

    Only the start and end are recorded (no per-epoch forensic events, to avoid noise,
    spec §17). The training dataset identity is what the training job itself hashed.
    """

    def __init__(
        self,
        logger: ForensicLogger,
        *,
        dataset_id: str,
        dataset_hash: str,
        run_id: str | None,
        hyperparameters: Mapping[str, Any],
        actor: str = "svc-training",
    ) -> None:
        self.logger = logger
        self.dataset_id = dataset_id
        self.dataset_hash = dataset_hash
        self.run_id = run_id
        self.hyperparameters = dict(hyperparameters)
        self.actor = actor

    def on_train_start(self, info: Mapping[str, Any]) -> None:
        self.logger.log(
            "TRAINING_STARTED",
            actor=self.actor,
            source_component="mlfref.models.train",
            artifact_type="dataset",
            artifact_id=self.dataset_id,
            artifact_hash=self.dataset_hash,
            run_id=self.run_id,
            metadata={"hyperparameters": self.hyperparameters, **dict(info)},
        )

    def on_train_end(self, info: Mapping[str, Any]) -> None:
        history = info.get("history") or [{}]
        final = history[-1]
        self.logger.log(
            "TRAINING_COMPLETED",
            actor=self.actor,
            source_component="mlfref.models.train",
            artifact_type="dataset",
            artifact_id=self.dataset_id,
            artifact_hash=self.dataset_hash,
            run_id=self.run_id,
            metadata={
                "epochs_completed": len(info.get("history") or []),
                "training_seconds": round(float(info.get("training_seconds", 0.0)), 3),
                "final_train_loss": final.get("train_loss"),
                "final_train_accuracy": final.get("train_accuracy"),
            },
        )


class CompositeHooks(TrainingHooks):
    """Run several hook sets in order (e.g. MLflow + forensic in pipeline C)."""

    def __init__(self, *hooks: TrainingHooks) -> None:
        self.hooks = [h for h in hooks if h is not None]

    def on_train_start(self, info: Mapping[str, Any]) -> None:
        for h in self.hooks:
            h.on_train_start(info)

    def on_epoch_end(self, record: Mapping[str, Any]) -> None:
        for h in self.hooks:
            h.on_epoch_end(record)

    def on_train_end(self, info: Mapping[str, Any]) -> None:
        for h in self.hooks:
            h.on_train_end(info)
