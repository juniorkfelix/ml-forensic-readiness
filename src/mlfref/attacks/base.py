"""Attack interface and ground-truth recording.

Attacks model the adversary in the data-store tampering threat model (D-015).
They run in the research harness, outside every pipeline. The pipeline only ever
sees the resulting data store. The exact modifications are recorded in ground truth
and nowhere else (spec §12).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from mlfref.data.cifar import CifarArrays
from mlfref.data.versioning import DatasetVersion, create_version
from mlfref.ground_truth.recorder import GroundTruthRecorder


@dataclass(frozen=True)
class AttackResult:
    poisoned: CifarArrays
    poisoned_sample_ids: np.ndarray  # sorted int64
    original_labels: np.ndarray
    new_labels: np.ndarray
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def number_poisoned(self) -> int:
        return len(self.poisoned_sample_ids)


class Attack(ABC):
    attack_type: str

    @abstractmethod
    def apply(self, clean: CifarArrays) -> AttackResult:
        """Return a poisoned COPY of ``clean``; ``clean`` must not be modified."""

    @abstractmethod
    def gt_fields(self) -> dict[str, Any]:
        """Attack-specific ground-truth fields (source/target class, trigger, ...)."""


def run_attack(
    attack: Attack,
    clean: CifarArrays,
    clean_version: DatasetVersion,
    recorder: GroundTruthRecorder,
    annotate=None,
) -> tuple[AttackResult, DatasetVersion]:
    """Apply ``attack`` and record the ground truth. Returns the result and the new version."""
    if recorder.attack_type != attack.attack_type:
        raise ValueError("recorder attack_type does not match the attack")
    recorder.record(
        "POISONING_STARTED",
        source_artifact=clean_version.manifest_sha256,
        metadata={"source_dataset_id": clean_version.dataset_id, **attack.gt_fields()},
    )
    result = attack.apply(clean)
    version, _ = create_version(
        result.poisoned,
        parent_dataset_id=clean_version.dataset_id,
        seed=result.params.get("seed"),
    )
    ids = result.poisoned_sample_ids.tolist()
    recorder.record(
        "POISONING_COMPLETED",
        source_artifact=clean_version.manifest_sha256,
        result_artifact=version.manifest_sha256,
        poisoned_sample_ids=ids,
        metadata={"number_poisoned": len(ids)},
    )
    recorder.record(
        "POISONED_DATASET_CREATED",
        affected_artifact=version.manifest_sha256,
        source_artifact=clean_version.manifest_sha256,
        result_artifact=version.manifest_sha256,
        poisoned_sample_ids=ids,
        expected_relationship="DERIVED_FROM",
        metadata={
            "dataset_id": version.dataset_id,
            "parent_dataset_id": clean_version.dataset_id,
            "attack_type": attack.attack_type,
            "poisoning_rate": result.params.get("poison_rate"),
            "class_distribution": version.class_distribution,
            **(annotate(result.poisoned) if annotate else {}),
        },
    )
    recorder.record_attack(
        poison_rate=result.params["poison_rate"],
        poisoned_sample_ids=ids,
        original_labels=result.original_labels.tolist(),
        new_labels=result.new_labels.tolist(),
        seed=result.params["seed"],
        source_dataset=clean_version.manifest_sha256,
        result_dataset=version.manifest_sha256,
        source_class=attack.gt_fields().get("source_class"),
        target_class=attack.gt_fields().get("target_class"),
        trigger=attack.gt_fields().get("trigger"),
        metadata={
            "source_dataset_id": clean_version.dataset_id,
            "result_dataset_id": version.dataset_id,
        },
    )
    return result, version
