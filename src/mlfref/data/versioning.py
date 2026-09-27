"""Dataset version records (spec §8).

A ``DatasetVersion`` identifies one dataset *state* by content:

    dataset_id = "<NAME>-<SPLIT>-<first 12 hex of manifest_sha256>"
                 e.g. CIFAR10-TRAIN-3f9a0c1b2d4e

Content-derived IDs are neutral: they reveal nothing about how the state came
about (D-014). Two versions with identical content get the same ID; any change
gives a new one.

The record holds what the *pipeline* can know. The spec's ``attack_type`` and
``poisoning_rate`` fields for derived datasets are harness knowledge and are
recorded only by the ground-truth recorder (mlfref.ground_truth), never here.
The research harness may additionally refer to the clean dataset by its
configured name (``CIFAR10-CLEAN-V1``); that alias is harness-level and is
kept in ``harness_alias``.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mlfref.data.cifar import CifarArrays, class_distribution, content_digest
from mlfref.data.manifest import build_manifest
from mlfref.forensic.hashing import HASH_ALGORITHM, manifest_hash

ID_HASH_CHARS = 12


def dataset_id_for(manifest_sha256: str, name: str = "CIFAR10", split: str = "TRAIN") -> str:
    return f"{name}-{split}-{manifest_sha256[:ID_HASH_CHARS]}"


@dataclass(frozen=True)
class DatasetVersion:
    dataset_id: str
    parent_dataset_id: str | None
    dataset_type: str  # e.g. "train", "test"
    created_at: str
    number_of_samples: int
    class_distribution: dict[str, int]
    manifest_sha256: str
    content_sha256: str
    hash_algorithm: str = HASH_ALGORITHM
    seed: int | None = None
    configuration_hash: str | None = None
    harness_alias: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def create_version(
    arrays: CifarArrays,
    *,
    dataset_type: str = "train",
    parent_dataset_id: str | None = None,
    seed: int | None = None,
    configuration_hash: str | None = None,
    harness_alias: str | None = None,
    name: str = "CIFAR10",
) -> tuple[DatasetVersion, list[dict[str, Any]]]:
    """Build the manifest and the version record for ``arrays``."""
    records = build_manifest(arrays)
    digest = manifest_hash(records)
    version = DatasetVersion(
        dataset_id=dataset_id_for(digest, name=name, split=dataset_type.upper()),
        parent_dataset_id=parent_dataset_id,
        dataset_type=dataset_type,
        created_at=datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        number_of_samples=len(arrays),
        class_distribution=class_distribution(arrays.labels),
        manifest_sha256=digest,
        content_sha256=content_digest(arrays),
        seed=seed,
        configuration_hash=configuration_hash,
        harness_alias=harness_alias,
    )
    return version, records


def save_version(version: DatasetVersion, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(version.as_dict(), indent=2), encoding="utf-8")
    return path


def load_version(path: str | Path) -> DatasetVersion:
    return DatasetVersion(**json.loads(Path(path).read_text(encoding="utf-8")))
