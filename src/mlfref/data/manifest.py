"""Per-sample dataset manifests (spec §9).

A manifest has one record per sample:

    {"sample_id": int, "label": int, "pixel_sha256": hex}

``pixel_sha256`` is the SHA-256 of the sample's raw uint8 image bytes (32x32x3,
C order). The manifest hash is SHA-256 over the canonical serialisation of the
records sorted by ``sample_id`` (mlfref.forensic.hashing.manifest_hash), so it
changes when any label or pixel changes, or when a sample is added or removed,
and does not change when only the record order changes.

The investigator-visible manifest has a single ``label`` field: the label as stored.
The original/effective label pair exists only in ground truth (docs/evidence_schema.md
§4.3).
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mlfref.data.cifar import CifarArrays
from mlfref.forensic.hashing import (
    HASH_ALGORITHM,
    canonical_json,
    canonical_manifest_records,
    manifest_hash,
    sha256_file,
)

Record = dict[str, Any]


def build_manifest(arrays: CifarArrays) -> list[Record]:
    """Manifest records in sample_id order."""
    order = arrays.sample_ids.argsort(kind="stable")
    return [
        {
            "sample_id": int(arrays.sample_ids[i]),
            "label": int(arrays.labels[i]),
            "pixel_sha256": hashlib.sha256(arrays.images[i].tobytes()).hexdigest(),
        }
        for i in order
    ]


def write_manifest(path: str | Path, dataset_id: str, records: Iterable[Mapping[str, Any]]) -> str:
    """Write a manifest file (canonical JSON) and return its ``manifest_sha256``.

    The file holds the dataset ID, the hash algorithm, the manifest hash and the
    records. The manifest hash covers the records only, so the same content yields
    the same hash whatever ID it is stored under.
    """
    recs = canonical_manifest_records(records)
    digest = manifest_hash(recs)
    doc = {
        "dataset_id": dataset_id,
        "hash_algorithm": HASH_ALGORITHM,
        "manifest_sha256": digest,
        "records": recs,
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(doc), encoding="utf-8")
    return digest


def read_manifest(path: str | Path, verify: bool = True) -> dict[str, Any]:
    """Load a manifest file; with ``verify`` the stored hash is recomputed and checked."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if verify:
        observed = manifest_hash(doc["records"])
        if observed != doc["manifest_sha256"]:
            raise ValueError(
                f"manifest hash mismatch for {path}: stored {doc['manifest_sha256']}, "
                f"recomputed {observed}"
            )
    return doc


def manifest_file_sha256(path: str | Path) -> str:
    return sha256_file(path)


@dataclass(frozen=True)
class ManifestDiff:
    """Differences between two manifests (``before`` -> ``after``)."""

    added: tuple[int, ...]
    removed: tuple[int, ...]
    label_changed: tuple[int, ...]
    pixels_changed: tuple[int, ...]
    label_transitions: dict[str, int]  # "old->new" -> count

    @property
    def changed(self) -> tuple[int, ...]:
        return tuple(sorted(set(self.label_changed) | set(self.pixels_changed)))

    @property
    def identical(self) -> bool:
        return not (self.added or self.removed or self.changed)

    def summary(self) -> dict[str, Any]:
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "changed": len(self.changed),
            "label_changed": len(self.label_changed),
            "pixels_changed": len(self.pixels_changed),
            "label_and_pixels_changed": len(set(self.label_changed) & set(self.pixels_changed)),
            "label_transitions": self.label_transitions,
        }


def compare_manifests(
    before: Iterable[Mapping[str, Any]], after: Iterable[Mapping[str, Any]]
) -> ManifestDiff:
    """Sample-level comparison of two manifests keyed by ``sample_id``."""
    a = {r["sample_id"]: r for r in before}
    b = {r["sample_id"]: r for r in after}
    common = sorted(a.keys() & b.keys())
    label_changed = [s for s in common if a[s]["label"] != b[s]["label"]]
    pixels_changed = [s for s in common if a[s]["pixel_sha256"] != b[s]["pixel_sha256"]]
    transitions = Counter(f"{a[s]['label']}->{b[s]['label']}" for s in label_changed)
    return ManifestDiff(
        added=tuple(sorted(b.keys() - a.keys())),
        removed=tuple(sorted(a.keys() - b.keys())),
        label_changed=tuple(label_changed),
        pixels_changed=tuple(pixels_changed),
        label_transitions=dict(sorted(transitions.items())),
    )
