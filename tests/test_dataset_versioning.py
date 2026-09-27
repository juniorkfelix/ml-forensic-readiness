"""Phase 6: per-sample manifests, dataset hashing and version records (spec §9)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import numpy as np
import pytest

from mlfref.data.cifar import CifarArrays, read_store
from mlfref.data.manifest import build_manifest, compare_manifests, read_manifest, write_manifest
from mlfref.data.versioning import create_version, load_version, save_version
from mlfref.forensic.hashing import manifest_hash

ROOT = Path(__file__).resolve().parents[1]
CLEAN_STORE = ROOT / "data" / "clean" / "cifar10_train.npz"
CLEAN_VERSION = ROOT / "data" / "manifests" / "CIFAR10-CLEAN-V1.version.json"


def _arrays(n=30, seed=0) -> CifarArrays:
    rng = np.random.default_rng(seed)
    return CifarArrays(
        rng.integers(0, 256, (n, 32, 32, 3), dtype=np.uint8),
        rng.integers(0, 10, n).astype(np.int64),
        np.arange(n, dtype=np.int64),
    )


def _with(arrays, images=None, labels=None, ids=None):
    return CifarArrays(
        arrays.images if images is None else images,
        arrays.labels if labels is None else labels,
        arrays.sample_ids if ids is None else ids,
    )


def test_dataset_hash_deterministic():
    a = _arrays()
    assert manifest_hash(build_manifest(a)) == manifest_hash(build_manifest(_arrays()))


def test_changed_label_changes_hash():
    a = _arrays()
    labels = a.labels.copy()
    labels[4] = (labels[4] + 1) % 10
    assert manifest_hash(build_manifest(_with(a, labels=labels))) != manifest_hash(
        build_manifest(a)
    )


def test_modified_pixels_change_hash():
    a = _arrays()
    images = a.images.copy()
    images[7, 31, 31, :] = 255 - images[7, 31, 31, :]
    assert manifest_hash(build_manifest(_with(a, images=images))) != manifest_hash(
        build_manifest(a)
    )


def test_ordering_alone_does_not_change_hash():
    a = _arrays()
    perm = np.random.default_rng(3).permutation(len(a))
    shuffled = CifarArrays(a.images[perm], a.labels[perm], a.sample_ids[perm])
    assert manifest_hash(build_manifest(shuffled)) == manifest_hash(build_manifest(a))


def test_version_ids_are_content_derived_and_neutral():
    a = _arrays()
    v1, _ = create_version(a)
    v2, _ = create_version(a, parent_dataset_id="whatever")
    assert v1.dataset_id == v2.dataset_id
    assert re.fullmatch(r"CIFAR10-TRAIN-[0-9a-f]{12}", v1.dataset_id)
    labels = a.labels.copy()
    labels[0] = (labels[0] + 1) % 10
    v3, _ = create_version(_with(a, labels=labels), parent_dataset_id=v1.dataset_id)
    assert v3.dataset_id != v1.dataset_id and v3.parent_dataset_id == v1.dataset_id
    # neutral: no attack vocabulary in the public record (D-014)
    text = json.dumps(v3.as_dict()).lower()
    for word in ("attack", "poison", "flip", "backdoor", "trigger"):
        assert word not in text


def test_version_record_fields(tmp_path):
    a = _arrays()
    v, _ = create_version(a, seed=3, configuration_hash="c" * 64, harness_alias="X-V1")
    for field in (
        "dataset_id",
        "parent_dataset_id",
        "dataset_type",
        "created_at",
        "number_of_samples",
        "class_distribution",
        "manifest_sha256",
        "content_sha256",
        "hash_algorithm",
        "seed",
        "configuration_hash",
    ):
        assert field in v.as_dict()
    assert v.number_of_samples == 30 and sum(v.class_distribution.values()) == 30
    assert v.hash_algorithm == "SHA-256"
    assert load_version(save_version(v, tmp_path / "v.json")) == v


def test_manifest_file_round_trip_and_tamper_detection(tmp_path):
    a = _arrays()
    records = build_manifest(a)
    path = tmp_path / "m.json"
    digest = write_manifest(path, "CIFAR10-TRAIN-x", records)
    doc = read_manifest(path)
    assert doc["manifest_sha256"] == digest == manifest_hash(records)
    tampered = json.loads(path.read_text())
    tampered["records"][2]["label"] = (tampered["records"][2]["label"] + 1) % 10
    path.write_text(json.dumps(tampered))
    with pytest.raises(ValueError, match="mismatch"):
        read_manifest(path)


def test_compare_manifests_finds_exact_changes():
    a = _arrays(50)
    labels, images = a.labels.copy(), a.images.copy()
    labels[[3, 9]] = (labels[[3, 9]] + 1) % 10  # label only
    images[[20]] ^= 1  # pixels only
    labels[[30]] = (labels[[30]] + 2) % 10
    images[[30]] ^= 1  # both
    diff = compare_manifests(build_manifest(a), build_manifest(_with(a, images, labels)))
    assert diff.label_changed == (3, 9, 30)
    assert diff.pixels_changed == (20, 30)
    assert diff.changed == (3, 9, 20, 30)
    assert sum(diff.label_transitions.values()) == 3
    assert diff.summary()["label_and_pixels_changed"] == 1
    assert compare_manifests(build_manifest(a), build_manifest(a)).identical


def test_compare_manifests_added_removed():
    a = _arrays(10)
    b = CifarArrays(a.images[:8], a.labels[:8], a.sample_ids[:8])
    diff = compare_manifests(build_manifest(a), build_manifest(b))
    assert diff.removed == (8, 9) and not diff.added


@pytest.mark.skipif(not CLEAN_VERSION.exists(), reason="run scripts/prepare_dataset.py")
def test_clean_store_matches_registered_clean_version():
    registered = load_version(CLEAN_VERSION)
    version, _ = create_version(read_store(CLEAN_STORE))
    assert version.manifest_sha256 == registered.manifest_sha256
    assert version.dataset_id == registered.dataset_id
    assert version.number_of_samples == 50_000
