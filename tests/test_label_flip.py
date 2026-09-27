"""Phase 8: label-flipping attack (spec §12)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from mlfref.attacks.base import run_attack
from mlfref.attacks.label_flip import LabelFlipAttack
from mlfref.data.cifar import CifarArrays, class_distribution, content_digest, read_store
from mlfref.data.manifest import build_manifest, compare_manifests
from mlfref.data.versioning import create_version
from mlfref.ground_truth.recorder import GroundTruthReader, GroundTruthRecorder

ROOT = Path(__file__).resolve().parents[1]
CLEAN_STORE = ROOT / "data" / "clean" / "cifar10_train.npz"
needs_store = pytest.mark.skipif(not CLEAN_STORE.exists(), reason="run prepare_dataset.py")


def _balanced(per_class=100, seed=0) -> CifarArrays:
    rng = np.random.default_rng(seed)
    n = per_class * 10
    labels = np.repeat(np.arange(10), per_class).astype(np.int64)
    perm = rng.permutation(n)
    return CifarArrays(
        rng.integers(0, 256, (n, 32, 32, 3), dtype=np.uint8),
        labels[perm],
        np.arange(n, dtype=np.int64),
    )


def test_label_flip_count():
    clean = _balanced()
    res = LabelFlipAttack("automobile", "truck", 0.05, seed=1).apply(clean)
    assert res.number_poisoned == 50  # 5 % of 1,000
    changed = np.nonzero(res.poisoned.labels != clean.labels)[0]
    assert len(changed) == 50
    assert np.array_equal(np.sort(clean.sample_ids[changed]), res.poisoned_sample_ids)


def test_only_source_samples_flipped_to_target_and_pixels_unchanged():
    clean = _balanced()
    res = LabelFlipAttack(1, 9, 0.05, seed=2).apply(clean)
    assert set(res.original_labels.tolist()) == {1}
    assert set(res.new_labels.tolist()) == {9}
    assert np.array_equal(res.poisoned.images, clean.images)
    dist = class_distribution(res.poisoned.labels)
    assert dist["automobile"] == 50 and dist["truck"] == 150


def test_clean_dataset_not_modified_by_attack():
    clean = _balanced()
    before = content_digest(clean)
    LabelFlipAttack(1, 9, 0.05, seed=3).apply(clean)
    assert content_digest(clean) == before


def test_label_flip_reproducibility():
    clean = _balanced()
    a = LabelFlipAttack(1, 9, 0.05, seed=7).apply(clean)
    b = LabelFlipAttack(1, 9, 0.05, seed=7).apply(clean)
    assert np.array_equal(a.poisoned_sample_ids, b.poisoned_sample_ids)
    assert content_digest(a.poisoned) == content_digest(b.poisoned)


def test_different_seed_gives_different_set():
    clean = _balanced()
    a = LabelFlipAttack(1, 9, 0.05, seed=1).apply(clean)
    b = LabelFlipAttack(1, 9, 0.05, seed=2).apply(clean)
    assert not np.array_equal(a.poisoned_sample_ids, b.poisoned_sample_ids)


def test_selection_independent_of_record_order():
    clean = _balanced()
    perm = np.random.default_rng(0).permutation(len(clean))
    shuffled = CifarArrays(clean.images[perm], clean.labels[perm], clean.sample_ids[perm])
    a = LabelFlipAttack(1, 9, 0.05, seed=4).apply(clean)
    b = LabelFlipAttack(1, 9, 0.05, seed=4).apply(shuffled)
    assert np.array_equal(a.poisoned_sample_ids, b.poisoned_sample_ids)


def test_rate_exceeding_source_class_rejected():
    with pytest.raises(ValueError, match="only"):
        LabelFlipAttack(1, 9, 0.2, seed=1).apply(_balanced())  # needs 200 > 100


def test_invalid_parameters_rejected():
    with pytest.raises(ValueError):
        LabelFlipAttack("automobile", "automobile", 0.05, 1)
    with pytest.raises(ValueError):
        LabelFlipAttack("automobile", "truck", 0.0, 1)


def test_run_attack_records_ground_truth_only(tmp_path):
    clean = _balanced()
    clean_version, _ = create_version(clean)
    db = tmp_path / "gt.sqlite"
    with GroundTruthRecorder(db, "EXP-LF-C-05-S001", "u-1", "label_flip") as gt:
        res, version = run_attack(LabelFlipAttack(1, 9, 0.05, 1), clean, clean_version, gt)
    with GroundTruthReader(db) as reader:
        events = reader.events("u-1")
        attack = reader.attack("u-1")
    assert [e["action"] for e in events] == [
        "POISONING_STARTED",
        "POISONING_COMPLETED",
        "POISONED_DATASET_CREATED",
    ]
    assert attack["poisoned_sample_ids"] == res.poisoned_sample_ids.tolist()
    assert attack["result_dataset"] == version.manifest_sha256
    assert version.parent_dataset_id == clean_version.dataset_id
    # The public version record stays neutral (D-014)
    assert "poison" not in str(version.as_dict()).lower()
    # The changed samples are recoverable from two manifests; this is what forensic
    # evidence would let an investigator derive.
    diff = compare_manifests(build_manifest(clean), build_manifest(res.poisoned))
    assert list(diff.label_changed) == attack["poisoned_sample_ids"]
    assert not diff.pixels_changed


@needs_store
def test_pilot_configuration_on_real_training_set():
    clean = read_store(CLEAN_STORE)
    res = LabelFlipAttack("automobile", "truck", 0.05, seed=1).apply(clean)
    assert res.number_poisoned == 2500
    dist = class_distribution(res.poisoned.labels)
    assert dist["automobile"] == 2500 and dist["truck"] == 7500
    assert sum(dist.values()) == 50_000
