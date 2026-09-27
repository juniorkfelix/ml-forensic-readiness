"""Phase 9: backdoor attack, triggered test set and ASR (spec §13, §42)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
import torch

from mlfref.attacks.backdoor import BackdoorAttack, trigger_pattern, trigger_slices
from mlfref.attacks.base import run_attack
from mlfref.config import compose_run_config
from mlfref.data.cifar import CifarArrays, TensorBatches, content_digest, read_store
from mlfref.data.manifest import build_manifest, compare_manifests
from mlfref.data.versioning import create_version
from mlfref.ground_truth.recorder import GroundTruthReader, GroundTruthRecorder
from mlfref.models.evaluate import attack_success_rate

ROOT = Path(__file__).resolve().parents[1]
CLEAN = ROOT / "data" / "clean"
needs_store = pytest.mark.skipif(
    not (CLEAN / "cifar10_train.npz").exists(), reason="run prepare_dataset.py"
)


def _balanced(per_class=100, seed=0) -> CifarArrays:
    rng = np.random.default_rng(seed)
    n = per_class * 10
    labels = np.repeat(np.arange(10), per_class).astype(np.int64)
    return CifarArrays(
        rng.integers(1, 255, (n, 32, 32, 3), dtype=np.uint8),  # avoid 0/255 by chance
        labels[rng.permutation(n)],
        np.arange(n, dtype=np.int64),
    )


def _attack(**kw):
    args = {"target_class": "airplane", "poison_rate": 0.05, "seed": 1}
    return BackdoorAttack(**{**args, **kw})


def test_backdoor_trigger_location():
    """Trigger occupies exactly rows/cols 28-30 (3x3, offset 1, bottom-right); nothing else
    in a poisoned image changes."""
    clean = _balanced()
    res = _attack().apply(clean)
    rows, cols = trigger_slices(3, "bottom_right", 1)
    assert (rows.start, rows.stop, cols.start, cols.stop) == (28, 31, 28, 31)
    pos = {int(s): i for i, s in enumerate(clean.sample_ids)}
    for sid in res.poisoned_sample_ids[:20]:
        i = pos[int(sid)]
        patch = res.poisoned.images[i, 28:31, 28:31, :]
        assert np.array_equal(patch, np.repeat(trigger_pattern(3)[:, :, None], 3, axis=2))
        mask = np.ones((32, 32), dtype=bool)
        mask[28:31, 28:31] = False
        assert np.array_equal(res.poisoned.images[i][mask], clean.images[i][mask])


def test_checkerboard_pattern_values():
    assert trigger_pattern(3).tolist() == [[255, 0, 255], [0, 255, 0], [255, 0, 255]]


@pytest.mark.parametrize(
    "position, expected",
    [("top_left", (1, 1)), ("top_right", (1, 28)), ("bottom_left", (28, 1))],
)
def test_other_positions(position, expected):
    rows, cols = trigger_slices(3, position, 1)
    assert (rows.start, cols.start) == expected


def test_trigger_size_configurable():
    res = _attack(trigger_size=5, trigger_offset=0).apply(_balanced())
    assert res.poisoned.images[res.poisoned_sample_ids[0], 27:32, 27:32, 0].tolist() == (
        trigger_pattern(5).tolist()
    )


def test_poison_count_labels_and_target_exclusion():
    clean = _balanced()
    res = _attack().apply(clean)
    assert res.number_poisoned == 50  # 5 % of 1,000
    assert set(res.new_labels.tolist()) == {0}
    assert 0 not in set(res.original_labels.tolist())  # target class excluded
    changed = np.nonzero(
        (res.poisoned.labels != clean.labels)
        | (res.poisoned.images != clean.images).any(axis=(1, 2, 3))
    )[0]
    assert np.array_equal(np.sort(clean.sample_ids[changed]), res.poisoned_sample_ids)


def test_backdoor_reproducibility():
    clean = _balanced()
    a, b = _attack(seed=5).apply(clean), _attack(seed=5).apply(clean)
    assert np.array_equal(a.poisoned_sample_ids, b.poisoned_sample_ids)
    assert content_digest(a.poisoned) == content_digest(b.poisoned)
    c = _attack(seed=6).apply(clean)
    assert not np.array_equal(a.poisoned_sample_ids, c.poisoned_sample_ids)


def test_clean_dataset_not_modified_by_backdoor():
    clean = _balanced()
    before = content_digest(clean)
    _attack().apply(clean)
    assert content_digest(clean) == before


def test_triggered_test_set_is_separate_and_excludes_target():
    test = _balanced(per_class=20, seed=9)
    before = content_digest(test)
    attack = _attack()
    trig = attack.triggered_test_set(test)
    assert content_digest(test) == before  # clean test set untouched
    assert len(trig) == 180 and 0 not in set(trig.labels.tolist())
    assert (trig.images[:, 28:31, 28:31, 0] == trigger_pattern(3)).all()


def test_attack_success_rate_metric():
    """ASR = predictions equal to target / triggered samples (stub model predicts class 0
    only when the trigger's top-left cell is white)."""
    test = _balanced(per_class=10, seed=2)
    attack = _attack()
    trig = attack.triggered_test_set(test)
    half = len(trig) // 2
    images = trig.images.copy()
    images[:half, 28, 28, :] = 0  # break the trigger on the first half
    data = TensorBatches(CifarArrays(images, trig.labels, trig.sample_ids), "cpu")

    class Stub(torch.nn.Module):
        def forward(self, x):
            white = x[:, 0, 28, 28] > 1.0  # normalised white > 1
            logits = torch.zeros(x.shape[0], 10)
            logits[white, 0] = 5.0
            logits[~white, 3] = 5.0
            return logits

    res = attack_success_rate(Stub(), data, target_class=0, batch_size=32)
    assert res.n == len(trig) and res.successes == len(trig) - half
    assert res.asr == pytest.approx((len(trig) - half) / len(trig))
    with pytest.raises(ValueError):
        attack_success_rate(Stub(), TensorBatches(test, "cpu"), target_class=0)


def test_run_attack_records_backdoor_ground_truth(tmp_path):
    clean = _balanced()
    clean_version, _ = create_version(clean)
    db = tmp_path / "gt.sqlite"
    with GroundTruthRecorder(db, "EXP-BD-C-05-S001", "u-1", "backdoor") as gt:
        res, version = run_attack(_attack(), clean, clean_version, gt)
    with GroundTruthReader(db) as reader:
        attack = reader.attack("u-1")
    assert attack["poisoned_sample_ids"] == res.poisoned_sample_ids.tolist()
    assert attack["target_class"] == 0 and attack["source_class"] is None
    assert attack["trigger"]["size"] == 3 and attack["trigger"]["position"] == "bottom_right"
    diff = compare_manifests(build_manifest(clean), build_manifest(res.poisoned))
    assert list(diff.changed) == attack["poisoned_sample_ids"]
    assert diff.summary()["label_and_pixels_changed"] == 50


def test_from_config_matches_pilot_file():
    cfg = compose_run_config(ROOT / "config", "C", "pilot_backdoor.yaml")
    attack = BackdoorAttack.from_config(cfg)
    assert attack.target == 0 and attack.size == 3 and attack.position == "bottom_right"
    assert attack.seed == cfg["experiment"]["seed"]


@needs_store
def test_pilot_backdoor_on_real_data_and_no_test_leakage():
    train = read_store(CLEAN / "cifar10_train.npz")
    test = read_store(CLEAN / "cifar10_test.npz")
    test_digest = content_digest(test)
    attack = _attack()
    res = attack.apply(train)
    trig = attack.triggered_test_set(test)
    assert res.number_poisoned == 2500
    assert len(trig) == 9000
    assert content_digest(test) == test_digest
    # Poisoned training data is still exactly the training split (same sample IDs).
    assert np.array_equal(res.poisoned.sample_ids, train.sample_ids)
