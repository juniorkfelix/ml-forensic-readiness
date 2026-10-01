"""Phase 3: CIFAR-10 loading, clean data stores, leakage guards and batching."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest
import torch

from mlfref.data import cifar

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data" / "raw"
INTEGRITY = ROOT / "data" / "manifests" / "cifar10_raw_integrity.json"
CLEAN = ROOT / "data" / "clean"

needs_cifar = pytest.mark.skipif(
    not (DATA_DIR / cifar.RAW_SUBDIR).is_dir() or not INTEGRITY.exists(),
    reason="CIFAR-10 not prepared (run scripts/prepare_dataset.py)",
)


def _synthetic(n=20, seed=0) -> cifar.CifarArrays:
    rng = np.random.default_rng(seed)
    return cifar.CifarArrays(
        images=rng.integers(0, 256, (n, 32, 32, 3), dtype=np.uint8),
        labels=rng.integers(0, 10, n).astype(np.int64),
        sample_ids=np.arange(n, dtype=np.int64),
    )


# ------------------------------------------------------------------ real dataset


@pytest.fixture(scope="module")
def official():
    return cifar.load_official_split(DATA_DIR, "train"), cifar.load_official_split(DATA_DIR, "test")


@needs_cifar
def test_official_split_sizes_and_balance(official):
    train, test = official
    assert len(train) == cifar.N_TRAIN and len(test) == cifar.N_TEST
    assert train.images.dtype == np.uint8 and train.images.shape[1:] == (32, 32, 3)
    assert set(cifar.class_distribution(train.labels).values()) == {5000}
    assert set(cifar.class_distribution(test.labels).values()) == {1000}


@needs_cifar
def test_clean_dataset_not_modified(official):
    """Official files still match the SHA-256 recorded when first downloaded,
    after loading and building stores."""
    expected = json.loads(INTEGRITY.read_text(encoding="utf-8"))["sha256"]
    result = cifar.verify_raw_integrity(DATA_DIR, expected)
    assert result and all(result.values()), result


@needs_cifar
def test_clean_stores_built_only_from_their_official_split(official):
    """Leakage guard: train store == data_batch_1..5 exactly; test store == test_batch."""
    train, test = official
    for name, ref in (("cifar10_train.npz", train), ("cifar10_test.npz", test)):
        store = cifar.read_store(CLEAN / name)
        assert cifar.content_digest(store) == cifar.content_digest(ref)
    assert cifar.content_digest(train) != cifar.content_digest(test)


@needs_cifar
def test_loading_is_deterministic(official):
    train, _ = official
    again = cifar.load_official_split(DATA_DIR, "train")
    assert cifar.content_digest(again) == cifar.content_digest(train)


# ------------------------------------------------------------------ stores / arrays


def test_store_round_trip(tmp_path):
    arrays = _synthetic()
    path = cifar.write_store(tmp_path / "s.npz", arrays)
    back = cifar.read_store(path)
    assert np.array_equal(back.images, arrays.images)
    assert np.array_equal(back.labels, arrays.labels)
    assert np.array_equal(back.sample_ids, arrays.sample_ids)
    assert cifar.content_digest(back) == cifar.content_digest(arrays)


def test_content_digest_sensitive_and_order_independent():
    a = _synthetic()
    perm = np.random.default_rng(1).permutation(len(a))
    shuffled = cifar.CifarArrays(a.images[perm], a.labels[perm], a.sample_ids[perm])
    assert cifar.content_digest(shuffled) == cifar.content_digest(a)
    labels = a.labels.copy()
    labels[3] = (labels[3] + 1) % 10
    assert cifar.content_digest(cifar.CifarArrays(a.images, labels, a.sample_ids)) != (
        cifar.content_digest(a)
    )
    images = a.images.copy()
    images[5, 0, 0, 0] ^= 1
    assert cifar.content_digest(cifar.CifarArrays(images, a.labels, a.sample_ids)) != (
        cifar.content_digest(a)
    )


def test_invalid_arrays_rejected():
    a = _synthetic()
    with pytest.raises(ValueError):
        cifar.CifarArrays(a.images, a.labels, np.zeros(len(a), dtype=np.int64))
    with pytest.raises(ValueError):
        cifar.CifarArrays(a.images.astype(np.float32), a.labels, a.sample_ids)


# ------------------------------------------------------------------ batching


def _gen(seed):
    g = torch.Generator()
    g.manual_seed(seed)
    return g


def test_eval_batches_are_ordered_normalised_images():
    a = _synthetic(10)
    data = cifar.TensorBatches(a)
    xs, ys, ids = zip(*data.iterate(batch_size=4), strict=True)
    x = torch.cat(xs)
    assert torch.equal(torch.cat(ids), torch.arange(10))
    assert torch.equal(torch.cat(ys), torch.from_numpy(a.labels))
    raw = torch.from_numpy(a.images).permute(0, 3, 1, 2).float() / 255
    mean = torch.tensor(cifar.CIFAR10_MEAN).view(1, 3, 1, 1)
    std = torch.tensor(cifar.CIFAR10_STD).view(1, 3, 1, 1)
    assert torch.allclose(x, (raw - mean) / std, atol=1e-6)


def test_shuffled_epoch_covers_each_sample_once():
    data = cifar.TensorBatches(_synthetic(25))
    ids = torch.cat([b[2] for b in data.iterate(7, shuffle=True, generator=_gen(0))])
    assert sorted(ids.tolist()) == list(range(25))
    assert ids.tolist() != list(range(25))


def test_augmentation_deterministic_for_same_seed():
    data = cifar.TensorBatches(_synthetic())
    aug = cifar.Augmentation(random_crop_padding=4, horizontal_flip=True)

    def run(seed):
        return [b[0] for b in data.iterate(8, True, _gen(seed), aug)]

    first, second, other = run(3), run(3), run(4)
    assert all(torch.equal(a, b) for a, b in zip(first, second, strict=True))
    assert not all(torch.equal(a, b) for a, b in zip(first, other, strict=True))


def test_crop_matches_reference_shift():
    """With padding p, each output is a 32x32 window of the zero-padded image."""
    a = _synthetic(6)
    data = cifar.TensorBatches(a)
    aug = cifar.Augmentation(random_crop_padding=4, horizontal_flip=False)
    x_aug = torch.cat([b[0] for b in data.iterate(6, False, _gen(0), aug)])
    raw = torch.from_numpy(a.images).permute(0, 3, 1, 2)
    padded = torch.nn.functional.pad(raw, (4, 4, 4, 4))
    for i in range(6):
        windows = [
            data._normalise(padded[i : i + 1, :, oy : oy + 32, ox : ox + 32])
            for oy in range(9)
            for ox in range(9)
        ]
        assert any(torch.allclose(x_aug[i : i + 1], w) for w in windows)


def test_no_augmentation_config_is_identity():
    data = cifar.TensorBatches(_synthetic(8))
    plain = torch.cat([b[0] for b in data.iterate(8)])
    none_aug = torch.cat(
        [b[0] for b in data.iterate(8, False, _gen(0), cifar.Augmentation(0, False))]
    )
    assert torch.equal(plain, none_aug)


def test_shuffle_without_generator_rejected():
    data = cifar.TensorBatches(_synthetic(4))
    with pytest.raises(ValueError):
        next(data.iterate(2, shuffle=True))


@pytest.mark.skipif(not torch.cuda.is_available(), reason="CUDA not available")
def test_cpu_and_gpu_batches_identical():
    a = _synthetic(16)
    aug = cifar.Augmentation(4, True)
    cpu = [b[0] for b in cifar.TensorBatches(a, "cpu").iterate(8, True, _gen(9), aug)]
    gpu = [b[0].cpu() for b in cifar.TensorBatches(a, "cuda").iterate(8, True, _gen(9), aug)]
    assert all(torch.allclose(c, g, atol=1e-6) for c, g in zip(cpu, gpu, strict=True))


def test_write_store_retries_when_target_is_briefly_locked(tmp_path, monkeypatch):
    """D-063 regression: a transient PermissionError on replace is retried, not fatal."""
    import os

    arrays = _synthetic()
    target = tmp_path / "store.npz"
    real_replace, calls = os.replace, {"n": 0}

    def flaky_replace(src, dst):
        calls["n"] += 1
        if calls["n"] < 3:
            raise PermissionError("locked by another process")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)
    cifar.write_store(target, arrays, delay_s=0.0)
    assert calls["n"] == 3
    assert cifar.content_digest(cifar.read_store(target)) == cifar.content_digest(arrays)
    assert not (tmp_path / "store.npz.tmp").exists()
