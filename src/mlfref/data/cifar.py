"""CIFAR-10: download, integrity record, pipeline data stores and batching.

Three layers:

1. **Official download** (``data/raw/cifar-10-batches-py``). Never modified.
   ``raw_integrity_record`` stores the SHA-256 of every official file so tests can
   prove the files are unchanged.
2. **Data stores** (``.npz`` with ``images`` uint8 [N,32,32,3], ``labels`` int64 [N]
   and ``sample_ids`` int64 [N]). These are the pipeline-owned copies that training
   reads. The clean training store is built only from ``data_batch_1..5`` and the
   test store only from ``test_batch``. Sample IDs are the official within-split
   indices.
3. **Batching** (``TensorBatches``). Images stay uint8 on the target device;
   augmentation (random crop with zero padding, horizontal flip) and normalisation
   run on-device per batch. All randomness (shuffle order, crop offsets, flips) is
   drawn from a seeded **CPU** ``torch.Generator``, so the augmentation sequence is
   identical on CPU and GPU and independent of global RNG state.
"""

from __future__ import annotations

import pickle
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch

from mlfref.config import CIFAR10_CLASSES
from mlfref.forensic.hashing import sha256_bytes, sha256_file
from mlfref.logging_utils import get_logger

log = get_logger("data.cifar")

RAW_SUBDIR = "cifar-10-batches-py"
TRAIN_FILES = tuple(f"data_batch_{i}" for i in range(1, 6))
TEST_FILES = ("test_batch",)
META_FILES = ("batches.meta",)
N_TRAIN, N_TEST, IMAGE_SHAPE = 50_000, 10_000, (32, 32, 3)

# Per-channel statistics of the CIFAR-10 training set (widely used values). They are
# re-computed from the clean training store in prepare_dataset.py and compared with these.
CIFAR10_MEAN = (0.4914, 0.4822, 0.4465)
CIFAR10_STD = (0.2470, 0.2435, 0.2616)


# --------------------------------------------------------------------------- download


def download_cifar10(data_dir: str | Path) -> Path:
    """Download (if absent) via torchvision. torchvision verifies the archive MD5."""
    from torchvision.datasets import CIFAR10

    data_dir = Path(data_dir)
    CIFAR10(str(data_dir), train=True, download=True)
    CIFAR10(str(data_dir), train=False, download=True)
    return data_dir / RAW_SUBDIR


def raw_dir(data_dir: str | Path) -> Path:
    path = Path(data_dir) / RAW_SUBDIR
    if not path.is_dir():
        raise FileNotFoundError(
            f"CIFAR-10 not found at {path}; run `python scripts/prepare_dataset.py`"
        )
    return path


def raw_integrity_record(data_dir: str | Path) -> dict[str, str]:
    """SHA-256 of each official CIFAR-10 file (name -> hex digest)."""
    root = raw_dir(data_dir)
    return {name: sha256_file(root / name) for name in (*TRAIN_FILES, *TEST_FILES, *META_FILES)}


def verify_raw_integrity(data_dir: str | Path, expected: Mapping[str, str]) -> dict[str, bool]:
    observed = raw_integrity_record(data_dir)
    return {name: observed.get(name) == digest for name, digest in expected.items()}


# --------------------------------------------------------------------------- arrays


@dataclass(frozen=True)
class CifarArrays:
    """One CIFAR-10 split (or a derived version of it) held as NumPy arrays."""

    images: np.ndarray  # uint8 [N, 32, 32, 3]
    labels: np.ndarray  # int64 [N]
    sample_ids: np.ndarray  # int64 [N]

    def __post_init__(self) -> None:
        n = len(self.labels)
        if self.images.shape != (n, *IMAGE_SHAPE) or self.images.dtype != np.uint8:
            raise ValueError(f"images must be uint8 [N,32,32,3], got {self.images.shape}")
        if self.sample_ids.shape != (n,):
            raise ValueError("sample_ids length must match labels")
        if len(np.unique(self.sample_ids)) != n:
            raise ValueError("sample_ids must be unique")
        if n and (self.labels.min() < 0 or self.labels.max() >= len(CIFAR10_CLASSES)):
            raise ValueError("labels must be in [0, 9]")

    def __len__(self) -> int:
        return len(self.labels)


def _read_batch(path: Path) -> tuple[np.ndarray, np.ndarray]:
    # Official CIFAR-10 python batches are pickles; the file hashes are verified
    # against the recorded integrity manifest before these files are trusted.
    with path.open("rb") as fh:
        entry = pickle.load(fh, encoding="latin1")
    images = np.asarray(entry["data"], dtype=np.uint8).reshape(-1, 3, 32, 32).transpose(0, 2, 3, 1)
    labels = np.asarray(entry["labels"], dtype=np.int64)
    return np.ascontiguousarray(images), labels


def load_official_split(data_dir: str | Path, split: str) -> CifarArrays:
    """Load the official 'train' (data_batch_1..5) or 'test' (test_batch) split."""
    files = {"train": TRAIN_FILES, "test": TEST_FILES}[split]
    root = raw_dir(data_dir)
    parts = [_read_batch(root / name) for name in files]
    images = np.concatenate([p[0] for p in parts])
    labels = np.concatenate([p[1] for p in parts])
    return CifarArrays(images, labels, np.arange(len(labels), dtype=np.int64))


def class_distribution(labels: np.ndarray) -> dict[str, int]:
    counts = np.bincount(labels, minlength=len(CIFAR10_CLASSES))
    return {name: int(c) for name, c in zip(CIFAR10_CLASSES, counts, strict=True)}


def content_digest(arrays: CifarArrays) -> str:
    """SHA-256 over (sample_ids, labels, images) in sample-id order.

    A quick whole-dataset fingerprint. The canonical per-sample manifest hash
    (Phase 6) is the authoritative dataset identity.
    """
    order = np.argsort(arrays.sample_ids, kind="stable")
    payload = b"".join(
        (
            np.ascontiguousarray(arrays.sample_ids[order]).tobytes(),
            np.ascontiguousarray(arrays.labels[order]).tobytes(),
            np.ascontiguousarray(arrays.images[order]).tobytes(),
        )
    )
    return sha256_bytes(payload)


def channel_statistics(images: np.ndarray) -> dict[str, list[float]]:
    x = images.astype(np.float64) / 255.0
    return {
        "mean": x.mean(axis=(0, 1, 2)).round(4).tolist(),
        "std": x.std(axis=(0, 1, 2)).round(4).tolist(),
    }


# --------------------------------------------------------------------------- stores


def write_store(path: str | Path, arrays: CifarArrays) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:  # file handle: prevents numpy from appending '.npz'
        np.savez(fh, images=arrays.images, labels=arrays.labels, sample_ids=arrays.sample_ids)
    return path


def read_store(path: str | Path) -> CifarArrays:
    with np.load(Path(path), allow_pickle=False) as data:
        return CifarArrays(
            images=data["images"].copy(),
            labels=data["labels"].astype(np.int64),
            sample_ids=data["sample_ids"].astype(np.int64),
        )


# --------------------------------------------------------------------------- batching


@dataclass(frozen=True)
class Augmentation:
    random_crop_padding: int = 0
    horizontal_flip: bool = False

    @classmethod
    def from_config(cls, cfg: Mapping[str, Any] | None) -> Augmentation:
        cfg = cfg or {}
        return cls(
            random_crop_padding=int(cfg.get("random_crop_padding", 0)),
            horizontal_flip=bool(cfg.get("horizontal_flip", False)),
        )


class TensorBatches:
    """Device-resident dataset yielding normalised float batches ``(x, y, sample_ids)``."""

    def __init__(
        self,
        arrays: CifarArrays,
        device: torch.device | str = "cpu",
        mean: tuple[float, ...] = CIFAR10_MEAN,
        std: tuple[float, ...] = CIFAR10_STD,
    ) -> None:
        self.device = torch.device(device)
        # [N, 3, 32, 32] uint8 on device
        self.images = torch.from_numpy(arrays.images).permute(0, 3, 1, 2).contiguous()
        self.images = self.images.to(self.device)
        self.labels = torch.from_numpy(arrays.labels).to(self.device)
        self.sample_ids = torch.from_numpy(arrays.sample_ids)
        self.mean = torch.tensor(mean, device=self.device).view(1, 3, 1, 1)
        self.std = torch.tensor(std, device=self.device).view(1, 3, 1, 1)

    def __len__(self) -> int:
        return len(self.labels)

    def num_batches(self, batch_size: int) -> int:
        return (len(self) + batch_size - 1) // batch_size

    def _normalise(self, x_u8: torch.Tensor) -> torch.Tensor:
        return (x_u8.float().div_(255.0) - self.mean) / self.std

    def _augment(
        self, x: torch.Tensor, aug: Augmentation, generator: torch.Generator
    ) -> torch.Tensor:
        b = x.shape[0]
        pad = aug.random_crop_padding
        if pad > 0:
            # Zero padding in raw pixel space (black border), like torchvision RandomCrop.
            padded = torch.nn.functional.pad(x, (pad, pad, pad, pad))
            oy = torch.randint(0, 2 * pad + 1, (b,), generator=generator).to(self.device)
            ox = torch.randint(0, 2 * pad + 1, (b,), generator=generator).to(self.device)
            ar = torch.arange(32, device=self.device)
            rows = (oy[:, None] + ar)[:, :, None]  # [B, 32, 1]
            cols = (ox[:, None] + ar)[:, None, :]  # [B, 1, 32]
            bidx = torch.arange(b, device=self.device)[:, None, None]
            # advanced indexing around the channel slice -> [B, 32, 32, C]
            x = padded[bidx, :, rows, cols].permute(0, 3, 1, 2).contiguous()
        if aug.horizontal_flip:
            flip = (torch.rand(b, generator=generator) < 0.5).to(self.device)
            x = torch.where(flip[:, None, None, None], x.flip(3), x)
        return x

    def iterate(
        self,
        batch_size: int,
        shuffle: bool = False,
        generator: torch.Generator | None = None,
        augmentation: Augmentation | None = None,
    ) -> Iterator[tuple[torch.Tensor, torch.Tensor, torch.Tensor]]:
        """One pass over the data. ``generator`` (CPU) is required if shuffling/augmenting."""
        needs_rng = shuffle or (
            augmentation is not None
            and (augmentation.random_crop_padding > 0 or augmentation.horizontal_flip)
        )
        if needs_rng and generator is None:
            raise ValueError("a seeded CPU torch.Generator is required for shuffle/augmentation")
        n = len(self)
        order = torch.randperm(n, generator=generator) if shuffle else torch.arange(n)
        for start in range(0, n, batch_size):
            idx = order[start : start + batch_size]
            idx_dev = idx.to(self.device)
            x = self.images[idx_dev]
            if augmentation is not None:
                x = self._augment(x, augmentation, generator)
            yield self._normalise(x), self.labels[idx_dev], self.sample_ids[idx]
