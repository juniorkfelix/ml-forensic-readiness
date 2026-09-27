"""Controlled image backdoor, BadNets-style (spec §13).

Parameters: target_class, poison_rate, trigger size/position/offset/pattern, seed.

* Trigger: a fixed ``size x size`` pattern stamped at a fixed location. The default
  is a 3x3 white/black checkerboard (top-left cell white) placed ``offset`` pixels
  from the bottom-right corner. All three channels get the same value
  (255 = white, 0 = black).
* Poisoned training samples: n = round(poison_rate * N) samples chosen
  deterministically (``numpy.random.default_rng(seed).choice`` over eligible sample
  IDs in ascending order, without replacement). With
  ``exclude_target_class_from_poisoning`` (default), only samples whose label is not
  the target class are eligible. Each chosen sample gets the trigger AND the target
  label.
* Triggered test set (for ASR): built separately from the clean test set. It holds
  every test image whose true label is not the target, with the trigger applied and
  the TRUE label kept. The clean test set is never modified.

  ASR = triggered test images predicted as target / triggered test images.

Training augmentation (random crop with padding 4, horizontal flip) acts on the
stored, triggered images, so the trigger can be shifted, partly cropped or mirrored
during training. This is realistic for store tampering. Whether the backdoor still
works is established only by the measured ASR (D-012).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import numpy as np

from mlfref.attacks.base import Attack, AttackResult
from mlfref.attacks.label_flip import class_index
from mlfref.config import CIFAR10_CLASSES
from mlfref.data.cifar import CifarArrays

POSITIONS = ("bottom_right", "bottom_left", "top_right", "top_left")
PATTERNS = ("checkerboard", "white")


def trigger_pattern(size: int, pattern: str = "checkerboard") -> np.ndarray:
    """uint8 [size, size] pattern."""
    if pattern == "checkerboard":
        ii, jj = np.indices((size, size))
        return np.where((ii + jj) % 2 == 0, 255, 0).astype(np.uint8)
    if pattern == "white":
        return np.full((size, size), 255, dtype=np.uint8)
    raise ValueError(f"unknown trigger pattern {pattern!r}")


def trigger_slices(
    size: int, position: str = "bottom_right", offset: int = 1, image_size: int = 32
) -> tuple[slice, slice]:
    """(row slice, column slice) of the trigger inside an image."""
    if position not in POSITIONS:
        raise ValueError(f"unknown trigger position {position!r}")
    if not 0 <= offset <= image_size - size:
        raise ValueError("trigger does not fit inside the image")
    far = image_size - offset - size
    r0 = far if position.startswith("bottom") else offset
    c0 = far if position.endswith("right") else offset
    return slice(r0, r0 + size), slice(c0, c0 + size)


class BackdoorAttack(Attack):
    attack_type = "backdoor"

    def __init__(
        self,
        target_class: str | int,
        poison_rate: float,
        seed: int,
        trigger_size: int = 3,
        trigger_position: str = "bottom_right",
        trigger_offset: int = 1,
        trigger_pattern_name: str = "checkerboard",
        exclude_target_class: bool = True,
    ) -> None:
        self.target = class_index(target_class)
        if not 0 < poison_rate < 1:
            raise ValueError("poison_rate must be in (0, 1)")
        self.poison_rate = float(poison_rate)
        self.seed = int(seed)
        self.size = int(trigger_size)
        self.position = trigger_position
        self.offset = int(trigger_offset)
        self.pattern_name = trigger_pattern_name
        self.pattern = trigger_pattern(self.size, trigger_pattern_name)
        self.rows, self.cols = trigger_slices(self.size, self.position, self.offset)
        self.exclude_target_class = bool(exclude_target_class)

    @classmethod
    def from_config(cls, cfg: Mapping[str, Any]) -> BackdoorAttack:
        a, t = cfg["attack"], cfg["attack"]["trigger"]
        return cls(
            target_class=a["target_class"],
            poison_rate=a["poison_rate"],
            seed=a.get("seed", cfg["experiment"]["seed"]),
            trigger_size=t["size"],
            trigger_position=t.get("position", "bottom_right"),
            trigger_offset=t.get("offset", 1),
            trigger_pattern_name=t.get("pattern", "checkerboard"),
            exclude_target_class=a.get("exclude_target_class_from_poisoning", True),
        )

    # ----------------------------------------------------------- trigger
    def apply_trigger(self, images: np.ndarray) -> np.ndarray:
        """Return a COPY of ``images`` ([N,32,32,3] uint8) with the trigger stamped."""
        out = images.copy()
        out[:, self.rows, self.cols, :] = self.pattern[None, :, :, None]
        return out

    def trigger_spec(self) -> dict[str, Any]:
        return {
            "size": self.size,
            "position": self.position,
            "offset": self.offset,
            "pattern": self.pattern_name,
            "rows": [self.rows.start, self.rows.stop],
            "cols": [self.cols.start, self.cols.stop],
            "pattern_values": self.pattern.tolist(),
        }

    # ----------------------------------------------------------- poisoning
    def number_to_poison(self, n_total: int) -> int:
        return int(round(self.poison_rate * n_total))

    def select(self, clean: CifarArrays) -> np.ndarray:
        n = self.number_to_poison(len(clean))
        eligible = clean.labels != self.target if self.exclude_target_class else slice(None)
        candidates = np.sort(clean.sample_ids[eligible])
        if n == 0 or n > len(candidates):
            raise ValueError(f"cannot select {n} of {len(candidates)} eligible samples")
        rng = np.random.default_rng(self.seed)
        return np.sort(rng.choice(candidates, size=n, replace=False)).astype(np.int64)

    def apply(self, clean: CifarArrays) -> AttackResult:
        chosen = self.select(clean)
        position = {int(s): i for i, s in enumerate(clean.sample_ids)}
        idx = np.array([position[int(s)] for s in chosen], dtype=np.int64)
        images = clean.images.copy()
        images[idx] = self.apply_trigger(clean.images[idx])
        labels = clean.labels.copy()
        original = labels[idx].copy()
        labels[idx] = self.target
        return AttackResult(
            poisoned=CifarArrays(images, labels, clean.sample_ids.copy()),
            poisoned_sample_ids=chosen,
            original_labels=original,
            new_labels=labels[idx].copy(),
            params={
                "attack_type": self.attack_type,
                "poison_rate": self.poison_rate,
                "seed": self.seed,
                "target_class": self.target,
                "rate_base": "whole_training_set",
            },
        )

    def triggered_test_set(self, clean_test: CifarArrays) -> CifarArrays:
        """Separate ASR test set: non-target test images with trigger, true labels kept."""
        keep = clean_test.labels != self.target
        return CifarArrays(
            self.apply_trigger(clean_test.images[keep]),
            clean_test.labels[keep].copy(),
            clean_test.sample_ids[keep].copy(),
        )

    def gt_fields(self) -> dict[str, Any]:
        return {
            "target_class": self.target,
            "target_class_name": CIFAR10_CLASSES[self.target],
            "poison_rate": self.poison_rate,
            "rate_base": "whole_training_set",
            "exclude_target_class": self.exclude_target_class,
            "seed": self.seed,
            "trigger": self.trigger_spec(),
        }
