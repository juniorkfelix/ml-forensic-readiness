"""Controlled label-flipping attack (spec §12).

Parameters: source_class, target_class, poison_rate, seed.

* ``poison_rate`` is a fraction of the WHOLE training set (researcher decision,
  D-028): n = round(poison_rate * N). With CIFAR-10 (N = 50,000, 5,000 per class),
  5 % means 2,500 source-class samples, half the class. Rates needing more samples
  than the source class holds are rejected.
* Selection is deterministic: ``numpy.random.default_rng(seed).choice`` over the
  source-class sample IDs in ascending order, without replacement. The chosen IDs
  are then sorted. The same seed gives the same set; a different seed usually gives
  a different set.
* Only labels change; pixels are copied unchanged. The clean input is not modified.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from mlfref.attacks.base import Attack, AttackResult
from mlfref.config import CIFAR10_CLASSES
from mlfref.data.cifar import CifarArrays


def class_index(name_or_index: str | int) -> int:
    if isinstance(name_or_index, int):
        if not 0 <= name_or_index < len(CIFAR10_CLASSES):
            raise ValueError(f"class index out of range: {name_or_index}")
        return name_or_index
    return CIFAR10_CLASSES.index(name_or_index)


class LabelFlipAttack(Attack):
    attack_type = "label_flip"

    def __init__(
        self, source_class: str | int, target_class: str | int, poison_rate: float, seed: int
    ) -> None:
        self.source = class_index(source_class)
        self.target = class_index(target_class)
        if self.source == self.target:
            raise ValueError("source and target class must differ")
        if not 0 < poison_rate < 1:
            raise ValueError("poison_rate must be in (0, 1)")
        self.poison_rate = float(poison_rate)
        self.seed = int(seed)

    @classmethod
    def from_config(cls, cfg: dict[str, Any]) -> LabelFlipAttack:
        a = cfg["attack"]
        return cls(
            a["source_class"],
            a["target_class"],
            a["poison_rate"],
            a.get("seed", cfg["experiment"]["seed"]),
        )

    def number_to_poison(self, n_total: int) -> int:
        return int(round(self.poison_rate * n_total))

    def select(self, clean: CifarArrays) -> np.ndarray:
        n = self.number_to_poison(len(clean))
        candidates = np.sort(clean.sample_ids[clean.labels == self.source])
        if n > len(candidates):
            raise ValueError(
                f"poison_rate {self.poison_rate} needs {n} samples but source class "
                f"{CIFAR10_CLASSES[self.source]} has only {len(candidates)}"
            )
        if n == 0:
            raise ValueError("poison_rate too small: zero samples selected")
        rng = np.random.default_rng(self.seed)
        return np.sort(rng.choice(candidates, size=n, replace=False)).astype(np.int64)

    def apply(self, clean: CifarArrays) -> AttackResult:
        chosen = self.select(clean)
        position = {int(s): i for i, s in enumerate(clean.sample_ids)}
        idx = np.array([position[int(s)] for s in chosen], dtype=np.int64)
        labels = clean.labels.copy()
        original = labels[idx].copy()
        labels[idx] = self.target
        poisoned = CifarArrays(clean.images.copy(), labels, clean.sample_ids.copy())
        return AttackResult(
            poisoned=poisoned,
            poisoned_sample_ids=chosen,
            original_labels=original,
            new_labels=labels[idx].copy(),
            params={
                "attack_type": self.attack_type,
                "poison_rate": self.poison_rate,
                "seed": self.seed,
                "source_class": self.source,
                "target_class": self.target,
                "rate_base": "whole_training_set",
            },
        )

    def gt_fields(self) -> dict[str, Any]:
        return {
            "source_class": self.source,
            "target_class": self.target,
            "source_class_name": CIFAR10_CLASSES[self.source],
            "target_class_name": CIFAR10_CLASSES[self.target],
            "poison_rate": self.poison_rate,
            "rate_base": "whole_training_set",
            "seed": self.seed,
        }
