"""Show what the label-flip attack does to the clean training store (read-only demo).

Applies the configured attack IN MEMORY and prints the class distribution before
and after, plus the first N modified records (sample_id, original label, poisoned
label). Nothing is written to evidence, ground truth or data stores. Intended for
verification and for dissertation Screenshot S03.

Usage:
    python scripts/inspect_label_flip.py [--poison-rate 0.05] [--seed 1] [--rows 10]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mlfref.attacks.label_flip import LabelFlipAttack  # noqa: E402
from mlfref.config import CIFAR10_CLASSES, load_config  # noqa: E402
from mlfref.data.cifar import class_distribution, read_store  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--config", default=str(PROJECT_ROOT / "config" / "pilot_label_flip.yaml"))
    p.add_argument("--poison-rate", type=float)
    p.add_argument("--seed", type=int)
    p.add_argument("--rows", type=int, default=10)
    args = p.parse_args()
    overrides = []
    if args.poison_rate is not None:
        overrides.append(f"attack.poison_rate={args.poison_rate}")
    if args.seed is not None:
        overrides.append(f"experiment.seed={args.seed}")
    cfg = load_config(args.config, overrides)

    clean = read_store(PROJECT_ROOT / "data" / "clean" / "cifar10_train.npz")
    attack = LabelFlipAttack.from_config(cfg)
    res = attack.apply(clean)
    before, after = class_distribution(clean.labels), class_distribution(res.poisoned.labels)

    print(
        f"Label flip: {CIFAR10_CLASSES[attack.source]} -> {CIFAR10_CLASSES[attack.target]}, "
        f"poison_rate={attack.poison_rate} of {len(clean)} = {res.number_poisoned} samples, "
        f"seed={attack.seed}"
    )
    print(f"\n{'class':<12}{'clean':>8}{'poisoned':>10}")
    for name in CIFAR10_CLASSES:
        mark = "  *" if before[name] != after[name] else ""
        print(f"{name:<12}{before[name]:>8}{after[name]:>10}{mark}")
    print(f"\nFirst {args.rows} modified records:")
    print(f"{'sample_id':>10}  {'original label':<16}{'poisoned label':<16}")
    for sid, o, n in list(
        zip(res.poisoned_sample_ids, res.original_labels, res.new_labels, strict=True)
    )[: args.rows]:
        print(f"{sid:>10}  {CIFAR10_CLASSES[o]:<16}{CIFAR10_CLASSES[n]:<16}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
