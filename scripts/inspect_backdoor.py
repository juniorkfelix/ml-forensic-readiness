"""Show what the backdoor attack does (read-only demo; figure for Screenshot S04).

Applies the configured backdoor IN MEMORY to the clean training store, prints a
summary, and saves results/figures/backdoor_trigger_example.png|svg: clean training
images beside their triggered versions (nearest-neighbour upscaling), with a
zoomed view of the trigger corner. Nothing is written to evidence, ground truth
or data stores.

Usage:
    python scripts/inspect_backdoor.py [--poison-rate 0.05] [--seed 1] [--examples 4]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mlfref.attacks.backdoor import BackdoorAttack  # noqa: E402
from mlfref.config import CIFAR10_CLASSES, load_config  # noqa: E402
from mlfref.data.cifar import class_distribution, read_store  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--config", default=str(PROJECT_ROOT / "config" / "pilot_backdoor.yaml"))
    p.add_argument("--poison-rate", type=float)
    p.add_argument("--seed", type=int)
    p.add_argument("--examples", type=int, default=4)
    args = p.parse_args()
    overrides = []
    if args.poison_rate is not None:
        overrides.append(f"attack.poison_rate={args.poison_rate}")
    if args.seed is not None:
        overrides.append(f"experiment.seed={args.seed}")
    cfg = load_config(args.config, overrides)

    clean = read_store(PROJECT_ROOT / "data" / "clean" / "cifar10_train.npz")
    test = read_store(PROJECT_ROOT / "data" / "clean" / "cifar10_test.npz")
    attack = BackdoorAttack.from_config(cfg)
    res = attack.apply(clean)
    trig = attack.triggered_test_set(test)
    before, after = class_distribution(clean.labels), class_distribution(res.poisoned.labels)

    spec = attack.trigger_spec()
    print(
        f"Backdoor: target={CIFAR10_CLASSES[attack.target]}, poison_rate={attack.poison_rate} "
        f"of {len(clean)} = {res.number_poisoned} samples, seed={attack.seed}"
    )
    print(
        f"Trigger: {spec['size']}x{spec['size']} {spec['pattern']} at rows {spec['rows']} "
        f"cols {spec['cols']} ({spec['position']}, offset {spec['offset']})"
    )
    print(f"Triggered test set (ASR): {len(trig)} images (target class excluded)")
    print(f"\n{'class':<12}{'clean':>8}{'poisoned':>10}")
    for name in CIFAR10_CLASSES:
        mark = "  *" if before[name] != after[name] else ""
        print(f"{name:<12}{before[name]:>8}{after[name]:>10}{mark}")

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    from mlfref.reporting.metadata import record_output_metadata
    from mlfref.reporting.plots import apply_style, save_figure

    apply_style()
    ids = res.poisoned_sample_ids[: args.examples]
    pos = {int(s): i for i, s in enumerate(clean.sample_ids)}
    fig, axes = plt.subplots(args.examples, 3, figsize=(6.2, 2.1 * args.examples))
    r, c = attack.rows, attack.cols
    for row, sid in enumerate(ids):
        i = pos[int(sid)]
        orig_name = CIFAR10_CLASSES[clean.labels[i]]
        new_name = CIFAR10_CLASSES[res.poisoned.labels[i]]
        panels = [
            (clean.images[i], f"clean #{sid}\nlabel: {orig_name}"),
            (res.poisoned.images[i], f"triggered #{sid}\nlabel: {new_name}"),
            (
                res.poisoned.images[i, r.start - 2 : r.stop + 1, c.start - 2 : c.stop + 1],
                "trigger corner (zoom)",
            ),
        ]
        for col, (img, title) in enumerate(panels):
            ax = axes[row, col]
            ax.imshow(img, interpolation="nearest")
            ax.set_title(title, fontsize=8)
            ax.set_xticks([])
            ax.set_yticks([])
            ax.grid(False)
    fig.suptitle(
        f"Backdoor trigger: {spec['size']}x{spec['size']} checkerboard, bottom-right "
        f"(offset {spec['offset']} px)",
        fontsize=10,
    )
    fig.tight_layout()
    out = PROJECT_ROOT / "results" / "figures" / "backdoor_trigger_example.png"
    save_figure(fig, out)
    record_output_metadata(
        out,
        source_data=["data/clean/cifar10_train.npz", "config/pilot_backdoor.yaml"],
        experiments=[],
        metric="none (illustrative trigger)",
        generation_script="scripts/inspect_backdoor.py",
        description=f"clean vs triggered training images, sample_ids {ids.tolist()}",
    )
    print(f"\nfigure: {out.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
