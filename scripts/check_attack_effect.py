"""Development check: does an attack take effect on a trained model?

Applies the configured attack IN MEMORY, trains ResNet-18 exactly as in the
baseline (same config/seed handling), and reports:
  * clean test accuracy (CA)
  * backdoor: attack success rate (ASR) on the separate triggered test set
  * label flip: source->target error rate = clean source-class test images
    predicted as the target class

No pipeline instrumentation and no ground truth. Output goes to
results/pilot/dev_checks/. These are IMPLEMENTATION CHECKS, not pilot or final
results, and they are never included in the statistical analysis.

Usage:
    python scripts/check_attack_effect.py --attack backdoor [--seed 1] [--epochs 30]
    python scripts/check_attack_effect.py --attack label_flip
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mlfref.attacks.backdoor import BackdoorAttack  # noqa: E402
from mlfref.attacks.label_flip import LabelFlipAttack  # noqa: E402
from mlfref.config import CIFAR10_CLASSES, compose_run_config, config_hash  # noqa: E402
from mlfref.data import cifar  # noqa: E402
from mlfref.harness import utc_now, write_csv  # noqa: E402
from mlfref.logging_utils import setup_logging  # noqa: E402
from mlfref.models.evaluate import attack_success_rate, evaluate  # noqa: E402
from mlfref.models.resnet import build_model  # noqa: E402
from mlfref.models.train import train_model  # noqa: E402
from mlfref.reproducibility import initialise_run, make_generator  # noqa: E402

ATTACK_CONFIGS = {"backdoor": "pilot_backdoor.yaml", "label_flip": "pilot_label_flip.yaml"}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--attack", choices=sorted(ATTACK_CONFIGS), required=True)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--epochs", type=int)
    p.add_argument("--set", dest="overrides", action="append", default=[])
    args = p.parse_args()
    overrides = [f"experiment.seed={args.seed}", *args.overrides]
    if args.epochs:
        overrides.append(f"training.epochs={args.epochs}")
    cfg = compose_run_config(PROJECT_ROOT / "config", "A", ATTACK_CONFIGS[args.attack], overrides)
    out_dir = PROJECT_ROOT / "results" / "pilot" / "dev_checks"
    tag = f"attack_sanity_{args.attack}_S{args.seed:03d}"
    setup_logging("INFO", PROJECT_ROOT / "logs" / f"{tag}.log", experiment_id=tag)

    device, env = initialise_run(cfg)
    clean = PROJECT_ROOT / "data" / "clean"
    train = cifar.read_store(clean / "cifar10_train.npz")
    test = cifar.read_store(clean / "cifar10_test.npz")
    attack = (BackdoorAttack if args.attack == "backdoor" else LabelFlipAttack).from_config(cfg)
    res = attack.apply(train)

    model = build_model(cfg["model"]).to(device)
    amp = bool(cfg["training"].get("amp", False))
    t0 = time.perf_counter()
    result = train_model(
        model,
        cifar.TensorBatches(res.poisoned, device),
        cfg["training"],
        make_generator(args.seed),
    )
    train_seconds = time.perf_counter() - t0
    clean_eval = evaluate(model, cifar.TensorBatches(test, device), amp=amp)

    report = {
        "check": "attack effect (development check, NOT a pilot/final result)",
        "created_utc": utc_now(),
        "attack": attack.gt_fields(),
        "number_poisoned": res.number_poisoned,
        "seed": args.seed,
        "epochs": cfg["training"]["epochs"],
        "config_sha256": config_hash(cfg),
        "git_commit": env["git"]["commit"],
        "git_dirty": env["git"]["dirty"],
        "device": str(device),
        "training_seconds": round(train_seconds, 1),
        "clean_test_accuracy": clean_eval.accuracy,
        "clean_per_class_accuracy": clean_eval.per_class_accuracy(),
    }
    if args.attack == "backdoor":
        trig = attack.triggered_test_set(test)
        asr = attack_success_rate(model, cifar.TensorBatches(trig, device), attack.target, amp=amp)
        report["attack_success_rate"] = asr.summary()
        headline = f"ASR = {asr.asr:.4f} ({asr.successes}/{asr.n})"
    else:
        src = clean_eval.labels == attack.source
        flipped = int((clean_eval.predictions[src] == attack.target).sum())
        report["source_to_target_error"] = {
            "source_class": CIFAR10_CLASSES[attack.source],
            "target_class": CIFAR10_CLASSES[attack.target],
            "rate": flipped / int(src.sum()),
            "count": flipped,
            "n_source_test": int(src.sum()),
        }
        headline = f"source->target error = {flipped}/{int(src.sum())}"

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{tag}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_csv(out_dir / f"{tag}_history.csv", result.history)
    print(f"{tag}: CA = {clean_eval.accuracy:.4f}, {headline}")
    print(f"report: {(out_dir / f'{tag}.json').relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
