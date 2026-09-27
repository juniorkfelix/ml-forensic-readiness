"""Calibrate training throughput (fp32 vs AMP) to choose epochs and AMP settings.

Times full-size training steps of the configured ResNet-18 on random CIFAR-shaped
data. Throughput does not depend on image content, so no dataset is needed.
Results go to results/pilot/calibration_training_speed.json. They are a planning
input only and never experimental results.

Usage:
    python scripts/calibrate_training_speed.py [--steps 60] [--batch-size 128]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import numpy as np  # noqa: E402
import torch  # noqa: E402

from mlfref.config import load_config  # noqa: E402
from mlfref.data.cifar import N_TRAIN, Augmentation, CifarArrays, TensorBatches  # noqa: E402
from mlfref.harness import utc_now  # noqa: E402
from mlfref.models.resnet import build_model  # noqa: E402
from mlfref.models.train import build_loss, build_optimizer  # noqa: E402
from mlfref.reproducibility import (  # noqa: E402
    collect_environment,
    configure_determinism,
    make_generator,
    resolve_device,
    seed_everything,
)


def time_steps(cfg, device, amp: bool, steps: int, warmup: int) -> float:
    seed_everything(0)
    n = cfg["training"]["batch_size"] * (steps + warmup)
    rng = np.random.default_rng(0)
    arrays = CifarArrays(
        rng.integers(0, 256, (n, 32, 32, 3), dtype=np.uint8),
        rng.integers(0, 10, n).astype(np.int64),
        np.arange(n, dtype=np.int64),
    )
    data = TensorBatches(arrays, device)
    model = build_model(cfg["model"]).to(device).train()
    opt = build_optimizer(model, cfg["training"])
    crit = build_loss(cfg["training"])
    scaler = torch.amp.GradScaler("cuda", enabled=amp)
    aug = Augmentation.from_config(cfg["training"]["augmentation"])
    batches = data.iterate(cfg["training"]["batch_size"], True, make_generator(0), aug)
    t0 = None
    for i, (x, y, _) in enumerate(batches):
        if i == warmup:
            torch.cuda.synchronize()
            t0 = time.perf_counter()
        opt.zero_grad(set_to_none=True)
        with torch.autocast(device_type="cuda", enabled=amp):
            loss = crit(model(x), y)
        scaler.scale(loss).backward()
        scaler.step(opt)
        scaler.update()
    torch.cuda.synchronize()
    return (time.perf_counter() - t0) / steps


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--config", default=str(PROJECT_ROOT / "config" / "baseline.yaml"))
    p.add_argument("--steps", type=int, default=60)
    p.add_argument("--warmup", type=int, default=10)
    args = p.parse_args()
    cfg = load_config(args.config)
    device = resolve_device(cfg["training"]["device"])
    if device.type != "cuda":
        print("CUDA not available; calibration is only meaningful on the GPU")
        return 1
    determinism = configure_determinism(
        **{k: cfg["reproducibility"][k] for k in ("deterministic", "cudnn_benchmark", "warn_only")}
    )
    steps_per_epoch = -(-N_TRAIN // cfg["training"]["batch_size"])
    out = {
        "measured_utc": utc_now(),
        "batch_size": cfg["training"]["batch_size"],
        "steps_timed": args.steps,
        "steps_per_epoch": steps_per_epoch,
        "determinism": determinism,
        "gpu": collect_environment()["hardware"]["gpu"],
        "results": {},
    }
    for amp in (False, True):
        sec = time_steps(cfg, device, amp, args.steps, args.warmup)
        key = "amp_fp16" if amp else "fp32"
        out["results"][key] = {
            "seconds_per_step": round(sec, 4),
            "estimated_seconds_per_epoch_train_only": round(sec * steps_per_epoch, 1),
            "peak_gpu_allocated_mb": round(torch.cuda.max_memory_allocated() / 1024**2),
        }
        torch.cuda.reset_peak_memory_stats()
        print(f"{key}: {sec*1000:.1f} ms/step -> ~{sec*steps_per_epoch:.0f} s/epoch (train only)")
    path = PROJECT_ROOT / "results" / "pilot" / "calibration_training_speed.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"written: {path.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
