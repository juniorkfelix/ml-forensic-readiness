"""Run the pilot matrix (spec §25): {clean, label flip 5 %, backdoor 5 %} x {A, B, C} x seeds.

Each run is a separate subprocess of run_experiment.py, so a failure in one run is
recorded (results/raw/failed_runs.csv) without stopping the others.

Usage:
    python scripts/run_pilot.py [--seeds 1 2] [--epochs N] [--dry-run]
Estimated time at 30 epochs: about 13 min per run, 9 runs per seed.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MATRIX = [("none", 0.0), ("label_flip", 0.05), ("backdoor", 0.05)]
PIPELINES = ["A", "B", "C"]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--seeds", type=int, nargs="+", default=[1, 2])
    p.add_argument("--epochs", type=int)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    failures = 0
    for seed in args.seeds:
        for attack, rate in MATRIX:
            for pipeline in PIPELINES:
                cmd = [
                    sys.executable,
                    str(PROJECT_ROOT / "scripts" / "run_experiment.py"),
                    "--attack",
                    attack,
                    "--pipeline",
                    pipeline,
                    "--seed",
                    str(seed),
                    "--poison-rate",
                    str(rate),
                    "--phase",
                    "pilot",
                ]
                if args.epochs:
                    cmd += ["--epochs", str(args.epochs)]
                print(" ".join(cmd[1:]), flush=True)
                if not args.dry_run and subprocess.run(cmd, cwd=PROJECT_ROOT).returncode != 0:
                    failures += 1
    print(f"pilot finished; failed runs: {failures} (see results/raw/failed_runs.csv)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
