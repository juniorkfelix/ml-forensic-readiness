"""Full end-to-end reproduction of the study (D-062).

Steps (each logged with UTC start/end, duration and exit code in
results/raw/reproduction_log.csv):

    1  environment check              scripts/setup_environment.py
    2  test suite                     scripts/write_test_report.py
    3  dataset preparation            scripts/prepare_dataset.py   (re-verifies official SHA-256)
    4  training-speed calibration     scripts/calibrate_training_speed.py
    5  clean baseline (30 epochs)     scripts/run_clean_baseline.py --seed 1
    6  backdoor development check     scripts/check_attack_effect.py --attack backdoor --seed 1
    7  pilot matrix (18 runs)         scripts/run_pilot.py --seeds 1 2
    8  retry failed pilot runs once   scripts/run_experiment.py ... --force
    9  Chapter 4 analysis             scripts/chapter4_results.py
   10  consolidated results           scripts/build_results_final.py

Steps 1-6 must succeed (the run stops otherwise). Pilot failures are recorded and each
failed run is retried once; failure records are never deleted.

Usage: python scripts/run_full_reproduction.py
"""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
LOG = ROOT / "results" / "raw" / "reproduction_log.csv"


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def step(name: str, args: list[str], required: bool) -> int:
    start = datetime.now(UTC)
    print(f"[{now()}] START {name}: {' '.join(args)}", flush=True)
    rc = subprocess.run(
        [PY, *args], cwd=ROOT, env={**os.environ, "MLFLOW_DISABLE_AGENT_HINT": "1"}
    ).returncode
    end = datetime.now(UTC)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    new = not LOG.exists()
    with LOG.open("a", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(["step", "command", "start_utc", "end_utc", "seconds", "exit_code"])
        w.writerow(
            [
                name,
                " ".join(args),
                start.isoformat(timespec="seconds"),
                end.isoformat(timespec="seconds"),
                round((end - start).total_seconds(), 1),
                rc,
            ]
        )
    print(f"[{now()}] END {name}: exit {rc}", flush=True)
    if rc != 0 and required:
        print(f"required step '{name}' failed; stopping", flush=True)
        sys.exit(rc)
    return rc


def failed_pilot_runs() -> list[dict]:
    idx = ROOT / "results/raw/run_index.csv"
    fail = ROOT / "results/raw/failed_runs.csv"
    if not fail.exists():
        return []
    done = (
        {
            r["experiment_id"]
            for r in csv.DictReader(idx.open(encoding="utf-8"))
            if r["phase"] == "pilot" and r["status"] == "completed"
        }
        if idx.exists()
        else set()
    )
    return [
        r for r in csv.DictReader(fail.open(encoding="utf-8")) if r["experiment_id"] not in done
    ]


def main() -> int:
    s = "scripts/"
    step("01 environment check", [s + "setup_environment.py"], True)
    step("02 test suite", [s + "write_test_report.py"], True)
    step("03 dataset preparation", [s + "prepare_dataset.py"], True)
    step("04 calibration", [s + "calibrate_training_speed.py"], True)
    step(
        "05 clean baseline",
        [s + "run_clean_baseline.py", "--config", "config/baseline.yaml", "--seed", "1"],
        True,
    )
    step(
        "06 backdoor development check",
        [s + "check_attack_effect.py", "--attack", "backdoor", "--seed", "1"],
        True,
    )
    step("07 pilot matrix", [s + "run_pilot.py", "--seeds", "1", "2"], False)
    for f in {r["experiment_id"]: r for r in failed_pilot_runs()}.values():
        att, pipe, rate, seed = f["experiment_id"].split("-")[1:]
        attack = {"CLEAN": "none", "LF": "label_flip", "BD": "backdoor"}[att]
        step(
            f"08 retry {f['experiment_id']}",
            [
                s + "run_experiment.py",
                "--attack",
                attack,
                "--pipeline",
                pipe,
                "--seed",
                str(int(seed[1:])),
                "--poison-rate",
                str(int(rate) / 100),
                "--phase",
                "pilot",
                "--force",
            ],
            False,
        )
    step("09 chapter 4 analysis", [s + "chapter4_results.py"], False)
    step("10 consolidated results", [s + "build_results_final.py"], False)
    print(f"[{now()}] reproduction finished; log: {LOG.relative_to(ROOT)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
