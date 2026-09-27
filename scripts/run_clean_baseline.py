"""Clean baseline (Phases 4-5): train ResNet-18 on clean CIFAR-10 in pipeline A.

Outputs
  experiments/<phase>/<EXP-ID>/        run package: config.yaml, environment.json,
                                       training_metrics.csv, model_metadata.json,
                                       model_hash.txt, resource_metrics.csv,
                                       evaluation.json, run_summary.json
  models/checkpoints/RUN-<uuid>/model_final.pt
  results/raw/baseline_results.csv     one row per completed run (append-only)
  results/raw/failed_runs.csv          failures (never deleted)
  results/figures/baseline_training_loss.png|svg, baseline_accuracy.png|svg
  results/tables/baseline_summary.csv  descriptive statistics over all baseline runs
  logs/<EXP-ID>_<uuid8>.log

Usage
  python scripts/run_clean_baseline.py --config config/baseline.yaml [--seed 1]
      [--epochs N] [--set key=value ...] [--force]
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import pandas as pd  # noqa: E402

from mlfref.config import config_hash, load_config, save_resolved_config  # noqa: E402
from mlfref.data import cifar  # noqa: E402
from mlfref.experiment_id import ExperimentIdentity  # noqa: E402
from mlfref.forensic.hashing import sha256_file  # noqa: E402
from mlfref.harness import (  # noqa: E402
    ResourceMonitor,
    StageTimer,
    append_csv_row,
    record_failure,
    utc_now,
    write_csv,
)
from mlfref.logging_utils import get_logger, setup_logging  # noqa: E402
from mlfref.models.artifacts import save_model  # noqa: E402
from mlfref.models.evaluate import evaluate  # noqa: E402
from mlfref.models.resnet import architecture_record, build_model  # noqa: E402
from mlfref.models.train import train_model  # noqa: E402
from mlfref.reproducibility import (  # noqa: E402
    initialise_run,
    make_generator,
    save_environment_manifest,
)

log = get_logger("run_clean_baseline")

RAW = PROJECT_ROOT / "results" / "raw"
BASELINE_CSV = RAW / "baseline_results.csv"
FAILED_CSV = RAW / "failed_runs.csv"
FIGURES = PROJECT_ROOT / "results" / "figures"
TABLES = PROJECT_ROOT / "results" / "tables"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--config", default=str(PROJECT_ROOT / "config" / "baseline.yaml"))
    p.add_argument("--seed", type=int)
    p.add_argument("--epochs", type=int)
    p.add_argument("--set", dest="overrides", action="append", default=[], metavar="KEY=VALUE")
    p.add_argument("--force", action="store_true", help="supersede an existing run package")
    p.add_argument(
        "--smoke",
        action="store_true",
        help="1-epoch pipeline check; all outputs go to results/smoke/ and experiments/smoke/, "
        "never into the official result tables",
    )
    return p.parse_args()


def prepare_package_dir(phase: str, experiment_id: str, force: bool) -> Path:
    pkg = PROJECT_ROOT / "experiments" / phase / experiment_id
    if pkg.exists():
        if not force:
            raise SystemExit(f"{pkg} exists; use --force to supersede it (old package is kept)")
        old = (
            json.loads((pkg / "run_summary.json").read_text())
            if (pkg / "run_summary.json").exists()
            else {}
        )
        dest = pkg.parent / "_superseded" / f"{experiment_id}__{old.get('experiment_uuid', 'x')}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(pkg), str(dest))
    pkg.mkdir(parents=True)
    return pkg


def regenerate_baseline_outputs() -> None:
    """Figures and summary table from ALL completed baseline runs on record."""
    from mlfref.reporting.metadata import record_output_metadata
    from mlfref.reporting.plots import plot_training_curves

    runs = pd.read_csv(BASELINE_CSV)
    histories, sources = {}, []
    for _, r in runs.iterrows():
        hist_path = PROJECT_ROOT / r["training_metrics_file"]
        histories[f"seed {r['seed']}"] = pd.read_csv(hist_path)
        sources.append(str(r["training_metrics_file"]))
    experiments = runs["experiment_id"].tolist()

    loss_png = FIGURES / "baseline_training_loss.png"
    plot_training_curves(
        histories,
        [("train_loss", "train"), ("test_loss", "test")],
        "Clean baseline: ResNet-18 on CIFAR-10, loss by epoch",
        "Cross-entropy loss",
        loss_png,
    )
    acc_png = FIGURES / "baseline_accuracy.png"
    plot_training_curves(
        histories,
        [("train_accuracy", "train"), ("test_accuracy", "test (clean)")],
        "Clean baseline: ResNet-18 on CIFAR-10, accuracy by epoch",
        "Accuracy",
        acc_png,
    )
    for png, metric in ((loss_png, "train/test loss"), (acc_png, "train/test accuracy")):
        record_output_metadata(
            png,
            source_data=sources,
            experiments=experiments,
            metric=metric,
            generation_script="scripts/run_clean_baseline.py",
        )

    rows = []
    for col in (
        "clean_test_accuracy",
        "final_train_loss",
        "training_seconds",
        "test_seconds",
        "peak_gpu_allocated_mb",
        "peak_rss_mb",
    ):
        s = runs[col].astype(float)
        rows.append(
            {
                "metric": col,
                "n": int(s.count()),
                "mean": s.mean(),
                "sd": s.std(ddof=1) if s.count() > 1 else float("nan"),
                "min": s.min(),
                "max": s.max(),
            }
        )
    table = TABLES / "baseline_summary.csv"
    write_csv(table, rows)
    record_output_metadata(
        table,
        source_data=[str(BASELINE_CSV.relative_to(PROJECT_ROOT))],
        experiments=experiments,
        metric="descriptive statistics of clean baseline runs",
        generation_script="scripts/run_clean_baseline.py",
        kind="table",
    )


def main() -> int:
    args = parse_args()
    overrides = list(args.overrides)
    if args.seed is not None:
        overrides.append(f"experiment.seed={args.seed}")
    if args.smoke:
        global RAW, BASELINE_CSV, FAILED_CSV, FIGURES, TABLES
        RAW = FIGURES = TABLES = PROJECT_ROOT / "results" / "smoke"
        BASELINE_CSV, FAILED_CSV = RAW / "baseline_results.csv", RAW / "failed_runs.csv"
        overrides += ["experiment.phase=smoke", "training.epochs=1"]
    if args.epochs is not None:
        overrides.append(f"training.epochs={args.epochs}")
    cfg = load_config(args.config, overrides)
    if cfg["attack"]["type"] != "none" or cfg["pipeline"]["mode"] != "conventional":
        raise SystemExit("clean baseline requires attack.type=none and pipeline.mode=conventional")

    identity = ExperimentIdentity.from_config(cfg)
    exp_id, exp_uuid = identity.experiment_id, identity.experiment_uuid
    setup_logging(
        cfg["logging"]["level"],
        PROJECT_ROOT / "logs" / f"{exp_id}_{exp_uuid[:8]}.log",
        experiment_id=exp_id,
    )
    pkg = prepare_package_dir(cfg["experiment"]["phase"], exp_id, args.force)
    timer, stage = StageTimer(), "setup"
    started = utc_now()
    try:
        with timer.stage("setup"):
            device, env = initialise_run(cfg, identity.as_dict())
            save_resolved_config(cfg, pkg / "config.yaml")
            save_environment_manifest(env, pkg / "environment.json")
            log.info("experiment %s (uuid %s) on device %s", exp_id, exp_uuid, device)

        stage = "data_loading"
        with timer.stage("data_loading"):
            clean = PROJECT_ROOT / "data" / "clean"
            train_arrays = cifar.read_store(clean / "cifar10_train.npz")
            test_arrays = cifar.read_store(clean / "cifar10_test.npz")
            dataset_digest = cifar.content_digest(train_arrays)
            train_data = cifar.TensorBatches(train_arrays, device)
            test_data = cifar.TensorBatches(test_arrays, device)
            log.info(
                "loaded training data: %d samples, test data: %d samples",
                len(train_arrays),
                len(test_arrays),
            )

        stage = "training"
        model = build_model(cfg["model"]).to(device)
        arch = architecture_record(model, cfg["model"])
        log.info("model %s, %d parameters", arch["architecture"], arch["parameters_total"])
        with ResourceMonitor() as monitor, timer.stage("training"):
            result = train_model(
                model,
                train_data,
                cfg["training"],
                make_generator(cfg["experiment"]["seed"]),
                monitor_data=test_data,
            )

        stage = "test"
        with timer.stage("test"):
            final = evaluate(model, test_data, amp=bool(cfg["training"].get("amp", False)))
        log.info("clean test accuracy %.4f (%d/%d)", final.accuracy, final.correct, final.n)

        stage = "save_model"
        with timer.stage("save_model"):
            model_path = save_model(
                model,
                PROJECT_ROOT / "models" / "checkpoints" / f"RUN-{exp_uuid}" / "model_final.pt",
            )
            model_sha = sha256_file(model_path)
            model_size = model_path.stat().st_size

        # ---------------------------------------------------------- run package
        stage = "packaging"
        history_path = pkg / "training_metrics.csv"
        write_csv(history_path, result.history)
        resources = monitor.summary()
        write_csv(pkg / "resource_metrics.csv", monitor.samples)
        model_rel = model_path.relative_to(PROJECT_ROOT).as_posix()
        (pkg / "model_hash.txt").write_text(f"{model_sha}  {model_rel}\n", encoding="utf-8")
        (pkg / "model_metadata.json").write_text(
            json.dumps(
                {
                    **arch,
                    "path": model_rel,
                    "size_bytes": model_size,
                    "sha256": model_sha,
                    "format": "torch.save(state_dict)",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        evaluation = {
            "clean_test": final.summary(),
            "confusion_matrix": final.confusion_matrix().tolist(),
        }
        (pkg / "evaluation.json").write_text(json.dumps(evaluation, indent=2), encoding="utf-8")

        tr = cfg["training"]
        summary = {
            **identity.as_dict(),
            "status": "completed",
            "started_utc": started,
            "completed_utc": utc_now(),
            "seed": cfg["experiment"]["seed"],
            "pipeline_mode": cfg["pipeline"]["mode"],
            "attack_type": "none",
            "device": str(device),
            "config_sha256": config_hash(cfg),
            "git_commit": env["git"]["commit"],
            "git_dirty": env["git"]["dirty"],
            "dataset_id": cfg["dataset"]["clean_dataset_id"],
            "dataset_content_sha256": dataset_digest,
            "model_sha256": model_sha,
            "model_size_bytes": model_size,
            "clean_test_accuracy": final.accuracy,
            "timings": {
                **timer.as_dict(),
                "training_loop_seconds": round(result.training_seconds, 3),
                "monitoring_eval_seconds": round(result.monitoring_eval_seconds, 3),
                "hook_seconds": round(result.hook_seconds, 3),
            },
            "resources": resources,
        }
        (pkg / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

        append_csv_row(
            BASELINE_CSV,
            {
                "experiment_id": exp_id,
                "experiment_uuid": exp_uuid,
                "completed_utc": summary["completed_utc"],
                "seed": cfg["experiment"]["seed"],
                "epochs": tr["epochs"],
                "batch_size": tr["batch_size"],
                "learning_rate": tr["learning_rate"],
                "optimizer": tr["optimizer"],
                "lr_scheduler": tr.get("lr_scheduler"),
                "loss_function": tr.get("loss"),
                "amp": bool(tr.get("amp", False)),
                "device": str(device),
                "gpu": (env["hardware"]["gpu"] or {}).get("name", ""),
                "training_seconds": round(timer.stages["training"], 3),
                "mean_epoch_train_seconds": round(
                    sum(h["epoch_train_seconds"] for h in result.history) / len(result.history), 3
                ),
                "test_seconds": round(timer.stages["test"], 3),
                "clean_test_accuracy": final.accuracy,
                "final_train_loss": result.history[-1]["train_loss"],
                "final_train_accuracy": result.history[-1]["train_accuracy"],
                "model_size_bytes": model_size,
                "model_sha256": model_sha,
                "dataset_content_sha256": dataset_digest,
                "config_sha256": config_hash(cfg),
                "git_commit": env["git"]["commit"],
                "git_dirty": env["git"]["dirty"],
                "peak_rss_mb": resources["peak_rss_mb"],
                "peak_gpu_allocated_mb": resources.get("peak_gpu_allocated_mb", ""),
                "training_metrics_file": history_path.relative_to(PROJECT_ROOT).as_posix(),
            },
        )
        regenerate_baseline_outputs()
    except Exception as exc:
        log.exception("run failed at stage %s", stage)
        record_failure(
            FAILED_CSV,
            experiment_id=exp_id,
            experiment_uuid=exp_uuid,
            stage=stage,
            exc=exc,
            config_sha256=config_hash(cfg),
        )
        (pkg / "run_summary.json").write_text(
            json.dumps(
                {
                    **identity.as_dict(),
                    "status": "failed",
                    "failure_stage": stage,
                    "error": str(exc),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return 1

    print(f"{exp_id}: clean test accuracy = {final.accuracy:.4f}")
    print(f"training {timer.stages['training']:.1f}s, test {timer.stages['test']:.1f}s")
    print(f"package: {pkg.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
