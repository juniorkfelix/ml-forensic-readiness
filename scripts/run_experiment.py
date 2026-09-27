"""Run ONE experiment end to end (research harness, Phase 16).

    config -> pipeline (A/B/C) -> [adversary tampers with the store] -> training ->
    deployment -> simulated traffic -> incident ticket -> reconstruction -> evaluation

Ground truth is recorded by the harness only (ground_truth/ground_truth.sqlite), with
timestamps taken as close to the true events as possible (D-052). Reconstruction
receives only the evidence directory and ticket. Evaluation reads ground truth only
after the reconstruction file exists and has been hashed.

Usage:
    python scripts/run_experiment.py --attack label_flip --pipeline forensic \
        --poison-rate 0.05 --seed 1 [--phase pilot] [--epochs N] [--set k=v]
    python scripts/run_experiment.py --attack none --pipeline A --seed 1
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import mlflow  # noqa: E402

from mlfref.attacks.backdoor import BackdoorAttack  # noqa: E402
from mlfref.attacks.base import run_attack  # noqa: E402
from mlfref.attacks.label_flip import LabelFlipAttack  # noqa: E402
from mlfref.config import compose_run_config, config_hash, save_resolved_config  # noqa: E402
from mlfref.data import cifar  # noqa: E402
from mlfref.data.versioning import create_version, save_version  # noqa: E402
from mlfref.evaluation.common import load_schema  # noqa: E402
from mlfref.evaluation.evaluate import evaluate_run  # noqa: E402
from mlfref.evaluation.overhead import evidence_storage, mlflow_run_storage  # noqa: E402
from mlfref.experiment_id import ExperimentIdentity  # noqa: E402
from mlfref.forensic.hashing import sha256_file  # noqa: E402
from mlfref.ground_truth.recorder import GroundTruthReader, GroundTruthRecorder  # noqa: E402
from mlfref.harness import (  # noqa: E402
    ResourceMonitor,
    StageTimer,
    append_csv_row,
    record_failure,
    utc_now,
    write_csv,
)
from mlfref.logging_utils import get_logger, setup_logging  # noqa: E402
from mlfref.models.evaluate import attack_success_rate  # noqa: E402
from mlfref.models.train import TrainingHooks  # noqa: E402
from mlfref.pipeline import Pipeline, PipelinePaths  # noqa: E402
from mlfref.reconstruction import reconstruct  # noqa: E402
from mlfref.reconstruction.report import write_json, write_markdown  # noqa: E402
from mlfref.reproducibility import (
    initialise_run,
    make_generator,
    save_environment_manifest,
)  # noqa: E402
from mlfref.simulation import (  # noqa: E402
    build_request_schedule,
    make_incident_ticket,
    run_traffic,
    select_incident,
)

log = get_logger("harness.run_experiment")
ATTACK_CONFIGS = {"label_flip": "pilot_label_flip.yaml", "backdoor": "pilot_backdoor.yaml"}
GT_DB = PROJECT_ROOT / "ground_truth" / "ground_truth.sqlite"
RUN_INDEX = PROJECT_ROOT / "results" / "raw" / "run_index.csv"
FAILED = PROJECT_ROOT / "results" / "raw" / "failed_runs.csv"


def mtime_utc(path: Path) -> str:
    return (
        datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def rel(path: Path) -> str:
    return path.resolve().relative_to(PROJECT_ROOT).as_posix()


def mlflow_digest(arrays: cifar.CifarArrays) -> str:
    return mlflow.data.from_numpy(arrays.images, targets=arrays.labels).digest


class GroundTruthTrainingHooks(TrainingHooks):
    """Harness-owned hooks: record GT training start/end at the true instants (D-052)."""

    def __init__(self, gt: GroundTruthRecorder, pipe: Pipeline, dataset_hash: str, cfg) -> None:
        self.gt, self.pipe, self.hash, self.cfg = gt, pipe, dataset_hash, cfg

    def _md(self):
        tr = self.cfg["training"]
        return {
            "mlflow_run_id": self.pipe.state.training_run_id,
            "store_path": rel(self.pipe.paths.store_path),
            "hyperparameters": {
                k: tr[k] for k in ("epochs", "batch_size", "learning_rate", "optimizer")
            },
            "git_commit": self.cfg.get("_git_commit"),
        }

    def on_train_start(self, info):
        self.gt.record(
            "TRAINING_STARTED",
            affected_artifact=self.hash,
            expected_relationship="USED",
            metadata=self._md(),
        )

    def on_train_end(self, info):
        self.gt.record("TRAINING_COMPLETED", affected_artifact=self.hash, metadata=self._md())


def build_config(args) -> dict:
    overrides = [f"experiment.seed={args.seed}", f"experiment.phase={args.phase}", *args.overrides]
    if args.epochs:
        overrides.append(f"training.epochs={args.epochs}")
    attack_cfg = ATTACK_CONFIGS.get(args.attack)
    if attack_cfg:
        overrides.append(f"attack.poison_rate={args.poison_rate}")
    return compose_run_config(PROJECT_ROOT / "config", args.pipeline, attack_cfg, overrides)


def run(cfg: dict, force: bool = False) -> dict:
    identity = ExperimentIdentity.from_config(cfg)
    exp_id, uid = identity.experiment_id, identity.experiment_uuid
    run_ref, mode, attack_type = f"RUN-{uid}", cfg["pipeline"]["mode"], cfg["attack"]["type"]
    phase = cfg["experiment"]["phase"]
    # Smoke checks never write into the official result locations.
    results_root = (
        PROJECT_ROOT / "results" / "smoke" if phase == "smoke" else PROJECT_ROOT / "results"
    )
    run_index = results_root / "run_index_smoke.csv" if phase == "smoke" else RUN_INDEX
    setup_logging("INFO", PROJECT_ROOT / "logs" / f"{exp_id}_{uid[:8]}.log", experiment_id=exp_id)
    pkg = PROJECT_ROOT / "experiments" / phase / exp_id
    if pkg.exists():
        if not force:
            raise SystemExit(f"{pkg} exists; use --force (old package is kept)")
        shutil.move(str(pkg), str(pkg.parent / "_superseded" / f"{exp_id}__{uid[:8]}"))
    pkg.mkdir(parents=True)
    timer, stage, pipe = StageTimer(), "setup", None
    try:
        with timer.stage("setup"):
            device, env = initialise_run(cfg, identity.as_dict())
            cfg["_git_commit"] = env["git"]["commit"]
            save_resolved_config(
                {k: v for k, v in cfg.items() if k != "_git_commit"}, pkg / "config.yaml"
            )
            save_environment_manifest(env, pkg / "environment.json")
            clean_train = cifar.read_store(PROJECT_ROOT / "data/clean/cifar10_train.npz")
            test = cifar.read_store(PROJECT_ROOT / "data/clean/cifar10_test.npz")
            paths = PipelinePaths.for_run(PROJECT_ROOT, mode, run_ref)
            gt = GroundTruthRecorder(GT_DB, exp_id, uid, attack_type, project_root=PROJECT_ROOT)
            pipe = Pipeline(cfg, uid, paths, device, git_commit=env["git"]["commit"])

        stage = "dataset_registration"
        with timer.stage("dataset_registration"):
            pipe.register_training_data(clean_train)
        clean_version, _ = create_version(clean_train)
        gt.record(
            "CLEAN_DATASET_CREATED",
            timestamp_utc=mtime_utc(paths.store_path),
            result_artifact=clean_version.manifest_sha256,
            metadata={
                "mlflow_digest": mlflow_digest(clean_train),
                "class_distribution": clean_version.class_distribution,
                "store_path": rel(paths.store_path),
            },
        )

        attack, train_version = None, clean_version
        if attack_type != "none":
            stage = "attack"
            attack = (
                LabelFlipAttack if attack_type == "label_flip" else BackdoorAttack
            ).from_config(cfg)
            with timer.stage("attack"):  # adversary, outside the pipeline
                res, train_version = run_attack(
                    attack,
                    clean_train,
                    clean_version,
                    gt,
                    annotate=lambda a: {
                        "mlflow_digest": mlflow_digest(a),
                        "store_path": rel(paths.store_path),
                    },
                )
                cifar.write_store(paths.store_path, res.poisoned)

        stage = "data_loading"
        with timer.stage("data_loading"):
            train_arrays = pipe.load_training_data()

        stage = "training"
        gt_hooks = GroundTruthTrainingHooks(gt, pipe, train_version.manifest_sha256, cfg)
        with ResourceMonitor() as monitor, timer.stage("training"):
            model, result = pipe.train(
                train_arrays,
                test,
                make_generator(cfg["experiment"]["seed"]),
                extra_hooks=(gt_hooks,),
            )
        stage = "evaluation"
        with timer.stage("evaluation"):
            ev = pipe.evaluate(model, test)
            harness = {"clean_test_accuracy": ev.accuracy}
            if attack_type == "backdoor":
                trig = cifar.TensorBatches(attack.triggered_test_set(test), device)
                harness["attack_success_rate"] = attack_success_rate(
                    model, trig, attack.target, amp=bool(cfg["training"].get("amp"))
                ).asr
            elif attack_type == "label_flip":
                src = ev.labels == attack.source
                harness["source_to_target_rate"] = float(
                    (ev.predictions[src] == attack.target).mean()
                )

        stage = "model"
        with timer.stage("save_model"):
            info = pipe.save_model(model)
        gt.record(
            "COMPROMISED_MODEL_CREATED" if attack else "MODEL_CREATED",
            timestamp_utc=mtime_utc(info.path),
            affected_artifact=info.sha256,
            expected_relationship="GENERATED_BY",
            metadata={
                "registry_version": info.registry_version,
                "mlflow_run_id": pipe.state.training_run_id,
                "model_path": rel(info.path),
            },
        )

        stage = "deployment"
        with timer.stage("deployment"):
            dep = pipe.deploy()
            service = pipe.service()
        gt.record(
            "MODEL_DEPLOYED",
            timestamp_utc=dep.deployed_at_utc,
            affected_artifact=info.sha256,
            expected_relationship="USED",
            metadata={
                "deployment_id": dep.deployment_id,
                "deployed_path": rel(dep.model_path),
                "model_path": rel(info.path),
                "registry_version": info.registry_version,
            },
        )

        stage = "inference"
        requests = build_request_schedule(
            test,
            int(cfg["deployment"]["inference_requests"]),
            cfg["experiment"]["seed"],
            backdoor=attack if attack_type == "backdoor" else None,
        )
        with timer.stage("inference"):
            served = run_traffic(service, requests, gt, attack_type, attack, info.sha256)
        write_csv(
            pkg / "inference_results.csv",
            [
                {
                    "request_id": r.request_id,
                    "received_utc": r.received_utc,
                    "predicted_class": r.predicted_class,
                    "confidence": round(r.confidence, 6),
                    "latency_ms": round(r.latency_ms, 3),
                }
                for _, r in served
            ],
        )
        incident = select_incident(served, attack_type, attack)
        ticket = make_incident_ticket(*incident, f"INC-{uid[:8]}") if incident else None
        if ticket:
            (paths.evidence_dir / "incident_ticket.json").write_text(
                json.dumps(ticket), encoding="utf-8"
            )

        stage = "finalize"
        with timer.stage("evidence_finalize"):
            pipe.finalize()
        storage = evidence_storage(paths.evidence_dir)
        storage["model_files"] = info.size_bytes + dep.model_path.stat().st_size
        if pipe.tracker:
            storage["mlflow_artifacts"] = mlflow_run_storage(
                pipe.tracker.client,
                [pipe.tracker.data_registration_run_id, pipe.state.training_run_id],
            )
        gt.close()

        recon_summary, evaluation = {}, None
        if ticket:
            stage = "reconstruction"
            with timer.stage("reconstruction"):
                recon = reconstruct(paths.evidence_dir, ticket, PROJECT_ROOT)
            rdir = results_root / "reconstruction"
            rpath = write_json(recon, rdir / f"{exp_id}.json")
            write_markdown(recon, rdir / f"{exp_id}.md", f"{exp_id} ({run_ref})")
            shutil.copyfile(rpath, pkg / "reconstruction.json")

            stage = "evaluation_vs_ground_truth"
            provenance = {
                "reconstruction_sha256": sha256_file(rpath),
                "ground_truth_opened_utc": utc_now(),
            }
            with GroundTruthReader(GT_DB) as reader:
                evaluation = evaluate_run(
                    recon,
                    reader.events(uid),
                    reader.attack(uid),
                    attack_type,
                    load_schema(),
                    PROJECT_ROOT,
                )
            evaluation["provenance"] = provenance
            (pkg / "evaluation.json").write_text(
                json.dumps(evaluation, indent=2, default=str), encoding="utf-8"
            )
            (results_root / "evaluation").mkdir(parents=True, exist_ok=True)
            shutil.copyfile(pkg / "evaluation.json", results_root / "evaluation" / f"{exp_id}.json")
            recon_summary = {
                "reconstruction_seconds": recon["runtime_seconds"],
                "root_cause_finding": recon["root_cause"]["finding"],
            }

        # ------------------------------------------------------------ package + index
        write_csv(pkg / "training_metrics.csv", result.history)
        write_csv(pkg / "resource_metrics.csv", monitor.samples)
        save_version(
            train_version if mode == "forensic" else clean_version, pkg / "dataset_manifest.json"
        )
        (pkg / "model_hash.txt").write_text(f"{info.sha256}  {rel(info.path)}\n", encoding="utf-8")
        (pkg / "model_metadata.json").write_text(
            json.dumps(
                {
                    "path": rel(info.path),
                    "sha256": info.sha256,
                    "size_bytes": info.size_bytes,
                    "registry_version": info.registry_version,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        if (paths.evidence_dir / "evidence_export.jsonl").exists():
            shutil.copyfile(
                paths.evidence_dir / "evidence_export.jsonl", pkg / "evidence_export.jsonl"
            )
        summary = {
            **identity.as_dict(),
            "status": "completed",
            "phase": phase,
            "pipeline": mode,
            "attack_type": attack_type,
            "poison_rate": cfg["attack"]["poison_rate"],
            "seed": cfg["experiment"]["seed"],
            "config_sha256": config_hash(cfg),
            "git_commit": env["git"]["commit"],
            "harness_metrics": harness,
            "incident": bool(ticket),
            "timings": timer.as_dict(),
            "resources": monitor.summary(),
            "storage_bytes": storage,
            "evidence_logging_seconds": pipe.forensic.logging_seconds if pipe.forensic else 0.0,
            **recon_summary,
        }
        (pkg / "run_summary.json").write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
        e = evaluation or {}
        append_csv_row(
            run_index,
            {
                "experiment_id": exp_id,
                "experiment_uuid": uid,
                "phase": phase,
                "pipeline": mode,
                "attack_type": attack_type,
                "poison_rate": cfg["attack"]["poison_rate"],
                "seed": cfg["experiment"]["seed"],
                "status": "completed",
                "evidence_dir": rel(paths.evidence_dir),
                "package_dir": rel(pkg),
                "ground_truth_db": rel(GT_DB),
                "clean_test_accuracy": harness["clean_test_accuracy"],
                "attack_success_rate": harness.get("attack_success_rate", ""),
                "source_to_target_rate": harness.get("source_to_target_rate", ""),
                "incident": bool(ticket),
                "evidence_completeness": e.get("evidence_completeness", {}).get("ec", ""),
                "event_recovery_rate": e.get("event_recovery", {}).get("err", ""),
                "timeline_kendall_tau_b": e.get("timeline", {}).get("kendall_tau_b", ""),
                "rci_score": (e.get("root_cause") or {}).get("rci_score", ""),
                "clean_control_correct": (e.get("clean_control") or {}).get("correct", ""),
                "reconstruction_seconds": recon_summary.get("reconstruction_seconds", ""),
                "training_seconds": timer.stages.get("training", ""),
                "evidence_logging_seconds": summary["evidence_logging_seconds"],
                "evidence_total_bytes": sum(v for k, v in storage.items() if k != "model_files"),
                "peak_rss_mb": summary["resources"]["peak_rss_mb"],
                "peak_gpu_allocated_mb": summary["resources"].get("peak_gpu_allocated_mb", ""),
                "completed_utc": utc_now(),
            },
        )
        log.info("completed %s", exp_id)
        return summary
    except Exception as exc:
        log.exception("failed at stage %s", stage)
        if pipe is not None:
            pipe.abort()
        record_failure(
            FAILED,
            experiment_id=exp_id,
            experiment_uuid=uid,
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
        raise


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--attack", choices=["none", "label_flip", "backdoor"], required=True)
    p.add_argument("--pipeline", required=True, help="A|B|C or conventional|provenance|forensic")
    p.add_argument("--poison-rate", type=float, default=0.05)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--phase", choices=["pilot", "main", "smoke"], default="pilot")
    p.add_argument("--epochs", type=int)
    p.add_argument("--set", dest="overrides", action="append", default=[])
    p.add_argument("--force", action="store_true")
    args = p.parse_args()
    summary = run(build_config(args), force=args.force)
    print(
        json.dumps(
            {k: summary[k] for k in ("experiment_id", "harness_metrics", "incident")}, indent=2
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
