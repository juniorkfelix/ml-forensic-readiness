"""The shared ML pipeline with mode-dependent evidence instrumentation.

One code path for A/B/C (D-005). The stages, in order, called by the research
harness (which may tamper with the data store between stages 1 and 2):

    1. register_training_data   the organisation registers its training data store
    2. load_training_data       the training job reads the store
    3. train                    ResNet-18 training (+ MLflow / forensic hooks)
    4. evaluate                 clean test accuracy (the pipeline's normal evaluation)
    5. save_model               model file (+ MLflow model registry, + forensic hashing)
    6. deploy / serve           deployment and inference service (mlfref.models.deployment)
    7. finalize                 evidence export and run references

Evidence per mode (docs/evidence_schema.md):
    A  app.log, metrics.json, artifacts.json (file listing: path, size, mtime; no hashes)
    B  A + MLflow runs (data registration, training), mlflow_ref.json
    C  B + forensic_evidence.sqlite, manifests/, evidence_export.jsonl

This module contains no ground-truth or attack code (enforced by
tests/test_ground_truth_isolation.py).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import torch

from mlfref.config import config_hash
from mlfref.data import cifar
from mlfref.data.manifest import write_manifest
from mlfref.data.versioning import DatasetVersion, create_version
from mlfref.forensic.evidence_store import ForensicEvidenceStore
from mlfref.forensic.hashing import sha256_file
from mlfref.forensic.integrity import IntegrityResult, log_integrity_check
from mlfref.forensic.logger import CompositeHooks, ForensicLogger, ForensicTrainingHooks
from mlfref.instrumentation import Instrumentation
from mlfref.logging_utils import attach_evidence_log, detach_evidence_log
from mlfref.models.artifacts import save_model
from mlfref.models.deployment import Deployment, InferenceService, deploy_model, model_id_for
from mlfref.models.evaluate import EvalResult, evaluate
from mlfref.models.resnet import architecture_record, build_model
from mlfref.models.train import TrainingResult, train_model

DATA_ACTOR, TRAIN_ACTOR, SYSTEM_ACTOR = "svc-data", "svc-training", "svc-ml-pipeline"
DATASET_NAME, TEST_DATASET_NAME = "cifar10_train", "cifar10_test"


@dataclass(frozen=True)
class PipelinePaths:
    workspace_root: Path
    evidence_dir: Path  # evidence/<mode>/RUN-<uuid>
    store_path: Path  # the run's training data store (tampering target)
    test_store_path: Path
    checkpoint_dir: Path
    deployed_dir: Path

    @classmethod
    def for_run(cls, root: Path, mode: str, run_ref: str) -> PipelinePaths:
        return cls(
            workspace_root=root,
            evidence_dir=root / "evidence" / mode / run_ref,
            store_path=root / "data" / "stores" / run_ref / "cifar10_train.npz",
            test_store_path=root / "data" / "clean" / "cifar10_test.npz",
            checkpoint_dir=root / "models" / "checkpoints" / run_ref,
            deployed_dir=root / "models" / "deployed" / run_ref,
        )


@dataclass
class ModelInfo:
    path: Path
    sha256: str
    size_bytes: int
    model_id: str
    registry_version: str | None = None


@dataclass
class PipelineState:
    registered: DatasetVersion | None = None
    observed: DatasetVersion | None = None
    training_run_id: str | None = None
    model: ModelInfo | None = None
    deployment: Deployment | None = None
    metrics: dict[str, Any] = field(default_factory=dict)


class Pipeline:
    def __init__(
        self,
        cfg: dict[str, Any],
        experiment_uuid: str,
        paths: PipelinePaths,
        device: torch.device,
        git_commit: str | None = None,
    ) -> None:
        self.cfg = cfg
        self.mode = cfg["pipeline"]["mode"]
        self.uuid = experiment_uuid
        self.run_ref = f"RUN-{experiment_uuid}"
        self.paths = paths
        self.device = device
        self.state = PipelineState()
        paths.evidence_dir.mkdir(parents=True, exist_ok=True)
        self._log_handler = attach_evidence_log(paths.evidence_dir / "app.log", self.run_ref)

        tracker = forensic = None
        self._fstore: ForensicEvidenceStore | None = None
        if cfg["mlflow"]["enabled"]:
            from mlfref.provenance.mlflow_tracker import MlflowTracker

            tracker = MlflowTracker.from_config(cfg, paths.workspace_root, self.run_ref, git_commit)
        if cfg["evidence"]["forensic_enabled"]:
            self._fstore = ForensicEvidenceStore(paths.evidence_dir / "forensic_evidence.sqlite")
            forensic = ForensicLogger(
                self._fstore, experiment_uuid, chain_hashing=cfg["evidence"]["event_chain_hashing"]
            )
        self.instr = Instrumentation(
            self.mode, self.run_ref, tracker, forensic, paths.workspace_root
        )
        self.log = self.instr.app_log("pipeline")
        self.log.info(
            "pipeline run %s started (mode=%s, device=%s)", self.run_ref, self.mode, device
        )
        if forensic:
            forensic.log(
                "EXPERIMENT_STARTED",
                actor=SYSTEM_ACTOR,
                source_component=__name__,
                artifact_type="system",
                metadata={"git_commit": git_commit},
            )
            forensic.log(
                "CONFIGURATION_LOADED",
                actor=SYSTEM_ACTOR,
                source_component=__name__,
                artifact_type="config",
                artifact_hash=config_hash(cfg),
                metadata={"layers": cfg.get("_meta", {}).get("layers", [])},
            )

    # ------------------------------------------------------------ helpers
    @property
    def tracker(self):
        return self.instr.tracker

    @property
    def forensic(self) -> ForensicLogger | None:
        return self.instr.forensic

    def _save_manifest(self, version: DatasetVersion, records) -> str:
        path = self.paths.evidence_dir / "manifests" / f"{version.dataset_id}.json"
        write_manifest(path, version.dataset_id, records)
        return self.instr.rel(path)

    # ------------------------------------------------------------ 1. registration
    def register_training_data(self, arrays: cifar.CifarArrays) -> None:
        """Write the run's data store and register it."""
        cifar.write_store(self.paths.store_path, arrays)
        store = self.instr.rel(self.paths.store_path)
        self.instr.app_log("data").info(
            "registered training data store %s: %d samples", store, len(arrays)
        )
        if self.tracker:
            self.tracker.log_data_registration(arrays, DATASET_NAME, store)
        if self.forensic:
            version, records = create_version(arrays)
            self.state.registered = version
            self.forensic.log(
                "DATASET_REGISTERED",
                actor=DATA_ACTOR,
                source_component=__name__,
                artifact_type="dataset",
                artifact_id=version.dataset_id,
                artifact_hash=version.manifest_sha256,
                metadata={
                    "store": store,
                    "num_samples": version.number_of_samples,
                    "class_distribution": version.class_distribution,
                    "content_sha256": version.content_sha256,
                    "manifest_path": self._save_manifest(version, records),
                },
            )

    # ------------------------------------------------------------ 2. load
    def load_training_data(self) -> cifar.CifarArrays:
        arrays = cifar.read_store(self.paths.store_path)
        store = self.instr.rel(self.paths.store_path)
        self.instr.app_log("data").info(
            "loaded training data from %s: %d samples", store, len(arrays)
        )
        if self.forensic:
            observed, records = create_version(arrays)
            self.state.observed = observed
            reg = self.state.registered
            result = IntegrityResult(
                store,
                reg.manifest_sha256 if reg else "",
                observed.manifest_sha256,
                "SHA-256(canonical manifest)",
            )
            log_integrity_check(
                self.forensic,
                result,
                artifact_type="dataset",
                artifact_id=observed.dataset_id,
                actor=TRAIN_ACTOR,
                source_component=__name__,
                event_type="DATASET_INTEGRITY_VERIFIED",
                extra_metadata={"registered_dataset_id": reg.dataset_id if reg else None},
            )
            if not result.match:
                # The observed state differs from what was registered: preserve it as a new
                # version (parent = registered). The pipeline did not create it (actor unknown).
                self.forensic.log(
                    "DATASET_VERSION_CREATED",
                    actor="unknown",
                    source_component=__name__,
                    artifact_type="dataset",
                    artifact_id=observed.dataset_id,
                    artifact_hash=observed.manifest_sha256,
                    parent_artifact_id=reg.dataset_id if reg else None,
                    metadata={
                        "store": store,
                        "num_samples": observed.number_of_samples,
                        "class_distribution": observed.class_distribution,
                        "content_sha256": observed.content_sha256,
                        "manifest_path": self._save_manifest(observed, records),
                        "observed_by": TRAIN_ACTOR,
                    },
                )
        return arrays

    # ------------------------------------------------------------ 3. training
    def train(
        self,
        train_arrays: cifar.CifarArrays,
        test_arrays: cifar.CifarArrays,
        generator: torch.Generator,
        extra_hooks=(),
    ) -> tuple[torch.nn.Module, TrainingResult]:
        tr = self.cfg["training"]
        model = build_model(self.cfg["model"]).to(self.device)
        arch = architecture_record(model, self.cfg["model"])
        hooks = []
        if self.tracker:
            self.state.training_run_id = self.tracker.start_training_run(
                train_arrays,
                DATASET_NAME,
                self.instr.rel(self.paths.store_path),
                test_arrays,
                TEST_DATASET_NAME,
                self.instr.rel(self.paths.test_store_path),
                self.cfg,
                arch,
            )
            hooks.append(self.tracker.hooks())
        if self.forensic:
            obs = self.state.observed
            hooks.append(
                ForensicTrainingHooks(
                    self.forensic,
                    dataset_id=obs.dataset_id,
                    dataset_hash=obs.manifest_sha256,
                    run_id=self.state.training_run_id,
                    hyperparameters={
                        k: tr.get(k)
                        for k in ("epochs", "batch_size", "optimizer", "learning_rate", "amp")
                    },
                )
            )
        tlog = self.instr.app_log("train")
        tlog.info(
            "training started: model=%s epochs=%d batch_size=%d optimizer=%s lr=%s seed=%d",
            arch["architecture"],
            tr["epochs"],
            tr["batch_size"],
            tr["optimizer"],
            tr["learning_rate"],
            self.cfg["experiment"]["seed"],
        )
        result = train_model(
            model,
            cifar.TensorBatches(train_arrays, self.device),
            tr,
            generator,
            monitor_data=cifar.TensorBatches(test_arrays, self.device),
            hooks=CompositeHooks(*hooks, *extra_hooks),
        )
        tlog.info("training completed: %d epochs in %.1fs", tr["epochs"], result.training_seconds)
        return model, result

    # ------------------------------------------------------------ 4. evaluation
    def evaluate(self, model: torch.nn.Module, test_arrays: cifar.CifarArrays) -> EvalResult:
        ev = evaluate(
            model,
            cifar.TensorBatches(test_arrays, self.device),
            amp=bool(self.cfg["training"].get("amp", False)),
        )
        self.state.metrics = {
            "clean_test_accuracy": ev.accuracy,
            "n_test": ev.n,
            "per_class_accuracy": ev.per_class_accuracy(),
        }
        self.instr.app_log("evaluate").info(
            "clean test accuracy %.4f on %d samples", ev.accuracy, ev.n
        )
        if self.tracker:
            self.tracker.log_final_metrics({"clean_accuracy": ev.accuracy})
        return ev

    # ------------------------------------------------------------ 5. model
    def save_model(self, model: torch.nn.Module) -> ModelInfo:
        path = save_model(model, self.paths.checkpoint_dir / "model_final.pt")
        sha, size = sha256_file(path), path.stat().st_size
        info = ModelInfo(path, sha, size, model_id_for(sha))
        rel = self.instr.rel(path)
        self.instr.app_log("model").info("saved model to %s (%d bytes)", rel, size)
        run_id = self.state.training_run_id
        if self.forensic:
            self.forensic.log(
                "MODEL_CREATED",
                actor=TRAIN_ACTOR,
                source_component=__name__,
                artifact_type="model",
                artifact_id=info.model_id,
                parent_artifact_id=self.state.observed.dataset_id,
                run_id=run_id,
                metadata={"path": rel, "size_bytes": size, "format": "torch.save(state_dict)"},
            )
            self.forensic.log(
                "MODEL_HASHED",
                actor=TRAIN_ACTOR,
                source_component=__name__,
                artifact_type="model",
                artifact_id=info.model_id,
                artifact_hash=sha,
                run_id=run_id,
                metadata={"path": rel, "hash_algorithm": "SHA-256"},
            )
        if self.tracker:
            reg = self.tracker.log_model(model)
            info.registry_version = reg["registered_model_version"]
            self.tracker.end_training_run()
            if self.forensic:
                self.forensic.log(
                    "MODEL_REGISTERED",
                    actor=TRAIN_ACTOR,
                    source_component=__name__,
                    artifact_type="model",
                    artifact_id=info.model_id,
                    artifact_hash=sha,
                    run_id=run_id,
                    metadata={
                        "registry": reg["registered_model_name"],
                        "registry_version": info.registry_version,
                        "model_uri": reg["model_uri"],
                    },
                )
        self.state.model = info
        return info

    # ------------------------------------------------------------ 6. deployment
    def deploy(self) -> Deployment:
        m = self.state.model
        dep = deploy_model(
            m.path,
            self.paths.deployed_dir,
            self.instr,
            model_sha256=m.sha256,
            training_run_id=self.state.training_run_id,
            registry_version=m.registry_version,
        )
        self.state.deployment = dep
        return dep

    def service(self) -> InferenceService:
        return InferenceService(
            self.state.deployment,
            self.cfg["model"],
            self.device,
            self.instr,
            training_run_id=self.state.training_run_id,
        )

    # ------------------------------------------------------------ 7. finalize
    def finalize(self) -> dict[str, Any]:
        """Write evidence exports and close stores. Returns evidence sizes by file."""
        ev = self.paths.evidence_dir
        (ev / "metrics.json").write_text(json.dumps(self.state.metrics, indent=2), encoding="utf-8")
        listing = []
        for p in (
            self.paths.store_path,
            self.paths.checkpoint_dir / "model_final.pt",
            self.paths.deployed_dir / "model.pt",
        ):
            if p.exists():
                st = p.stat()
                listing.append(
                    {
                        "path": self.instr.rel(p),
                        "size_bytes": st.st_size,
                        "modified_utc": _mtime(st.st_mtime),
                    }
                )
        (ev / "artifacts.json").write_text(json.dumps(listing, indent=2), encoding="utf-8")
        if self.tracker:
            ref = self.tracker.reference()
            prefix = "sqlite:///"
            if ref["tracking_uri"].startswith(prefix):  # workspace-relative, no personal path
                ref["tracking_uri"] = prefix + self.instr.rel(ref["tracking_uri"][len(prefix) :])
            (ev / "mlflow_ref.json").write_text(json.dumps(ref, indent=2), encoding="utf-8")
        if self.forensic:
            self.forensic.log(
                "EXPERIMENT_COMPLETED",
                actor=SYSTEM_ACTOR,
                source_component=__name__,
                artifact_type="system",
                metadata={"events_written": self.forensic.events_written + 1},
            )
            if self.cfg["evidence"].get("export_jsonl", True):
                self._fstore.export_jsonl(ev / "evidence_export.jsonl")
            self._fstore.close()
        self.log.info("pipeline run %s completed", self.run_ref)
        detach_evidence_log(self._log_handler)
        return {
            p.relative_to(ev).as_posix(): p.stat().st_size
            for p in sorted(ev.rglob("*"))
            if p.is_file()
        }

    def abort(self) -> None:
        """Release resources after a failure (evidence written so far is kept)."""
        if self.tracker:
            import mlflow

            if mlflow.active_run():
                mlflow.end_run(status="FAILED")
        if self._fstore:
            self._fstore.close()
        detach_evidence_log(self._log_handler)


def _mtime(ts: float) -> str:
    from datetime import UTC, datetime

    return (
        datetime.fromtimestamp(ts, tz=UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )
