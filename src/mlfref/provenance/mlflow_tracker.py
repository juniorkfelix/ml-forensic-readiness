"""MLflow provenance tracking for pipelines B and C (docs/evidence_schema.md §3).

Models a *legitimate* ML experiment-tracking setup: a local SQLite backend, one
data-registration run when the training data is registered, and one training run
with parameters, per-epoch metrics, dataset inputs, and a logged and registered model.

Deliberately NOT logged (D-014, D-031):
* attack type, poison rate, classes and trigger parameters. The pipeline does not
  know an attack happened.
* attack success rate. ASR needs knowledge of the trigger and is a research-harness
  metric only.

Datasets are logged with MLflow's native ``mlflow.data.from_numpy``, so the digest is
MLflow's own. That digest is a truncated MD5 over the first 10,000 flattened feature
values and the first 10,000 targets plus the array shapes, which is a property of
real-world MLflow provenance (D-032). The per-class label distribution is logged
with each dataset input, as a routine data-profiling step (D-033).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")

import mlflow  # noqa: E402
from mlflow.tracking import MlflowClient  # noqa: E402

from mlfref.data.cifar import CifarArrays, class_distribution  # noqa: E402
from mlfref.models.train import TrainingHooks  # noqa: E402

REGISTERED_MODEL_NAME = "cifar10-resnet18"
SERVICE_ACCOUNT = "svc-ml-pipeline"
PRODUCTION_ALIAS = "production"

# Training-config keys logged as run parameters (flattened).
_TRAINING_PARAM_KEYS = (
    "epochs",
    "batch_size",
    "optimizer",
    "learning_rate",
    "momentum",
    "weight_decay",
    "nesterov",
    "lr_scheduler",
    "loss",
    "amp",
)


def resolve_tracking_uri(uri: str, project_root: Path) -> str:
    """Make a relative ``sqlite:///path`` URI absolute (relative to the project root)."""
    prefix = "sqlite:///"
    if uri.startswith(prefix):
        path = Path(uri[len(prefix) :])
        if not path.is_absolute():
            path = project_root / path
        path.parent.mkdir(parents=True, exist_ok=True)
        return prefix + path.resolve().as_posix()
    return uri


class MlflowTracker:
    """Thin wrapper around the MLflow client for one pipeline execution."""

    def __init__(
        self,
        tracking_uri: str,
        experiment_name: str,
        artifact_location: str | Path,
        run_ref: str,
        pipeline_mode: str,
        git_commit: str | None = None,
    ) -> None:
        self.tracking_uri = tracking_uri
        mlflow.set_tracking_uri(tracking_uri)
        self.client = MlflowClient(tracking_uri)
        artifact_uri = Path(artifact_location).resolve()
        artifact_uri.mkdir(parents=True, exist_ok=True)
        existing = self.client.get_experiment_by_name(experiment_name)
        self.experiment_id = (
            existing.experiment_id
            if existing
            else self.client.create_experiment(
                experiment_name, artifact_location=artifact_uri.as_uri()
            )
        )
        self.run_ref = run_ref
        self.pipeline_mode = pipeline_mode
        self.git_commit = git_commit
        self.data_registration_run_id: str | None = None
        self.training_run_id: str | None = None

    @classmethod
    def from_config(
        cls, cfg: Mapping[str, Any], project_root: Path, run_ref: str, git_commit: str | None
    ) -> MlflowTracker:
        m = cfg["mlflow"]
        artifact = Path(m["artifact_location"])
        return cls(
            tracking_uri=resolve_tracking_uri(m["tracking_uri"], project_root),
            experiment_name=m["experiment_name"],
            artifact_location=artifact if artifact.is_absolute() else project_root / artifact,
            run_ref=run_ref,
            pipeline_mode=cfg["pipeline"]["mode"],
            git_commit=git_commit,
        )

    # ------------------------------------------------------------------ helpers
    def _base_tags(self, run_type: str) -> dict[str, str]:
        # MLflow would otherwise auto-tag the OS user name and the absolute path of the
        # entry script (personal information, spec §32/§39). An automated pipeline runs
        # under a service account, so that is recorded instead, with the script name only.
        tags = {
            "run_type": run_type,
            "run_ref": self.run_ref,
            "pipeline_mode": self.pipeline_mode,
            "mlflow.user": SERVICE_ACCOUNT,
            "mlflow.source.name": Path(sys.argv[0]).name if sys.argv and sys.argv[0] else "mlfref",
        }
        if self.git_commit:
            tags["mlflow.source.git.commit"] = self.git_commit
        return tags

    @staticmethod
    def _dataset(arrays: CifarArrays, name: str, source: str):
        return mlflow.data.from_numpy(
            features=arrays.images, targets=arrays.labels, source=source, name=name
        )

    @staticmethod
    def _profile(arrays: CifarArrays) -> dict[str, Any]:
        return {"num_samples": len(arrays), "class_distribution": class_distribution(arrays.labels)}

    def _log_dataset(self, arrays: CifarArrays, name: str, source: str, context: str) -> str:
        """Log a dataset input plus its label-distribution profile; returns the MLflow digest."""
        ds = self._dataset(arrays, name, source)
        mlflow.log_input(ds, context=context)
        profile = self._profile(arrays)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / f"{context}_data_profile.json"
            path.write_text(json.dumps({"name": name, "digest": ds.digest, **profile}, indent=2))
            mlflow.log_artifact(str(path), artifact_path="data_profiles")
        return ds.digest

    # ------------------------------------------------------------------ runs
    def log_data_registration(self, arrays: CifarArrays, name: str, source: str) -> str:
        """Data-registration run: records the dataset as registered. Returns the MLflow run ID."""
        with mlflow.start_run(
            experiment_id=self.experiment_id,
            run_name=f"data-registration-{self.run_ref[-8:]}",
            tags=self._base_tags("data_registration"),
        ) as run:
            digest = self._log_dataset(arrays, name, source, context="registration")
            mlflow.log_param("dataset_name", name)
            mlflow.log_param("dataset_source", source)
            mlflow.log_param("dataset_digest", digest)
            self.data_registration_run_id = run.info.run_id
        return self.data_registration_run_id

    def start_training_run(
        self,
        train_arrays: CifarArrays,
        train_name: str,
        train_source: str,
        eval_arrays: CifarArrays,
        eval_name: str,
        eval_source: str,
        cfg: Mapping[str, Any],
        architecture: Mapping[str, Any],
    ) -> str:
        run = mlflow.start_run(
            experiment_id=self.experiment_id,
            run_name=f"training-{self.run_ref[-8:]}",
            tags=self._base_tags("training"),
        )
        self.training_run_id = run.info.run_id
        tr = cfg["training"]
        params = {k: tr.get(k) for k in _TRAINING_PARAM_KEYS if k in tr}
        params.update(
            {
                "seed": cfg["experiment"]["seed"],
                "augmentation": json.dumps(tr.get("augmentation", {}), sort_keys=True),
                "model_architecture": architecture["architecture"],
                "model_cifar_stem": architecture["cifar_stem"],
                "model_pretrained": architecture["pretrained"],
                "model_parameters": architecture["parameters_total"],
                "train_dataset_name": train_name,
                "train_dataset_source": train_source,
            }
        )
        mlflow.log_params(params)
        digest = self._log_dataset(train_arrays, train_name, train_source, context="training")
        mlflow.log_param("train_dataset_digest", digest)
        self._log_dataset(eval_arrays, eval_name, eval_source, context="evaluation")
        return self.training_run_id

    def hooks(self) -> MlflowTrainingHooks:
        return MlflowTrainingHooks()

    def log_final_metrics(self, metrics: Mapping[str, float]) -> None:
        mlflow.log_metrics(dict(metrics))

    def log_model(self, model, pip_requirements: list[str] | None = None) -> dict[str, Any]:
        """Log the trained model and register a new version of REGISTERED_MODEL_NAME.

        MLflow 3.x defaults to the traced 'pt2' format, which needs an input example and
        validates by reloading the model on the current device. The long-standing
        'pickle' format (the MLflow 2.x default) is used instead (D-034). The model is
        logged from a CPU copy so the artefact does not depend on the training device.
        """
        import copy

        cpu_model = copy.deepcopy(model).cpu().eval()
        info = mlflow.pytorch.log_model(
            cpu_model,
            name="model",
            registered_model_name=REGISTERED_MODEL_NAME,
            serialization_format="pickle",
            pip_requirements=pip_requirements or [f"torch=={_torch_version()}"],
        )
        return {
            "model_uri": info.model_uri,
            "registered_model_name": REGISTERED_MODEL_NAME,
            "registered_model_version": str(info.registered_model_version),
        }

    def end_training_run(self, status: str = "FINISHED") -> None:
        mlflow.end_run(status=status)

    def set_production_alias(self, version: str) -> None:
        """Deployment record in the model registry (used in Phase 13)."""
        self.client.set_registered_model_alias(REGISTERED_MODEL_NAME, PRODUCTION_ALIAS, version)

    def reference(self) -> dict[str, Any]:
        """Contents of ``mlflow_ref.json`` in the evidence directory."""
        return {
            "tracking_uri": self.tracking_uri,
            "experiment_id": self.experiment_id,
            "data_registration_run_id": self.data_registration_run_id,
            "training_run_id": self.training_run_id,
            "registered_model_name": REGISTERED_MODEL_NAME,
        }


class MlflowTrainingHooks(TrainingHooks):
    """Per-epoch metric logging into the active training run."""

    def on_epoch_end(self, record: Mapping[str, Any]) -> None:
        step = int(record["epoch"])
        metrics = {
            k: float(record[k])
            for k in ("train_loss", "train_accuracy", "test_loss", "test_accuracy", "learning_rate")
            if k in record
        }
        mlflow.log_metrics(metrics, step=step)


def _torch_version() -> str:
    import torch

    return torch.__version__.split("+")[0]


__all__ = [
    "MlflowTracker",
    "MlflowTrainingHooks",
    "PRODUCTION_ALIAS",
    "REGISTERED_MODEL_NAME",
    "resolve_tracking_uri",
]
