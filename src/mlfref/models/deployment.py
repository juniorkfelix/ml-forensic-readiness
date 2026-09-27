"""Model deployment and inference service (spec §13 pipeline stages; Phase 13).

``deploy_model`` copies the trained model file into the serving location. The
inference service loads it and answers one request at a time. Evidence per mode:

* A: application log ("deployed model file ...", "serving model file ...", one INFO
  line per request with request ID, predicted class and latency). No model identity
  beyond the file path, no hashes, no input identity.
* B: A + MLflow registry alias ``production`` set to the deployed model version, and
  the service logs the registry URI and version it serves.
* C: B + forensic events MODEL_DEPLOYED, an ARTIFACT_INTEGRITY_CHECK of the deployed
  file at service start (record-only, D-016), and per request INFERENCE_REQUEST
  (input SHA-256) and INFERENCE_RESULT (prediction, confidence, model hash).

The service sees only what a real service would: a request ID and an image. Whether
a request is adversarial is known only to the research harness.
"""

from __future__ import annotations

import hashlib
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch

from mlfref.config import CIFAR10_CLASSES
from mlfref.data.cifar import CIFAR10_MEAN, CIFAR10_STD
from mlfref.forensic.hashing import sha256_file
from mlfref.forensic.integrity import log_integrity_check, verify_file
from mlfref.forensic.logger import utc_timestamp as utc_now
from mlfref.instrumentation import Instrumentation
from mlfref.models.artifacts import load_model_state
from mlfref.models.resnet import build_model

SERVING_ACTOR = "svc-serving"
DEPLOY_ACTOR = "svc-deploy"


def model_id_for(model_sha256: str) -> str:
    return f"MODEL-{model_sha256[:12]}"


@dataclass(frozen=True)
class Deployment:
    deployment_id: str
    model_path: Path
    source_model_path: Path
    deployed_at_utc: str
    model_sha256: str | None  # known to B/C records; A does not record it
    registry_version: str | None


def deploy_model(
    source_model_path: Path,
    deployed_dir: Path,
    instr: Instrumentation,
    *,
    model_sha256: str,
    training_run_id: str | None = None,
    registry_version: str | None = None,
) -> Deployment:
    """Copy the model into the serving location and record the deployment."""
    log = instr.app_log("deployment")
    deployed_dir.mkdir(parents=True, exist_ok=True)
    target = deployed_dir / "model.pt"
    previous = target.exists()
    shutil.copyfile(source_model_path, target)
    dep = Deployment(
        deployment_id=f"DEP-{uuid.uuid4().hex[:8]}",
        model_path=target,
        source_model_path=source_model_path,
        deployed_at_utc=utc_now(),
        model_sha256=model_sha256,
        registry_version=registry_version,
    )
    log.info("deployed model file %s -> %s", source_model_path.name, target.as_posix())

    if instr.has_provenance and registry_version is not None:
        instr.tracker.set_production_alias(registry_version)
        log.info("registry alias production -> version %s", registry_version)

    if instr.has_forensic:
        instr.forensic.log(
            "MODEL_REPLACED" if previous else "MODEL_DEPLOYED",
            actor=DEPLOY_ACTOR,
            source_component="mlfref.models.deployment",
            artifact_type="deployment",
            artifact_id=dep.deployment_id,
            artifact_hash=model_sha256,
            parent_artifact_id=model_id_for(model_sha256),
            run_id=training_run_id,
            deployment_id=dep.deployment_id,
            metadata={
                "model_id": model_id_for(model_sha256),
                "deployed_path": target.as_posix(),
                "source_path": source_model_path.as_posix(),
                "registry_version": registry_version,
            },
        )
    return dep


@dataclass(frozen=True)
class InferenceRecord:
    request_id: str
    received_utc: str
    predicted_class: int
    confidence: float
    latency_ms: float


class InferenceService:
    """Loads the deployed model and serves single-image requests."""

    def __init__(
        self,
        deployment: Deployment,
        model_cfg: dict[str, Any],
        device: torch.device | str,
        instr: Instrumentation,
        training_run_id: str | None = None,
    ) -> None:
        self.dep = deployment
        self.device = torch.device(device)
        self.instr = instr
        self.log = instr.app_log("inference")
        self.training_run_id = training_run_id
        self.model = load_model_state(build_model(model_cfg), deployment.model_path, self.device)
        self.model.eval()
        self.mean = torch.tensor(CIFAR10_MEAN, device=self.device).view(1, 3, 1, 1)
        self.std = torch.tensor(CIFAR10_STD, device=self.device).view(1, 3, 1, 1)
        self.records: list[InferenceRecord] = []

        if instr.has_provenance and deployment.registry_version is not None:
            self.log.info(
                "serving models:/cifar10-resnet18@production (version %s)",
                deployment.registry_version,
            )
        else:
            self.log.info("serving model file %s", deployment.model_path.as_posix())

        if instr.has_forensic:
            # Record-only integrity check of the deployed file against the trained model hash.
            log_integrity_check(
                instr.forensic,
                verify_file(deployment.model_path, deployment.model_sha256),
                artifact_type="model",
                artifact_id=model_id_for(deployment.model_sha256),
                actor=SERVING_ACTOR,
                source_component="mlfref.models.deployment",
                run_id=training_run_id,
                deployment_id=deployment.deployment_id,
                extra_metadata={"check": "deployed model file vs trained model hash"},
            )
            self._serving_hash = sha256_file(deployment.model_path)

    @torch.no_grad()
    def predict(self, request_id: str, image: np.ndarray) -> InferenceRecord:
        received = utc_now()
        t0 = time.perf_counter()
        if self.instr.has_forensic:
            self.instr.forensic.log(
                "INFERENCE_REQUEST",
                actor=SERVING_ACTOR,
                source_component="mlfref.models.deployment",
                artifact_type="inference",
                artifact_id=request_id,
                artifact_hash=hashlib.sha256(image.tobytes()).hexdigest(),
                parent_artifact_id=model_id_for(self.dep.model_sha256),
                deployment_id=self.dep.deployment_id,
                metadata={"input_shape": list(image.shape), "input_dtype": str(image.dtype)},
            )
        x = torch.from_numpy(np.ascontiguousarray(image)).permute(2, 0, 1)[None].to(self.device)
        x = (x.float() / 255.0 - self.mean) / self.std
        prob = torch.softmax(self.model(x).float(), dim=1)[0]
        conf, pred = prob.max(dim=0)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        rec = InferenceRecord(request_id, received, int(pred), float(conf), latency_ms)
        self.records.append(rec)
        self.log.info(
            "request_id=%s predicted=%s latency_ms=%.1f",
            request_id,
            CIFAR10_CLASSES[rec.predicted_class],
            latency_ms,
        )
        if self.instr.has_forensic:
            self.instr.forensic.log(
                "INFERENCE_RESULT",
                actor=SERVING_ACTOR,
                source_component="mlfref.models.deployment",
                artifact_type="inference",
                artifact_id=request_id,
                artifact_hash=self._serving_hash,
                parent_artifact_id=model_id_for(self.dep.model_sha256),
                deployment_id=self.dep.deployment_id,
                metadata={
                    "predicted_class": rec.predicted_class,
                    "predicted_label": CIFAR10_CLASSES[rec.predicted_class],
                    "confidence": round(rec.confidence, 6),
                    "model_sha256": self._serving_hash,
                },
            )
        return rec
