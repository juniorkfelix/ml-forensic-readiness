"""Inference-traffic simulation and incident tickets (research harness, not a pipeline).

* ``build_request_schedule``: a fixed, seed-determined stream of requests. Benign
  requests are clean test images sampled uniformly without replacement. For backdoor
  runs the adversary also submits ``n_triggered`` triggered images (non-target test
  images carrying the trigger) at seed-determined positions. The schedule depends only
  on (seed, attack settings), so A/B/C receive identical traffic.
* ``run_traffic``: sends each request (ID + image only) to the inference service and
  records the ground truth: TRIGGER_SUBMITTED for adversarial requests and
  MALICIOUS_PREDICTION for served predictions that meet the attack objective
  (backdoor: triggered input predicted as the target; label flip: source-class input
  predicted as the target class).
* ``make_incident_ticket``: what an affected user could report about the FIRST
  malicious prediction (clean runs: the first misclassification, for the clean-control
  investigation). It holds only observable facts: request ID, time, the submitted
  image and its hash, the observed prediction, the label the reporter expected. No
  attack parameters or ground-truth identifiers.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from mlfref.config import CIFAR10_CLASSES
from mlfref.data.cifar import CifarArrays
from mlfref.ground_truth.recorder import GroundTruthRecorder
from mlfref.models.deployment import InferenceRecord, InferenceService

SCHEDULE_SEED_OFFSET = 7_919  # decorrelates the traffic RNG from the attack-selection RNG


@dataclass(frozen=True)
class Request:
    request_id: str
    image: np.ndarray  # uint8 [32, 32, 3]
    # --- harness-only fields (never sent to the service) ---
    test_sample_id: int
    true_label: int
    adversarial: bool


def build_request_schedule(
    test: CifarArrays,
    n_requests: int,
    seed: int,
    backdoor=None,  # mlfref.attacks.backdoor.BackdoorAttack | None
    n_triggered: int = 10,
) -> list[Request]:
    rng = np.random.default_rng(seed + SCHEDULE_SEED_OFFSET)
    n_adv = n_triggered if backdoor is not None else 0
    if n_adv > n_requests:
        raise ValueError("more triggered requests than total requests")
    order = rng.permutation(len(test))
    benign_idx = order[: n_requests - n_adv]
    adv_positions: set[int] = set()
    adv_idx: list[int] = []
    if n_adv:
        eligible = [i for i in order[n_requests - n_adv :] if test.labels[i] != backdoor.target]
        adv_idx = eligible[:n_adv]
        adv_positions = set(rng.choice(n_requests, size=n_adv, replace=False).tolist())

    requests: list[Request] = []
    benign_iter, adv_iter = iter(benign_idx), iter(adv_idx)
    for pos in range(n_requests):
        adversarial = pos in adv_positions
        i = int(next(adv_iter) if adversarial else next(benign_iter))
        image = test.images[i]
        if adversarial:
            image = backdoor.apply_trigger(image[None])[0]
        requests.append(
            Request(
                request_id=f"REQ-{pos + 1:05d}",
                image=image,
                test_sample_id=int(test.sample_ids[i]),
                true_label=int(test.labels[i]),
                adversarial=adversarial,
            )
        )
    return requests


def is_malicious(req: Request, rec: InferenceRecord, attack_type: str, attack: Any) -> bool:
    if attack_type == "backdoor":
        return req.adversarial and rec.predicted_class == attack.target
    if attack_type == "label_flip":
        return req.true_label == attack.source and rec.predicted_class == attack.target
    return False


def run_traffic(
    service: InferenceService,
    requests: Sequence[Request],
    recorder: GroundTruthRecorder,
    attack_type: str,
    attack: Any = None,
    model_sha256: str | None = None,
) -> list[tuple[Request, InferenceRecord]]:
    served = []
    for req in requests:
        if req.adversarial:
            recorder.record(
                "TRIGGER_SUBMITTED",
                affected_artifact=model_sha256,
                metadata={
                    "request_id": req.request_id,
                    "input_sha256": hashlib.sha256(req.image.tobytes()).hexdigest(),
                    "test_sample_id": req.test_sample_id,
                    "true_label": req.true_label,
                },
            )
        rec = service.predict(req.request_id, req.image)
        if is_malicious(req, rec, attack_type, attack):
            recorder.record(
                "MALICIOUS_PREDICTION",
                affected_artifact=model_sha256,
                metadata={
                    "request_id": req.request_id,
                    "input_sha256": hashlib.sha256(req.image.tobytes()).hexdigest(),
                    "predicted_class": rec.predicted_class,
                    "true_label": req.true_label,
                    "confidence": rec.confidence,
                    "served_at_utc": rec.received_utc,
                },
            )
        served.append((req, rec))
    return served


def select_incident(
    served: Sequence[tuple[Request, InferenceRecord]], attack_type: str, attack: Any = None
) -> tuple[Request, InferenceRecord] | None:
    """First served request meeting the attack objective (clean: first misclassification)."""
    for req, rec in served:
        if attack_type == "none":
            if rec.predicted_class != req.true_label:
                return req, rec
        elif is_malicious(req, rec, attack_type, attack):
            return req, rec
    return None


def make_incident_ticket(req: Request, rec: InferenceRecord, ticket_id: str) -> dict[str, Any]:
    """Observable facts only (D-018)."""
    return {
        "ticket_id": ticket_id,
        "reported_issue": "unexpected prediction returned by the image classification service",
        "request_id": rec.request_id,
        "request_time_utc": rec.received_utc,
        "observed_prediction": CIFAR10_CLASSES[rec.predicted_class],
        "observed_confidence": round(rec.confidence, 6),
        "expected_label": CIFAR10_CLASSES[req.true_label],
        "input_sha256": hashlib.sha256(req.image.tobytes()).hexdigest(),
        "input_image_uint8": req.image.tolist(),
    }
