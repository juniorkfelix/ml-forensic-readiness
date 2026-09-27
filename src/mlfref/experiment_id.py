"""Experiment identifiers.

Human-readable, deterministic ID:

    EXP-{ATTACK}-{PIPELINE}-{RATE}-{SEED}      e.g. EXP-LF-C-05-S003

  ATTACK   CLEAN | LF (label flip) | BD (backdoor)
  PIPELINE A (conventional) | B (provenance) | C (forensic)
  RATE     poisoning rate as whole percent, at least two digits (05 = 5 %)
  SEED     S + seed zero-padded to three digits

Each *execution* of an experiment also gets a random UUID4 (``experiment_uuid``).
The human ID is the same for every repetition of the same design cell. The UUID
tells apart individual executions, including retries after a failure. Both are
recorded.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

ATTACK_CODES = {"none": "CLEAN", "label_flip": "LF", "backdoor": "BD"}
PIPELINE_CODES = {"conventional": "A", "provenance": "B", "forensic": "C"}

_ID_PATTERN = re.compile(
    r"^EXP-(?P<attack>CLEAN|LF|BD)-(?P<pipeline>[ABC])-(?P<rate>\d{2,})-S(?P<seed>\d{3,})$"
)


def rate_to_percent_code(poison_rate: float) -> str:
    """0.05 -> '05', 0.10 -> '10', 0.0 -> '00'. Non-integer percentages are rejected
    rather than silently rounded, so two different rates never share an ID."""
    percent = round(poison_rate * 100, 9)
    if percent < 0 or percent >= 100 or percent != int(percent):
        raise ValueError(
            f"poison_rate {poison_rate!r} must be a whole percentage in [0, 100) for experiment IDs"
        )
    return f"{int(percent):02d}"


def build_experiment_id(attack_type: str, pipeline_mode: str, poison_rate: float, seed: int) -> str:
    try:
        attack = ATTACK_CODES[attack_type]
        pipeline = PIPELINE_CODES[pipeline_mode]
    except KeyError as exc:
        raise ValueError(f"unknown attack/pipeline: {exc}") from exc
    if attack == "CLEAN" and poison_rate != 0:
        raise ValueError("clean experiments must have poison_rate 0")
    if attack != "CLEAN" and poison_rate <= 0:
        raise ValueError("attack experiments must have poison_rate > 0")
    if not isinstance(seed, int) or seed < 0:
        raise ValueError(f"seed must be a non-negative int, got {seed!r}")
    return f"EXP-{attack}-{pipeline}-{rate_to_percent_code(poison_rate)}-S{seed:03d}"


def parse_experiment_id(experiment_id: str) -> dict[str, Any]:
    """Inverse of build_experiment_id (returns attack_type, pipeline_mode, poison_rate, seed)."""
    match = _ID_PATTERN.match(experiment_id)
    if not match:
        raise ValueError(f"not a valid experiment ID: {experiment_id!r}")
    attack = {v: k for k, v in ATTACK_CODES.items()}[match["attack"]]
    pipeline = {v: k for k, v in PIPELINE_CODES.items()}[match["pipeline"]]
    return {
        "attack_type": attack,
        "pipeline_mode": pipeline,
        "poison_rate": int(match["rate"]) / 100,
        "seed": int(match["seed"]),
    }


@dataclass(frozen=True)
class ExperimentIdentity:
    experiment_id: str
    experiment_uuid: str

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> ExperimentIdentity:
        return cls(
            experiment_id=build_experiment_id(
                attack_type=config["attack"]["type"],
                pipeline_mode=config["pipeline"]["mode"],
                poison_rate=config["attack"]["poison_rate"],
                seed=config["experiment"]["seed"],
            ),
            experiment_uuid=str(uuid.uuid4()),
        )

    def as_dict(self) -> dict[str, str]:
        return {"experiment_id": self.experiment_id, "experiment_uuid": self.experiment_uuid}
