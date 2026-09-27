"""Phase 2: experiment identifiers."""

import uuid
from pathlib import Path

import pytest

from mlfref.config import compose_run_config
from mlfref.experiment_id import (
    ExperimentIdentity,
    build_experiment_id,
    parse_experiment_id,
    rate_to_percent_code,
)

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"


@pytest.mark.parametrize(
    "attack, pipeline, rate, seed, expected",
    [
        ("none", "conventional", 0.0, 1, "EXP-CLEAN-A-00-S001"),
        ("label_flip", "conventional", 0.05, 3, "EXP-LF-A-05-S003"),
        ("label_flip", "provenance", 0.05, 3, "EXP-LF-B-05-S003"),
        ("label_flip", "forensic", 0.05, 3, "EXP-LF-C-05-S003"),
        ("backdoor", "forensic", 0.10, 12, "EXP-BD-C-10-S012"),
        ("backdoor", "provenance", 0.01, 3, "EXP-BD-B-01-S003"),
    ],
)
def test_build_and_parse_round_trip(attack, pipeline, rate, seed, expected):
    exp_id = build_experiment_id(attack, pipeline, rate, seed)
    assert exp_id == expected
    parsed = parse_experiment_id(exp_id)
    assert parsed == {
        "attack_type": attack,
        "pipeline_mode": pipeline,
        "poison_rate": pytest.approx(rate),
        "seed": seed,
    }


@pytest.mark.parametrize("rate", [0.03, 0.07, 0.29, 0.1])
def test_float_rates_do_not_misround(rate):
    assert rate_to_percent_code(rate) == f"{round(rate * 100):02d}"


def test_non_integer_percentage_rejected():
    with pytest.raises(ValueError):
        rate_to_percent_code(0.025)


def test_inconsistent_attack_rate_rejected():
    with pytest.raises(ValueError):
        build_experiment_id("none", "conventional", 0.05, 1)
    with pytest.raises(ValueError):
        build_experiment_id("backdoor", "conventional", 0.0, 1)


def test_identity_from_config_has_unique_uuid_per_execution():
    cfg = compose_run_config(
        CONFIG_DIR, "forensic", "pilot_backdoor.yaml", overrides=["experiment.seed=3"]
    )
    first = ExperimentIdentity.from_config(cfg)
    second = ExperimentIdentity.from_config(cfg)
    assert first.experiment_id == second.experiment_id == "EXP-BD-C-05-S003"
    assert first.experiment_uuid != second.experiment_uuid
    assert uuid.UUID(first.experiment_uuid).version == 4
