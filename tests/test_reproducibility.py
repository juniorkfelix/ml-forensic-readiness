"""Phase 2: seeding, determinism configuration and environment manifests."""

import json
import random
import socket
from pathlib import Path

import numpy as np
import torch

from mlfref.config import compose_run_config, config_hash
from mlfref.experiment_id import ExperimentIdentity
from mlfref.reproducibility import (
    collect_environment,
    configure_determinism,
    initialise_run,
    make_generator,
    save_environment_manifest,
    seed_everything,
)

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"


def _draw():
    return (
        random.random(),
        float(np.random.rand()),
        torch.rand(3).tolist(),
    )


def test_same_seed_same_random_streams():
    seed_everything(123)
    first = _draw()
    seed_everything(123)
    assert _draw() == first


def test_different_seed_different_random_streams():
    seed_everything(1)
    a = _draw()
    seed_everything(2)
    assert _draw() != a


def test_generator_is_independent_of_global_state():
    g1 = make_generator(7)
    torch.manual_seed(999)
    torch.rand(10)  # consume global RNG
    g2 = make_generator(7)
    assert torch.equal(torch.randperm(100, generator=g1), torch.randperm(100, generator=g2))


def test_same_seed_same_model_initialisation():
    seed_everything(5)
    a = torch.nn.Linear(16, 4).weight.detach().clone()
    seed_everything(5)
    b = torch.nn.Linear(16, 4).weight.detach().clone()
    assert torch.equal(a, b)


def test_configure_determinism_records_settings():
    record = configure_determinism(deterministic=True, cudnn_benchmark=False, warn_only=True)
    assert record["deterministic_algorithms_enabled"] is True
    assert record["cudnn_deterministic"] is True
    assert record["cudnn_benchmark"] is False
    assert record["cublas_workspace_config"]
    assert any("warn_only" in n for n in record["notes"])


def test_environment_manifest_contents(tmp_path):
    cfg = compose_run_config(CONFIG_DIR, "A")
    identity = ExperimentIdentity.from_config(cfg).as_dict()
    manifest = collect_environment(cfg, identity)
    assert manifest["experiment"]["experiment_id"] == "EXP-CLEAN-A-00-S001"
    assert manifest["seed"] == cfg["experiment"]["seed"]
    assert manifest["config_sha256"] == config_hash(cfg)
    for key in ("python", "torch", "torchvision", "cuda_build"):
        assert key in manifest["software"]
    for key in ("cpu", "ram_total_gb", "cuda_available", "gpu"):
        assert key in manifest["hardware"]
    assert {"commit", "dirty"} <= manifest["git"].keys()
    assert len(manifest["machine_id"]) == 16

    path = save_environment_manifest(manifest, tmp_path / "env.json")
    text = path.read_text(encoding="utf-8")
    assert json.loads(text)["config_sha256"] == config_hash(cfg)
    # The raw hostname must not be written to the manifest.
    assert socket.gethostname() not in text


def test_initialise_run_returns_device_and_manifest():
    cfg = compose_run_config(CONFIG_DIR, "A", overrides=["training.device=cpu"])
    device, manifest = initialise_run(cfg)
    assert device.type == "cpu"
    assert manifest["device"] == "cpu"
    assert manifest["determinism"]["deterministic_algorithms_enabled"] is True
