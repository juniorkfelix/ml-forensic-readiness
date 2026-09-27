"""Phase 10: MLflow provenance tracking (pipeline B/C) and PROV-style lineage."""

from __future__ import annotations

import json
import re

import numpy as np
import pytest
import torch

from mlfref.config import compose_run_config
from mlfref.data.cifar import CifarArrays, TensorBatches
from mlfref.models.resnet import architecture_record, build_model
from mlfref.models.train import train_model
from mlfref.provenance.lineage import ProvGraph, lineage_from_mlflow
from mlfref.provenance.mlflow_tracker import (
    PRODUCTION_ALIAS,
    REGISTERED_MODEL_NAME,
    MlflowTracker,
    resolve_tracking_uri,
)
from mlfref.reproducibility import make_generator, seed_everything

# Word-level patterns ("horizontal_flip" is a legitimate augmentation parameter).
ATTACK_PATTERNS = (
    r"attack",
    r"poison",
    r"label_flip",
    r"flipped",
    r"backdoor",
    r"trigger",
    r"\basr\b",
)


def _arrays(n=48, seed=0) -> CifarArrays:
    rng = np.random.default_rng(seed)
    return CifarArrays(
        rng.integers(0, 256, (n, 32, 32, 3), dtype=np.uint8),
        rng.integers(0, 10, n).astype(np.int64),
        np.arange(n, dtype=np.int64),
    )


@pytest.fixture()
def tracker(tmp_path):
    uri = f"sqlite:///{(tmp_path / 'mlflow.db').as_posix()}"
    return MlflowTracker(
        uri, "test-exp", tmp_path / "artifacts", "RUN-1234abcd", "provenance", git_commit="deadbeef"
    )


@pytest.fixture()
def tiny_cfg():
    cfg = compose_run_config(
        __import__("pathlib").Path(__file__).resolve().parents[1] / "config",
        "B",
        overrides=[
            "training.epochs=2",
            "training.batch_size=16",
            "training.device=cpu",
            "training.amp=false",
        ],
    )
    return cfg


def _full_run(tracker, cfg, train, test):
    tracker.log_data_registration(train, "cifar10_train", "data/store/train.npz")
    seed_everything(0)
    model = build_model(cfg["model"])
    arch = architecture_record(model, cfg["model"])
    tracker.start_training_run(
        train,
        "cifar10_train",
        "data/store/train.npz",
        test,
        "cifar10_test",
        "data/clean/test.npz",
        cfg,
        arch,
    )
    train_model(
        model,
        TensorBatches(train, "cpu"),
        cfg["training"],
        make_generator(0),
        monitor_data=TensorBatches(test, "cpu"),
        hooks=tracker.hooks(),
    )
    tracker.log_final_metrics({"clean_accuracy": 0.5})
    info = tracker.log_model(model)
    tracker.end_training_run()
    return info


def test_mlflow_logging(tracker, tiny_cfg):
    train, test = _arrays(), _arrays(24, seed=1)
    info = _full_run(tracker, tiny_cfg, train, test)
    client = tracker.client
    run = client.get_run(tracker.training_run_id)

    # parameters, tags, metrics
    assert run.data.params["epochs"] == "2" and run.data.params["seed"] == str(
        tiny_cfg["experiment"]["seed"]
    )
    assert run.data.params["model_architecture"] == "resnet18"
    assert run.data.tags["run_ref"] == "RUN-1234abcd"
    assert run.data.tags["mlflow.source.git.commit"] == "deadbeef"
    history = client.get_metric_history(run.info.run_id, "train_loss")
    assert [m.step for m in history] == [1, 2]
    assert run.data.metrics["clean_accuracy"] == 0.5
    assert run.info.start_time and run.info.end_time

    # dataset inputs with contexts, digests and profiles
    contexts = {
        next(t.value for t in d.tags if t.key == "mlflow.data.context"): d.dataset
        for d in run.inputs.dataset_inputs
    }
    assert set(contexts) == {"training", "evaluation"}
    assert contexts["training"].name == "cifar10_train"
    assert run.data.params["train_dataset_digest"] == contexts["training"].digest
    profiles = [a.path for a in client.list_artifacts(run.info.run_id, "data_profiles")]
    assert "data_profiles/training_data_profile.json" in profiles

    # registered model linked to the run
    assert info["registered_model_name"] == REGISTERED_MODEL_NAME
    mv = client.get_model_version(REGISTERED_MODEL_NAME, info["registered_model_version"])
    assert mv.run_id == tracker.training_run_id

    # deployment alias
    tracker.set_production_alias(info["registered_model_version"])
    alias_mv = client.get_model_version_by_alias(REGISTERED_MODEL_NAME, PRODUCTION_ALIAS)
    assert str(alias_mv.version) == info["registered_model_version"]


def test_no_attack_information_logged(tracker, tiny_cfg):
    """Covert-attack rule (D-014): nothing attack-related in params, tags or metrics."""
    _full_run(tracker, tiny_cfg, _arrays(), _arrays(24, 1))
    for run_id in (tracker.training_run_id, tracker.data_registration_run_id):
        run = tracker.client.get_run(run_id)
        blob = json.dumps(
            [run.data.params, run.data.tags, list(run.data.metrics)], default=str
        ).lower()
        for pattern in ATTACK_PATTERNS:
            assert not re.search(pattern, blob), pattern


def test_no_personal_information_in_mlflow_tags(tracker, tiny_cfg):
    """MLflow's automatic user/source tags are replaced (spec §32/§39)."""
    import getpass

    _full_run(tracker, tiny_cfg, _arrays(), _arrays(24, 1))
    user = getpass.getuser().lower()
    for run_id in (tracker.training_run_id, tracker.data_registration_run_id):
        tags = tracker.client.get_run(run_id).data.tags
        assert tags["mlflow.user"] == "svc-ml-pipeline"
        assert "/" not in tags["mlflow.source.name"] and "\\" not in tags["mlflow.source.name"]
        assert user not in json.dumps(tags).lower()


def test_mlflow_native_digest_behaviour():
    """Documents a property of MLflow provenance (D-032): the native numpy digest covers only
    the first 10,000 flattened values of each array (plus shapes), so a label change beyond
    sample 10,000 does NOT change the digest, while one within the first 10,000 does."""
    import mlflow

    a = _arrays(12_000)
    late, early = a.labels.copy(), a.labels.copy()
    late[11_000] = (late[11_000] + 1) % 10
    early[5] = (early[5] + 1) % 10
    d = lambda labels: mlflow.data.from_numpy(a.images, targets=labels).digest  # noqa: E731
    assert d(late) == d(a.labels)
    assert d(early) != d(a.labels)


def test_data_registration_and_training_digests_differ_when_data_changes(tracker, tiny_cfg):
    train = _arrays()
    tracker.log_data_registration(train, "cifar10_train", "store")
    changed = CifarArrays(train.images, (train.labels + 1) % 10, train.sample_ids)
    seed_everything(0)
    model = build_model(tiny_cfg["model"])
    tracker.start_training_run(
        changed,
        "cifar10_train",
        "store",
        train,
        "test",
        "t",
        tiny_cfg,
        architecture_record(model, tiny_cfg["model"]),
    )
    tracker.end_training_run()
    graph = lineage_from_mlflow(tracker.client, tracker.training_run_id)
    digests = {a["digest"] for a in graph.nodes("entity").values() if a["name"] == "cifar10_train"}
    assert len(digests) == 2  # same name, two different recorded digests


def test_lineage_from_mlflow(tracker, tiny_cfg):
    info = _full_run(tracker, tiny_cfg, _arrays(), _arrays(24, 1))
    graph = lineage_from_mlflow(tracker.client, tracker.training_run_id)
    train_node = f"mlflow-run:{tracker.training_run_id}"
    model_node = f"model:{REGISTERED_MODEL_NAME}/v{info['registered_model_version']}"
    rels = graph.relations()
    assert (model_node, "WAS_GENERATED_BY", train_node) in rels
    used = [t for s, r, t in rels if s == train_node and r == "USED"]
    assert len(used) == 2
    reg_node = f"mlflow-run:{tracker.data_registration_run_id}"
    assert graph.nodes()[reg_node]["type"] == "data_registration"


def test_prov_graph_rules_and_round_trip(tmp_path):
    g = ProvGraph()
    g.add_entity("ds1", "dataset")
    g.add_entity("ds2", "dataset")
    g.add_activity("train", "training")
    g.add_entity("model", "model")
    g.relate("WAS_DERIVED_FROM", "ds2", "ds1")
    g.relate("USED", "train", "ds2")
    g.relate("WAS_GENERATED_BY", "model", "train")
    with pytest.raises(ValueError):
        g.relate("USED", "ds1", "train")  # wrong direction
    with pytest.raises(ValueError):
        g.relate("CAUSED", "train", "ds1")
    assert g.upstream("model") == {"train", "ds2", "ds1"}
    back = ProvGraph.from_dict(json.loads(g.save(tmp_path / "g.json").read_text()))
    assert back.relations() == g.relations()


def test_resolve_tracking_uri(tmp_path):
    uri = resolve_tracking_uri("sqlite:///mlruns/mlflow.db", tmp_path)
    assert uri == "sqlite:///" + (tmp_path / "mlruns" / "mlflow.db").resolve().as_posix()
    assert resolve_tracking_uri("http://server:5000", tmp_path) == "http://server:5000"


def test_hooks_do_not_change_training(tracker, tiny_cfg):
    """Instrumentation must not alter the ML outcome (single independent variable)."""
    train = _arrays()

    def run(hooks):
        seed_everything(3)
        model = build_model(tiny_cfg["model"])
        train_model(
            model,
            TensorBatches(train, "cpu"),
            {**tiny_cfg["training"], "epochs": 1},
            make_generator(3),
            hooks=hooks,
        )
        return model.state_dict()

    plain = run(None)
    tracker.start_training_run(
        train,
        "x",
        "x",
        train,
        "y",
        "y",
        tiny_cfg,
        architecture_record(build_model(tiny_cfg["model"]), tiny_cfg["model"]),
    )
    tracked = run(tracker.hooks())
    tracker.end_training_run()
    assert all(torch.allclose(plain[k].float(), tracked[k].float()) for k in plain)
