"""Phase 2: layered configuration loading, validation and hashing."""

from pathlib import Path

import pytest
import yaml

from mlfref.config import (
    ConfigError,
    compose_run_config,
    config_hash,
    deep_merge,
    load_config,
    save_resolved_config,
)

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"


def test_deep_merge_does_not_mutate_inputs():
    base = {"a": {"x": 1, "y": 2}, "b": [1, 2]}
    override = {"a": {"y": 3}, "b": [9]}
    merged = deep_merge(base, override)
    assert merged == {"a": {"x": 1, "y": 3}, "b": [9]}
    assert base == {"a": {"x": 1, "y": 2}, "b": [1, 2]}


@pytest.mark.parametrize(
    "file_name, mode, mlflow_on, forensic_on",
    [
        ("baseline.yaml", "conventional", False, False),
        ("provenance.yaml", "provenance", True, False),
        ("forensic.yaml", "forensic", True, True),
    ],
)
def test_pipeline_overlays(file_name, mode, mlflow_on, forensic_on):
    cfg = load_config(CONFIG_DIR / file_name)
    assert cfg["pipeline"]["mode"] == mode
    assert cfg["mlflow"]["enabled"] is mlflow_on
    assert cfg["evidence"]["forensic_enabled"] is forensic_on
    assert cfg["attack"]["type"] == "none"
    # ML hyper-parameters are shared: the pipelines differ only in instrumentation.
    base = load_config(CONFIG_DIR / "experiment.yaml")
    for section in ("dataset", "model", "training", "reproducibility"):
        assert cfg[section] == base[section]


def test_attack_overlay_does_not_reset_pipeline_mode():
    """The attack overlay also extends experiment.yaml; the defaults must not be re-applied
    over the pipeline overlay."""
    cfg = compose_run_config(CONFIG_DIR, "forensic", "pilot_label_flip.yaml")
    assert cfg["pipeline"]["mode"] == "forensic"
    assert cfg["evidence"]["forensic_enabled"] is True
    assert cfg["attack"]["type"] == "label_flip"
    assert cfg["_meta"]["layers"] == ["experiment.yaml", "forensic.yaml", "pilot_label_flip.yaml"]


def test_cli_overrides_parse_yaml_scalars():
    cfg = compose_run_config(
        CONFIG_DIR,
        "C",
        "pilot_backdoor.yaml",
        overrides=["attack.poison_rate=0.1", "experiment.seed=3"],
    )
    assert cfg["attack"]["poison_rate"] == 0.1
    assert cfg["experiment"]["seed"] == 3


def test_inconsistent_pipeline_mode_rejected():
    with pytest.raises(ConfigError, match="requires mlflow.enabled"):
        load_config(CONFIG_DIR / "provenance.yaml", overrides=["mlflow.enabled=false"])


@pytest.mark.parametrize(
    "overrides",
    [
        ["attack.poison_rate=0.05"],  # rate without attack
        ["experiment.seed=-1"],
        ["training.device=tpu"],
        ["training.epochs=0"],
    ],
)
def test_invalid_values_rejected(overrides):
    with pytest.raises(ConfigError):
        load_config(CONFIG_DIR / "baseline.yaml", overrides=overrides)


def test_label_flip_same_class_rejected():
    with pytest.raises(ConfigError):
        compose_run_config(
            CONFIG_DIR, "A", "pilot_label_flip.yaml", overrides=["attack.target_class=automobile"]
        )


def test_config_hash_deterministic_and_sensitive():
    a = load_config(CONFIG_DIR / "baseline.yaml")
    b = load_config(CONFIG_DIR / "baseline.yaml")
    assert config_hash(a) == config_hash(b)
    assert len(config_hash(a)) == 64
    c = load_config(CONFIG_DIR / "baseline.yaml", overrides=["training.learning_rate=0.05"])
    assert config_hash(a) != config_hash(c)


def test_config_hash_ignores_meta_and_key_order():
    a = load_config(CONFIG_DIR / "baseline.yaml")
    reordered = {k: a[k] for k in reversed(list(a))}
    reordered["_meta"] = {"layers": ["something-else"]}
    assert config_hash(a) == config_hash(reordered)


def test_circular_extends_rejected(tmp_path):
    (tmp_path / "x.yaml").write_text("extends: y.yaml\n")
    (tmp_path / "y.yaml").write_text("extends: x.yaml\n")
    with pytest.raises(ConfigError, match="circular"):
        load_config(tmp_path / "x.yaml", validate=False)


def test_saved_config_round_trips(tmp_path):
    cfg = compose_run_config(CONFIG_DIR, "B", "pilot_label_flip.yaml")
    path = save_resolved_config(cfg, tmp_path / "config.yaml")
    reloaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert reloaded["_meta"]["config_sha256"] == config_hash(cfg)
    assert config_hash(reloaded) == config_hash(cfg)
