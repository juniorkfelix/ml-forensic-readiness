"""Layered YAML configuration loading, validation and hashing.

Composition order (later layers override earlier ones):

    experiment.yaml  ->  pipeline overlay  ->  attack overlay  ->  CLI overrides

Each YAML file may declare ``extends: <relative path>``. When several files are
composed, their ``extends`` chains are flattened in order and each file is applied
at most once. So an attack overlay that also extends ``experiment.yaml`` does not
re-apply the defaults over the pipeline overlay.

The resolved configuration is hashed as SHA-256 over canonical JSON (sorted keys,
no insignificant whitespace). This hash is the *experiment configuration hash*
recorded in environment manifests.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

from mlfref.forensic.hashing import canonical_json

EXTENDS_KEY = "extends"

PIPELINE_MODES = ("conventional", "provenance", "forensic")
ATTACK_TYPES = ("none", "label_flip", "backdoor")
CIFAR10_CLASSES = (
    "airplane",
    "automobile",
    "bird",
    "cat",
    "deer",
    "dog",
    "frog",
    "horse",
    "ship",
    "truck",
)

# Expected behaviour of each pipeline mode. validate_config() rejects a config
# whose evidence switches contradict its declared mode, so that a mis-composed
# config cannot silently change the independent variable.
PIPELINE_EXPECTATIONS = {
    "conventional": {"mlflow.enabled": False, "evidence.forensic_enabled": False},
    "provenance": {"mlflow.enabled": True, "evidence.forensic_enabled": False},
    "forensic": {"mlflow.enabled": True, "evidence.forensic_enabled": True},
}

# Pipeline-name aliases accepted on the command line.
PIPELINE_ALIASES = {
    "a": "conventional",
    "conventional": "conventional",
    "baseline": "conventional",
    "b": "provenance",
    "provenance": "provenance",
    "c": "forensic",
    "forensic": "forensic",
    "forensic_ready": "forensic",
}
PIPELINE_CONFIG_FILES = {
    "conventional": "baseline.yaml",
    "provenance": "provenance.yaml",
    "forensic": "forensic.yaml",
}


class ConfigError(ValueError):
    """Raised for an invalid or inconsistent configuration."""


# --------------------------------------------------------------------------- merging


def deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    """Return a new dict: ``override`` recursively merged over ``base``.

    Mappings are merged key by key; any other value (including lists) in
    ``override`` replaces the value in ``base``.
    """
    result = copy.deepcopy(dict(base))
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return data


def _extends_chain(path: Path, _seen: tuple[Path, ...] = ()) -> list[Path]:
    """Return [root ancestor, ..., path] following ``extends`` links."""
    path = path.resolve()
    if path in _seen:
        raise ConfigError(f"circular 'extends' involving {path}")
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    parent = _read_yaml(path).get(EXTENDS_KEY)
    if parent is None:
        return [path]
    return _extends_chain(path.parent / parent, _seen + (path,)) + [path]


def resolve_layers(config_paths: Iterable[str | Path]) -> list[Path]:
    """Flatten the ``extends`` chains of several files, applying each file once."""
    layers: list[Path] = []
    for p in config_paths:
        for layer in _extends_chain(Path(p)):
            if layer not in layers:
                layers.append(layer)
    return layers


def _parse_override(item: str) -> tuple[list[str], Any]:
    """Parse ``a.b.c=value``; the value is parsed as YAML (so 0.05 -> float)."""
    if "=" not in item:
        raise ConfigError(f"override must be key=value, got {item!r}")
    key, raw = item.split("=", 1)
    key = key.strip()
    if not key:
        raise ConfigError(f"empty override key in {item!r}")
    return key.split("."), yaml.safe_load(raw)


def apply_overrides(config: Mapping[str, Any], overrides: Iterable[str] | None) -> dict[str, Any]:
    result = copy.deepcopy(dict(config))
    for item in overrides or []:
        keys, value = _parse_override(item)
        node = result
        for k in keys[:-1]:
            if not isinstance(node.get(k), dict):
                node[k] = {}
            node = node[k]
        node[keys[-1]] = value
    return result


# --------------------------------------------------------------------------- public API


def load_config(
    config_paths: str | Path | Iterable[str | Path],
    overrides: Iterable[str] | None = None,
    validate: bool = True,
) -> dict[str, Any]:
    """Load, compose, override and (optionally) validate a configuration.

    Returns the resolved config. The ``_meta`` key records the source layers and
    overrides for the archive; ``_meta`` is excluded from the configuration hash.
    """
    if isinstance(config_paths, (str, Path)):
        config_paths = [config_paths]
    layers = resolve_layers(config_paths)

    config: dict[str, Any] = {}
    for layer in layers:
        data = _read_yaml(layer)
        data.pop(EXTENDS_KEY, None)
        config = deep_merge(config, data)

    overrides = list(overrides or [])
    config = apply_overrides(config, overrides)

    if validate:
        validate_config(config)

    config["_meta"] = {
        "layers": [layer.name for layer in layers],
        "overrides": overrides,
    }
    return config


def compose_run_config(
    config_dir: str | Path,
    pipeline: str,
    attack_config: str | Path | None = None,
    overrides: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Convenience: experiment.yaml -> pipeline overlay -> [attack overlay] -> overrides."""
    config_dir = Path(config_dir)
    mode = normalise_pipeline(pipeline)
    paths: list[Path] = [config_dir / PIPELINE_CONFIG_FILES[mode]]
    if attack_config is not None:
        attack_path = Path(attack_config)
        paths.append(attack_path if attack_path.is_absolute() else config_dir / attack_path)
    return load_config(paths, overrides)


def normalise_pipeline(name: str) -> str:
    try:
        return PIPELINE_ALIASES[name.strip().lower()]
    except KeyError as exc:
        raise ConfigError(
            f"unknown pipeline {name!r}; expected one of {sorted(set(PIPELINE_ALIASES))}"
        ) from exc


def _get(config: Mapping[str, Any], dotted: str) -> Any:
    node: Any = config
    for key in dotted.split("."):
        if not isinstance(node, Mapping) or key not in node:
            raise ConfigError(f"missing required config key: {dotted}")
        node = node[key]
    return node


def validate_config(config: Mapping[str, Any]) -> None:
    """Check required keys, value ranges and pipeline-mode consistency."""
    seed = _get(config, "experiment.seed")
    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise ConfigError(f"experiment.seed must be a non-negative integer, got {seed!r}")

    mode = _get(config, "pipeline.mode")
    if mode not in PIPELINE_MODES:
        raise ConfigError(f"pipeline.mode must be one of {PIPELINE_MODES}, got {mode!r}")
    for key, expected in PIPELINE_EXPECTATIONS[mode].items():
        actual = _get(config, key)
        if actual is not expected:
            raise ConfigError(f"pipeline.mode={mode!r} requires {key}={expected}, got {actual!r}")

    attack = _get(config, "attack.type")
    if attack not in ATTACK_TYPES:
        raise ConfigError(f"attack.type must be one of {ATTACK_TYPES}, got {attack!r}")
    rate = _get(config, "attack.poison_rate")
    if not isinstance(rate, (int, float)) or isinstance(rate, bool) or not 0.0 <= rate < 1.0:
        raise ConfigError(f"attack.poison_rate must be in [0, 1), got {rate!r}")
    if attack == "none" and rate != 0:
        raise ConfigError("attack.type='none' requires attack.poison_rate=0")
    if attack != "none" and rate <= 0:
        raise ConfigError(f"attack.type={attack!r} requires attack.poison_rate > 0")

    if attack == "label_flip":
        src, tgt = _get(config, "attack.source_class"), _get(config, "attack.target_class")
        for name in (src, tgt):
            if name not in CIFAR10_CLASSES:
                raise ConfigError(f"unknown CIFAR-10 class {name!r}")
        if src == tgt:
            raise ConfigError("label_flip source_class and target_class must differ")
    if attack == "backdoor":
        if _get(config, "attack.target_class") not in CIFAR10_CLASSES:
            raise ConfigError(f"unknown CIFAR-10 class {config['attack']['target_class']!r}")
        size = _get(config, "attack.trigger.size")
        if not isinstance(size, int) or not 1 <= size <= 16:
            raise ConfigError(f"attack.trigger.size must be an int in [1, 16], got {size!r}")

    for key in ("training.epochs", "training.batch_size"):
        value = _get(config, key)
        if not isinstance(value, int) or value < 1:
            raise ConfigError(f"{key} must be a positive integer, got {value!r}")
    lr = _get(config, "training.learning_rate")
    if not isinstance(lr, (int, float)) or lr <= 0:
        raise ConfigError(f"training.learning_rate must be > 0, got {lr!r}")
    device = _get(config, "training.device")
    if device not in ("auto", "cuda", "cpu"):
        raise ConfigError(f"training.device must be auto|cuda|cpu, got {device!r}")


def config_hash(config: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical resolved configuration, excluding ``_meta``."""
    payload = {k: v for k, v in config.items() if k != "_meta"}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def save_resolved_config(config: Mapping[str, Any], path: str | Path) -> Path:
    """Archive the exact resolved configuration (YAML) alongside its hash."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    archived = dict(config)
    archived["_meta"] = {**config.get("_meta", {}), "config_sha256": config_hash(config)}
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(archived, fh, sort_keys=False, default_flow_style=False)
    return path
