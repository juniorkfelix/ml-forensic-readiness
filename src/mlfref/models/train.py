"""Training loop shared by all pipeline modes.

Pipelines differ only in the ``TrainingHooks`` attached. Pipeline A uses the no-op
base class; B/C attach MLflow and forensic hooks (Phases 10-11). The optimisation
itself is identical in every mode.

Test-set use: the clean test set is evaluated after each epoch for *monitoring
only* (the training curve). It is never used for model selection, early stopping
or hyper-parameter tuning, and the model kept is always the final-epoch model, so
no test information flows into training.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import torch
from torch import nn

from mlfref.data.cifar import Augmentation, TensorBatches
from mlfref.logging_utils import get_logger
from mlfref.models.evaluate import evaluate

log = get_logger("pipeline.train")


class TrainingHooks:
    """Instrumentation points. Default: do nothing (pipeline A)."""

    def on_train_start(self, info: Mapping[str, Any]) -> None: ...

    def on_epoch_end(self, record: Mapping[str, Any]) -> None: ...

    def on_train_end(self, info: Mapping[str, Any]) -> None: ...


@dataclass
class TrainingResult:
    history: list[dict[str, Any]] = field(default_factory=list)
    training_seconds: float = 0.0  # wall clock: start hook + epoch loop (excl. end hook)
    monitoring_eval_seconds: float = 0.0  # part of training_seconds spent on per-epoch test eval
    hook_seconds: float = 0.0  # part of training_seconds spent inside hooks


def build_optimizer(model: nn.Module, cfg: Mapping[str, Any]) -> torch.optim.Optimizer:
    name = cfg["optimizer"].lower()
    if name == "sgd":
        return torch.optim.SGD(
            model.parameters(),
            lr=cfg["learning_rate"],
            momentum=cfg.get("momentum", 0.0),
            weight_decay=cfg.get("weight_decay", 0.0),
            nesterov=cfg.get("nesterov", False),
        )
    if name == "adam":
        return torch.optim.Adam(
            model.parameters(), lr=cfg["learning_rate"], weight_decay=cfg.get("weight_decay", 0.0)
        )
    raise ValueError(f"unsupported optimizer {name!r}")


def build_scheduler(optimizer: torch.optim.Optimizer, cfg: Mapping[str, Any]):
    name = (cfg.get("lr_scheduler") or "none").lower()
    if name == "cosine":
        return torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=cfg["epochs"])
    if name == "none":
        return None
    raise ValueError(f"unsupported lr_scheduler {name!r}")


def build_loss(cfg: Mapping[str, Any]) -> nn.Module:
    if cfg.get("loss", "cross_entropy") != "cross_entropy":
        raise ValueError(f"unsupported loss {cfg['loss']!r}")
    return nn.CrossEntropyLoss()


def train_model(
    model: nn.Module,
    train_data: TensorBatches,
    train_cfg: Mapping[str, Any],
    generator: torch.Generator,
    monitor_data: TensorBatches | None = None,
    hooks: TrainingHooks | None = None,
) -> TrainingResult:
    """Train ``model`` in place. ``generator`` (seeded, CPU) drives shuffling/augmentation."""
    hooks = hooks or TrainingHooks()
    device = train_data.device
    amp = bool(train_cfg.get("amp", False)) and device.type == "cuda"
    epochs, batch_size = train_cfg["epochs"], train_cfg["batch_size"]
    augmentation = Augmentation.from_config(train_cfg.get("augmentation"))
    optimizer = build_optimizer(model, train_cfg)
    scheduler = build_scheduler(optimizer, train_cfg)
    criterion = build_loss(train_cfg)
    scaler = torch.amp.GradScaler("cuda", enabled=amp)

    result = TrainingResult()
    t_start = time.perf_counter()
    h0 = time.perf_counter()
    hooks.on_train_start({"epochs": epochs, "batch_size": batch_size, "amp": amp})
    result.hook_seconds += time.perf_counter() - h0

    for epoch in range(1, epochs + 1):
        model.train()
        t_epoch = time.perf_counter()
        loss_sum = torch.zeros((), device=device)
        correct = torch.zeros((), device=device, dtype=torch.long)
        seen = 0
        for x, y, _ in train_data.iterate(batch_size, True, generator, augmentation):
            optimizer.zero_grad(set_to_none=True)
            with torch.autocast(device_type=device.type, enabled=amp):
                logits = model(x)
                loss = criterion(logits, y)
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()
            loss_sum += loss.detach() * y.shape[0]
            correct += (logits.argmax(1) == y).sum()
            seen += y.shape[0]
        lr = optimizer.param_groups[0]["lr"]
        if scheduler is not None:
            scheduler.step()
        if device.type == "cuda":
            torch.cuda.synchronize()
        train_seconds = time.perf_counter() - t_epoch

        record: dict[str, Any] = {
            "epoch": epoch,
            "train_loss": float(loss_sum) / seen,
            "train_accuracy": int(correct) / seen,
            "learning_rate": lr,
            "epoch_train_seconds": train_seconds,
        }
        if monitor_data is not None:
            t_eval = time.perf_counter()
            ev = evaluate(model, monitor_data, amp=amp)
            eval_seconds = time.perf_counter() - t_eval
            result.monitoring_eval_seconds += eval_seconds
            record.update(
                {
                    "test_loss": ev.loss,
                    "test_accuracy": ev.accuracy,
                    "epoch_eval_seconds": eval_seconds,
                }
            )
        result.history.append(record)
        log.info(
            "epoch %d/%d train_loss=%.4f train_acc=%.4f%s lr=%.5f (%.1fs)",
            epoch,
            epochs,
            record["train_loss"],
            record["train_accuracy"],
            f" test_acc={record['test_accuracy']:.4f}" if "test_accuracy" in record else "",
            lr,
            train_seconds,
        )
        h0 = time.perf_counter()
        hooks.on_epoch_end(record)
        result.hook_seconds += time.perf_counter() - h0

    result.training_seconds = time.perf_counter() - t_start
    h0 = time.perf_counter()
    hooks.on_train_end({"training_seconds": result.training_seconds, "history": result.history})
    result.hook_seconds += time.perf_counter() - h0
    return result
