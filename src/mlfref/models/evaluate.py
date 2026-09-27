"""Model evaluation: loss, accuracy, per-class accuracy, confusion matrix, predictions.

Clean Accuracy (CA) = correct clean predictions / total clean predictions.
(Attack Success Rate is added in Phase 9.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np
import torch
from torch import nn

from mlfref.config import CIFAR10_CLASSES
from mlfref.data.cifar import TensorBatches


@dataclass
class EvalResult:
    loss: float
    accuracy: float
    n: int
    correct: int
    predictions: np.ndarray = field(repr=False)  # int64 [N]
    confidences: np.ndarray = field(repr=False)  # float32 [N] max softmax probability
    labels: np.ndarray = field(repr=False)  # int64 [N]
    sample_ids: np.ndarray = field(repr=False)  # int64 [N]

    def confusion_matrix(self, num_classes: int = len(CIFAR10_CLASSES)) -> np.ndarray:
        cm = np.zeros((num_classes, num_classes), dtype=np.int64)
        np.add.at(cm, (self.labels, self.predictions), 1)
        return cm  # rows = true class, columns = predicted class

    def per_class_accuracy(self) -> dict[str, float]:
        cm = self.confusion_matrix()
        totals = cm.sum(axis=1)
        return {
            name: float(cm[i, i] / totals[i]) if totals[i] else float("nan")
            for i, name in enumerate(CIFAR10_CLASSES)
        }

    def summary(self) -> dict[str, Any]:
        return {
            "loss": self.loss,
            "accuracy": self.accuracy,
            "n": self.n,
            "correct": self.correct,
            "per_class_accuracy": self.per_class_accuracy(),
        }


@torch.no_grad()
def evaluate(
    model: nn.Module, data: TensorBatches, batch_size: int = 512, amp: bool = False
) -> EvalResult:
    model.eval()
    criterion = nn.CrossEntropyLoss(reduction="sum")
    total_loss, preds, confs, labels, ids = 0.0, [], [], [], []
    device_type = data.device.type
    for x, y, sid in data.iterate(batch_size):
        with torch.autocast(device_type=device_type, enabled=amp and device_type == "cuda"):
            logits = model(x)
        logits = logits.float()
        total_loss += float(criterion(logits, y))
        prob = torch.softmax(logits, dim=1)
        conf, pred = prob.max(dim=1)
        preds.append(pred.cpu())
        confs.append(conf.cpu())
        labels.append(y.cpu())
        ids.append(sid)
    predictions = torch.cat(preds).numpy().astype(np.int64)
    label_arr = torch.cat(labels).numpy().astype(np.int64)
    correct = int((predictions == label_arr).sum())
    n = len(label_arr)
    return EvalResult(
        loss=total_loss / n,
        accuracy=correct / n,
        n=n,
        correct=correct,
        predictions=predictions,
        confidences=torch.cat(confs).numpy().astype(np.float32),
        labels=label_arr,
        sample_ids=torch.cat(ids).numpy().astype(np.int64),
    )
