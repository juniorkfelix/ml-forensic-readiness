"""ResNet-18 for CIFAR-10 (torchvision implementation, adapted for 32x32 inputs).

Architecture changes relative to torchvision ``resnet18`` (applied when
``model.cifar_stem: true``, the default):

* ``conv1``: 7x7 stride-2 convolution  ->  **3x3 stride-1** convolution (64 filters,
  padding 1, no bias). Reason: a 7x7/2 stem followed by max-pooling reduces a 32x32
  image to 8x8 before the first residual stage, discarding most spatial information.
* ``maxpool``: 3x3 stride-2 max-pool  ->  **removed** (``nn.Identity``).
* ``fc``: 1000 outputs -> ``num_classes`` (10) outputs.

Everything else (four residual stages of two BasicBlocks with 64/128/256/512
channels, batch normalisation, global average pooling) is unchanged. This is the
common "CIFAR ResNet-18" variant. Weights are randomly initialised (training from
scratch) unless ``model.pretrained: true``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import torch
from torch import nn
from torchvision.models import ResNet18_Weights, resnet18


def build_resnet18(
    num_classes: int = 10, cifar_stem: bool = True, pretrained: bool = False
) -> nn.Module:
    if pretrained:
        # Downloads ImageNet weights; only when explicitly configured.
        model = resnet18(weights=ResNet18_Weights.IMAGENET1K_V1)
        model.fc = nn.Linear(model.fc.in_features, num_classes)
    else:
        model = resnet18(weights=None, num_classes=num_classes)
    if cifar_stem:
        model.conv1 = nn.Conv2d(3, 64, kernel_size=3, stride=1, padding=1, bias=False)
        model.maxpool = nn.Identity()
    return model


def build_model(model_cfg: Mapping[str, Any]) -> nn.Module:
    if model_cfg["architecture"] != "resnet18":
        raise ValueError(f"unsupported architecture {model_cfg['architecture']!r}")
    return build_resnet18(
        num_classes=model_cfg["num_classes"],
        cifar_stem=model_cfg.get("cifar_stem", True),
        pretrained=model_cfg.get("pretrained", False),
    )


def architecture_record(model: nn.Module, model_cfg: Mapping[str, Any]) -> dict[str, Any]:
    """Architecture configuration recorded with every run."""
    n_params = sum(p.numel() for p in model.parameters())
    n_trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    conv1 = model.conv1
    return {
        "architecture": model_cfg["architecture"],
        "implementation": "torchvision.models.resnet18",
        "num_classes": model_cfg["num_classes"],
        "pretrained": bool(model_cfg.get("pretrained", False)),
        "cifar_stem": bool(model_cfg.get("cifar_stem", True)),
        "conv1": {
            "kernel_size": list(conv1.kernel_size),
            "stride": list(conv1.stride),
            "padding": list(conv1.padding),
        },
        "maxpool": type(model.maxpool).__name__,
        "parameters_total": n_params,
        "parameters_trainable": n_trainable,
        "modifications": (
            ["conv1 7x7/2 -> 3x3/1", "maxpool removed", f"fc -> {model_cfg['num_classes']}"]
            if model_cfg.get("cifar_stem", True)
            else [f"fc -> {model_cfg['num_classes']}"]
        ),
    }


def count_parameters(model: nn.Module) -> int:
    return sum(p.numel() for p in model.parameters())


@torch.no_grad()
def output_shape(model: nn.Module, device: torch.device | str = "cpu") -> tuple[int, ...]:
    model.eval()
    return tuple(model(torch.zeros(2, 3, 32, 32, device=device)).shape)
