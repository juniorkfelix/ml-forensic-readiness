"""Saving/loading model artefacts.

Models are saved as ``state_dict`` files with ``torch.save``. The saved file is the
model artefact whose SHA-256 identifies the model (spec §10). Whether that hash is
also *recorded as evidence* depends on the pipeline mode (not in A).
"""

from __future__ import annotations

import io
from pathlib import Path

import torch
from torch import nn


def model_bytes(model: nn.Module) -> bytes:
    """Serialise the state_dict to bytes that depend only on the weights.

    ``torch.save(obj, path)`` names the zip archive's internal root folder after the
    target file, so identical weights saved under different file names produce
    different bytes and different SHA-256 hashes. Saving to an in-memory buffer uses
    a fixed archive name, so the bytes, and therefore the model hash, depend on
    content only and survive copying or renaming at deployment.
    """
    buffer = io.BytesIO()
    torch.save({k: v.detach().cpu() for k, v in model.state_dict().items()}, buffer)
    return buffer.getvalue()


def save_model(model: nn.Module, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(model_bytes(model))
    return path


def load_model_state(model: nn.Module, path: str | Path, device: torch.device | str) -> nn.Module:
    state = torch.load(Path(path), map_location=device, weights_only=True)
    model.load_state_dict(state)
    return model.to(device)
