"""Phase 4: ResNet-18 construction, training loop, evaluation and model hashing."""

from __future__ import annotations

import numpy as np
import pytest
import torch

from mlfref.data.cifar import CifarArrays, TensorBatches
from mlfref.forensic.hashing import sha256_file
from mlfref.models.artifacts import load_model_state, save_model
from mlfref.models.evaluate import evaluate
from mlfref.models.resnet import architecture_record, build_model, build_resnet18, output_shape
from mlfref.models.train import TrainingHooks, train_model
from mlfref.reproducibility import make_generator, seed_everything

MODEL_CFG = {"architecture": "resnet18", "num_classes": 10, "pretrained": False, "cifar_stem": True}
TRAIN_CFG = {
    "epochs": 2,
    "batch_size": 16,
    "optimizer": "sgd",
    "learning_rate": 0.05,
    "momentum": 0.9,
    "weight_decay": 5e-4,
    "lr_scheduler": "cosine",
    "loss": "cross_entropy",
    "augmentation": {"random_crop_padding": 4, "horizontal_flip": True},
}


def _tiny(n=64, seed=0) -> CifarArrays:
    """Learnable synthetic task: class = which colour channel is bright."""
    rng = np.random.default_rng(seed)
    labels = rng.integers(0, 3, n).astype(np.int64)
    images = rng.integers(0, 60, (n, 32, 32, 3), dtype=np.uint8)
    for i, c in enumerate(labels):
        images[i, :, :, c] += 180
    return CifarArrays(images, labels, np.arange(n, dtype=np.int64))


def test_cifar_stem_modifications():
    model = build_resnet18(cifar_stem=True)
    assert model.conv1.kernel_size == (3, 3) and model.conv1.stride == (1, 1)
    assert isinstance(model.maxpool, torch.nn.Identity)
    assert model.fc.out_features == 10
    assert output_shape(model) == (2, 10)
    rec = architecture_record(model, MODEL_CFG)
    assert rec["pretrained"] is False and "maxpool removed" in rec["modifications"]
    assert rec["parameters_total"] == 11_173_962  # standard CIFAR ResNet-18 count


def test_standard_stem_when_disabled():
    model = build_resnet18(cifar_stem=False)
    assert model.conv1.kernel_size == (7, 7)
    assert isinstance(model.maxpool, torch.nn.MaxPool2d)


def test_same_seed_same_initial_weights():
    seed_everything(11)
    a = build_model(MODEL_CFG).state_dict()
    seed_everything(11)
    b = build_model(MODEL_CFG).state_dict()
    assert all(torch.equal(a[k], b[k]) for k in a)


class _RecordingHooks(TrainingHooks):
    def __init__(self):
        self.calls = []

    def on_train_start(self, info):
        self.calls.append("start")

    def on_epoch_end(self, record):
        self.calls.append(f"epoch{record['epoch']}")

    def on_train_end(self, info):
        self.calls.append("end")


def test_training_runs_learns_and_calls_hooks():
    seed_everything(0)
    data = TensorBatches(_tiny(), "cpu")
    model = build_model(MODEL_CFG)
    hooks = _RecordingHooks()
    cfg = {**TRAIN_CFG, "epochs": 3}
    result = train_model(model, data, cfg, make_generator(0), monitor_data=data, hooks=hooks)
    assert hooks.calls == ["start", "epoch1", "epoch2", "epoch3", "end"]
    assert len(result.history) == 3
    assert {"train_loss", "test_accuracy", "learning_rate"} <= result.history[0].keys()
    assert result.history[-1]["train_loss"] < result.history[0]["train_loss"]


def test_training_is_reproducible_on_cpu():
    def run():
        seed_everything(5)
        model = build_model(MODEL_CFG)
        train_model(
            model, TensorBatches(_tiny(32), "cpu"), {**TRAIN_CFG, "epochs": 1}, make_generator(5)
        )
        return model.state_dict()

    a, b = run(), run()
    assert all(torch.allclose(a[k].float(), b[k].float()) for k in a)


def test_evaluate_outputs():
    seed_everything(0)
    data = TensorBatches(_tiny(40), "cpu")
    ev = evaluate(build_model(MODEL_CFG), data, batch_size=16)
    assert ev.n == 40 and 0 <= ev.accuracy <= 1
    assert ev.confusion_matrix().sum() == 40
    assert np.array_equal(ev.sample_ids, np.arange(40))
    assert ev.confidences.min() > 0 and ev.confidences.max() <= 1


def test_model_hashing(tmp_path):
    """Same weights -> same file hash (independent of file name); one changed weight ->
    different hash. Regression test: torch.save(obj, path) embeds the file name."""
    seed_everything(1)
    model = build_model(MODEL_CFG)
    h1 = sha256_file(save_model(model, tmp_path / "a.pt"))
    h2 = sha256_file(save_model(model, tmp_path / "sub" / "deployed_model.pt"))
    assert h1 == h2
    with torch.no_grad():
        model.fc.bias[0] += 1e-3
    assert sha256_file(save_model(model, tmp_path / "c.pt")) != h1


def test_model_round_trip(tmp_path):
    seed_everything(2)
    model = build_model(MODEL_CFG)
    path = save_model(model, tmp_path / "m.pt")
    other = load_model_state(build_model(MODEL_CFG), path, "cpu")
    assert all(
        torch.equal(model.state_dict()[k], other.state_dict()[k]) for k in model.state_dict()
    )


def test_unknown_architecture_rejected():
    with pytest.raises(ValueError):
        build_model({**MODEL_CFG, "architecture": "vgg"})
