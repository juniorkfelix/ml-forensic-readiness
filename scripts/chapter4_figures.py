"""Chapter 4 figures from GENUINE data only, plus a complete figure inventory.

Figure 4.1 (clean baseline performance) is generated from the real 30-epoch baseline.
Figures 4.2-4.11 require experimental data that do not exist and are recorded as
"FIGURE NOT GENERATED - MISSING EXPERIMENTAL DATA".

Usage: python scripts/chapter4_figures.py
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from mlfref.reporting.metadata import record_output_metadata  # noqa: E402
from mlfref.reporting.plots import CATEGORICAL, apply_style, save_figure  # noqa: E402

OUT = ROOT / "results" / "chapter4"
FIGS = OUT / "figures"
SRC = ROOT / "experiments" / "pilot" / "EXP-CLEAN-A-00-S001" / "training_metrics.csv"


def figure_4_1() -> Path:
    rows = list(csv.DictReader(SRC.open(encoding="utf-8")))
    ep = [int(r["epoch"]) for r in rows]
    apply_style()
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10, 3.8))
    a1.plot(ep, [float(r["train_loss"]) for r in rows], color=CATEGORICAL[0], label="train")
    a1.plot(
        ep,
        [float(r["test_loss"]) for r in rows],
        color=CATEGORICAL[0],
        ls="--",
        label="test (clean)",
    )
    a1.set(xlabel="Epoch", ylabel="Cross-entropy loss")
    a1.set_title("(a) Loss", loc="left")
    a1.legend()
    a2.plot(ep, [float(r["train_accuracy"]) for r in rows], color=CATEGORICAL[0], label="train")
    a2.plot(
        ep,
        [float(r["test_accuracy"]) for r in rows],
        color=CATEGORICAL[0],
        ls="--",
        label="test (clean)",
    )
    a2.set(xlabel="Epoch", ylabel="Accuracy")
    a2.set_title("(b) Accuracy", loc="left")
    a2.annotate(
        f"final clean test accuracy {float(rows[-1]['test_accuracy']):.4f}",
        (ep[-1], float(rows[-1]["test_accuracy"])),
        xytext=(-150, -40),
        textcoords="offset points",
        fontsize=8,
        arrowprops={"arrowstyle": "-", "color": "#898781"},
    )
    a2.legend(loc="lower right")
    fig.suptitle(
        "Figure 4.1. Clean baseline: ResNet-18 on CIFAR-10 (pipeline A, seed 1, " "30 epochs)",
        x=0.01,
        ha="left",
        fontsize=11,
    )
    fig.tight_layout()
    path = FIGS / "figure4_1_clean_baseline.png"
    save_figure(fig, path)
    record_output_metadata(
        path,
        source_data=[SRC.relative_to(ROOT).as_posix()],
        experiments=["EXP-CLEAN-A-00-S001"],
        metric="train/test loss and " "accuracy by epoch",
        generation_script="scripts/chapter4_figures.py",
        description="MEASURED (genuine full-protocol run)",
    )
    return path


def inventory() -> None:
    known = {
        "figure4_1_clean_baseline": (
            "Clean baseline loss/accuracy curves",
            "EXP-CLEAN-A-00-S001",
            "loss, accuracy",
            "YES",
            "USE IN CHAPTER 4",
        ),
        "baseline_accuracy": (
            "Clean baseline accuracy by epoch",
            "EXP-CLEAN-A-00-S001",
            "accuracy",
            "YES",
            "MOVE TO APPENDIX (superseded by Fig 4.1)",
        ),
        "baseline_training_loss": (
            "Clean baseline loss by epoch",
            "EXP-CLEAN-A-00-S001",
            "loss",
            "YES",
            "MOVE TO APPENDIX (superseded by Fig 4.1)",
        ),
        "cifar10_clean_samples": (
            "CIFAR-10 samples per class",
            "none (dataset)",
            "none",
            "YES",
            "USE IN CHAPTER 3",
        ),
        "backdoor_trigger_example": (
            "Clean vs triggered images, 3x3 trigger",
            "none (attack " "illustration)",
            "none",
            "YES",
            "USE IN CHAPTER 3",
        ),
        "figure01_architecture": (
            "Experimental architecture diagram",
            "none",
            "none",
            "YES",
            "USE IN CHAPTER 3",
        ),
        "figure02_evidence_points": (
            "Evidence collection points A/B/C (design)",
            "none",
            "none",
            "YES (design)",
            "USE IN CHAPTER 3",
        ),
        "figure03_attack_lifecycle": (
            "Attack lifecycle diagram",
            "none",
            "none",
            "YES",
            "USE IN CHAPTER 3",
        ),
    }
    rows = []
    for p in sorted(ROOT.rglob("*")):
        if p.suffix.lower() not in (".png", ".jpg", ".jpeg", ".svg", ".pdf"):
            continue
        rp = p.relative_to(ROOT).as_posix()
        if rp.startswith((".venv/", "mlruns/", ".git/")):
            continue
        stem = p.stem
        if rp.startswith("results/synthetic/"):
            info = (
                "Synthetic demonstration figure (watermarked)",
                "synthetic set (D-056)",
                stem.split("_", 1)[-1],
                "NO (SYNTHETIC)",
                "DO NOT USE",
            )
        elif rp.startswith("results/smoke/"):
            info = (
                "Smoke-check (1-epoch) baseline figure",
                "EXP-CLEAN-A-00-S001 (smoke)",
                stem,
                "YES (smoke check)",
                "DO NOT USE",
            )
        else:
            info = known.get(
                stem, ("unclassified", "unknown", "unknown", "unknown", "MOVE TO APPENDIX")
            )
        rows.append(
            {
                "filename": rp,
                "format": p.suffix.lower()[1:],
                "description": info[0],
                "experiments_represented": info[1],
                "metric_represented": info[2],
                "values_genuine": info[3],
                "recommended_location": info[4],
            }
        )
    for num, title in [
        ("4.2", "Clean accuracy by poisoning rate"),
        ("4.3", "Backdoor ASR by poisoning rate"),
        ("4.4", "Evidence completeness by pipeline"),
        ("4.5", "Event recovery rate by pipeline"),
        ("4.6", "Timeline reconstruction accuracy by pipeline"),
        ("4.7", "Root-cause identification by pipeline"),
        ("4.8", "Reconstruction time by pipeline"),
        ("4.9", "Evidence storage by pipeline"),
        ("4.10", "Runtime overhead by pipeline"),
        ("4.11", "A/B/C reconstruction comparison"),
    ]:
        rows.append(
            {
                "filename": f"(Figure {num})",
                "format": "",
                "description": title,
                "experiments_represented": "",
                "metric_represented": "",
                "values_genuine": "",
                "recommended_location": "FIGURE NOT GENERATED - MISSING EXPERIMENTAL DATA",
            }
        )
    with (OUT / "figure_inventory.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    print("generated", figure_4_1().relative_to(ROOT))
    inventory()
    print("inventory written: results/chapter4/figure_inventory.csv")
