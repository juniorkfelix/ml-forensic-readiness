"""Figures 1-3 (spec §30): architecture diagrams. They contain no experimental values.

    Figure 1  experimental architecture (trust boundaries)
    Figure 2  ML lifecycle and evidence collection points per pipeline
    Figure 3  poisoning attack lifecycle (data-store tampering threat model)

Usage: python scripts/generate_thesis_figures.py
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

from mlfref.reporting.metadata import record_output_metadata  # noqa: E402
from mlfref.reporting.plots import CATEGORICAL, INK_PRIMARY, apply_style, save_figure  # noqa: E402

OUT = PROJECT_ROOT / "results" / "figures"
GREY, RED = "#c3c2b7", "#d03b3b"


def box(ax, x, y, w, h, text, color, fs=8):
    ax.add_patch(
        FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.02", fc=color, ec=INK_PRIMARY, lw=0.8, alpha=0.9
        )
    )
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=INK_PRIMARY)


def arrow(ax, x1, y1, x2, y2, color=INK_PRIMARY, style="-|>"):
    ax.annotate("", (x2, y2), (x1, y1), arrowprops={"arrowstyle": style, "color": color, "lw": 1.2})


def canvas(w=10, h=5.5):
    apply_style()
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 6)
    ax.axis("off")
    return fig, ax


def figure1():
    fig, ax = canvas()
    stages = [
        "CIFAR-10\ndata store",
        "training\n(ResNet-18)",
        "model",
        "deployment",
        "inference\nservice",
    ]
    for i, s in enumerate(stages):
        box(ax, 0.3 + i * 1.95, 3.6, 1.6, 0.9, s, "#e8f0fb")
        if i:
            arrow(ax, 0.3 + i * 1.95 - 0.35, 4.05, 0.3 + i * 1.95, 4.05)
    box(ax, 0.3, 5.0, 1.6, 0.7, "adversary\n(tampers store)", "#f7d0d0")
    arrow(ax, 1.1, 5.0, 1.1, 4.5, RED)
    box(
        ax,
        0.3,
        2.3,
        9.4,
        0.8,
        "evidence instrumentation:  A app log  |  B + MLflow provenance"
        "  |  C + forensic event store (hash-chained)",
        "#eef7f2",
    )
    box(
        ax,
        0.3,
        0.6,
        3.0,
        1.1,
        "investigator-visible evidence\nevidence/<mode>/RUN-<uuid>",
        "#eef7f2",
    )
    box(ax, 3.7, 0.6, 2.6, 1.1, "reconstruction engine\nreconstruct(evidence, ticket)", "#e8f0fb")
    box(ax, 6.7, 0.6, 3.0, 1.1, "evaluator\n(only component seeing both)", "#fdf1d6")
    box(ax, 6.7, 4.95, 3.0, 0.8, "ground truth (hidden)\nground_truth.sqlite", "#f7d0d0")
    arrow(ax, 1.8, 2.3, 1.8, 1.7)
    arrow(ax, 3.3, 1.15, 3.7, 1.15)
    arrow(ax, 6.3, 1.15, 6.7, 1.15)
    arrow(ax, 8.2, 4.95, 8.2, 1.7, RED)
    ax.set_title("Figure 1. ML-FREF experimental architecture and trust boundaries", loc="left")
    return fig


def figure2():
    fig, ax = canvas(10, 4.8)
    stages = ["dataset", "training", "model", "deployment", "inference", "integrity"]
    rows = {
        "A": ["app log", "app log", "file", "app log", "app log", "-"],
        "B": ["MLflow digest\n+ profile", "MLflow run", "registry", "alias", "app log", "digest"],
        "C": [
            "manifest\n+ SHA-256",
            "hash-linked\nevents",
            "SHA-256",
            "deploy event",
            "request/result\nevents",
            "checks + chain",
        ],
    }
    for j, s in enumerate(stages):
        ax.text(1.9 + j * 1.35, 5.4, s, ha="center", fontsize=9, weight="bold")
    for i, (p, cells) in enumerate(rows.items()):
        y = 4.1 - i * 1.4
        ax.text(
            0.2,
            y + 0.45,
            {"A": "A conventional", "B": "B provenance", "C": "C forensic-ready"}[p],
            fontsize=9,
            color=INK_PRIMARY,
        )
        for j, c in enumerate(cells):
            box(
                ax,
                1.3 + j * 1.35,
                y,
                1.2,
                0.9,
                c,
                CATEGORICAL[i] + "33" if c != "-" else "#f4f4f2",
                fs=7,
            )
    ax.set_title("Figure 2. Evidence collection points across the ML lifecycle", loc="left")
    return fig


def figure3():
    fig, ax = canvas(10, 3.6)
    steps = [
        ("register\nclean data", "#e8f0fb"),
        ("adversary\nmodifies store", "#f7d0d0"),
        ("training job\nloads store", "#e8f0fb"),
        ("compromised\nmodel", "#f7d0d0"),
        ("deployment", "#e8f0fb"),
        ("triggered input /\nmalicious prediction", "#f7d0d0"),
        ("incident\nticket", "#fdf1d6"),
    ]
    for i, (s, c) in enumerate(steps):
        box(ax, 0.1 + i * 1.42, 2.4, 1.25, 1.2, s, c, fs=7.5)
        if i:
            arrow(ax, 0.1 + i * 1.42 - 0.17, 3.0, 0.1 + i * 1.42, 3.0)
    ax.text(
        0.1 + 1.42 * 1.1,
        1.8,
        "not observed by any pipeline\n(time bounded by evidence)",
        fontsize=7.5,
        color=RED,
        ha="center",
    )
    arrow(ax, 9.3, 2.4, 0.8, 1.2, GREY, "-|>")
    ax.text(
        5,
        0.8,
        "investigation traces backwards: inference -> deployment -> model -> "
        "training run -> dataset -> registered state",
        ha="center",
        fontsize=8,
    )
    ax.set_title(
        "Figure 3. Data-poisoning attack lifecycle (store-tampering threat model)", loc="left"
    )
    return fig


def main() -> int:
    for name, fn, desc in (
        ("figure01_architecture.png", figure1, "architecture"),
        ("figure02_evidence_points.png", figure2, "evidence points"),
        ("figure03_attack_lifecycle.png", figure3, "attack lifecycle"),
    ):
        save_figure(fn(), OUT / name)
        record_output_metadata(
            OUT / name,
            source_data=["docs/architecture.md", "docs/evidence_schema.md"],
            experiments=[],
            metric="none (diagram)",
            generation_script="scripts/generate_thesis_figures.py",
            description=desc,
        )
        print(f"written results/figures/{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
