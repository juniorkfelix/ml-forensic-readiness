"""Thesis figures (matplotlib; PNG at 300 DPI plus SVG).

Style rules:
* Categorical colours are assigned in a fixed slot order and never cycled.
  Pipelines always use A=slot 1, B=slot 2, C=slot 3, so a pipeline keeps the same
  colour in every figure. Only the first three slots stay distinguishable under
  colour-vision deficiency when all series appear together, so any figure with more
  series than that facets or aggregates instead of adding hues.
* One y-axis per chart (no dual axes). Loss and accuracy are separate figures.
* Thin 2 px lines, recessive grid and axes, text in neutral ink (never the series
  colour), and a legend whenever there are two or more series.
* Figures are generated only from actual result files. Every call records metadata
  (mlfref.reporting.metadata).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

CATEGORICAL = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7"]
PIPELINE_COLORS = {"A": CATEGORICAL[0], "B": CATEGORICAL[1], "C": CATEGORICAL[2]}
PIPELINE_LABELS = {"A": "A · conventional", "B": "B · provenance", "C": "C · forensic-ready"}
INK_PRIMARY, INK_SECONDARY, INK_MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS, SURFACE = "#e1e0d9", "#c3c2b7", "#ffffff"
MAX_DISTINCT_SERIES = 3


def apply_style() -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": SURFACE,
            "axes.facecolor": SURFACE,
            "axes.edgecolor": AXIS,
            "axes.linewidth": 0.8,
            "axes.labelcolor": INK_SECONDARY,
            "axes.titlecolor": INK_PRIMARY,
            "axes.titlesize": 11,
            "axes.labelsize": 10,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "axes.axisbelow": True,
            "grid.color": GRID,
            "grid.linewidth": 0.6,
            "xtick.color": INK_MUTED,
            "ytick.color": INK_MUTED,
            "xtick.labelcolor": INK_SECONDARY,
            "ytick.labelcolor": INK_SECONDARY,
            "legend.frameon": False,
            "legend.fontsize": 9,
            "lines.linewidth": 2.0,
            "font.family": "sans-serif",
            "font.sans-serif": ["Segoe UI", "DejaVu Sans", "Arial"],
            "svg.fonttype": "none",
            "savefig.dpi": 300,
            "savefig.bbox": "tight",
        }
    )


def save_figure(fig: plt.Figure, path: str | Path) -> list[Path]:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=300)
    svg = path.with_suffix(".svg")
    fig.savefig(svg)
    plt.close(fig)
    return [path, svg]


def plot_training_curves(
    histories: Mapping[str, pd.DataFrame],
    metrics: Sequence[tuple[str, str]],
    title: str,
    ylabel: str,
    path: str | Path,
) -> list[Path]:
    """One line per (run, metric).

    ``histories`` maps a run label (e.g. 'seed 1') to its per-epoch history.
    ``metrics`` is a list of (column, legend suffix) pairs. Up to three runs get
    distinct slot colours; with more runs every run is drawn in thin neutral grey and
    the across-run mean is drawn in slot 1, so the figure stays readable.
    """
    apply_style()
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    styles = ["-", "--", ":"]
    many = len(histories) > MAX_DISTINCT_SERIES
    for m_idx, (col, suffix) in enumerate(metrics):
        ls = styles[m_idx % len(styles)]
        if many:
            for df in histories.values():
                ax.plot(df["epoch"], df[col], color=AXIS, linewidth=0.8, linestyle=ls)
            mean = pd.concat([df.set_index("epoch")[col] for df in histories.values()], axis=1)
            ax.plot(
                mean.index,
                mean.mean(axis=1),
                color=CATEGORICAL[0],
                linestyle=ls,
                label=f"mean of {len(histories)} runs · {suffix}",
            )
        else:
            for r_idx, (label, df) in enumerate(histories.items()):
                ax.plot(
                    df["epoch"],
                    df[col],
                    color=CATEGORICAL[r_idx],
                    linestyle=ls,
                    label=f"{label} · {suffix}" if suffix else label,
                )
    ax.set_title(title, loc="left")
    ax.set_xlabel("Epoch")
    ax.set_ylabel(ylabel)
    n_series = len(metrics) * (1 if many else len(histories))
    if n_series >= 2:
        ax.legend(loc="best")
    return save_figure(fig, path)
