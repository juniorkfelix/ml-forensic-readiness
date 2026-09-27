"""Phases 19-20: statistics, dissertation tables and figures from a run index.

Works on REAL results (results/raw/run_index.csv -> results/chapter4/) or on the
SYNTHETIC set (results/synthetic/run_index_SYNTHETIC.csv -> results/synthetic/chapter4/).
If any row has data_origin=SYNTHETIC, every table gets a data_origin column, every
figure is watermarked "SYNTHETIC - NOT EXPERIMENTAL RESULTS", and the README carries
a banner.

Usage:
    python scripts/analyse_results.py --synthetic
    python scripts/analyse_results.py --input results/raw/run_index.csv --phase main
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from mlfref.evaluation.statistics import compare_pipelines, describe  # noqa: E402
from mlfref.reporting.metadata import record_output_metadata  # noqa: E402
from mlfref.reporting.plots import (  # noqa: E402
    AXIS,
    PIPELINE_COLORS,
    PIPELINE_LABELS,
    apply_style,
    save_figure,
)

METRICS = {  # metric -> (label, research question)
    "evidence_completeness": ("Evidence completeness", "RQ1, RQ3"),
    "event_recovery_rate": ("Event recovery rate", "RQ2, RQ3"),
    "timeline_kendall_tau_b": ("Timeline accuracy (Kendall tau-b)", "RQ2, RQ3"),
    "rci_score": ("Root-cause identification score", "RQ3"),
    "reconstruction_seconds": ("Reconstruction runtime (s)", "RQ3"),
    "evidence_total_mb": ("Evidence storage (MB)", "RQ4"),
    "training_seconds": ("Training runtime (s)", "RQ4"),
    "peak_rss_mb": ("Peak RAM (MB)", "RQ4"),
}
WATERMARK = "SYNTHETIC - NOT EXPERIMENTAL RESULTS"


def mark(fig, synthetic: bool) -> None:
    if synthetic:
        fig.text(
            0.5,
            0.5,
            WATERMARK,
            fontsize=22,
            color="#d03b3b",
            alpha=0.25,
            ha="center",
            va="center",
            rotation=25,
            weight="bold",
        )


def box_by_pipeline(df, metric, label, path, synthetic, title):
    apply_style()
    fig, ax = plt.subplots(figsize=(5.6, 3.6))
    groups = [df.loc[df.pipeline == p, metric].dropna() for p in "ABC"]
    bp = ax.boxplot(groups, patch_artist=True, widths=0.5, medianprops={"color": "#0b0b0b"})
    for patch, p in zip(bp["boxes"], "ABC", strict=True):
        patch.set_facecolor(PIPELINE_COLORS[p])
        patch.set_alpha(0.85)
        patch.set_edgecolor(AXIS)
    ax.set_xticks([1, 2, 3], [PIPELINE_LABELS[p] for p in "ABC"])
    ax.set_ylabel(label)
    ax.set_title(title, loc="left")
    mark(fig, synthetic)
    save_figure(fig, path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--input")
    ap.add_argument("--synthetic", action="store_true")
    ap.add_argument("--phase", help="filter run index by phase (real data)")
    args = ap.parse_args()
    src = (
        Path(args.input)
        if args.input
        else (
            PROJECT_ROOT / "results/synthetic/run_index_SYNTHETIC.csv"
            if args.synthetic
            else PROJECT_ROOT / "results/raw/run_index.csv"
        )
    )
    df = pd.read_csv(src)
    if args.phase and "phase" in df:
        df = df[df.phase == args.phase]
    if "status" in df:
        df = df[df.status == "completed"]  # failed runs never enter statistics (spec §38)
    synthetic = "data_origin" in df and (df.data_origin == "SYNTHETIC").any()
    out = PROJECT_ROOT / "results" / ("synthetic/chapter4" if synthetic else "chapter4")
    tables, figs = out / "tables", out / "figures"
    tables.mkdir(parents=True, exist_ok=True)
    figs.mkdir(parents=True, exist_ok=True)
    df["evidence_total_mb"] = df["evidence_total_bytes"] / 1024**2
    origin = "SYNTHETIC" if synthetic else "MEASURED"
    exps = df["experiment_id"].tolist()
    srcrel = src.resolve().relative_to(PROJECT_ROOT).as_posix()

    def save_table(frame: pd.DataFrame, name: str, metric: str):
        frame = frame.copy()
        frame.insert(0, "data_origin", origin)
        path = tables / name
        frame.to_csv(path, index=False)
        record_output_metadata(
            path,
            source_data=[srcrel],
            experiments=exps,
            metric=metric,
            generation_script="scripts/analyse_results.py",
            kind="table",
            description=f"data_origin={origin}",
        )

    attacked = df[df.attack_type != "none"]
    # Table 1: environment (real, from the environment manifest)
    env = json.loads((PROJECT_ROOT / "results/environment/environment_manifest.json").read_text())
    save_table(
        pd.DataFrame(
            [
                {
                    "Python": env["software"]["python"],
                    "PyTorch": env["software"]["torch"],
                    "Torchvision": env["software"]["torchvision"],
                    "CUDA": env["software"]["cuda_build"],
                    "GPU": (env["hardware"]["gpu"] or {}).get("name"),
                    "CPU": env["hardware"]["cpu"],
                    "RAM (GB)": env["hardware"]["ram_total_gb"],
                    "Operating System": f"{env['os']['system']} {env['os']['release']}",
                }
            ]
        ),
        "table1_environment.csv",
        "environment",
    )
    # Table 2: configuration
    save_table(
        df.groupby(["pipeline", "attack_type", "poison_rate"])
        .seed.agg(Seeds=lambda s: len(set(s)))
        .reset_index()
        .assign(Model="ResNet-18 (CIFAR stem)", Dataset="CIFAR-10"),
        "table2_configuration.csv",
        "configuration",
    )
    # Table 3: attack effectiveness
    save_table(
        df.groupby(["pipeline", "attack_type", "poison_rate"])[
            ["clean_test_accuracy", "attack_success_rate", "source_to_target_rate"]
        ]
        .mean()
        .reset_index(),
        "table3_attack_effectiveness.csv",
        "CA, ASR",
    )
    # Table 4: evidence availability
    save_table(
        attacked.groupby("pipeline")["evidence_completeness"].agg(["mean", "std"]).reset_index(),
        "table4_evidence_availability.csv",
        "evidence completeness",
    )
    # Table 5: reconstruction performance
    save_table(
        attacked.groupby("pipeline")[
            ["event_recovery_rate", "timeline_kendall_tau_b", "rci_score", "reconstruction_seconds"]
        ]
        .mean()
        .reset_index(),
        "table5_reconstruction_performance.csv",
        "ERR, tau, RCI, runtime",
    )
    # Table 6: overhead
    ov = df.groupby("pipeline")[["evidence_total_mb", "training_seconds", "peak_rss_mb"]].mean()
    for col, name in (
        ("evidence_total_mb", "storage_overhead_pct"),
        ("training_seconds", "runtime_overhead_pct"),
    ):
        ov[name] = (ov[col] - ov.loc["A", col]) / ov.loc["A", col] * 100
    save_table(ov.reset_index(), "table6_operational_overhead.csv", "storage, runtime overhead")
    # Summary statistics + Table 7
    summ = []
    for m in METRICS:
        base = attacked if m in ("rci_score",) else df
        for p in "ABC":
            summ.append(
                {
                    "metric": m,
                    "pipeline": p,
                    "rq": METRICS[m][1],
                    **describe(base.loc[base.pipeline == p, m].tolist()),
                }
            )
    pd.DataFrame(summ).insert(0, "data_origin", origin)
    sdf = pd.DataFrame(summ)
    sdf.insert(0, "data_origin", origin)
    sdf.to_csv(out / "summary_statistics.csv", index=False)
    tests = []
    for m in (
        "evidence_completeness",
        "event_recovery_rate",
        "rci_score",
        "reconstruction_seconds",
        "evidence_total_mb",
        "training_seconds",
    ):
        base = attacked if m == "rci_score" else df
        tests += compare_pipelines(base, m)
    tdf = pd.DataFrame(tests)
    tdf.insert(0, "data_origin", origin)
    tdf.to_csv(out / "statistical_tests.csv", index=False)
    save_table(
        tdf[
            ["metric", "test", "statistic", "p_value"]
            + [
                c
                for c in ("p_holm", "effect_size", "effect_size_name", "ci_low", "ci_high")
                if c in tdf
            ]
        ],
        "table7_statistical_comparison.csv",
        "statistical tests",
    )
    df.to_csv(out / "experiment_index.csv", index=False)

    # Figures 5-13 (result figures)
    fig_specs = [
        (
            "figure05_clean_accuracy_by_pipeline.png",
            "clean_test_accuracy",
            "Clean accuracy",
            df,
            "Clean accuracy by pipeline",
        ),
        (
            "figure07_evidence_completeness.png",
            "evidence_completeness",
            "Evidence completeness",
            attacked,
            "Evidence completeness by pipeline (attacked runs)",
        ),
        (
            "figure08_event_recovery.png",
            "event_recovery_rate",
            "Event recovery rate",
            attacked,
            "Event recovery rate by pipeline",
        ),
        (
            "figure09_timeline_accuracy.png",
            "timeline_kendall_tau_b",
            "Kendall tau-b",
            attacked,
            "Timeline ordering accuracy by pipeline",
        ),
        (
            "figure10_root_cause.png",
            "rci_score",
            "RCI score",
            attacked,
            "Root-cause identification by pipeline",
        ),
        (
            "figure11_reconstruction_time.png",
            "reconstruction_seconds",
            "Seconds",
            attacked,
            "Reconstruction runtime by pipeline",
        ),
        (
            "figure12_storage.png",
            "evidence_total_mb",
            "Evidence storage (MB)",
            df,
            "Evidence storage by pipeline",
        ),
        (
            "figure13_training_runtime.png",
            "training_seconds",
            "Training runtime (s)",
            df,
            "Training runtime by pipeline",
        ),
    ]
    for name, m, label, data, title in fig_specs:
        box_by_pipeline(data, m, label, figs / name, synthetic, title)
        record_output_metadata(
            figs / name,
            source_data=[srcrel],
            experiments=exps,
            metric=m,
            generation_script="scripts/analyse_results.py",
            description=f"data_origin={origin}",
        )
    # Figure 6: ASR by poisoning rate (backdoor)
    apply_style()
    fig, ax = plt.subplots(figsize=(5.6, 3.6))
    bd = df[df.attack_type == "backdoor"].groupby("poison_rate").attack_success_rate.mean()
    ax.plot(bd.index * 100, bd.values, marker="o", color=PIPELINE_COLORS["A"])
    ax.set_xlabel("Poisoning rate (%)")
    ax.set_ylabel("Attack success rate")
    ax.set_title("Backdoor attack success rate by poisoning rate", loc="left")
    mark(fig, synthetic)
    save_figure(fig, figs / "figure06_asr_by_rate.png")
    record_output_metadata(
        figs / "figure06_asr_by_rate.png",
        source_data=[srcrel],
        experiments=exps,
        metric="ASR",
        generation_script="scripts/analyse_results.py",
        description=f"data_origin={origin}",
    )

    banner = (
        f"# {WATERMARK}\n\nGenerated from `{srcrel}` (synthetic, D-056). Demonstrates the "
        "Chapter 4 pipeline only; **do not report these values as findings.**\n\n"
        if synthetic
        else f"# Chapter 4 outputs (measured)\n\nGenerated from `{srcrel}`.\n\n"
    )
    (out / "README.md").write_text(
        banner + """| File | Contents | Supports |
|---|---|---|
| tables/table1_environment.csv | software/hardware environment (always real) | methodology |
| tables/table2_configuration.csv | runs per pipeline/attack/rate | methodology |
| tables/table3_attack_effectiveness.csv | CA, ASR, source->target rate | manipulation check |
| tables/table4_evidence_availability.csv | evidence completeness | RQ1, RQ3 |
| tables/table5_reconstruction_performance.csv | ERR, tau, RCI, runtime | RQ2, RQ3 |
| tables/table6_operational_overhead.csv | storage/runtime overhead vs A | RQ4 |
| tables/table7_statistical_comparison.csv | paired tests, Holm-adjusted, effect sizes | RQ3, RQ4 |
| summary_statistics.csv | n, mean, median, SD, IQR, 95% CI per metric/pipeline | all |
| statistical_tests.csv | full test output | RQ3, RQ4 |
| experiment_index.csv | runs included | traceability |
| figures/ | Figures 5-13 (PNG 300 dpi + SVG), metadata in figure_metadata.json | RQ1-RQ4 |

Interpretation is written separately in the dissertation (spec §35).
""",
        encoding="utf-8",
    )
    print(f"{origin}: {len(df)} runs -> {out.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
