"""Fill docs/chapter4_draft.md placeholders from MEASURED Chapter 4 outputs.

Reads results/chapter4/ (produced by analyse_results.py from real runs) and writes
docs/chapter4_filled.md. Refuses synthetic inputs. Placeholders without data stay as
{{KEY}}, so nothing is invented.

Usage: python scripts/fill_chapter4.py [--chapter4-dir results/chapter4]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
ABBR = {
    "clean_test_accuracy": "CA",
    "evidence_completeness": "EC",
    "event_recovery_rate": "ERR",
    "timeline_kendall_tau_b": "TAU",
    "rci_score": "RCI",
    "reconstruction_seconds": "RT",
    "evidence_total_mb": "MB",
    "training_seconds": "TRAIN",
}


def fmt(v, nd=3):
    return "n/a" if pd.isna(v) else f"{v:.{nd}f}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--chapter4-dir", default=str(ROOT / "results" / "chapter4"))
    args = ap.parse_args()
    c4 = Path(args.chapter4_dir)
    summ = pd.read_csv(c4 / "summary_statistics.csv")
    if (summ.get("data_origin") == "SYNTHETIC").any():
        raise SystemExit("refusing to fill the chapter from SYNTHETIC data")
    v: dict[str, str] = {}
    for _, r in summ.iterrows():
        key = ABBR.get(r["metric"])
        if key:
            v[f"{key}_{r['pipeline']}_mean"] = fmt(r["mean"])
            v[f"{key}_{r['pipeline']}_ci"] = f"{fmt(r['ci_low'])}–{fmt(r['ci_high'])}"
    idx = pd.read_csv(c4 / "experiment_index.csv")
    v["N_RUNS"] = str(len(idx))
    failed = ROOT / "results" / "raw" / "failed_runs.csv"
    v["N_FAILED"] = str(len(pd.read_csv(failed))) if failed.exists() else "0"
    v["ASR_mean"] = fmt(idx["attack_success_rate"].mean())
    v["S2T_mean"] = fmt(idx["source_to_target_rate"].mean())
    env = pd.read_csv(c4 / "tables" / "table1_environment.csv").iloc[0]
    v.update(ENV_PYTHON=str(env["Python"]), ENV_TORCH=str(env["PyTorch"]), ENV_GPU=str(env["GPU"]))
    ov = pd.read_csv(c4 / "tables" / "table6_operational_overhead.csv").set_index("pipeline")
    for p in "BC":
        v[f"TRAIN_{p}_ovh"] = fmt(ov.loc[p, "runtime_overhead_pct"], 1)
    tests = pd.read_csv(c4 / "statistical_tests.csv")
    for metric, key in (
        ("evidence_completeness", "EC"),
        ("event_recovery_rate", "ERR"),
        ("rci_score", "RCI"),
    ):
        row = tests[(tests.metric == metric) & ~tests.test.str.startswith("post hoc")]
        if len(row):
            r = row.iloc[0]
            v[f"{key}_TEST"] = (
                f"{r['test']}: statistic = {fmt(r['statistic'], 2)}, "
                f"p = {r['p_value']:.3g}, {r['effect_size_name']} = "
                f"{fmt(r['effect_size'])}"
            )
    text = (ROOT / "docs" / "chapter4_draft.md").read_text(encoding="utf-8")
    filled = re.sub(r"\{\{(\w+)\}\}", lambda m: v.get(m.group(1), m.group(0)), text)
    out = ROOT / "docs" / "chapter4_filled.md"
    out.write_text(filled, encoding="utf-8")
    left = sorted(set(re.findall(r"\{\{(\w+)\}\}", filled)))
    print(f"written {out.relative_to(ROOT)}; unfilled placeholders: {left or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
