"""Phase 19: paired A/B/C comparison (on synthetic inputs with known structure)."""

import numpy as np
import pandas as pd

from mlfref.evaluation.statistics import _holm, compare_pipelines


def _frame(effect_c=0.3, n=8, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for s in range(n):
        base = rng.normal(0.5, 0.05)
        for p, shift in (("A", 0.0), ("B", 0.1), ("C", effect_c)):
            rows.append(
                {
                    "attack_type": "lf",
                    "poison_rate": 0.05,
                    "seed": s,
                    "pipeline": p,
                    "m": base + shift + rng.normal(0, 0.01),
                }
            )
    return pd.DataFrame(rows)


def test_detects_paired_difference_with_holm_and_effect_sizes():
    out = compare_pipelines(_frame(), "m")
    omnibus = out[0]
    assert omnibus["test"] in ("repeated-measures ANOVA", "Friedman")
    assert omnibus["p_value"] < 0.05 and omnibus["effect_size"] > 0.5
    posthoc = [r for r in out if r["test"].startswith("post hoc")]
    assert len(posthoc) == 3 and all("p_holm" in r and r["p_holm"] >= r["p_value"] for r in posthoc)
    assert all(r["ci_low"] <= r["mean_difference"] <= r["ci_high"] for r in posthoc)


def test_too_few_blocks_not_tested():
    assert compare_pipelines(_frame(n=2), "m")[0]["test"] == "not run"


def test_holm_adjustment():
    assert _holm([0.01, 0.04, 0.03]) == [0.03, 0.06, 0.06]
