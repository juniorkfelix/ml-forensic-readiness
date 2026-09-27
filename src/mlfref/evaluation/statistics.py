"""Statistics for ML-FREF results (spec §28).

Phase 15 provides descriptive statistics. Inferential tests (assumption checks,
ANOVA / Kruskal-Wallis or repeated-measures alternatives, corrected post-hoc tests,
effect sizes) are added in Phase 19 once the final design is approved.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

import numpy as np
from scipy import stats


def describe(values: Sequence[float], confidence: float = 0.95) -> dict[str, Any]:
    """n, mean, median, SD, min, max, IQR, and a t-based CI of the mean (n >= 2)."""
    x = np.asarray([v for v in values if v is not None and not math.isnan(v)], dtype=float)
    n = len(x)
    out: dict[str, Any] = {
        "n": n,
        "mean": None,
        "median": None,
        "sd": None,
        "min": None,
        "max": None,
        "q1": None,
        "q3": None,
        "iqr": None,
        "ci_low": None,
        "ci_high": None,
        "ci_method": None,
    }
    if n == 0:
        return out
    q1, q3 = np.percentile(x, [25, 75])
    out.update(
        mean=float(x.mean()),
        median=float(np.median(x)),
        min=float(x.min()),
        max=float(x.max()),
        q1=float(q1),
        q3=float(q3),
        iqr=float(q3 - q1),
    )
    if n >= 2:
        sd = float(x.std(ddof=1))
        out["sd"] = sd
        if sd == 0:
            out.update(ci_low=out["mean"], ci_high=out["mean"], ci_method="degenerate (sd=0)")
        else:
            half = stats.t.ppf((1 + confidence) / 2, n - 1) * sd / math.sqrt(n)
            out.update(
                ci_low=out["mean"] - half,
                ci_high=out["mean"] + half,
                ci_method=f"t ({int(confidence * 100)}%, df={n - 1})",
            )
    else:
        out["ci_method"] = "n/a (n < 2)"
    return out
