"""Statistics for ML-FREF results (spec §28).

Phase 15 provides descriptive statistics. Inferential tests (assumption checks,
ANOVA / Kruskal-Wallis or repeated-measures alternatives, corrected post-hoc tests,
effect sizes) are added in Phase 19 once the final design is approved.
"""

from __future__ import annotations

import itertools
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


# --------------------------------------------------------------------------- Phase 19


def _holm(pvals: list[float]) -> list[float]:
    order = np.argsort(pvals)
    m, adj, running = len(pvals), [0.0] * len(pvals), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvals[i]))
        adj[i] = running
    return adj


def compare_pipelines(
    df,
    metric: str,
    block_cols=("attack_type", "poison_rate", "seed"),
    group: str = "pipeline",
    alpha: float = 0.05,
) -> list[dict[str, Any]]:
    """Paired comparison of A/B/C on one metric (spec §28).

    Runs are paired within blocks (same attack, rate and seed: identical ML outcome,
    only instrumentation differs). Assumptions: Shapiro-Wilk on within-block
    differences. Omnibus: repeated-measures ANOVA (statsmodels AnovaRM) if all
    difference sets look normal, otherwise Friedman. Post hoc: paired t-tests or
    Wilcoxon signed-rank with Holm correction. Effect sizes: partial eta^2 (RM-ANOVA),
    Kendall's W (Friedman), Cohen's d_z or matched-pairs rank-biserial r (pairwise),
    each with a 95 % bootstrap CI of the paired median/mean difference.
    """
    wide = df.pivot_table(index=list(block_cols), columns=group, values=metric).dropna()
    levels = [c for c in ("A", "B", "C") if c in wide.columns]
    rows: list[dict[str, Any]] = []
    if len(wide) < 3 or len(levels) < 2:
        return [{"metric": metric, "test": "not run", "note": f"n_blocks={len(wide)} < 3"}]
    diffs = {f"{a}-{b}": wide[a] - wide[b] for a, b in itertools.combinations(levels, 2)}
    normal = all(np.ptp(d) == 0 or stats.shapiro(d).pvalue > alpha for d in diffs.values())
    n = len(wide)
    if normal:
        from statsmodels.stats.anova import AnovaRM

        long = wide[levels].reset_index(drop=True).stack().reset_index()
        long.columns = ["block", group, metric]
        res = AnovaRM(long, metric, "block", within=[group]).fit().anova_table.iloc[0]
        f, df1, df2, p = res["F Value"], res["Num DF"], res["Den DF"], res["Pr > F"]
        eta = f * df1 / (f * df1 + df2)
        rows.append(
            {
                "metric": metric,
                "test": "repeated-measures ANOVA",
                "statistic": f,
                "df": f"{df1:.0f}, {df2:.0f}",
                "p_value": p,
                "effect_size": eta,
                "effect_size_name": "partial eta^2",
                "n_blocks": n,
                "assumption": "within-block differences normal (Shapiro-Wilk)",
            }
        )
    else:
        chi, p = stats.friedmanchisquare(*[wide[c] for c in levels])
        w = chi / (n * (len(levels) - 1))
        rows.append(
            {
                "metric": metric,
                "test": "Friedman",
                "statistic": chi,
                "df": str(len(levels) - 1),
                "p_value": p,
                "effect_size": w,
                "effect_size_name": "Kendall's W",
                "n_blocks": n,
                "assumption": "normality rejected for >=1 difference set",
            }
        )
    pw, raw = [], []
    rng = np.random.default_rng(0)
    for name, d in diffs.items():
        d = np.asarray(d, dtype=float)
        boot = [np.mean(rng.choice(d, len(d))) for _ in range(2000)]
        ci = (float(np.percentile(boot, 2.5)), float(np.percentile(boot, 97.5)))
        if np.ptp(d) == 0:
            stat, p, es, es_name, test = (
                np.nan,
                (0.0 if d[0] != 0 else 1.0),
                np.nan,
                "-",
                "constant difference (no test)",
            )
        elif normal:
            stat, p = stats.ttest_1samp(d, 0.0)
            es, es_name, test = d.mean() / d.std(ddof=1), "Cohen's d_z", "paired t-test"
        else:
            r = stats.wilcoxon(d)
            stat, p = r.statistic, r.pvalue
            pos, neg = np.sum(stats.rankdata(np.abs(d))[d > 0]), np.sum(
                stats.rankdata(np.abs(d))[d < 0]
            )
            es, es_name, test = (pos - neg) / (pos + neg), "rank-biserial r", "Wilcoxon signed-rank"
        raw.append(p)
        pw.append(
            {
                "metric": metric,
                "test": f"post hoc {test} ({name})",
                "statistic": stat,
                "df": str(n - 1) if test == "paired t-test" else "",
                "p_value": p,
                "effect_size": es,
                "effect_size_name": es_name,
                "n_blocks": n,
                "mean_difference": float(d.mean()),
                "ci_low": ci[0],
                "ci_high": ci[1],
            }
        )
    for row, adj in zip(pw, _holm(raw), strict=True):
        row["p_holm"] = adj
    return rows + pw
