"""C. Timeline reconstruction accuracy: coverage AND ordering.

* coverage = matched required GT events / required GT events (equals ERR)
* ordering over the commonly recovered events only:
    - Kendall's tau-b between true order (GT sequence) and reconstructed order
      (reconstructed ``order``), computed only when at least ``min_events_for_tau``
      events were recovered; otherwise NA (never imputed);
    - pairwise order accuracy = fraction of event pairs in the correct relative order.
"""

from __future__ import annotations

import itertools
import math
from typing import Any

from scipy.stats import kendalltau


def timeline_accuracy(
    matches: list[dict[str, Any]], recon_events: list[dict[str, Any]], schema: dict[str, Any]
) -> dict[str, Any]:
    applicable = [m for m in matches if m.get("applicable", True)]
    pairs = [
        (m["gt_sequence"], recon_events[m["recon_index"]].get("order"))
        for m in applicable
        if m["recovered"]
    ]
    ordered = [(g, r) for g, r in pairs if r is not None]
    n = len(ordered)
    min_n = int(schema["timeline"]["min_events_for_tau"])
    out: dict[str, Any] = {
        "coverage": (
            (sum(m["recovered"] for m in applicable) / len(applicable))
            if applicable
            else float("nan")
        ),
        "n_ordered_events": n,
        "kendall_tau_b": None,
        "kendall_p_value": None,
        "pairwise_order_accuracy": None,
        "tau_status": None,
    }
    if n >= 2:
        correct = sum(
            (g1 < g2) == (r1 < r2) for (g1, r1), (g2, r2) in itertools.combinations(ordered, 2)
        )
        out["pairwise_order_accuracy"] = correct / math.comb(n, 2)
    if n >= min_n:
        tau, p = kendalltau([g for g, _ in ordered], [r for _, r in ordered], variant="b")
        out.update(kendall_tau_b=float(tau), kendall_p_value=float(p), tau_status="COMPUTED")
    else:
        out["tau_status"] = f"NA (fewer than {min_n} recovered events)"
    return out
