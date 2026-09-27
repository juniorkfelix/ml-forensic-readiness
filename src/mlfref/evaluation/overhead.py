"""F/G. Storage and computational overhead (RQ4).

Storage is measured per category (spec §44) from the files one run produced. The
CIFAR-10 download and the shared clean stores are counted once (in the environment
record), never per run. Overhead is relative to the pipeline-A mean of comparable runs:

    overhead % = (mean_X - mean_A) / mean_A * 100
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import pandas as pd

STORAGE_CATEGORIES = (
    "model_files",
    "mlflow_backend_db",
    "mlflow_artifacts",
    "forensic_sqlite",
    "forensic_jsonl",
    "manifests",
    "logs",
    "other_evidence",
)


def dir_bytes(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file()) if path.exists() else 0


def evidence_storage(evidence_dir: Path) -> dict[str, int]:
    """Bytes per category inside one run's evidence directory."""
    out = dict.fromkeys(
        ("forensic_sqlite", "forensic_jsonl", "manifests", "logs", "other_evidence"), 0
    )
    for p in evidence_dir.rglob("*"):
        if not p.is_file():
            continue
        size = p.stat().st_size
        rel = p.relative_to(evidence_dir).as_posix()
        if p.suffix == ".sqlite":
            out["forensic_sqlite"] += size
        elif p.suffix == ".jsonl":
            out["forensic_jsonl"] += size
        elif rel.startswith("manifests/"):
            out["manifests"] += size
        elif p.suffix == ".log":
            out["logs"] += size
        else:
            out["other_evidence"] += size
    return out


def mlflow_run_storage(client, run_ids: Iterable[str]) -> int:
    """Bytes of MLflow artefacts of the given runs (logged models + profiles)."""
    total = 0
    for rid in run_ids:
        if not rid:
            continue
        uri = client.get_run(rid).info.artifact_uri
        if uri.startswith("file:"):
            from urllib.parse import unquote, urlparse

            path = Path(unquote(urlparse(uri).path.lstrip("/")))
            total += dir_bytes(path)
    return total  # registered model versions point at the run's artefacts (not re-counted)


def relative_overhead(
    df: pd.DataFrame, metric: str, group: str = "pipeline", baseline: str = "A"
) -> pd.DataFrame:
    means = df.groupby(group)[metric].mean()
    base = means.get(baseline)
    out = pd.DataFrame({"mean": means})
    out["overhead_pct"] = (means - base) / base * 100 if base else float("nan")
    return out


def bytes_to_mb(value: float) -> float:
    return value / 1024**2


def storage_row(
    evidence: Mapping[str, int],
    model_bytes: int,
    mlflow_db_delta: int | None,
    mlflow_artifact_bytes: int,
) -> dict[str, Any]:
    row = {
        "model_files": model_bytes,
        "mlflow_backend_db": mlflow_db_delta or 0,
        "mlflow_artifacts": mlflow_artifact_bytes,
        **evidence,
    }
    row["evidence_total_bytes"] = sum(
        row[k]
        for k in (
            "mlflow_backend_db",
            "mlflow_artifacts",
            "forensic_sqlite",
            "forensic_jsonl",
            "manifests",
            "logs",
            "other_evidence",
        )
    )
    return row
