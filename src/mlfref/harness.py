"""Research-harness utilities (not part of any pipeline's evidence).

* ``StageTimer``: wall-clock timing of named stages (setup, training, test, ...),
  kept separate as required by spec §43.
* ``ResourceMonitor``: background sampling of process RSS and CPU utilisation,
  plus peak CUDA memory, for RQ4.
* CSV helpers for append-only result tables, and ``record_failure`` for
  ``results/raw/failed_runs.csv`` (spec §38). Failed runs are never deleted.
"""

from __future__ import annotations

import csv
import threading
import time
import traceback
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil
import torch

from mlfref.forensic.hashing import canonical_json


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class StageTimer:
    def __init__(self) -> None:
        self.stages: dict[str, float] = {}

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        if torch.cuda.is_available():
            torch.cuda.synchronize()
        t0 = time.perf_counter()
        try:
            yield
        finally:
            if torch.cuda.is_available():
                torch.cuda.synchronize()
            self.stages[name] = self.stages.get(name, 0.0) + time.perf_counter() - t0

    def as_dict(self) -> dict[str, float]:
        return {f"{k}_seconds": round(v, 3) for k, v in self.stages.items()}


class ResourceMonitor:
    """Samples this process's RSS and CPU% every ``interval`` seconds in a daemon thread."""

    def __init__(self, interval: float = 1.0) -> None:
        self.interval = interval
        self.samples: list[dict[str, float]] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc = psutil.Process()
        self._t0 = 0.0

    def _run(self) -> None:
        self._proc.cpu_percent(None)  # prime
        while not self._stop.wait(self.interval):
            self.samples.append(
                {
                    "t_seconds": round(time.perf_counter() - self._t0, 2),
                    "rss_mb": self._proc.memory_info().rss / 1024**2,
                    "cpu_percent": self._proc.cpu_percent(None),
                }
            )

    def __enter__(self) -> ResourceMonitor:
        if torch.cuda.is_available():
            torch.cuda.reset_peak_memory_stats()
        self._t0 = time.perf_counter()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join()

    def summary(self) -> dict[str, Any]:
        rss = [s["rss_mb"] for s in self.samples] or [self._proc.memory_info().rss / 1024**2]
        cpu = [s["cpu_percent"] for s in self.samples] or [float("nan")]
        out = {
            "peak_rss_mb": round(max(rss), 1),
            "mean_cpu_percent": round(sum(cpu) / len(cpu), 1),
            "resource_samples": len(self.samples),
        }
        if torch.cuda.is_available():
            out["peak_gpu_allocated_mb"] = round(torch.cuda.max_memory_allocated() / 1024**2, 1)
            out["peak_gpu_reserved_mb"] = round(torch.cuda.max_memory_reserved() / 1024**2, 1)
        return out


def append_csv_row(path: str | Path, row: Mapping[str, Any]) -> Path:
    """Append a row; writes the header on first use. New columns are rejected so the
    table schema stays stable (a changed schema requires a new file)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    if exists:
        with path.open("r", encoding="utf-8", newline="") as fh:
            header = next(csv.reader(fh))
        unknown = set(row) - set(header)
        if unknown:
            raise ValueError(f"{path.name}: columns {sorted(unknown)} not in existing header")
    else:
        header = list(row)
    with path.open("a", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header)
        if not exists:
            writer.writeheader()
        writer.writerow({k: _cell(row.get(k, "")) for k in header})
    return path


def write_csv(path: str | Path, rows: list[Mapping[str, Any]]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    header: list[str] = []
    for r in rows:
        header += [k for k in r if k not in header]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: _cell(r.get(k, "")) for k in header})
    return path


def _cell(value: Any) -> Any:
    return canonical_json(value) if isinstance(value, (dict, list, tuple)) else value


def record_failure(
    path: str | Path,
    *,
    experiment_id: str,
    experiment_uuid: str,
    stage: str,
    exc: BaseException,
    config_sha256: str | None,
    retry_of: str | None = None,
) -> Path:
    return append_csv_row(
        path,
        {
            "timestamp_utc": utc_now(),
            "experiment_id": experiment_id,
            "experiment_uuid": experiment_uuid,
            "failure_stage": stage,
            "exception_type": type(exc).__name__,
            "exception": str(exc)[:500],
            "traceback_tail": " | ".join(traceback.format_exception(exc)[-3:]).replace("\n", " ")[
                :1000
            ],
            "config_sha256": config_sha256 or "",
            "retry_of_uuid": retry_of or "",
            "included_in_analysis": False,
            "exclusion_reason": "run failed before completion",
        },
    )
