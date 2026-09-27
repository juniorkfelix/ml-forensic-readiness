"""Traceability metadata for generated figures and tables (spec §47).

Each output directory holds a ``figure_metadata.json`` (or ``table_metadata.json``)
keyed by file name. It records the source data, the experiments included, the metric,
the generating script, the Git commit and the creation date.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from mlfref.reproducibility import get_git_info


def record_output_metadata(
    output_file: str | Path,
    *,
    source_data: Sequence[str],
    experiments: Sequence[str],
    metric: str,
    generation_script: str,
    description: str = "",
    kind: str = "figure",
) -> Path:
    output_file = Path(output_file)
    registry = output_file.parent / f"{kind}_metadata.json"
    entries = json.loads(registry.read_text(encoding="utf-8")) if registry.exists() else {}
    git = get_git_info()
    entries[output_file.name] = {
        "filename": output_file.name,
        "description": description,
        "source_data": list(source_data),
        "experiments_included": list(experiments),
        "metric": metric,
        "generation_script": generation_script,
        "git_commit": git["commit"],
        "git_dirty": git["dirty"],
        "created_utc": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    registry.write_text(json.dumps(entries, indent=2, sort_keys=True), encoding="utf-8")
    return registry
