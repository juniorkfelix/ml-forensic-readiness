"""Harness utilities: timing, CSV result tables, failure records (spec §38)."""

import csv
import time

import pytest

from mlfref.harness import ResourceMonitor, StageTimer, append_csv_row, record_failure


def test_stage_timer_accumulates():
    t = StageTimer()
    with t.stage("a"):
        time.sleep(0.01)
    with t.stage("a"):
        time.sleep(0.01)
    assert t.stages["a"] >= 0.02
    assert "a_seconds" in t.as_dict()


def test_append_csv_row_header_and_schema_guard(tmp_path):
    path = tmp_path / "r.csv"
    append_csv_row(path, {"x": 1, "y": {"k": 2}})
    append_csv_row(path, {"x": 3})
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    assert rows == [{"x": "1", "y": '{"k":2}'}, {"x": "3", "y": ""}]
    with pytest.raises(ValueError):
        append_csv_row(path, {"x": 1, "new_column": 2})


def test_record_failure_appends_and_marks_excluded(tmp_path):
    path = tmp_path / "failed.csv"
    try:
        raise RuntimeError("CUDA out of memory")
    except RuntimeError as exc:
        record_failure(
            path,
            experiment_id="EXP-CLEAN-A-00-S001",
            experiment_uuid="u1",
            stage="training",
            exc=exc,
            config_sha256="abc",
        )
    row = next(csv.DictReader(path.open(encoding="utf-8")))
    assert row["failure_stage"] == "training"
    assert row["exception_type"] == "RuntimeError"
    assert row["included_in_analysis"] == "False"
    assert row["exclusion_reason"]


def test_resource_monitor_summary():
    with ResourceMonitor(interval=0.05) as mon:
        time.sleep(0.2)
    s = mon.summary()
    assert s["peak_rss_mb"] > 0 and s["resource_samples"] >= 1
