"""Reconstruction engine entry point: ``reconstruct(evidence_dir, incident_ticket)``.

One function for all pipelines (spec §45). It receives only an evidence directory and
the incident ticket, plus the workspace root so that files referenced by the evidence
can be located. It never receives ground truth.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from mlfref.reconstruction.correlate import (
    INSUFFICIENT,
    NOT_OBSERVABLE,
    ticket_summary,
    trace,
)
from mlfref.reconstruction.graph import build_graph
from mlfref.reconstruction.loader import load_evidence
from mlfref.reconstruction.report import LIMITATIONS
from mlfref.reconstruction.timeline import build_events

ENGINE_VERSION = "1.1"  # v1.1: D-061 registration-run link


def _missing(findings: dict[str, Any], sources: dict[str, bool]) -> list[str]:
    out = [f"evidence source not available: {name}" for name, ok in sources.items() if not ok]
    for name, hop in findings["hops"].items():
        if hop["status"] != "IDENTIFIED":
            out.append(f"{name}: {INSUFFICIENT} (no supporting evidence)")
    change = findings["dataset_change"]
    if change["changed"] not in (True, False):
        out.append(f"dataset change between registration and training: {NOT_OBSERVABLE}")
    elif change["changed"] and change.get("changed_sample_ids") is None:
        out.append(f"which samples changed: {NOT_OBSERVABLE} (no per-sample manifests)")
    for k, v in findings["integrity"].items():
        if v.get("status") == NOT_OBSERVABLE:
            out.append(f"integrity/{k}: {NOT_OBSERVABLE}")
    return out


def reconstruct(
    evidence_dir: str | Path,
    incident_ticket: dict[str, Any],
    workspace_root: str | Path | None = None,
) -> dict[str, Any]:
    t0 = time.perf_counter()
    bundle = load_evidence(evidence_dir, workspace_root)
    findings = trace(bundle, incident_ticket)
    events = build_events(findings)
    graph = build_graph(findings)
    recon = {
        "engine_version": ENGINE_VERSION,
        "incident": ticket_summary(incident_ticket),
        "evidence_sources": bundle.sources,
        "observations_used": len(bundle.observations),
        "hops": findings["hops"],
        "events": events,
        "graph": graph.to_dict(),
        "integrity": findings["integrity"],
        "dataset_change": findings["dataset_change"],
        "identified": {
            "model": findings["hops"]["model"]["value"] or None,
            "training_run": findings["hops"]["training_run"]["value"] or None,
            "training_dataset": findings["hops"]["training_dataset"]["value"] or None,
            "prior_dataset": findings["hops"]["prior_dataset"]["value"] or None,
        },
        "root_cause": {
            "finding": findings["dataset_change"]["finding"],
            "changed_sample_ids": findings["dataset_change"]["changed_sample_ids"],
            "change_type": findings["dataset_change"]["change_type"],
        },
        "missing_evidence": _missing(findings, bundle.sources),
        "limitations": LIMITATIONS,
    }
    if bundle.mlflow_error:
        recon["missing_evidence"].append(f"MLflow store unreadable: {bundle.mlflow_error}")
    recon["runtime_seconds"] = time.perf_counter() - t0
    return recon
