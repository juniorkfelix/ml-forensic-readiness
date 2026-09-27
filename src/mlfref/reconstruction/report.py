"""Reconstruction reports: JSON (machine-readable) and Markdown (human-readable), spec §22."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

HOP_TITLES = {
    "inference": "Inference (incident request)",
    "deployment": "Deployment",
    "model": "Model",
    "training_run": "Training run",
    "training_dataset": "Training dataset",
    "prior_dataset": "Prior (registered) dataset state",
}

LIMITATIONS = [
    "Only investigator-visible evidence of this pipeline was used; no external reference data.",
    "Post-hoc file hashes show the current state of a file, not its state at the time of the "
    "event.",
    "MLflow dataset digests cover only the first 10,000 values of each array; equal digests do "
    "not prove identical datasets.",
    "The forensic hash chain gives tamper evidence, not tamper prevention.",
]


def write_json(recon: dict[str, Any], path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(recon, indent=2, default=str), encoding="utf-8")
    return path


def _fmt(v: Any, n: int = 16) -> str:
    if v is None:
        return "-"
    s = str(v)
    return s if len(s) <= n else s[:n] + "…"


def to_markdown(recon: dict[str, Any], title: str) -> str:
    L: list[str] = [f"# Incident reconstruction: {title}", ""]
    t = recon["incident"]
    L += [
        "## Incident",
        "",
        f"- Ticket: `{t.get('ticket_id')}`; request `{t.get('request_id')}` at "
        f"{t.get('request_time_utc')}",
        f"- Observed prediction **{t.get('observed_prediction')}** "
        f"(confidence {t.get('observed_confidence')}); expected **{t.get('expected_label')}**",
        f"- Input SHA-256: `{_fmt(t.get('input_sha256'), 64)}`",
        "",
    ]
    L += ["## Evidence sources", ""]
    for name, present in recon["evidence_sources"].items():
        L.append(f"- {name}: {'available' if present else 'NOT AVAILABLE'}")
    L += [
        "",
        "## Backward trace",
        "",
        "| Hop | Status | Confidence | Identified as | Basis |",
        "|---|---|---|---|---|",
    ]
    for key, title_ in HOP_TITLES.items():
        hop = recon["hops"][key]
        v = hop["value"]
        ident = (
            v.get("request_id")
            or v.get("deployment_id")
            or v.get("model_id")
            or v.get("run_id")
            or v.get("dataset_id")
            or v.get("registry_version")
            or v.get("mlflow_digest")
            or v.get("path")
            or v.get("store")
            or v.get("deployed_path")
            or "-"
        )
        L.append(
            f"| {title_} | {hop['status']} | {hop['confidence']} | `{_fmt(ident, 36)}` | "
            f"{'; '.join(hop['basis']) or 'no supporting evidence'} |"
        )
    L += [
        "",
        "## Event chronology",
        "",
        "| # | Event | Time | Time basis | Confidence |",
        "|---|---|---|---|---|",
    ]
    for e in recon["events"]:
        when = (
            f"{e['time_lower']} … {e['time_upper']}"
            if e["time_basis"] == "bounded"
            else e["time"] or "-"
        )
        L.append(
            f"| {e.get('order') or '-'} | {e['event_class']} | {when} | {e['time_basis']} | "
            f"{e['confidence']} |"
        )
    L += ["", "## Artefact relationships", ""]
    rels = recon["graph"]["relations"]
    L += [f"- {r['from']} **{r['relation']}** {r['to']}" for r in rels] or ["- none recovered"]
    L += ["", "## Integrity findings", ""]
    for k, v in recon["integrity"].items():
        L.append(f"- {k}: {json.dumps(v, default=str)}")
    c = recon["dataset_change"]
    L += [
        "",
        "## Root-cause finding",
        "",
        f"- Finding: **{c['finding']}** (dataset changed: {c['changed']}; basis: {c['basis']})",
    ]
    if c.get("changed_sample_ids") is not None:
        L.append(
            f"- Changed samples: {len(c['changed_sample_ids'])} "
            f"(first: {c['changed_sample_ids'][:10]})"
        )
    if c.get("label_transitions"):
        L.append(f"- Label transitions: {c['label_transitions']}")
    if c.get("profile_delta"):
        L.append(f"- Class-count changes: {c['profile_delta']}")
    if c.get("modification_window"):
        L.append(
            f"- Modification window: {c['modification_window'][0]} … "
            f"{c['modification_window'][1]}"
        )
    L += ["", "## Missing evidence", ""]
    L += [f"- {m}" for m in recon["missing_evidence"]] or ["- none"]
    L += ["", "## Limitations", ""] + [f"- {x}" for x in recon["limitations"]]
    L += ["", f"_Reconstruction runtime: {recon['runtime_seconds']:.3f} s_", ""]
    return "\n".join(L)


def write_markdown(recon: dict[str, Any], path: str | Path, title: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_markdown(recon, title), encoding="utf-8")
    return path
