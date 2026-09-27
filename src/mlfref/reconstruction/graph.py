"""PROV-style relationship graph of a reconstructed incident (spec §19)."""

from __future__ import annotations

from typing import Any

from mlfref.provenance.lineage import ProvGraph


def build_graph(findings: dict[str, Any]) -> ProvGraph:
    h = findings["hops"]
    g = ProvGraph()
    pri, tds, tr = h["prior_dataset"], h["training_dataset"], h["training_run"]
    mod, dep, inf = h["model"], h["deployment"], h["inference"]

    def label(v: dict[str, Any], *keys: str) -> str:
        for k in keys:
            if v.get(k):
                return str(v[k])[:24]
        return "unidentified"

    if tds["status"] == "IDENTIFIED":
        g.add_entity(
            "training_dataset",
            "dataset",
            confidence=tds["confidence"],
            label=label(tds["value"], "dataset_id", "mlflow_digest", "store"),
        )
    if pri["status"] == "IDENTIFIED":
        g.add_entity(
            "registered_dataset",
            "dataset",
            confidence=pri["confidence"],
            label=label(pri["value"], "dataset_id", "mlflow_digest", "store"),
        )
        if findings["dataset_change"].get("changed") is True and "training_dataset" in g.g:
            g.add_activity(
                "dataset_modification",
                "modification",
                window=findings["dataset_change"].get("modification_window"),
            )
            g.relate("USED", "dataset_modification", "registered_dataset")
            g.relate("WAS_GENERATED_BY", "training_dataset", "dataset_modification")
            g.relate("WAS_DERIVED_FROM", "training_dataset", "registered_dataset")
    if tr["status"] == "IDENTIFIED":
        g.add_activity(
            "training",
            "training",
            confidence=tr["confidence"],
            label=label(tr["value"], "run_id", "start_time"),
        )
        if "training_dataset" in g.g:
            g.relate("USED", "training", "training_dataset")
    if mod["status"] == "IDENTIFIED":
        g.add_entity(
            "model",
            "model",
            confidence=mod["confidence"],
            label=label(mod["value"], "model_id", "registry_version", "path"),
        )
        if "training" in g.g:
            g.relate("WAS_GENERATED_BY", "model", "training")
    if dep["status"] == "IDENTIFIED":
        g.add_activity(
            "deployment",
            "deployment",
            confidence=dep["confidence"],
            label=label(dep["value"], "deployment_id", "deployed_path"),
        )
        if "model" in g.g:
            g.relate("USED", "deployment", "model")
    if inf["status"] == "IDENTIFIED":
        g.add_activity(
            "inference",
            "inference",
            confidence=inf["confidence"],
            label=inf["value"].get("request_id"),
        )
        g.add_entity(
            "incident_input",
            "inference_input",
            label=str(inf["value"].get("input_sha256") or "not recorded")[:24],
        )
        g.relate("USED", "inference", "incident_input")
        if "model" in g.g:
            g.relate("USED", "inference", "model")
        if "deployment" in g.g:
            g.relate("WAS_INFORMED_BY", "inference", "deployment")
    return g
