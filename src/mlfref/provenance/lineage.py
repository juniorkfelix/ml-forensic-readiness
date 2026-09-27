"""PROV-style lineage graphs (spec §19), conceptually compatible with W3C PROV.

Nodes are **entities** (datasets, models, configuration, code versions, inference
inputs) or **activities** (data registration, poisoning, training, deployment,
inference). Edges use a small subset of PROV relations:

    USED              activity -> entity     (training USED dataset)
    WAS_GENERATED_BY  entity   -> activity   (model WAS_GENERATED_BY training)
    WAS_DERIVED_FROM  entity   -> entity     (dataset WAS_DERIVED_FROM dataset)
    WAS_INFORMED_BY   activity -> activity   (deployment WAS_INFORMED_BY training)

The full PROV standard (agents, qualified relations, bundles) is not implemented.

``lineage_from_mlflow`` reads what MLflow recorded for one training run. It only
*reads* existing provenance and draws no conclusions, so it can serve as a source
adapter for the reconstruction engine in pipelines B and C.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import networkx as nx

RELATIONS = {
    "USED": ("activity", "entity"),
    "WAS_GENERATED_BY": ("entity", "activity"),
    "WAS_DERIVED_FROM": ("entity", "entity"),
    "WAS_INFORMED_BY": ("activity", "activity"),
}


class ProvGraph:
    def __init__(self) -> None:
        self.g = nx.MultiDiGraph()

    # ------------------------------------------------------------- building
    def add_entity(self, node_id: str, entity_type: str, **attrs: Any) -> str:
        self._add(node_id, "entity", entity_type, attrs)
        return node_id

    def add_activity(self, node_id: str, activity_type: str, **attrs: Any) -> str:
        self._add(node_id, "activity", activity_type, attrs)
        return node_id

    def _add(self, node_id: str, kind: str, subtype: str, attrs: Mapping[str, Any]) -> None:
        if node_id in self.g and self.g.nodes[node_id]["kind"] != kind:
            raise ValueError(f"{node_id} already exists as {self.g.nodes[node_id]['kind']}")
        existing = dict(self.g.nodes[node_id]) if node_id in self.g else {}
        self.g.add_node(node_id, **{**existing, **attrs, "kind": kind, "type": subtype})

    def relate(self, relation: str, src: str, dst: str, **attrs: Any) -> None:
        if relation not in RELATIONS:
            raise ValueError(f"unknown relation {relation!r}")
        want_src, want_dst = RELATIONS[relation]
        for node, want in ((src, want_src), (dst, want_dst)):
            if node not in self.g:
                raise KeyError(f"unknown node {node!r}")
            if self.g.nodes[node]["kind"] != want:
                raise ValueError(f"{relation} requires {want} {node!r}")
        if not any(
            d.get("relation") == relation
            for d in self.g.get_edge_data(src, dst, default={}).values()
        ):
            self.g.add_edge(src, dst, relation=relation, **attrs)

    # ------------------------------------------------------------- querying
    def relations(self, relation: str | None = None) -> list[tuple[str, str, str]]:
        return sorted(
            (s, d["relation"], t)
            for s, t, d in self.g.edges(data=True)
            if relation is None or d["relation"] == relation
        )

    def nodes(self, kind: str | None = None) -> dict[str, dict[str, Any]]:
        return {n: dict(a) for n, a in self.g.nodes(data=True) if kind is None or a["kind"] == kind}

    def upstream(self, node_id: str) -> set[str]:
        """Everything ``node_id`` depends on (transitively, following edge direction)."""
        return nx.descendants(self.g, node_id)

    # ------------------------------------------------------------- export
    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [{"id": n, **a} for n, a in sorted(self.g.nodes(data=True))],
            "relations": [{"from": s, "relation": r, "to": t} for s, r, t in self.relations()],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProvGraph:
        graph = cls()
        for node in data["nodes"]:
            attrs = {k: v for k, v in node.items() if k not in ("id", "kind", "type")}
            graph._add(node["id"], node["kind"], node["type"], attrs)
        for rel in data["relations"]:
            graph.relate(rel["relation"], rel["from"], rel["to"])
        return graph

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str), encoding="utf-8")
        return path


def lineage_from_mlflow(client, training_run_id: str) -> ProvGraph:
    """Lineage recorded by MLflow for one training run (read-only).

    Nodes: the training run; each logged dataset input (by name + digest); each
    data-registration run in the same experiment that logged the same dataset NAME;
    registered model versions created from the run. No inference is made about
    whether datasets with the same name but different digests are "the same";
    both are recorded with their digests.
    """
    graph = ProvGraph()
    run = client.get_run(training_run_id)
    train_node = graph.add_activity(
        f"mlflow-run:{training_run_id}",
        "training",
        start_time=run.info.start_time,
        end_time=run.info.end_time,
        run_ref=run.data.tags.get("run_ref"),
    )
    names = set()
    for dsi in run.inputs.dataset_inputs:
        ctx = next((t.value for t in dsi.tags if t.key == "mlflow.data.context"), None)
        ds = graph.add_entity(
            f"dataset:{dsi.dataset.name}@{dsi.dataset.digest}",
            "dataset",
            name=dsi.dataset.name,
            digest=dsi.dataset.digest,
            source=dsi.dataset.source,
            context=ctx,
        )
        graph.relate("USED", train_node, ds, context=ctx)
        names.add(dsi.dataset.name)

    exp_id = run.info.experiment_id
    for reg in client.search_runs([exp_id], filter_string="tags.run_type = 'data_registration'"):
        for dsi in reg.inputs.dataset_inputs:
            if dsi.dataset.name not in names:
                continue
            reg_node = graph.add_activity(
                f"mlflow-run:{reg.info.run_id}",
                "data_registration",
                start_time=reg.info.start_time,
                end_time=reg.info.end_time,
                run_ref=reg.data.tags.get("run_ref"),
            )
            ds = graph.add_entity(
                f"dataset:{dsi.dataset.name}@{dsi.dataset.digest}",
                "dataset",
                name=dsi.dataset.name,
                digest=dsi.dataset.digest,
                source=dsi.dataset.source,
            )
            graph.relate("USED", reg_node, ds, context="registration")

    for mv in client.search_model_versions(f"run_id = '{training_run_id}'"):
        node = graph.add_entity(
            f"model:{mv.name}/v{mv.version}",
            "model",
            name=mv.name,
            version=mv.version,
            source=mv.source,
            creation_timestamp=mv.creation_timestamp,
            aliases=list(getattr(mv, "aliases", []) or []),
        )
        graph.relate("WAS_GENERATED_BY", node, train_node)
    return graph
