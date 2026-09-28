"""Evidence loading: source adapters that turn investigator-visible evidence into
common ``Observation`` records (docs/reconstruction.md §1).

Sources are discovered, not configured. Whatever exists in the evidence directory is
used:

    app.log                    application log           (A, B, C)
    artifacts.json             file-system listing       (A, B, C)
    metrics.json               evaluation output         (A, B, C)
    mlflow_ref.json + MLflow   experiment tracking       (B, C)
    forensic_evidence.sqlite   forensic event store      (C)

The same downstream logic processes the observations whatever their source. With
less evidence there are simply fewer observations. Adapters only translate recorded
facts. They make no inferences and never read anything outside the evidence directory
except the files the evidence itself references (and, for MLflow, the tracking store
named in mlflow_ref.json).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mlfref.forensic.integrity import ChainReport, read_events_readonly, verify_chain


@dataclass
class Observation:
    kind: str
    source: str  # app_log | artifact_listing | mlflow | forensic
    time: str | None = None
    time_basis: str = "exact"  # exact | file_mtime | unknown
    refs: dict[str, Any] = field(default_factory=dict)
    attrs: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "source": self.source,
            "time": self.time,
            "time_basis": self.time_basis,
            "refs": self.refs,
        }


@dataclass
class EvidenceBundle:
    evidence_dir: Path
    workspace_root: Path | None
    sources: dict[str, bool]
    observations: list[Observation]
    chain_report: ChainReport | None = None
    mlflow_error: str | None = None

    def find(self, kind: str, source: str | None = None, **refs: Any) -> list[Observation]:
        out = []
        for o in self.observations:
            if o.kind != kind or (source and o.source != source):
                continue
            if all(o.refs.get(k) == v for k, v in refs.items()):
                out.append(o)
        return out

    def resolve(self, rel_path: str | None) -> Path | None:
        """Workspace file referenced by the evidence (for post-hoc acquisition)."""
        if not rel_path or self.workspace_root is None:
            return None
        p = self.workspace_root / rel_path
        return p if p.exists() else None


# ------------------------------------------------------------------ app.log

_LINE = re.compile(
    r"^(?P<ts>\S+) \| (?P<level>\w+) \| (?P<run>\S+) \| (?P<logger>\S+) \| (?P<msg>.*)$"
)
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "DATASET_REGISTERED",
        re.compile(r"^registered training data store (?P<store>\S+): " r"(?P<n>\d+) samples$"),
    ),
    (
        "TRAINING_DATA_LOADED",
        re.compile(r"^loaded training data from (?P<store>\S+): " r"(?P<n>\d+) samples$"),
    ),
    ("TRAINING_STARTED", re.compile(r"^training started: (?P<params>.*)$")),
    (
        "TRAINING_COMPLETED",
        re.compile(r"^training completed: (?P<epochs>\d+) epochs in " r"(?P<seconds>[\d.]+)s$"),
    ),
    ("MODEL_CREATED", re.compile(r"^saved model to (?P<path>\S+) \((?P<size>\d+) bytes\)$")),
    ("MODEL_DEPLOYED", re.compile(r"^deployed model file (?P<source>\S+) -> (?P<path>\S+)$")),
    ("DEPLOYMENT_ALIAS", re.compile(r"^registry alias production -> version (?P<version>\S+)$")),
    (
        "SERVICE_STARTED",
        re.compile(
            r"^serving (?:model file (?P<path>\S+)|models:/\S+@production"
            r" \(version (?P<version>[^)]+)\))$"
        ),
    ),
    (
        "INFERENCE_RESULT",
        re.compile(
            r"^request_id=(?P<request_id>\S+) predicted=(?P<pred>\S+) "
            r"latency_ms=(?P<latency>[\d.]+)$"
        ),
    ),
    ("EVALUATION", re.compile(r"^clean test accuracy (?P<acc>[\d.]+) on (?P<n>\d+) samples$")),
]


def _parse_kv(text: str) -> dict[str, str]:
    return dict(kv.split("=", 1) for kv in text.split() if "=" in kv)


def load_app_log(path: Path) -> list[Observation]:
    obs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        for kind, pattern in _PATTERNS:
            pm = pattern.match(m["msg"])
            if not pm:
                continue
            g = {k: v for k, v in pm.groupdict().items() if v is not None}
            refs: dict[str, Any] = {}
            attrs: dict[str, Any] = {}
            if "store" in g:
                refs["store"] = g["store"]
                attrs["num_samples"] = int(g["n"])
            if kind == "TRAINING_STARTED":
                attrs["parameters"] = _parse_kv(g["params"])
            if kind == "TRAINING_COMPLETED":
                attrs.update(epochs=int(g["epochs"]), seconds=float(g["seconds"]))
            if kind == "MODEL_CREATED":
                refs["model_path"] = g["path"]
                attrs["size_bytes"] = int(g["size"])
            if kind == "MODEL_DEPLOYED":
                refs.update(source_path=g["source"], deployed_path=g["path"])
            if kind in ("DEPLOYMENT_ALIAS", "SERVICE_STARTED") and "version" in g:
                refs["registry_version"] = g["version"]
            if kind == "SERVICE_STARTED" and "path" in g:
                refs["deployed_path"] = g["path"]
            if kind == "INFERENCE_RESULT":
                refs["request_id"] = g["request_id"]
                attrs.update(predicted_label=g["pred"], latency_ms=float(g["latency"]))
            if kind == "EVALUATION":
                attrs.update(accuracy=float(g["acc"]), n=int(g["n"]))
            obs.append(Observation(kind, "app_log", m["ts"], "exact", refs, attrs))
            break
    return obs


# ------------------------------------------------------------------ artifacts.json


def load_artifact_listing(path: Path) -> list[Observation]:
    return [
        Observation(
            "FILE_OBSERVED",
            "artifact_listing",
            e["modified_utc"],
            "file_mtime",
            {"path": e["path"]},
            {"size_bytes": e["size_bytes"]},
        )
        for e in json.loads(path.read_text(encoding="utf-8"))
    ]


# ------------------------------------------------------------------ MLflow


def _ms(ts: int | None) -> str | None:
    if ts is None:
        return None
    return (
        datetime.fromtimestamp(ts / 1000, tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _profile(client, run_id: str, context: str) -> dict[str, Any] | None:
    try:
        local = client.download_artifacts(run_id, f"data_profiles/{context}_data_profile.json")
        return json.loads(Path(local).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - profile not recorded
        return None


def load_mlflow(ref_path: Path, workspace_root: Path | None = None) -> list[Observation]:
    from mlflow.tracking import MlflowClient

    ref = json.loads(ref_path.read_text(encoding="utf-8"))
    uri = ref["tracking_uri"]
    prefix = "sqlite:///"
    if uri.startswith(prefix) and workspace_root and not Path(uri[len(prefix) :]).is_absolute():
        uri = prefix + (workspace_root / uri[len(prefix) :]).resolve().as_posix()
    client = MlflowClient(uri)
    obs: list[Observation] = []
    run_id = ref.get("training_run_id")
    if not run_id:
        return obs
    run = client.get_run(run_id)
    obs.append(
        Observation(
            "TRAINING_STARTED",
            "mlflow",
            _ms(run.info.start_time),
            "exact",
            {"run_id": run_id},
            {
                "parameters": dict(run.data.params),
                "git_commit": run.data.tags.get("mlflow.source.git.commit"),
            },
        )
    )
    if run.info.end_time:
        obs.append(
            Observation(
                "TRAINING_COMPLETED",
                "mlflow",
                _ms(run.info.end_time),
                "exact",
                {"run_id": run_id},
                {"metrics": dict(run.data.metrics)},
            )
        )
    sources = set()
    for dsi in run.inputs.dataset_inputs:
        ctx = next((t.value for t in dsi.tags if t.key == "mlflow.data.context"), None)
        if ctx != "training":
            continue
        sources.add(dsi.dataset.source)
        # MLflow reuses one dataset record per (name, digest) across the tracking store, so
        # the recorded source can be the path of the FIRST run that logged identical data
        # (D-060). It is kept as ``mlflow_source`` and is not used as this run's store.
        obs.append(
            Observation(
                "TRAINING_DATASET",
                "mlflow",
                _ms(run.info.start_time),
                "exact",
                {
                    "run_id": run_id,
                    "dataset_name": dsi.dataset.name,
                    "mlflow_digest": dsi.dataset.digest,
                    "mlflow_source": _source_path(dsi.dataset.source),
                },
                {"profile": _profile(client, run_id, "training")},
            )
        )
    # Data-registration run(s) linked to this training run. Preferred: the registration run ID
    # the pipeline recorded (mlflow_ref.json), or a registration run carrying the same run_ref
    # tag. Fallback when no such record exists: a registration run with the same data source.
    # Engine v1.1 (D-061).
    run_ref = run.data.tags.get("run_ref")
    recorded = ref.get("data_registration_run_id")
    for reg in client.search_runs(
        [run.info.experiment_id], filter_string="tags.run_type = 'data_registration'"
    ):
        if recorded:
            link = "recorded registration run ID" if reg.info.run_id == recorded else None
        elif run_ref and reg.data.tags.get("run_ref") == run_ref:
            link = "same run_ref tag"
        else:
            link = None
        for dsi in reg.inputs.dataset_inputs:
            if link is None and not recorded and dsi.dataset.source in sources:
                link = "same recorded data source"
            if link is None:
                continue
            obs.append(
                Observation(
                    "DATASET_REGISTERED",
                    "mlflow",
                    _ms(reg.info.start_time),
                    "exact",
                    {
                        "run_id": reg.info.run_id,
                        "dataset_name": dsi.dataset.name,
                        "mlflow_digest": dsi.dataset.digest,
                        "mlflow_source": _source_path(dsi.dataset.source),
                        "linked_training_run_id": run_id,
                    },
                    {
                        "profile": _profile(client, reg.info.run_id, "registration"),
                        "link_basis": link,
                    },
                )
            )
    for mv in client.search_model_versions(f"run_id = '{run_id}'"):
        obs.append(
            Observation(
                "MODEL_REGISTERED",
                "mlflow",
                _ms(mv.creation_timestamp),
                "exact",
                {"run_id": run_id, "registry_version": str(mv.version), "model_name": mv.name},
                {"aliases": list(getattr(mv, "aliases", []) or []), "source": mv.source},
            )
        )
    return obs


def _source_path(source: str) -> str:
    """MLflow stores dataset sources as JSON ({"uri": ...}) for local paths."""
    try:
        data = json.loads(source)
        return str(data.get("uri") or data.get("path") or source)
    except (ValueError, TypeError, AttributeError):
        return source


# ------------------------------------------------------------------ forensic store


def load_forensic(db_path: Path) -> tuple[list[Observation], ChainReport]:
    events = read_events_readonly(db_path)
    obs = []
    for e in events:
        meta = json.loads(e.metadata_json)
        refs = {
            k: v
            for k, v in {
                "artifact_id": e.artifact_id,
                "artifact_hash": e.artifact_hash,
                "parent_artifact_id": e.parent_artifact_id,
                "run_id": e.run_id,
                "deployment_id": e.deployment_id,
            }.items()
            if v is not None
        }
        if e.artifact_type == "inference":
            refs["request_id"] = e.artifact_id
        obs.append(
            Observation(
                e.event_type,
                "forensic",
                e.timestamp_utc,
                "exact",
                refs,
                {
                    **meta,
                    "event_id": e.event_id,
                    "actor": e.actor,
                    "sequence_number": e.sequence_number,
                },
            )
        )
    return obs, verify_chain(events)


# ------------------------------------------------------------------ bundle


def load_evidence(
    evidence_dir: str | Path, workspace_root: str | Path | None = None
) -> EvidenceBundle:
    ev = Path(evidence_dir)
    root = Path(workspace_root) if workspace_root else None
    files = {
        "app_log": ev / "app.log",
        "artifact_listing": ev / "artifacts.json",
        "metrics": ev / "metrics.json",
        "mlflow": ev / "mlflow_ref.json",
        "forensic": ev / "forensic_evidence.sqlite",
    }
    sources = {name: path.exists() for name, path in files.items()}
    observations: list[Observation] = []
    chain = None
    mlflow_error = None
    if sources["app_log"]:
        observations += load_app_log(files["app_log"])
    if sources["artifact_listing"]:
        observations += load_artifact_listing(files["artifact_listing"])
    if sources["mlflow"]:
        try:
            observations += load_mlflow(files["mlflow"], root)
        except Exception as exc:  # noqa: BLE001 - record, do not invent
            sources["mlflow"] = False
            mlflow_error = f"{type(exc).__name__}: {exc}"
    if sources["forensic"]:
        forensic_obs, chain = load_forensic(files["forensic"])
        observations += forensic_obs
    return EvidenceBundle(ev, root, sources, observations, chain, mlflow_error)
