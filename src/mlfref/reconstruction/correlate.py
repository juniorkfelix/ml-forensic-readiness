"""Backward correlation from an incident to its origin (docs/reconstruction.md §2-3).

    incident ticket -> INFERENCE -> DEPLOYMENT -> MODEL -> TRAINING RUN
                    -> TRAINING DATASET -> PRIOR (REGISTERED) DATASET STATE

The same rules run for every pipeline. Each hop takes the strongest supporting link
available in the observations and records its basis and confidence:

    STRONG    cryptographic hash, or an explicit ID link recorded at the time of the event
    MODERATE  recorded ID/path link without a hash, or native MLflow lineage
    WEAK      inferred from time proximity / ordering within a log, or file mtimes
    NONE      no supporting evidence -> UNKNOWN (never guessed)

Post-hoc acquisition: files referenced by the evidence may be hashed *now*
(``POST_HOC``). This shows the current state of a file, not its state at the time of
the event, and is labelled as such.

Root-cause rule (fixed in advance, docs/reconstruction.md §3):
    two per-sample manifests  -> changed sample IDs + change type
        labels only                 -> LABEL_MODIFICATION
        pixels and labels           -> CONTENT_AND_LABEL_MODIFICATION
        pixels only                 -> CONTENT_MODIFICATION
        no differences              -> NO_DATASET_MODIFICATION_FOUND
    digest/hash comparison only -> DATASET_MODIFIED_UNSPECIFIED | NO_DATASET_MODIFICATION_FOUND
    no comparable dataset states -> INSUFFICIENT_EVIDENCE
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mlfref.data.manifest import compare_manifests
from mlfref.forensic.hashing import sha256_file
from mlfref.reconstruction.loader import EvidenceBundle, Observation

STRONG, MODERATE, WEAK, NONE = "STRONG", "MODERATE", "WEAK", "NONE"
UNKNOWN, NOT_OBSERVABLE, INSUFFICIENT = "UNKNOWN", "NOT_OBSERVABLE", "INSUFFICIENT_EVIDENCE"


@dataclass
class Hop:
    name: str
    status: str = UNKNOWN  # IDENTIFIED | UNKNOWN
    confidence: str = NONE
    basis: list[str] = field(default_factory=list)
    value: dict[str, Any] = field(default_factory=dict)

    def identify(self, confidence: str, basis: str, **value: Any) -> None:
        self.status = "IDENTIFIED"
        self.confidence = confidence
        self.basis.append(basis)
        self.value.update({k: v for k, v in value.items() if v is not None})

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _first(obs: list[Observation]) -> Observation | None:
    return min(obs, key=lambda o: o.time or "") if obs else None


def _last_before(obs: list[Observation], t: str | None) -> Observation | None:
    cands = [o for o in obs if o.time and (t is None or o.time <= t)]
    return max(cands, key=lambda o: o.time) if cands else None


def _load_manifest(bundle: EvidenceBundle, rel: str | None) -> list[dict[str, Any]] | None:
    path = bundle.resolve(rel)
    if path is None:
        return None
    return json.loads(path.read_text(encoding="utf-8"))["records"]


def _post_hoc_hash(bundle: EvidenceBundle, rel: str | None) -> str | None:
    path = bundle.resolve(rel)
    return sha256_file(path) if path else None


def trace(bundle: EvidenceBundle, ticket: dict[str, Any]) -> dict[str, Any]:
    hops = {
        n: Hop(n)
        for n in (
            "inference",
            "deployment",
            "model",
            "training_run",
            "training_dataset",
            "prior_dataset",
        )
    }
    rid = ticket["request_id"]

    # ---------------------------------------------------------------- INFERENCE
    inf = hops["inference"]
    results = bundle.find("INFERENCE_RESULT", request_id=rid)
    requests = bundle.find("INFERENCE_REQUEST", request_id=rid)
    if results:
        res = next((o for o in results if o.source == "forensic"), results[0])
        req = requests[0] if requests else None
        predicted = res.attrs.get("predicted_label")
        value = {
            "request_id": rid,
            "time": res.time,
            "predicted_label": predicted,
            "prediction_matches_ticket": predicted == ticket.get("observed_prediction"),
            "deployment_id": res.refs.get("deployment_id"),
            "model_sha256": res.attrs.get("model_sha256"),
            "request_time": req.time if req else None,
            "input_sha256": req.refs.get("artifact_hash") if req else None,
        }
        if req and req.refs.get("artifact_hash") == ticket.get("input_sha256"):
            inf.identify(
                STRONG, "input SHA-256 recorded at request time equals ticket input hash", **value
            )
        else:
            inf.identify(MODERATE, f"request_id {rid} recorded in {res.source}", **value)

    # ---------------------------------------------------------------- DEPLOYMENT
    dep = hops["deployment"]
    dep_obs = bundle.find("MODEL_DEPLOYED") + bundle.find("MODEL_REPLACED")
    dep_id = inf.value.get("deployment_id")
    by_id = [o for o in dep_obs if dep_id and o.refs.get("deployment_id") == dep_id]
    alias = _first(
        bundle.find("DEPLOYMENT_ALIAS")
        or [o for o in bundle.find("SERVICE_STARTED") if "registry_version" in o.refs]
    )
    if by_id:
        o = by_id[0]
        dep.identify(
            STRONG,
            "deployment_id recorded with the inference result",
            time=o.time,
            deployment_id=dep_id,
            model_sha256=o.refs.get("artifact_hash"),
            model_id=o.attrs.get("model_id"),
            deployed_path=o.attrs.get("deployed_path"),
            source_path=o.attrs.get("source_path"),
            registry_version=o.attrs.get("registry_version"),
        )
    else:
        app_dep = _last_before([o for o in dep_obs if o.source == "app_log"], inf.value.get("time"))
        if app_dep:
            dep.identify(
                WEAK,
                "latest recorded deployment before the incident (time ordering)",
                time=app_dep.time,
                deployed_path=app_dep.refs.get("deployed_path"),
                source_path=app_dep.refs.get("source_path"),
            )
    if alias and alias.refs.get("registry_version"):
        dep.value.setdefault("registry_version", alias.refs["registry_version"])
        dep.basis.append(f"registry alias production -> version {alias.refs['registry_version']}")

    # ---------------------------------------------------------------- MODEL
    mod = hops["model"]
    served_hash = inf.value.get("model_sha256") or dep.value.get("model_sha256")
    hashed = [
        o
        for o in bundle.find("MODEL_HASHED")
        if served_hash and o.refs.get("artifact_hash") == served_hash
    ]
    version = dep.value.get("registry_version")
    registered = [
        o
        for o in bundle.find("MODEL_REGISTERED", source="mlflow")
        if version and o.refs.get("registry_version") == version
    ]
    created_app = [
        o
        for o in bundle.find("MODEL_CREATED", source="app_log")
        if dep.value.get("source_path") and o.refs.get("model_path") == dep.value.get("source_path")
    ]
    if hashed:
        o = hashed[0]
        mod.identify(
            STRONG,
            "served model SHA-256 equals hash recorded when the model was created",
            model_id=o.refs.get("artifact_id"),
            model_sha256=served_hash,
            path=o.attrs.get("path"),
            time=o.time,
            run_id=o.refs.get("run_id"),
        )
    if registered:
        o = registered[0]
        conf = mod.confidence if mod.status == "IDENTIFIED" else MODERATE
        mod.identify(
            conf,
            f"registry version {version} (MLflow model registry)",
            registry_version=version,
            run_id=mod.value.get("run_id") or o.refs["run_id"],
            time=mod.value.get("time") or o.time,
        )
    if created_app:
        o = created_app[0]
        conf = mod.confidence if mod.status == "IDENTIFIED" else MODERATE
        mod.identify(
            conf,
            "deployed file copied from recorded model path",
            path=mod.value.get("path") or o.refs["model_path"],
            time=mod.value.get("time") or o.time,
        )
    if mod.status == "IDENTIFIED":
        # Creation time = earliest record of this model's creation, from any source.
        model_id, model_path = mod.value.get("model_id"), mod.value.get("path")
        creation = (
            hashed
            + registered
            + created_app
            + [
                o
                for o in bundle.find("MODEL_CREATED")
                if model_id and o.refs.get("artifact_id") == model_id
            ]
            + [
                o
                for o in bundle.find("MODEL_CREATED", source="app_log")
                if model_path and o.refs.get("model_path") == model_path
            ]
        )
        times = [o.time for o in creation if o.time]
        if times:
            mod.value["time"] = min(times)
    if mod.status == "IDENTIFIED" and mod.value.get("path"):
        mod.value["post_hoc_sha256"] = _post_hoc_hash(bundle, mod.value["path"])
        if not mod.value.get("model_sha256") and mod.value["post_hoc_sha256"]:
            mod.basis.append("model file hashed post hoc (current state, not historical)")

    # ---------------------------------------------------------------- TRAINING RUN
    # Generic rule for every pipeline: training start = latest start record before the model
    # was created; completion = earliest completion record after that start. Records linked
    # to the run ID and application-log records are both candidates.
    tr = hops["training_run"]
    run_id = mod.value.get("run_id")
    model_time = mod.value.get("time")
    starts = bundle.find("TRAINING_STARTED")
    ends = bundle.find("TRAINING_COMPLETED")

    def linked(obs: list[Observation]) -> list[Observation]:
        return [
            o for o in obs if (run_id and o.refs.get("run_id") == run_id) or o.source == "app_log"
        ]

    start = _last_before(linked(starts), model_time)
    end = None
    if start:
        after = [
            o
            for o in linked(ends)
            if o.time
            and o.time >= start.time
            and (model_time is None or o.time <= model_time or o.source != "app_log")
        ]
        end = _first(after)
    run_starts = [o for o in starts if run_id and o.refs.get("run_id") == run_id]
    params = (
        next((o.attrs.get("parameters") for o in run_starts if o.source == "mlflow"), None)
        or next((o.attrs.get("hyperparameters") for o in run_starts), None)
        or (start.attrs.get("parameters") if start else None)
    )
    code = next(
        (o.attrs.get("git_commit") for o in run_starts if o.attrs.get("git_commit")), None
    ) or next(
        (
            o.attrs.get("git_commit")
            for o in bundle.find("EXPERIMENT_STARTED")
            if o.attrs.get("git_commit")
        ),
        None,
    )
    if run_id:
        conf = STRONG if hashed and hashed[0].refs.get("run_id") == run_id else MODERATE
        basis = (
            "run ID recorded with the model hash"
            if conf == STRONG
            else "MLflow model version lineage (run_id)"
        )
        tr.identify(
            conf,
            basis,
            run_id=run_id,
            start_time=start.time if start else None,
            end_time=end.time if end else None,
            parameters=params,
            code_version=code,
        )
    elif mod.status == "IDENTIFIED" and start:
        tr.identify(
            WEAK,
            "training start/completion logged before the model was saved",
            start_time=start.time,
            end_time=end.time if end else None,
            parameters=params,
            code_version=code,
        )

    # ---------------------------------------------------------------- TRAINING DATASET
    tds = hops["training_dataset"]
    f_start = [
        o for o in starts if o.source == "forensic" and run_id and o.refs.get("run_id") == run_id
    ] or ([o for o in starts if o.source == "forensic"] if tr.status == "IDENTIFIED" else [])
    ml_ds = [
        o for o in bundle.find("TRAINING_DATASET") if run_id and o.refs.get("run_id") == run_id
    ]
    loaded = _last_before(bundle.find("TRAINING_DATA_LOADED"), tr.value.get("start_time"))
    if f_start:
        o = f_start[0]
        tds.identify(
            STRONG,
            "dataset hash recorded when training started",
            dataset_id=o.refs.get("artifact_id"),
            manifest_sha256=o.refs.get("artifact_hash"),
        )
    if ml_ds:
        o = ml_ds[0]
        conf = tds.confidence if tds.status == "IDENTIFIED" else MODERATE
        tds.identify(
            conf,
            "MLflow dataset input of the training run",
            mlflow_digest=o.refs["mlflow_digest"],
            store=o.refs.get("store"),
            profile=(o.attrs.get("profile") or {}).get("class_distribution"),
        )
    if loaded and tr.status == "IDENTIFIED":
        conf = tds.confidence if tds.status == "IDENTIFIED" else WEAK
        tds.identify(
            conf,
            "training data store logged as loaded before training",
            store=tds.value.get("store") or loaded.refs["store"],
            load_time=loaded.time,
            num_samples=loaded.attrs.get("num_samples"),
        )
    observed_version = [
        o
        for o in bundle.find("DATASET_VERSION_CREATED")
        if o.refs.get("artifact_id") == tds.value.get("dataset_id")
    ]
    integrity = [
        o
        for o in bundle.find("DATASET_INTEGRITY_VERIFIED")
        if o.refs.get("artifact_id") == tds.value.get("dataset_id")
    ]
    same_as_registered = [
        o
        for o in bundle.find("DATASET_REGISTERED", source="forensic")
        if tds.value.get("dataset_id") and o.refs.get("artifact_id") == tds.value.get("dataset_id")
    ]
    ds_meta = (
        observed_version[0].attrs
        if observed_version
        else same_as_registered[0].attrs if same_as_registered else {}
    )
    if ds_meta.get("class_distribution"):
        tds.value["profile"] = ds_meta["class_distribution"]
    if ds_meta.get("manifest_path"):
        tds.value["manifest_path"] = ds_meta["manifest_path"]
    if integrity:
        tds.value["load_time"] = tds.value.get("load_time") or integrity[0].time

    # ---------------------------------------------------------------- PRIOR DATASET
    pri = hops["prior_dataset"]
    parent = observed_version[0].refs.get("parent_artifact_id") if observed_version else None
    f_reg = bundle.find("DATASET_REGISTERED", source="forensic")
    f_reg_match = [o for o in f_reg if parent and o.refs.get("artifact_id") == parent] or [
        o for o in f_reg if o.refs.get("artifact_id") == tds.value.get("dataset_id")
    ]
    ml_reg = [
        o
        for o in bundle.find("DATASET_REGISTERED", source="mlflow")
        if tds.value.get("store") and o.refs.get("store") == tds.value.get("store")
    ]
    app_reg = [
        o
        for o in bundle.find("DATASET_REGISTERED", source="app_log")
        if tds.value.get("store") and o.refs.get("store") == tds.value.get("store")
    ]
    if f_reg_match:
        o = f_reg_match[0]
        basis = (
            "observed dataset version records the registered version as its parent"
            if parent
            else "registered dataset hash recorded"
        )
        pri.identify(
            STRONG,
            basis,
            dataset_id=o.refs.get("artifact_id"),
            manifest_sha256=o.refs.get("artifact_hash"),
            time=o.time,
            manifest_path=o.attrs.get("manifest_path"),
            profile=o.attrs.get("class_distribution"),
            store=o.attrs.get("store"),
        )
    if ml_reg:
        o = ml_reg[0]
        conf = pri.confidence if pri.status == "IDENTIFIED" else MODERATE
        pri.identify(
            conf,
            "MLflow data-registration run for the same data source",
            mlflow_digest=o.refs["mlflow_digest"],
            store=o.refs.get("store"),
            time=pri.value.get("time") or o.time,
            profile=pri.value.get("profile")
            or (o.attrs.get("profile") or {}).get("class_distribution"),
        )
    if app_reg:
        o = app_reg[0]
        conf = pri.confidence if pri.status == "IDENTIFIED" else WEAK
        pri.identify(
            conf,
            "registration of the same data store logged earlier",
            store=o.refs["store"],
            time=pri.value.get("time") or o.time,
            num_samples=o.attrs.get("num_samples"),
        )

    change = _characterise_change(bundle, tds, pri)
    integrity_findings = _integrity(bundle, inf, dep, mod, tds)
    return {
        "hops": {k: h.as_dict() for k, h in hops.items()},
        "dataset_change": change,
        "integrity": integrity_findings,
    }


def _characterise_change(bundle: EvidenceBundle, tds: Hop, pri: Hop) -> dict[str, Any]:
    out: dict[str, Any] = {
        "changed": UNKNOWN,
        "basis": NOT_OBSERVABLE,
        "finding": INSUFFICIENT,
        "changed_sample_ids": None,
        "change_type": None,
        "label_transitions": None,
        "profile_delta": None,
        "modification_window": None,
    }
    if pri.status != "IDENTIFIED" or tds.status != "IDENTIFIED":
        return out
    a, b = pri.value, tds.value
    if a.get("time") and b.get("load_time"):
        out["modification_window"] = [a["time"], b["load_time"]]
    if a.get("profile") and b.get("profile"):
        delta = {k: b["profile"].get(k, 0) - a["profile"].get(k, 0) for k in a["profile"]}
        out["profile_delta"] = {k: v for k, v in delta.items() if v}

    before = _load_manifest(bundle, a.get("manifest_path"))
    after = _load_manifest(bundle, b.get("manifest_path")) if b.get("manifest_path") else None
    if a.get("manifest_sha256") and b.get("manifest_sha256"):
        changed = a["manifest_sha256"] != b["manifest_sha256"]
        out.update(changed=changed, basis="SHA-256 of canonical per-sample manifests")
        if changed and before is not None and after is not None:
            diff = compare_manifests(before, after)
            labels, pixels = set(diff.label_changed), set(diff.pixels_changed)
            change_type = (
                "CONTENT_AND_LABEL_MODIFICATION"
                if labels and pixels and labels == pixels
                else (
                    "LABEL_MODIFICATION"
                    if labels and not pixels
                    else "CONTENT_MODIFICATION" if pixels and not labels else "MIXED_MODIFICATION"
                )
            )
            out.update(
                finding=change_type,
                change_type=change_type,
                changed_sample_ids=list(diff.changed),
                label_transitions=diff.label_transitions,
                diff_summary=diff.summary(),
                basis="comparison of preserved per-sample manifests",
            )
        elif changed:
            out["finding"] = "DATASET_MODIFIED_UNSPECIFIED"
        else:
            out["finding"] = "NO_DATASET_MODIFICATION_FOUND"
            out["modification_window"] = None
        return out
    if a.get("mlflow_digest") and b.get("mlflow_digest"):
        changed = a["mlflow_digest"] != b["mlflow_digest"]
        out.update(
            changed=changed,
            basis="MLflow dataset digests (partial coverage: first 10,000 values per array)",
            finding="DATASET_MODIFIED_UNSPECIFIED" if changed else "NO_DATASET_MODIFICATION_FOUND",
        )
        if not changed:
            out["modification_window"] = None
        return out
    out["modification_window"] = None
    return out


def _integrity(bundle: EvidenceBundle, inf: Hop, dep: Hop, mod: Hop, tds: Hop) -> dict[str, Any]:
    out: dict[str, Any] = {}
    chain = bundle.chain_report
    out["evidence_chain"] = chain.summary() if chain else {"status": NOT_OBSERVABLE}
    ds_checks = bundle.find("DATASET_INTEGRITY_VERIFIED")
    out["dataset_check"] = (
        {
            "status": "RECORDED",
            "result": ds_checks[0].attrs.get("result"),
            "expected": ds_checks[0].attrs.get("expected"),
            "observed": ds_checks[0].attrs.get("observed"),
            "time": ds_checks[0].time,
        }
        if ds_checks
        else {"status": NOT_OBSERVABLE}
    )
    m_checks = bundle.find("ARTIFACT_INTEGRITY_CHECK")
    if m_checks:
        o = m_checks[0]
        out["deployed_model_check"] = {
            "status": "RECORDED",
            "result": o.attrs.get("result"),
            "basis": "integrity check recorded at service start",
            "time": o.time,
        }
    else:
        deployed = _post_hoc_hash(bundle, dep.value.get("deployed_path"))
        trained = mod.value.get("post_hoc_sha256")
        if deployed and trained:
            out["deployed_model_check"] = {
                "status": "POST_HOC",
                "result": "MATCH" if deployed == trained else "MISMATCH",
                "basis": "deployed and trained model files hashed during the investigation "
                "(current state only)",
            }
        else:
            out["deployed_model_check"] = {"status": NOT_OBSERVABLE}
    return out


def ticket_summary(ticket: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in ticket.items() if k != "input_image_uint8"}


def relative(path: Path, root: Path | None) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix() if root else path.name
    except ValueError:
        return path.name
