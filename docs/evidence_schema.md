# Evidence Schema

**Status:** DRAFT design (implemented in Phases 10–13). This file defines what evidence each
pipeline preserves. It must stay consistent with `config/evaluation_schema.yaml`.

Governing rules:
- Evidence is **preserved, not interpreted** (D-019). No logger writes a conclusion such as
  "sample 42 poisoned" or "root cause = …".
- The attack is **covert** (D-014). No investigator-visible artefact contains `attack_type`,
  `poison_rate`, source/target class, trigger parameters, or an attack-revealing experiment ID.
  Runs are referenced by `RUN-<experiment_uuid>` (D-021).
- Evidence exists only where the pipeline could realistically record it. The adversary's tampering
  happens outside the pipeline and is **not** logged by any pipeline (D-015).

## 1. Storage layout (investigator-visible)

```
evidence/
  conventional/RUN-<uuid>/          # pipeline A
    app.log                         # application log
    metrics.json                    # standard evaluation output (clean accuracy etc.)
    artifacts.json                  # file-system listing of model/data-store files: path, size, mtime
  provenance/RUN-<uuid>/            # pipeline B = A's files + MLflow reference
    app.log, metrics.json, artifacts.json
    mlflow_ref.json                 # tracking URI, experiment and run IDs for this run
  forensic/RUN-<uuid>/              # pipeline C = B's files + forensic store
    app.log, metrics.json, artifacts.json, mlflow_ref.json
    forensic_evidence.sqlite
    manifests/<dataset_id>.json     # per-sample manifests preserved as evidence
    evidence_export.jsonl
mlruns/                             # MLflow backend (sqlite) + artefacts, used by B and C
models/deployed/, data store        # operational artefacts, present for all pipelines
```

`artifacts.json` in A is the kind of file-system listing an investigator could take themselves
(path, size, modification time). It contains **no hashes**, because §14 excludes investigation-
specific hashes from A.

The MLflow store is shared across runs, as in real use. The reconstruction engine is given only
this run's `mlflow_ref.json`, but it may query MLflow for related runs, e.g. the data-registration
run, as an investigator could.

## 2. Pipeline A — conventional

| Stage | Evidence | Content |
|---|---|---|
| Dataset | app log | "loaded training data from <store path>: N samples" |
| Training | app log | start/end lines with epoch, loss, accuracy, device; hyper-parameters printed at start |
| Model | model file; app log | "saved model to <path>"; file size/mtime in `artifacts.json` |
| Deployment | app log | "serving model <path>" at service start |
| Inference | app log | one INFO line per request: request_id, predicted class, latency (no model identity, no input hash) |
| Integrity | — | none |
| System | app log | device, library versions printed at start |

## 3. Pipeline B — provenance (adds MLflow)

| Stage | MLflow record |
|---|---|
| Dataset | **data-registration run** (`run_type=data_registration`): `mlflow.log_input` with dataset name `CIFAR10-TRAIN-<hash12>`, digest, source path, profile (N, class counts) |
| Training | **training run**: params (architecture, epochs, batch size, lr, optimizer, seed, loss, augmentation), tags (git commit, `run_ref=RUN-<uuid>`, `pipeline_mode`), per-epoch metrics, `mlflow.log_input` of the dataset **as loaded at training time** (digest + profile), start/end times (MLflow native) |
| Model | logged model artefact; registered model version linked to the training run |
| Deployment | registry alias `production` → version (MLflow records the version and its timestamps); app log "serving models:/cifar-resnet18@production (version N)" |
| Inference | as A (MLflow does not track inference) |
| Integrity | MLflow dataset digests (not a dedicated integrity check) |

No `attack_type` or `poison_rate` parameter is logged (D-014). The data-registration and training
runs each log a dataset input. Any difference in digest or class profile between the two is genuine,
organic evidence.

## 4. Pipeline C — forensic ready (adds forensic event store)

### 4.1 Common event header (table `forensic_events`)

| Column | Type | Notes |
|---|---|---|
| `event_id` | TEXT PK | UUID4 |
| `sequence_number` | INTEGER | monotonically increasing per store |
| `timestamp_utc` | TEXT | ISO-8601, microsecond precision, `Z` suffix |
| `experiment_id` | TEXT | run reference `RUN-<uuid>` (D-021) |
| `experiment_uuid` | TEXT | |
| `pipeline_mode` | TEXT | `forensic` |
| `event_type` | TEXT | see §4.2 |
| `actor` | TEXT | component/service account that performed the action, e.g. `svc-training` |
| `source_component` | TEXT | Python module that emitted the event |
| `artifact_type` | TEXT | `dataset` \| `model` \| `deployment` \| `inference` \| `config` \| `code` \| `system` |
| `artifact_id` | TEXT | e.g. `CIFAR10-TRAIN-<hash12>`, `MODEL-<hash12>`, `DEP-<uuid8>`, `REQ-<n>` |
| `artifact_hash` | TEXT | SHA-256 where applicable |
| `parent_artifact_id` | TEXT | lineage link (e.g. model → dataset it was trained on) |
| `run_id` | TEXT | MLflow run ID where applicable |
| `deployment_id` | TEXT | |
| `previous_event_id` | TEXT | chain link |
| `previous_event_hash` | TEXT | |
| `event_hash` | TEXT | `SHA256(canonical_json(payload_without_event_hash) + previous_event_hash)` |
| `metadata_json` | TEXT | event-specific fields (canonical JSON) |

The hash chain gives **tamper evidence**: a later modification, deletion or reordering of a stored
event is detectable by recomputing the chain. It does **not** prevent tampering. An attacker who can
rewrite the entire database can also recompute every hash. No stronger claim is made.

### 4.2 Event types and metadata

| Event | Emitted when | Key metadata (never attack parameters) |
|---|---|---|
| `EXPERIMENT_STARTED` / `EXPERIMENT_COMPLETED` | run start/end | config hash, git commit |
| `CONFIGURATION_LOADED` | config resolved | config SHA-256, layer names |
| `DATASET_REGISTERED` | clean dataset registered | N, class counts, manifest SHA-256, content SHA-256, manifest path |
| `DATASET_INTEGRITY_VERIFIED` | training job re-hashes the store before training | expected hash, observed hash, `result` = MATCH/MISMATCH, observed manifest path |
| `DATASET_VERSION_CREATED` | the observed dataset differs from the registered one, so the pipeline records the observed state as a new version whose parent is the registered version | new dataset ID, parent ID, N, class counts, manifest path. `actor = unknown` (the pipeline did not create it) |
| `ARTIFACT_INTEGRITY_FAILURE` | any integrity mismatch | artefact, expected, observed |
| `TRAINING_STARTED` / `TRAINING_COMPLETED` | training job | dataset ID + hash used, hyper-parameters, MLflow run ID, final metrics |
| `MODEL_CREATED` / `MODEL_HASHED` / `MODEL_REGISTERED` | model saved / hashed / registered in MLflow | path, size, SHA-256, registry version |
| `MODEL_DEPLOYED` / `MODEL_REPLACED` | deployment | deployment ID, model ID + hash, registry version |
| `ARTIFACT_INTEGRITY_CHECK` | deployed file re-hashed at service start | expected/observed hash, result |
| `INFERENCE_REQUEST` | per request | request ID, input SHA-256, deployment ID |
| `INFERENCE_RESULT` | per request | request ID, predicted class, confidence (softmax max), model hash |

Per-request inference events are real evidence and scale with traffic. The number of simulated
requests is fixed per run (`deployment.inference_requests`) so that storage overhead is comparable.

### 4.3 Dataset manifest format (per-sample)

Canonical JSON, records sorted by `sample_id`:
```json
{"dataset_id": "CIFAR10-TRAIN-3f9a…", "hash_algorithm": "SHA-256", "records": [
  {"sample_id": 0, "label": 6, "pixel_sha256": "…"}, …]}
```
`manifest_sha256` = SHA-256 of the canonical serialisation. Changing the order of the records does
not change it; changing any label or any pixel does.

Note: the investigator-visible manifest has a single `label` field, the label currently stored.
The spec's "original label / effective label" pair (§9) is kept in **ground truth** only, because
recording both in evidence would reveal the poisoning directly.

## 5. What is deliberately NOT evidence

- Attack type, poison rate, classes and trigger parameters in any pipeline.
- A list of modified samples written by any logger. It can only be *derived* by the reconstruction
  engine from two preserved manifests.
- Any event describing the adversary's modification as it happened.
