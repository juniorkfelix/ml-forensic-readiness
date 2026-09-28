# Incident reconstruction: EXP-LF-B-05-S001 (RUN-380525b0-c415-479e-993c-def64de10f0e), engine 1.1

## Incident

- Ticket: `INC-380525b0`; request `REQ-00005` at 2026-09-28T09:16:16.121086Z
- Observed prediction **truck** (confidence 0.566549); expected **automobile**
- Input SHA-256: `a9b3556efe09797b0fa8e7c9dd14a00ba7e66feea8a0d1fadc87b2340e2e92c2`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: available
- forensic: NOT AVAILABLE

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | MODERATE | `REQ-00005` | request_id REQ-00005 recorded in app_log |
| Deployment | IDENTIFIED | WEAK | `5` | latest recorded deployment before the incident (time ordering); registry alias production -> version 5 |
| Model | IDENTIFIED | MODERATE | `82404e9a152b496f88ed37b4e83e638b` | registry version 5 (MLflow model registry); deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | MODERATE | `82404e9a152b496f88ed37b4e83e638b` | MLflow model version lineage (run_id) |
| Training dataset | IDENTIFIED | MODERATE | `3783ddd9` | MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | MODERATE | `f133e984` | MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T08:59:35.978000Z | exact | MODERATE |
| 2 | DATASET_MODIFIED | 2026-09-28T08:59:35.978000Z … 2026-09-28T08:59:38.237263Z | bounded | MODERATE |
| 3 | TRAINING_STARTED | 2026-09-28T08:59:38.638197Z | exact | MODERATE |
| 4 | TRAINING_COMPLETED | 2026-09-28T09:16:11.309978Z | exact | MODERATE |
| 5 | MODEL_CREATED | 2026-09-28T09:16:13.798551Z | exact | MODERATE |
| 6 | MODEL_DEPLOYED | 2026-09-28T09:16:15.631587Z | exact | WEAK |
| 7 | INPUT_SUBMITTED | 2026-09-28T09:16:16.131273Z | inferred | MODERATE |
| 8 | INCIDENT_PREDICTION | 2026-09-28T09:16:16.131273Z | exact | MODERATE |

## Artefact relationships

- dataset_modification **USED** registered_dataset
- deployment **USED** model
- inference **USED** incident_input
- inference **USED** model
- inference **WAS_INFORMED_BY** deployment
- model **WAS_GENERATED_BY** training
- training **USED** training_dataset
- training_dataset **WAS_DERIVED_FROM** registered_dataset
- training_dataset **WAS_GENERATED_BY** dataset_modification

## Integrity findings

- evidence_chain: {"status": "NOT_OBSERVABLE"}
- dataset_check: {"status": "NOT_OBSERVABLE"}
- deployed_model_check: {"status": "POST_HOC", "result": "MATCH", "basis": "deployed and trained model files hashed during the investigation (current state only)"}

## Root-cause finding

- Finding: **DATASET_MODIFIED_UNSPECIFIED** (dataset changed: True; basis: MLflow dataset digests (partial coverage: first 10,000 values per array))
- Class-count changes: {'automobile': -2500, 'truck': 2500}
- Modification window: 2026-09-28T08:59:35.978000Z … 2026-09-28T08:59:38.237263Z

## Missing evidence

- evidence source not available: forensic
- which samples changed: NOT_OBSERVABLE (no per-sample manifests)
- integrity/evidence_chain: NOT_OBSERVABLE
- integrity/dataset_check: NOT_OBSERVABLE

## Limitations

- Only investigator-visible evidence of this pipeline was used; no external reference data.
- Post-hoc file hashes show the current state of a file, not its state at the time of the event.
- MLflow dataset digests cover only the first 10,000 values of each array; equal digests do not prove identical datasets.
- The forensic hash chain gives tamper evidence, not tamper prevention.

_Reconstruction runtime: 0.136 s_
