# Incident reconstruction: EXP-BD-B-05-S002 (RUN-c57e6eed-8275-4285-a8a6-7d6ed53231b8)

## Incident

- Ticket: `INC-c57e6eed`; request `REQ-00016` at 2026-10-01T11:49:52.545457Z
- Observed prediction **airplane** (confidence 0.999989); expected **automobile**
- Input SHA-256: `b6f5c16697d356069a011891984a729152d16df636202c209882ab17aa7d9b67`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: available
- forensic: NOT AVAILABLE

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | MODERATE | `REQ-00016` | request_id REQ-00016 recorded in app_log |
| Deployment | IDENTIFIED | WEAK | `11` | latest recorded deployment before the incident (time ordering); registry alias production -> version 11 |
| Model | IDENTIFIED | MODERATE | `463327c9f6454dafa74bbab042806ce4` | registry version 11 (MLflow model registry); deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | MODERATE | `463327c9f6454dafa74bbab042806ce4` | MLflow model version lineage (run_id) |
| Training dataset | IDENTIFIED | MODERATE | `bbbffe6a` | MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | MODERATE | `f133e984` | MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-10-01T11:37:03.075000Z | exact | MODERATE |
| 2 | DATASET_MODIFIED | 2026-10-01T11:37:03.075000Z … 2026-10-01T11:37:06.957464Z | bounded | MODERATE |
| 3 | TRAINING_STARTED | 2026-10-01T11:37:07.793164Z | exact | MODERATE |
| 4 | TRAINING_COMPLETED | 2026-10-01T11:49:44.700474Z | exact | MODERATE |
| 5 | MODEL_CREATED | 2026-10-01T11:49:47.870749Z | exact | MODERATE |
| 6 | MODEL_DEPLOYED | 2026-10-01T11:49:51.511404Z | exact | WEAK |
| 7 | INPUT_SUBMITTED | 2026-10-01T11:49:52.556758Z | inferred | MODERATE |
| 8 | INCIDENT_PREDICTION | 2026-10-01T11:49:52.556758Z | exact | MODERATE |

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
- Class-count changes: {'airplane': 2500, 'automobile': -304, 'bird': -295, 'cat': -254, 'deer': -289, 'dog': -279, 'frog': -282, 'horse': -261, 'ship': -237, 'truck': -299}
- Modification window: 2026-10-01T11:37:03.075000Z … 2026-10-01T11:37:06.957464Z

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

_Reconstruction runtime: 0.379 s_
