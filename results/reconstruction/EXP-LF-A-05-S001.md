# Incident reconstruction: EXP-LF-A-05-S001 (RUN-abab1863-7503-410c-98d3-b0dd285928b3)

## Incident

- Ticket: `INC-abab1863`; request `REQ-00005` at 2026-10-01T08:50:14.294404Z
- Observed prediction **truck** (confidence 0.566549); expected **automobile**
- Input SHA-256: `a9b3556efe09797b0fa8e7c9dd14a00ba7e66feea8a0d1fadc87b2340e2e92c2`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: NOT AVAILABLE
- forensic: NOT AVAILABLE

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | MODERATE | `REQ-00005` | request_id REQ-00005 recorded in app_log |
| Deployment | IDENTIFIED | WEAK | `models/deployed/RUN-abab1863-7503-41…` | latest recorded deployment before the incident (time ordering) |
| Model | IDENTIFIED | MODERATE | `models/checkpoints/RUN-abab1863-7503…` | deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | WEAK | `-` | training start/completion logged before the model was saved |
| Training dataset | IDENTIFIED | WEAK | `data/stores/RUN-abab1863-7503-410c-9…` | training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | WEAK | `data/stores/RUN-abab1863-7503-410c-9…` | registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-10-01T08:37:18.936060Z | exact | WEAK |
| 2 | TRAINING_STARTED | 2026-10-01T08:37:24.532286Z | exact | WEAK |
| 3 | TRAINING_COMPLETED | 2026-10-01T08:50:11.162844Z | exact | WEAK |
| 4 | MODEL_CREATED | 2026-10-01T08:50:13.317374Z | exact | MODERATE |
| 5 | MODEL_DEPLOYED | 2026-10-01T08:50:13.395756Z | exact | WEAK |
| 6 | INPUT_SUBMITTED | 2026-10-01T08:50:14.307805Z | inferred | MODERATE |
| 7 | INCIDENT_PREDICTION | 2026-10-01T08:50:14.307805Z | exact | MODERATE |

## Artefact relationships

- deployment **USED** model
- inference **USED** incident_input
- inference **USED** model
- inference **WAS_INFORMED_BY** deployment
- model **WAS_GENERATED_BY** training
- training **USED** training_dataset

## Integrity findings

- evidence_chain: {"status": "NOT_OBSERVABLE"}
- dataset_check: {"status": "NOT_OBSERVABLE"}
- deployed_model_check: {"status": "POST_HOC", "result": "MATCH", "basis": "deployed and trained model files hashed during the investigation (current state only)"}

## Root-cause finding

- Finding: **INSUFFICIENT_EVIDENCE** (dataset changed: UNKNOWN; basis: NOT_OBSERVABLE)

## Missing evidence

- evidence source not available: mlflow
- evidence source not available: forensic
- dataset change between registration and training: NOT_OBSERVABLE
- integrity/evidence_chain: NOT_OBSERVABLE
- integrity/dataset_check: NOT_OBSERVABLE

## Limitations

- Only investigator-visible evidence of this pipeline was used; no external reference data.
- Post-hoc file hashes show the current state of a file, not its state at the time of the event.
- MLflow dataset digests cover only the first 10,000 values of each array; equal digests do not prove identical datasets.
- The forensic hash chain gives tamper evidence, not tamper prevention.

_Reconstruction runtime: 0.235 s_
