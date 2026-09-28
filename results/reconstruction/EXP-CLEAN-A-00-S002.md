# Incident reconstruction: EXP-CLEAN-A-00-S002 (RUN-a8d61fbc-83f6-4d70-90c7-de2dc3fa0c05), engine 1.1

## Incident

- Ticket: `INC-a8d61fbc`; request `REQ-00017` at 2026-09-28T10:20:03.274866Z
- Observed prediction **horse** (confidence 0.911105); expected **bird**
- Input SHA-256: `fa7ecc1d38ec3ccdae7be1a44ffdf85b5ba4a2caf6bea3c28feb3204bb8ff838`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: NOT AVAILABLE
- forensic: NOT AVAILABLE

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | MODERATE | `REQ-00017` | request_id REQ-00017 recorded in app_log |
| Deployment | IDENTIFIED | WEAK | `models/deployed/RUN-a8d61fbc-83f6-4d…` | latest recorded deployment before the incident (time ordering) |
| Model | IDENTIFIED | MODERATE | `models/checkpoints/RUN-a8d61fbc-83f6…` | deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | WEAK | `-` | training start/completion logged before the model was saved |
| Training dataset | IDENTIFIED | WEAK | `data/stores/RUN-a8d61fbc-83f6-4d70-9…` | training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | WEAK | `data/stores/RUN-a8d61fbc-83f6-4d70-9…` | registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T10:08:52.327491Z | exact | WEAK |
| 2 | TRAINING_STARTED | 2026-09-28T10:08:54.962998Z | exact | WEAK |
| 3 | TRAINING_COMPLETED | 2026-09-28T10:20:00.992087Z | exact | WEAK |
| 4 | MODEL_CREATED | 2026-09-28T10:20:02.635360Z | exact | MODERATE |
| 5 | MODEL_DEPLOYED | 2026-09-28T10:20:02.685911Z | exact | WEAK |
| 6 | INPUT_SUBMITTED | 2026-09-28T10:20:03.288525Z | inferred | MODERATE |
| 7 | INCIDENT_PREDICTION | 2026-09-28T10:20:03.288525Z | exact | MODERATE |

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

_Reconstruction runtime: 0.079 s_
