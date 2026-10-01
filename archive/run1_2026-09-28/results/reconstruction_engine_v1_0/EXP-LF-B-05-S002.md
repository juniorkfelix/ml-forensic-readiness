# Incident reconstruction: EXP-LF-B-05-S002 (RUN-b9cbe476-9864-45da-8caa-74cf647e6bd0)

## Incident

- Ticket: `INC-b9cbe476`; request `REQ-00038` at 2026-09-28T11:07:35.545298Z
- Observed prediction **truck** (confidence 0.734165); expected **automobile**
- Input SHA-256: `4f1694ce9865f23c5468a9c180903730463fc93f3cab734621b1474b5384a33a`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: available
- forensic: NOT AVAILABLE

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | MODERATE | `REQ-00038` | request_id REQ-00038 recorded in app_log |
| Deployment | IDENTIFIED | WEAK | `11` | latest recorded deployment before the incident (time ordering); registry alias production -> version 11 |
| Model | IDENTIFIED | MODERATE | `df12246e50a8423b96fc7ca4068f86fd` | registry version 11 (MLflow model registry); deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | MODERATE | `df12246e50a8423b96fc7ca4068f86fd` | MLflow model version lineage (run_id) |
| Training dataset | IDENTIFIED | MODERATE | `f92f93f9` | MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | WEAK | `data/stores/RUN-b9cbe476-9864-45da-8…` | registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T10:55:50.352097Z | exact | WEAK |
| 2 | TRAINING_STARTED | 2026-09-28T10:55:55.474302Z | exact | MODERATE |
| 3 | TRAINING_COMPLETED | 2026-09-28T11:07:29.105308Z | exact | MODERATE |
| 4 | MODEL_CREATED | 2026-09-28T11:07:30.951895Z | exact | MODERATE |
| 5 | MODEL_DEPLOYED | 2026-09-28T11:07:34.411849Z | exact | WEAK |
| 6 | INPUT_SUBMITTED | 2026-09-28T11:07:35.554772Z | inferred | MODERATE |
| 7 | INCIDENT_PREDICTION | 2026-09-28T11:07:35.554772Z | exact | MODERATE |

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

- evidence source not available: forensic
- dataset change between registration and training: NOT_OBSERVABLE
- integrity/evidence_chain: NOT_OBSERVABLE
- integrity/dataset_check: NOT_OBSERVABLE

## Limitations

- Only investigator-visible evidence of this pipeline was used; no external reference data.
- Post-hoc file hashes show the current state of a file, not its state at the time of the event.
- MLflow dataset digests cover only the first 10,000 values of each array; equal digests do not prove identical datasets.
- The forensic hash chain gives tamper evidence, not tamper prevention.

_Reconstruction runtime: 0.284 s_
