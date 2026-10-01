# Incident reconstruction: EXP-CLEAN-A-00-S001 (RUN-113821e2-4cec-4eed-b18f-0b8a79c294f3), engine 1.1

## Incident

- Ticket: `INC-113821e2`; request `REQ-00006` at 2026-09-28T08:07:38.651620Z
- Observed prediction **cat** (confidence 0.690073); expected **deer**
- Input SHA-256: `7bbac3efc461eab19a1a4110e0dbfb6b3ff1bdde78b189b216b6882ad4e70bab`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: NOT AVAILABLE
- forensic: NOT AVAILABLE

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | MODERATE | `REQ-00006` | request_id REQ-00006 recorded in app_log |
| Deployment | IDENTIFIED | WEAK | `models/deployed/RUN-113821e2-4cec-4e…` | latest recorded deployment before the incident (time ordering) |
| Model | IDENTIFIED | MODERATE | `models/checkpoints/RUN-113821e2-4cec…` | deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | WEAK | `-` | training start/completion logged before the model was saved |
| Training dataset | IDENTIFIED | WEAK | `data/stores/RUN-113821e2-4cec-4eed-b…` | training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | WEAK | `data/stores/RUN-113821e2-4cec-4eed-b…` | registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T07:48:48.841338Z | exact | WEAK |
| 2 | TRAINING_STARTED | 2026-09-28T07:48:52.483995Z | exact | WEAK |
| 3 | TRAINING_COMPLETED | 2026-09-28T08:07:35.599978Z | exact | WEAK |
| 4 | MODEL_CREATED | 2026-09-28T08:07:38.151441Z | exact | MODERATE |
| 5 | MODEL_DEPLOYED | 2026-09-28T08:07:38.191515Z | exact | WEAK |
| 6 | INPUT_SUBMITTED | 2026-09-28T08:07:38.658742Z | inferred | MODERATE |
| 7 | INCIDENT_PREDICTION | 2026-09-28T08:07:38.658742Z | exact | MODERATE |

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

_Reconstruction runtime: 0.076 s_
