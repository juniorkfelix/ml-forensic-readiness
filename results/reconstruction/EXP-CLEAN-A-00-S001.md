# Incident reconstruction: EXP-CLEAN-A-00-S001 (RUN-587947f3-e917-43f0-b1d4-b916e0b02c22)

## Incident

- Ticket: `INC-587947f3`; request `REQ-00006` at 2026-10-01T08:11:07.007712Z
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
| Deployment | IDENTIFIED | WEAK | `models/deployed/RUN-587947f3-e917-43…` | latest recorded deployment before the incident (time ordering) |
| Model | IDENTIFIED | MODERATE | `models/checkpoints/RUN-587947f3-e917…` | deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | WEAK | `-` | training start/completion logged before the model was saved |
| Training dataset | IDENTIFIED | WEAK | `data/stores/RUN-587947f3-e917-43f0-b…` | training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | WEAK | `data/stores/RUN-587947f3-e917-43f0-b…` | registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-10-01T07:58:41.208436Z | exact | WEAK |
| 2 | TRAINING_STARTED | 2026-10-01T07:58:44.246568Z | exact | WEAK |
| 3 | TRAINING_COMPLETED | 2026-10-01T08:11:04.460091Z | exact | WEAK |
| 4 | MODEL_CREATED | 2026-10-01T08:11:06.226357Z | exact | MODERATE |
| 5 | MODEL_DEPLOYED | 2026-10-01T08:11:06.308388Z | exact | WEAK |
| 6 | INPUT_SUBMITTED | 2026-10-01T08:11:07.026167Z | inferred | MODERATE |
| 7 | INCIDENT_PREDICTION | 2026-10-01T08:11:07.026167Z | exact | MODERATE |

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

_Reconstruction runtime: 0.215 s_
