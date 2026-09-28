# Incident reconstruction: EXP-BD-A-05-S002 (RUN-01c81c4e-b2ae-4de9-80a0-fb5b566ea39f), engine 1.1

## Incident

- Ticket: `INC-01c81c4e`; request `REQ-00016` at 2026-09-28T11:31:55.405950Z
- Observed prediction **airplane** (confidence 0.999989); expected **automobile**
- Input SHA-256: `b6f5c16697d356069a011891984a729152d16df636202c209882ab17aa7d9b67`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: NOT AVAILABLE
- forensic: NOT AVAILABLE

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | MODERATE | `REQ-00016` | request_id REQ-00016 recorded in app_log |
| Deployment | IDENTIFIED | WEAK | `models/deployed/RUN-01c81c4e-b2ae-4d…` | latest recorded deployment before the incident (time ordering) |
| Model | IDENTIFIED | MODERATE | `models/checkpoints/RUN-01c81c4e-b2ae…` | deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | WEAK | `-` | training start/completion logged before the model was saved |
| Training dataset | IDENTIFIED | WEAK | `data/stores/RUN-01c81c4e-b2ae-4de9-8…` | training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | WEAK | `data/stores/RUN-01c81c4e-b2ae-4de9-8…` | registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T11:20:19.773024Z | exact | WEAK |
| 2 | TRAINING_STARTED | 2026-09-28T11:20:24.324881Z | exact | WEAK |
| 3 | TRAINING_COMPLETED | 2026-09-28T11:31:51.238609Z | exact | WEAK |
| 4 | MODEL_CREATED | 2026-09-28T11:31:54.310550Z | exact | MODERATE |
| 5 | MODEL_DEPLOYED | 2026-09-28T11:31:54.405163Z | exact | WEAK |
| 6 | INPUT_SUBMITTED | 2026-09-28T11:31:55.416647Z | inferred | MODERATE |
| 7 | INCIDENT_PREDICTION | 2026-09-28T11:31:55.416647Z | exact | MODERATE |

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

_Reconstruction runtime: 0.080 s_
