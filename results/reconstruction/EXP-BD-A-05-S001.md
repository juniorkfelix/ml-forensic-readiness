# Incident reconstruction: EXP-BD-A-05-S001 (RUN-bc81cf32-607e-4463-9723-c14a51d93b03), engine 1.1

## Incident

- Ticket: `INC-bc81cf32`; request `REQ-00016` at 2026-09-28T09:44:24.537140Z
- Observed prediction **airplane** (confidence 0.999673); expected **automobile**
- Input SHA-256: `88719ab26db5b0c4b362472f69c17f5d2356eaacbf4a8194c10cc12d80179c63`

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
| Deployment | IDENTIFIED | WEAK | `models/deployed/RUN-bc81cf32-607e-44…` | latest recorded deployment before the incident (time ordering) |
| Model | IDENTIFIED | MODERATE | `models/checkpoints/RUN-bc81cf32-607e…` | deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | WEAK | `-` | training start/completion logged before the model was saved |
| Training dataset | IDENTIFIED | WEAK | `data/stores/RUN-bc81cf32-607e-4463-9…` | training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | WEAK | `data/stores/RUN-bc81cf32-607e-4463-9…` | registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T09:32:59.416679Z | exact | WEAK |
| 2 | TRAINING_STARTED | 2026-09-28T09:33:03.389006Z | exact | WEAK |
| 3 | TRAINING_COMPLETED | 2026-09-28T09:44:20.287330Z | exact | WEAK |
| 4 | MODEL_CREATED | 2026-09-28T09:44:23.333556Z | exact | MODERATE |
| 5 | MODEL_DEPLOYED | 2026-09-28T09:44:23.417992Z | exact | WEAK |
| 6 | INPUT_SUBMITTED | 2026-09-28T09:44:24.562876Z | inferred | MODERATE |
| 7 | INCIDENT_PREDICTION | 2026-09-28T09:44:24.562876Z | exact | MODERATE |

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
