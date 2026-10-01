# Incident reconstruction: EXP-BD-B-05-S002 (RUN-797a675e-6d90-46ac-a40a-26d70f254273)

## Incident

- Ticket: `INC-797a675e`; request `REQ-00016` at 2026-09-28T11:44:02.326234Z
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
| Deployment | IDENTIFIED | WEAK | `13` | latest recorded deployment before the incident (time ordering); registry alias production -> version 13 |
| Model | IDENTIFIED | MODERATE | `6639c323d02e4d09bdd89edb49ce9727` | registry version 13 (MLflow model registry); deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | MODERATE | `6639c323d02e4d09bdd89edb49ce9727` | MLflow model version lineage (run_id) |
| Training dataset | IDENTIFIED | MODERATE | `bbbffe6a` | MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | WEAK | `data/stores/RUN-797a675e-6d90-46ac-a…` | registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T11:32:20.492856Z | exact | WEAK |
| 2 | TRAINING_STARTED | 2026-09-28T11:32:25.422718Z | exact | MODERATE |
| 3 | TRAINING_COMPLETED | 2026-09-28T11:43:55.437291Z | exact | MODERATE |
| 4 | MODEL_CREATED | 2026-09-28T11:43:58.530685Z | exact | MODERATE |
| 5 | MODEL_DEPLOYED | 2026-09-28T11:44:01.525648Z | exact | WEAK |
| 6 | INPUT_SUBMITTED | 2026-09-28T11:44:02.338998Z | inferred | MODERATE |
| 7 | INCIDENT_PREDICTION | 2026-09-28T11:44:02.338998Z | exact | MODERATE |

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

_Reconstruction runtime: 0.314 s_
