# Incident reconstruction: EXP-CLEAN-B-00-S002 (RUN-076a8647-a0dc-4af2-9794-13f624dd04f9), engine 1.1

## Incident

- Ticket: `INC-076a8647`; request `REQ-00017` at 2026-09-28T10:31:47.829078Z
- Observed prediction **horse** (confidence 0.911105); expected **bird**
- Input SHA-256: `fa7ecc1d38ec3ccdae7be1a44ffdf85b5ba4a2caf6bea3c28feb3204bb8ff838`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: available
- forensic: NOT AVAILABLE

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | MODERATE | `REQ-00017` | request_id REQ-00017 recorded in app_log |
| Deployment | IDENTIFIED | WEAK | `9` | latest recorded deployment before the incident (time ordering); registry alias production -> version 9 |
| Model | IDENTIFIED | MODERATE | `ea92d16e22ed4b28b6b39aa83d77c399` | registry version 9 (MLflow model registry); deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | MODERATE | `ea92d16e22ed4b28b6b39aa83d77c399` | MLflow model version lineage (run_id) |
| Training dataset | IDENTIFIED | MODERATE | `f133e984` | MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | MODERATE | `f133e984` | MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T10:20:25.007000Z | exact | MODERATE |
| 2 | TRAINING_STARTED | 2026-09-28T10:20:27.140757Z | exact | MODERATE |
| 3 | TRAINING_COMPLETED | 2026-09-28T10:31:42.121879Z | exact | MODERATE |
| 4 | MODEL_CREATED | 2026-09-28T10:31:43.923576Z | exact | MODERATE |
| 5 | MODEL_DEPLOYED | 2026-09-28T10:31:46.862530Z | exact | WEAK |
| 6 | INPUT_SUBMITTED | 2026-09-28T10:31:47.837317Z | inferred | MODERATE |
| 7 | INCIDENT_PREDICTION | 2026-09-28T10:31:47.837317Z | exact | MODERATE |

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

- Finding: **NO_DATASET_MODIFICATION_FOUND** (dataset changed: False; basis: MLflow dataset digests (partial coverage: first 10,000 values per array))

## Missing evidence

- evidence source not available: forensic
- integrity/evidence_chain: NOT_OBSERVABLE
- integrity/dataset_check: NOT_OBSERVABLE

## Limitations

- Only investigator-visible evidence of this pipeline was used; no external reference data.
- Post-hoc file hashes show the current state of a file, not its state at the time of the event.
- MLflow dataset digests cover only the first 10,000 values of each array; equal digests do not prove identical datasets.
- The forensic hash chain gives tamper evidence, not tamper prevention.

_Reconstruction runtime: 0.149 s_
