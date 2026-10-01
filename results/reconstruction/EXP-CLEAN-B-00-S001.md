# Incident reconstruction: EXP-CLEAN-B-00-S001 (RUN-152e796a-46ba-4163-b039-d892aee7362b)

## Incident

- Ticket: `INC-152e796a`; request `REQ-00006` at 2026-10-01T08:24:09.708853Z
- Observed prediction **cat** (confidence 0.690073); expected **deer**
- Input SHA-256: `7bbac3efc461eab19a1a4110e0dbfb6b3ff1bdde78b189b216b6882ad4e70bab`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: available
- forensic: NOT AVAILABLE

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | MODERATE | `REQ-00006` | request_id REQ-00006 recorded in app_log |
| Deployment | IDENTIFIED | WEAK | `1` | latest recorded deployment before the incident (time ordering); registry alias production -> version 1 |
| Model | IDENTIFIED | MODERATE | `029ecf29ab54424d905237a42f7a8437` | registry version 1 (MLflow model registry); deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | MODERATE | `029ecf29ab54424d905237a42f7a8437` | MLflow model version lineage (run_id) |
| Training dataset | IDENTIFIED | MODERATE | `f133e984` | MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | MODERATE | `f133e984` | MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-10-01T08:11:42.439000Z | exact | MODERATE |
| 2 | TRAINING_STARTED | 2026-10-01T08:11:45.689985Z | exact | MODERATE |
| 3 | TRAINING_COMPLETED | 2026-10-01T08:24:02.283207Z | exact | MODERATE |
| 4 | MODEL_CREATED | 2026-10-01T08:24:04.107159Z | exact | MODERATE |
| 5 | MODEL_DEPLOYED | 2026-10-01T08:24:08.892710Z | exact | WEAK |
| 6 | INPUT_SUBMITTED | 2026-10-01T08:24:09.728769Z | inferred | MODERATE |
| 7 | INCIDENT_PREDICTION | 2026-10-01T08:24:09.728769Z | exact | MODERATE |

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

_Reconstruction runtime: 0.331 s_
