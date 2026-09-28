# Incident reconstruction: EXP-CLEAN-B-00-S001 (RUN-ffa47dc0-899d-4409-b96e-6cb9f99b51c8), engine 1.1

## Incident

- Ticket: `INC-ffa47dc0`; request `REQ-00006` at 2026-09-28T08:24:58.197781Z
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
| Deployment | IDENTIFIED | WEAK | `3` | latest recorded deployment before the incident (time ordering); registry alias production -> version 3 |
| Model | IDENTIFIED | MODERATE | `67c1762c08244011a0ae02e0f85a35f8` | registry version 3 (MLflow model registry); deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | MODERATE | `67c1762c08244011a0ae02e0f85a35f8` | MLflow model version lineage (run_id) |
| Training dataset | IDENTIFIED | MODERATE | `f133e984` | MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | MODERATE | `f133e984` | MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T08:07:56.746000Z | exact | MODERATE |
| 2 | TRAINING_STARTED | 2026-09-28T08:07:58.259968Z | exact | MODERATE |
| 3 | TRAINING_COMPLETED | 2026-09-28T08:24:52.330117Z | exact | MODERATE |
| 4 | MODEL_CREATED | 2026-09-28T08:24:54.809589Z | exact | MODERATE |
| 5 | MODEL_DEPLOYED | 2026-09-28T08:24:57.726995Z | exact | WEAK |
| 6 | INPUT_SUBMITTED | 2026-09-28T08:24:58.208690Z | inferred | MODERATE |
| 7 | INCIDENT_PREDICTION | 2026-09-28T08:24:58.208690Z | exact | MODERATE |

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

_Reconstruction runtime: 0.136 s_
