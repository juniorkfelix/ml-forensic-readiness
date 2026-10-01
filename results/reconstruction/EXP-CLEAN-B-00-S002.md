# Incident reconstruction: EXP-CLEAN-B-00-S002 (RUN-f565c5b5-0af4-4ad9-8892-0b415cc666c5)

## Incident

- Ticket: `INC-f565c5b5`; request `REQ-00017` at 2026-10-01T10:12:27.835785Z
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
| Deployment | IDENTIFIED | WEAK | `6` | latest recorded deployment before the incident (time ordering); registry alias production -> version 6 |
| Model | IDENTIFIED | MODERATE | `ff2115a69e3f4cd4941dbada2692a16f` | registry version 6 (MLflow model registry); deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | MODERATE | `ff2115a69e3f4cd4941dbada2692a16f` | MLflow model version lineage (run_id) |
| Training dataset | IDENTIFIED | MODERATE | `f133e984` | MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | MODERATE | `f133e984` | MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-10-01T10:00:27.142000Z | exact | MODERATE |
| 2 | TRAINING_STARTED | 2026-10-01T10:00:29.610675Z | exact | MODERATE |
| 3 | TRAINING_COMPLETED | 2026-10-01T10:12:20.879994Z | exact | MODERATE |
| 4 | MODEL_CREATED | 2026-10-01T10:12:22.835167Z | exact | MODERATE |
| 5 | MODEL_DEPLOYED | 2026-10-01T10:12:26.960687Z | exact | WEAK |
| 6 | INPUT_SUBMITTED | 2026-10-01T10:12:27.850410Z | inferred | MODERATE |
| 7 | INCIDENT_PREDICTION | 2026-10-01T10:12:27.850410Z | exact | MODERATE |

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

_Reconstruction runtime: 0.373 s_
