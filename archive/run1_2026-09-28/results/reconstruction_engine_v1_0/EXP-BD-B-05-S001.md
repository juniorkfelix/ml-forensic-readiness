# Incident reconstruction: EXP-BD-B-05-S001 (RUN-5b1679c2-d570-47d6-a42c-fd11176a4456)

## Incident

- Ticket: `INC-5b1679c2`; request `REQ-00016` at 2026-09-28T09:56:25.805399Z
- Observed prediction **airplane** (confidence 0.999673); expected **automobile**
- Input SHA-256: `88719ab26db5b0c4b362472f69c17f5d2356eaacbf4a8194c10cc12d80179c63`

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
| Deployment | IDENTIFIED | WEAK | `7` | latest recorded deployment before the incident (time ordering); registry alias production -> version 7 |
| Model | IDENTIFIED | MODERATE | `ae3fa39144974e05858ef36c2109990c` | registry version 7 (MLflow model registry); deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | MODERATE | `ae3fa39144974e05858ef36c2109990c` | MLflow model version lineage (run_id) |
| Training dataset | IDENTIFIED | MODERATE | `6ca94090` | MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | MODERATE | `f133e984` | MLflow data-registration run for the same data source |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T09:44:51.195000Z | exact | MODERATE |
| 2 | DATASET_MODIFIED | 2026-09-28T09:44:51.195000Z … 2026-09-28T09:44:54.370306Z | bounded | MODERATE |
| 3 | TRAINING_STARTED | 2026-09-28T09:44:54.934553Z | exact | MODERATE |
| 4 | TRAINING_COMPLETED | 2026-09-28T09:56:19.440487Z | exact | MODERATE |
| 5 | MODEL_CREATED | 2026-09-28T09:56:22.325641Z | exact | MODERATE |
| 6 | MODEL_DEPLOYED | 2026-09-28T09:56:25.101354Z | exact | WEAK |
| 7 | INPUT_SUBMITTED | 2026-09-28T09:56:25.819467Z | inferred | MODERATE |
| 8 | INCIDENT_PREDICTION | 2026-09-28T09:56:25.819467Z | exact | MODERATE |

## Artefact relationships

- dataset_modification **USED** registered_dataset
- deployment **USED** model
- inference **USED** incident_input
- inference **USED** model
- inference **WAS_INFORMED_BY** deployment
- model **WAS_GENERATED_BY** training
- training **USED** training_dataset
- training_dataset **WAS_DERIVED_FROM** registered_dataset
- training_dataset **WAS_GENERATED_BY** dataset_modification

## Integrity findings

- evidence_chain: {"status": "NOT_OBSERVABLE"}
- dataset_check: {"status": "NOT_OBSERVABLE"}
- deployed_model_check: {"status": "POST_HOC", "result": "MATCH", "basis": "deployed and trained model files hashed during the investigation (current state only)"}

## Root-cause finding

- Finding: **DATASET_MODIFIED_UNSPECIFIED** (dataset changed: True; basis: MLflow dataset digests (partial coverage: first 10,000 values per array))
- Class-count changes: {'airplane': 2500, 'automobile': -276, 'bird': -284, 'cat': -272, 'deer': -306, 'dog': -283, 'frog': -256, 'horse': -274, 'ship': -261, 'truck': -288}
- Modification window: 2026-09-28T09:44:51.195000Z … 2026-09-28T09:44:54.370306Z

## Missing evidence

- evidence source not available: forensic
- which samples changed: NOT_OBSERVABLE (no per-sample manifests)
- integrity/evidence_chain: NOT_OBSERVABLE
- integrity/dataset_check: NOT_OBSERVABLE

## Limitations

- Only investigator-visible evidence of this pipeline was used; no external reference data.
- Post-hoc file hashes show the current state of a file, not its state at the time of the event.
- MLflow dataset digests cover only the first 10,000 values of each array; equal digests do not prove identical datasets.
- The forensic hash chain gives tamper evidence, not tamper prevention.

_Reconstruction runtime: 0.524 s_
