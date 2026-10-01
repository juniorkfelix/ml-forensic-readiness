# Incident reconstruction: EXP-BD-B-05-S001 (RUN-98f31094-838f-4091-b87f-e149db0ccaa5)

## Incident

- Ticket: `INC-98f31094`; request `REQ-00016` at 2026-10-01T09:34:08.414517Z
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
| Deployment | IDENTIFIED | WEAK | `4` | latest recorded deployment before the incident (time ordering); registry alias production -> version 4 |
| Model | IDENTIFIED | MODERATE | `7d86ec1fc4a449eb904999d916cc90a0` | registry version 4 (MLflow model registry); deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | MODERATE | `7d86ec1fc4a449eb904999d916cc90a0` | MLflow model version lineage (run_id) |
| Training dataset | IDENTIFIED | MODERATE | `6ca94090` | MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | MODERATE | `f133e984` | MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-10-01T09:19:53.271000Z | exact | MODERATE |
| 2 | DATASET_MODIFIED | 2026-10-01T09:19:53.271000Z … 2026-10-01T09:19:57.871621Z | bounded | MODERATE |
| 3 | TRAINING_STARTED | 2026-10-01T09:19:58.706445Z | exact | MODERATE |
| 4 | TRAINING_COMPLETED | 2026-10-01T09:33:58.535446Z | exact | MODERATE |
| 5 | MODEL_CREATED | 2026-10-01T09:34:01.783949Z | exact | MODERATE |
| 6 | MODEL_DEPLOYED | 2026-10-01T09:34:07.011420Z | exact | WEAK |
| 7 | INPUT_SUBMITTED | 2026-10-01T09:34:08.433128Z | inferred | MODERATE |
| 8 | INCIDENT_PREDICTION | 2026-10-01T09:34:08.433128Z | exact | MODERATE |

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
- Modification window: 2026-10-01T09:19:53.271000Z … 2026-10-01T09:19:57.871621Z

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

_Reconstruction runtime: 0.345 s_
