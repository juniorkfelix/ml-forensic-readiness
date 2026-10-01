# Incident reconstruction: EXP-LF-B-05-S002 (RUN-6ba0e82c-d849-4d01-8110-2a6c4a811757)

## Incident

- Ticket: `INC-6ba0e82c`; request `REQ-00038` at 2026-10-01T11:36:20.322357Z
- Observed prediction **truck** (confidence 0.734165); expected **automobile**
- Input SHA-256: `4f1694ce9865f23c5468a9c180903730463fc93f3cab734621b1474b5384a33a`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: available
- forensic: NOT AVAILABLE

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | MODERATE | `REQ-00038` | request_id REQ-00038 recorded in app_log |
| Deployment | IDENTIFIED | WEAK | `10` | latest recorded deployment before the incident (time ordering); registry alias production -> version 10 |
| Model | IDENTIFIED | MODERATE | `b6b29480ef874c4682918375a94dcf76` | registry version 10 (MLflow model registry); deployed file copied from recorded model path; model file hashed post hoc (current state, not historical) |
| Training run | IDENTIFIED | MODERATE | `b6b29480ef874c4682918375a94dcf76` | MLflow model version lineage (run_id) |
| Training dataset | IDENTIFIED | MODERATE | `f92f93f9` | MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | MODERATE | `f133e984` | MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-10-01T11:23:58.385000Z | exact | MODERATE |
| 2 | DATASET_MODIFIED | 2026-10-01T11:23:58.385000Z … 2026-10-01T11:24:00.778031Z | bounded | MODERATE |
| 3 | TRAINING_STARTED | 2026-10-01T11:24:01.219514Z | exact | MODERATE |
| 4 | TRAINING_COMPLETED | 2026-10-01T11:36:10.444809Z | exact | MODERATE |
| 5 | MODEL_CREATED | 2026-10-01T11:36:13.081713Z | exact | MODERATE |
| 6 | MODEL_DEPLOYED | 2026-10-01T11:36:18.613665Z | exact | WEAK |
| 7 | INPUT_SUBMITTED | 2026-10-01T11:36:20.336299Z | inferred | MODERATE |
| 8 | INCIDENT_PREDICTION | 2026-10-01T11:36:20.336299Z | exact | MODERATE |

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
- Class-count changes: {'automobile': -2500, 'truck': 2500}
- Modification window: 2026-10-01T11:23:58.385000Z … 2026-10-01T11:24:00.778031Z

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

_Reconstruction runtime: 0.563 s_
