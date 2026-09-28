# Incident reconstruction: EXP-BD-C-05-S002 (RUN-c90d6b9c-cdaf-4b38-90f6-6482a2f96290), engine 1.1

## Incident

- Ticket: `INC-c90d6b9c`; request `REQ-00016` at 2026-09-28T11:57:50.887331Z
- Observed prediction **airplane** (confidence 0.999989); expected **automobile**
- Input SHA-256: `b6f5c16697d356069a011891984a729152d16df636202c209882ab17aa7d9b67`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: available
- forensic: available

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | STRONG | `REQ-00016` | input SHA-256 recorded at request time equals ticket input hash |
| Deployment | IDENTIFIED | STRONG | `DEP-a8e0fe76` | deployment_id recorded with the inference result; registry alias production -> version 14 |
| Model | IDENTIFIED | STRONG | `MODEL-1285deb1b912` | served model SHA-256 equals hash recorded when the model was created; registry version 14 (MLflow model registry); deployed file copied from recorded model path |
| Training run | IDENTIFIED | STRONG | `c1d2dbd3cddc466a9b4b2ef1d085ca6c` | run ID recorded with the model hash |
| Training dataset | IDENTIFIED | STRONG | `CIFAR10-TRAIN-337dbf1e666b` | dataset hash recorded when training started; MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | STRONG | `CIFAR10-TRAIN-f7285605e556` | observed dataset version records the registered version as its parent; MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T11:46:21.041059Z | exact | STRONG |
| 2 | DATASET_MODIFIED | 2026-09-28T11:46:21.041059Z … 2026-09-28T11:46:22.387428Z | bounded | STRONG |
| 3 | TRAINING_STARTED | 2026-09-28T11:46:23.379196Z | exact | STRONG |
| 4 | TRAINING_COMPLETED | 2026-09-28T11:57:42.779432Z | exact | STRONG |
| 5 | MODEL_CREATED | 2026-09-28T11:57:46.081198Z | exact | STRONG |
| 6 | MODEL_DEPLOYED | 2026-09-28T11:57:49.486730Z | exact | STRONG |
| 7 | INPUT_SUBMITTED | 2026-09-28T11:57:50.887518Z | exact | STRONG |
| 8 | INCIDENT_PREDICTION | 2026-09-28T11:57:50.911676Z | exact | STRONG |

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

- evidence_chain: {"n_events": 414, "hash_chained": true, "valid": true, "n_problems": 0, "first_bad_sequence": null, "head_hash": "01351b7e5a9dd59dfd93296760a6e49bf58fa95d9a8a4c518fcfa2c74c694948"}
- dataset_check: {"status": "RECORDED", "result": "MISMATCH", "expected": "f7285605e556be1f453be1f05ea295de43e5e5a1c1d01b7de8d3f449dedb1649", "observed": "337dbf1e666ba4cabcd270e42fec5d42ac3fd775db5ed44ed5ed6a8d6b144070", "time": "2026-09-28T11:46:22.780501Z"}
- deployed_model_check: {"status": "RECORDED", "result": "MATCH", "basis": "integrity check recorded at service start", "time": "2026-09-28T11:57:50.018611Z"}

## Root-cause finding

- Finding: **CONTENT_AND_LABEL_MODIFICATION** (dataset changed: True; basis: comparison of preserved per-sample manifests)
- Changed samples: 2500 (first: [9, 20, 82, 85, 98, 99, 104, 111, 137, 151])
- Label transitions: {'1->0': 304, '2->0': 295, '3->0': 254, '4->0': 289, '5->0': 279, '6->0': 282, '7->0': 261, '8->0': 237, '9->0': 299}
- Class-count changes: {'airplane': 2500, 'automobile': -304, 'bird': -295, 'cat': -254, 'deer': -289, 'dog': -279, 'frog': -282, 'horse': -261, 'ship': -237, 'truck': -299}
- Modification window: 2026-09-28T11:46:21.041059Z … 2026-09-28T11:46:22.387428Z

## Missing evidence

- none

## Limitations

- Only investigator-visible evidence of this pipeline was used; no external reference data.
- Post-hoc file hashes show the current state of a file, not its state at the time of the event.
- MLflow dataset digests cover only the first 10,000 values of each array; equal digests do not prove identical datasets.
- The forensic hash chain gives tamper evidence, not tamper prevention.

_Reconstruction runtime: 0.183 s_
