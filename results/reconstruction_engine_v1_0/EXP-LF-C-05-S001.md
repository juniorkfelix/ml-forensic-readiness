# Incident reconstruction: EXP-LF-C-05-S001 (RUN-e2835110-6824-464f-98f3-5725fbca89b8)

## Incident

- Ticket: `INC-e2835110`; request `REQ-00005` at 2026-09-28T09:32:37.696187Z
- Observed prediction **truck** (confidence 0.566549); expected **automobile**
- Input SHA-256: `a9b3556efe09797b0fa8e7c9dd14a00ba7e66feea8a0d1fadc87b2340e2e92c2`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: available
- forensic: available

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | STRONG | `REQ-00005` | input SHA-256 recorded at request time equals ticket input hash |
| Deployment | IDENTIFIED | STRONG | `DEP-5ae1123a` | deployment_id recorded with the inference result; registry alias production -> version 6 |
| Model | IDENTIFIED | STRONG | `MODEL-4d634c055d47` | served model SHA-256 equals hash recorded when the model was created; registry version 6 (MLflow model registry); deployed file copied from recorded model path |
| Training run | IDENTIFIED | STRONG | `3914e27a03924a0abdf98c86105c1f28` | run ID recorded with the model hash |
| Training dataset | IDENTIFIED | STRONG | `CIFAR10-TRAIN-a703e34d1ba0` | dataset hash recorded when training started; MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | STRONG | `CIFAR10-TRAIN-f7285605e556` | observed dataset version records the registered version as its parent |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T09:16:35.903148Z | exact | STRONG |
| 2 | DATASET_MODIFIED | 2026-09-28T09:16:35.903148Z … 2026-09-28T09:16:37.558872Z | bounded | STRONG |
| 3 | TRAINING_STARTED | 2026-09-28T09:16:38.906907Z | exact | STRONG |
| 4 | TRAINING_COMPLETED | 2026-09-28T09:32:33.032625Z | exact | STRONG |
| 5 | MODEL_CREATED | 2026-09-28T09:32:34.820521Z | exact | STRONG |
| 6 | MODEL_DEPLOYED | 2026-09-28T09:32:36.961203Z | exact | STRONG |
| 7 | INPUT_SUBMITTED | 2026-09-28T09:32:37.696295Z | exact | STRONG |
| 8 | INCIDENT_PREDICTION | 2026-09-28T09:32:37.719075Z | exact | STRONG |

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

- evidence_chain: {"n_events": 414, "hash_chained": true, "valid": true, "n_problems": 0, "first_bad_sequence": null, "head_hash": "1f3a76c47fccce1ed2fe33380b6f5ef05874296c6ce4499c3b048605ab2bbd12"}
- dataset_check: {"status": "RECORDED", "result": "MISMATCH", "expected": "f7285605e556be1f453be1f05ea295de43e5e5a1c1d01b7de8d3f449dedb1649", "observed": "a703e34d1ba044453353c8bf7cc9468978b8f036fd0cbbc7080ae75074fe75d8", "time": "2026-09-28T09:16:38.081343Z"}
- deployed_model_check: {"status": "RECORDED", "result": "MATCH", "basis": "integrity check recorded at service start", "time": "2026-09-28T09:32:37.367778Z"}

## Root-cause finding

- Finding: **LABEL_MODIFICATION** (dataset changed: True; basis: comparison of preserved per-sample manifests)
- Changed samples: 2500 (first: [45, 46, 61, 64, 96, 99, 119, 126, 137, 212])
- Label transitions: {'1->9': 2500}
- Class-count changes: {'automobile': -2500, 'truck': 2500}
- Modification window: 2026-09-28T09:16:35.903148Z … 2026-09-28T09:16:37.558872Z

## Missing evidence

- none

## Limitations

- Only investigator-visible evidence of this pipeline was used; no external reference data.
- Post-hoc file hashes show the current state of a file, not its state at the time of the event.
- MLflow dataset digests cover only the first 10,000 values of each array; equal digests do not prove identical datasets.
- The forensic hash chain gives tamper evidence, not tamper prevention.

_Reconstruction runtime: 0.245 s_
