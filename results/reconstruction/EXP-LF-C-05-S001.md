# Incident reconstruction: EXP-LF-C-05-S001 (RUN-2caaf4ca-7608-47e3-9f5c-c4899d1843bb)

## Incident

- Ticket: `INC-2caaf4ca`; request `REQ-00005` at 2026-10-01T09:05:32.886880Z
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
| Deployment | IDENTIFIED | STRONG | `DEP-97033a07` | deployment_id recorded with the inference result; registry alias production -> version 3 |
| Model | IDENTIFIED | STRONG | `MODEL-4d634c055d47` | served model SHA-256 equals hash recorded when the model was created; registry version 3 (MLflow model registry); deployed file copied from recorded model path |
| Training run | IDENTIFIED | STRONG | `7338243b6b614133bc0aecd3de50556b` | run ID recorded with the model hash |
| Training dataset | IDENTIFIED | STRONG | `CIFAR10-TRAIN-a703e34d1ba0` | dataset hash recorded when training started; MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | STRONG | `CIFAR10-TRAIN-f7285605e556` | observed dataset version records the registered version as its parent; MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-10-01T08:51:10.292432Z | exact | STRONG |
| 2 | DATASET_MODIFIED | 2026-10-01T08:51:10.292432Z … 2026-10-01T08:51:12.832300Z | bounded | STRONG |
| 3 | TRAINING_STARTED | 2026-10-01T08:51:14.765345Z | exact | STRONG |
| 4 | TRAINING_COMPLETED | 2026-10-01T09:05:10.894414Z | exact | STRONG |
| 5 | MODEL_CREATED | 2026-10-01T09:05:13.476282Z | exact | STRONG |
| 6 | MODEL_DEPLOYED | 2026-10-01T09:05:31.101173Z | exact | STRONG |
| 7 | INPUT_SUBMITTED | 2026-10-01T09:05:32.887105Z | exact | STRONG |
| 8 | INCIDENT_PREDICTION | 2026-10-01T09:05:32.931316Z | exact | STRONG |

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

- evidence_chain: {"n_events": 414, "hash_chained": true, "valid": true, "n_problems": 0, "first_bad_sequence": null, "head_hash": "2afba145655b8b4e611f3e0c0e16d7a3945bb5b54f97c3c25968b8b007172a00"}
- dataset_check: {"status": "RECORDED", "result": "MISMATCH", "expected": "f7285605e556be1f453be1f05ea295de43e5e5a1c1d01b7de8d3f449dedb1649", "observed": "a703e34d1ba044453353c8bf7cc9468978b8f036fd0cbbc7080ae75074fe75d8", "time": "2026-10-01T08:51:13.600998Z"}
- deployed_model_check: {"status": "RECORDED", "result": "MATCH", "basis": "integrity check recorded at service start", "time": "2026-10-01T09:05:32.019114Z"}

## Root-cause finding

- Finding: **LABEL_MODIFICATION** (dataset changed: True; basis: comparison of preserved per-sample manifests)
- Changed samples: 2500 (first: [45, 46, 61, 64, 96, 99, 119, 126, 137, 212])
- Label transitions: {'1->9': 2500}
- Class-count changes: {'automobile': -2500, 'truck': 2500}
- Modification window: 2026-10-01T08:51:10.292432Z … 2026-10-01T08:51:12.832300Z

## Missing evidence

- none

## Limitations

- Only investigator-visible evidence of this pipeline was used; no external reference data.
- Post-hoc file hashes show the current state of a file, not its state at the time of the event.
- MLflow dataset digests cover only the first 10,000 values of each array; equal digests do not prove identical datasets.
- The forensic hash chain gives tamper evidence, not tamper prevention.

_Reconstruction runtime: 1.195 s_
