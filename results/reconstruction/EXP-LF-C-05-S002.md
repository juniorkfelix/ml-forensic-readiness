# Incident reconstruction: EXP-LF-C-05-S002 (RUN-78b3c550-915e-4022-aaad-41624c1e7e9d)

## Incident

- Ticket: `INC-78b3c550`; request `REQ-00038` at 2026-10-01T10:53:16.660314Z
- Observed prediction **truck** (confidence 0.734165); expected **automobile**
- Input SHA-256: `4f1694ce9865f23c5468a9c180903730463fc93f3cab734621b1474b5384a33a`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: available
- forensic: available

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | STRONG | `REQ-00038` | input SHA-256 recorded at request time equals ticket input hash |
| Deployment | IDENTIFIED | STRONG | `DEP-7569156f` | deployment_id recorded with the inference result; registry alias production -> version 8 |
| Model | IDENTIFIED | STRONG | `MODEL-c09adc48df35` | served model SHA-256 equals hash recorded when the model was created; registry version 8 (MLflow model registry); deployed file copied from recorded model path |
| Training run | IDENTIFIED | STRONG | `0998ac099165451887685b1991cf3fd6` | run ID recorded with the model hash |
| Training dataset | IDENTIFIED | STRONG | `CIFAR10-TRAIN-8f2fbba3042d` | dataset hash recorded when training started; MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | STRONG | `CIFAR10-TRAIN-f7285605e556` | observed dataset version records the registered version as its parent; MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-10-01T10:39:34.422689Z | exact | STRONG |
| 2 | DATASET_MODIFIED | 2026-10-01T10:39:34.422689Z … 2026-10-01T10:39:38.448968Z | bounded | STRONG |
| 3 | TRAINING_STARTED | 2026-10-01T10:39:41.397145Z | exact | STRONG |
| 4 | TRAINING_COMPLETED | 2026-10-01T10:53:08.340907Z | exact | STRONG |
| 5 | MODEL_CREATED | 2026-10-01T10:53:10.094862Z | exact | STRONG |
| 6 | MODEL_DEPLOYED | 2026-10-01T10:53:14.443500Z | exact | STRONG |
| 7 | INPUT_SUBMITTED | 2026-10-01T10:53:16.660616Z | exact | STRONG |
| 8 | INCIDENT_PREDICTION | 2026-10-01T10:53:16.693715Z | exact | STRONG |

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

- evidence_chain: {"n_events": 414, "hash_chained": true, "valid": true, "n_problems": 0, "first_bad_sequence": null, "head_hash": "da6bb730acd46e0975038ded8b5848d7eb5ace05d1fb376ff494f2c11a855e43"}
- dataset_check: {"status": "RECORDED", "result": "MISMATCH", "expected": "f7285605e556be1f453be1f05ea295de43e5e5a1c1d01b7de8d3f449dedb1649", "observed": "8f2fbba3042d6bcbb23688208e90b9aa93ef198bd1d85ad6eacdc2b4131b5504", "time": "2026-10-01T10:39:39.639614Z"}
- deployed_model_check: {"status": "RECORDED", "result": "MATCH", "basis": "integrity check recorded at service start", "time": "2026-10-01T10:53:14.948066Z"}

## Root-cause finding

- Finding: **LABEL_MODIFICATION** (dataset changed: True; basis: comparison of preserved per-sample manifests)
- Changed samples: 2500 (first: [5, 32, 46, 60, 61, 64, 65, 75, 79, 119])
- Label transitions: {'1->9': 2500}
- Class-count changes: {'automobile': -2500, 'truck': 2500}
- Modification window: 2026-10-01T10:39:34.422689Z … 2026-10-01T10:39:38.448968Z

## Missing evidence

- none

## Limitations

- Only investigator-visible evidence of this pipeline was used; no external reference data.
- Post-hoc file hashes show the current state of a file, not its state at the time of the event.
- MLflow dataset digests cover only the first 10,000 values of each array; equal digests do not prove identical datasets.
- The forensic hash chain gives tamper evidence, not tamper prevention.

_Reconstruction runtime: 0.354 s_
