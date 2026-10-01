# Incident reconstruction: EXP-LF-C-05-S002 (RUN-d52567d8-d88a-46b6-b28c-047141d8cefd)

## Incident

- Ticket: `INC-d52567d8`; request `REQ-00038` at 2026-09-28T11:19:53.313282Z
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
| Deployment | IDENTIFIED | STRONG | `DEP-ee4a828a` | deployment_id recorded with the inference result; registry alias production -> version 12 |
| Model | IDENTIFIED | STRONG | `MODEL-c09adc48df35` | served model SHA-256 equals hash recorded when the model was created; registry version 12 (MLflow model registry); deployed file copied from recorded model path |
| Training run | IDENTIFIED | STRONG | `04d28f97504f443f8b2921bab62f0bcc` | run ID recorded with the model hash |
| Training dataset | IDENTIFIED | STRONG | `CIFAR10-TRAIN-8f2fbba3042d` | dataset hash recorded when training started; MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | STRONG | `CIFAR10-TRAIN-f7285605e556` | observed dataset version records the registered version as its parent |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T11:08:01.246962Z | exact | STRONG |
| 2 | DATASET_MODIFIED | 2026-09-28T11:08:01.246962Z … 2026-09-28T11:08:03.660875Z | bounded | STRONG |
| 3 | TRAINING_STARTED | 2026-09-28T11:08:05.582513Z | exact | STRONG |
| 4 | TRAINING_COMPLETED | 2026-09-28T11:19:45.480491Z | exact | STRONG |
| 5 | MODEL_CREATED | 2026-09-28T11:19:47.292812Z | exact | STRONG |
| 6 | MODEL_DEPLOYED | 2026-09-28T11:19:50.789404Z | exact | STRONG |
| 7 | INPUT_SUBMITTED | 2026-09-28T11:19:53.313419Z | exact | STRONG |
| 8 | INCIDENT_PREDICTION | 2026-09-28T11:19:53.335582Z | exact | STRONG |

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

- evidence_chain: {"n_events": 414, "hash_chained": true, "valid": true, "n_problems": 0, "first_bad_sequence": null, "head_hash": "4dbe1ad4d6edfb6ff5ee5406e4b35cb77b9dbf57ee02526ea961b67a14c7780e"}
- dataset_check: {"status": "RECORDED", "result": "MISMATCH", "expected": "f7285605e556be1f453be1f05ea295de43e5e5a1c1d01b7de8d3f449dedb1649", "observed": "8f2fbba3042d6bcbb23688208e90b9aa93ef198bd1d85ad6eacdc2b4131b5504", "time": "2026-09-28T11:08:04.532301Z"}
- deployed_model_check: {"status": "RECORDED", "result": "MATCH", "basis": "integrity check recorded at service start", "time": "2026-09-28T11:19:51.376030Z"}

## Root-cause finding

- Finding: **LABEL_MODIFICATION** (dataset changed: True; basis: comparison of preserved per-sample manifests)
- Changed samples: 2500 (first: [5, 32, 46, 60, 61, 64, 65, 75, 79, 119])
- Label transitions: {'1->9': 2500}
- Class-count changes: {'automobile': -2500, 'truck': 2500}
- Modification window: 2026-09-28T11:08:01.246962Z … 2026-09-28T11:08:03.660875Z

## Missing evidence

- none

## Limitations

- Only investigator-visible evidence of this pipeline was used; no external reference data.
- Post-hoc file hashes show the current state of a file, not its state at the time of the event.
- MLflow dataset digests cover only the first 10,000 values of each array; equal digests do not prove identical datasets.
- The forensic hash chain gives tamper evidence, not tamper prevention.

_Reconstruction runtime: 0.347 s_
