# Incident reconstruction: EXP-BD-C-05-S001 (RUN-55a655bf-40bc-463a-8719-813fcff3ed51), engine 1.1

## Incident

- Ticket: `INC-55a655bf`; request `REQ-00016` at 2026-09-28T10:08:26.959378Z
- Observed prediction **airplane** (confidence 0.999673); expected **automobile**
- Input SHA-256: `88719ab26db5b0c4b362472f69c17f5d2356eaacbf4a8194c10cc12d80179c63`

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
| Deployment | IDENTIFIED | STRONG | `DEP-c2a2e795` | deployment_id recorded with the inference result; registry alias production -> version 8 |
| Model | IDENTIFIED | STRONG | `MODEL-e7174af106f4` | served model SHA-256 equals hash recorded when the model was created; registry version 8 (MLflow model registry); deployed file copied from recorded model path |
| Training run | IDENTIFIED | STRONG | `035b707ef03d490c86c1a1509aecd13b` | run ID recorded with the model hash |
| Training dataset | IDENTIFIED | STRONG | `CIFAR10-TRAIN-7b85a9b6c5f9` | dataset hash recorded when training started; MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | STRONG | `CIFAR10-TRAIN-f7285605e556` | observed dataset version records the registered version as its parent; MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T09:56:49.927650Z | exact | STRONG |
| 2 | DATASET_MODIFIED | 2026-09-28T09:56:49.927650Z … 2026-09-28T09:56:52.127158Z | bounded | STRONG |
| 3 | TRAINING_STARTED | 2026-09-28T09:56:54.078316Z | exact | STRONG |
| 4 | TRAINING_COMPLETED | 2026-09-28T10:08:18.932442Z | exact | STRONG |
| 5 | MODEL_CREATED | 2026-09-28T10:08:21.953113Z | exact | STRONG |
| 6 | MODEL_DEPLOYED | 2026-09-28T10:08:25.274279Z | exact | STRONG |
| 7 | INPUT_SUBMITTED | 2026-09-28T10:08:26.959616Z | exact | STRONG |
| 8 | INCIDENT_PREDICTION | 2026-09-28T10:08:26.990629Z | exact | STRONG |

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

- evidence_chain: {"n_events": 414, "hash_chained": true, "valid": true, "n_problems": 0, "first_bad_sequence": null, "head_hash": "b4112c4a6255656bb23bd1cbaeac436872fec8720e5a0ab54d456a32e7658034"}
- dataset_check: {"status": "RECORDED", "result": "MISMATCH", "expected": "f7285605e556be1f453be1f05ea295de43e5e5a1c1d01b7de8d3f449dedb1649", "observed": "7b85a9b6c5f9ec987089000e62e40b6107b9adaf5dab69df0b6b9ae5465025ce", "time": "2026-09-28T09:56:52.936769Z"}
- deployed_model_check: {"status": "RECORDED", "result": "MATCH", "basis": "integrity check recorded at service start", "time": "2026-09-28T10:08:25.879179Z"}

## Root-cause finding

- Finding: **CONTENT_AND_LABEL_MODIFICATION** (dataset changed: True; basis: comparison of preserved per-sample manifests)
- Changed samples: 2500 (first: [47, 54, 96, 130, 173, 190, 195, 245, 257, 282])
- Label transitions: {'1->0': 276, '2->0': 284, '3->0': 272, '4->0': 306, '5->0': 283, '6->0': 256, '7->0': 274, '8->0': 261, '9->0': 288}
- Class-count changes: {'airplane': 2500, 'automobile': -276, 'bird': -284, 'cat': -272, 'deer': -306, 'dog': -283, 'frog': -256, 'horse': -274, 'ship': -261, 'truck': -288}
- Modification window: 2026-09-28T09:56:49.927650Z … 2026-09-28T09:56:52.127158Z

## Missing evidence

- none

## Limitations

- Only investigator-visible evidence of this pipeline was used; no external reference data.
- Post-hoc file hashes show the current state of a file, not its state at the time of the event.
- MLflow dataset digests cover only the first 10,000 values of each array; equal digests do not prove identical datasets.
- The forensic hash chain gives tamper evidence, not tamper prevention.

_Reconstruction runtime: 0.173 s_
