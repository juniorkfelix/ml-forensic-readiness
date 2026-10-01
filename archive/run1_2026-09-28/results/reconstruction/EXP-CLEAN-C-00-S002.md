# Incident reconstruction: EXP-CLEAN-C-00-S002 (RUN-da6d80c1-594f-4aa0-bf78-fe9551052fd1), engine 1.1

## Incident

- Ticket: `INC-da6d80c1`; request `REQ-00017` at 2026-09-28T10:43:38.071621Z
- Observed prediction **horse** (confidence 0.911105); expected **bird**
- Input SHA-256: `fa7ecc1d38ec3ccdae7be1a44ffdf85b5ba4a2caf6bea3c28feb3204bb8ff838`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: available
- forensic: available

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | STRONG | `REQ-00017` | input SHA-256 recorded at request time equals ticket input hash |
| Deployment | IDENTIFIED | STRONG | `DEP-80553ba2` | deployment_id recorded with the inference result; registry alias production -> version 10 |
| Model | IDENTIFIED | STRONG | `MODEL-3a07aa1253ef` | served model SHA-256 equals hash recorded when the model was created; registry version 10 (MLflow model registry); deployed file copied from recorded model path |
| Training run | IDENTIFIED | STRONG | `94ad6d0cdeff4def94432c91e4a11088` | run ID recorded with the model hash |
| Training dataset | IDENTIFIED | STRONG | `CIFAR10-TRAIN-f7285605e556` | dataset hash recorded when training started; MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | STRONG | `CIFAR10-TRAIN-f7285605e556` | registered dataset hash recorded; MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T10:32:12.800734Z | exact | STRONG |
| 2 | TRAINING_STARTED | 2026-09-28T10:32:15.497300Z | exact | STRONG |
| 3 | TRAINING_COMPLETED | 2026-09-28T10:43:31.869624Z | exact | STRONG |
| 4 | MODEL_CREATED | 2026-09-28T10:43:33.687709Z | exact | STRONG |
| 5 | MODEL_DEPLOYED | 2026-09-28T10:43:36.647795Z | exact | STRONG |
| 6 | INPUT_SUBMITTED | 2026-09-28T10:43:38.071767Z | exact | STRONG |
| 7 | INCIDENT_PREDICTION | 2026-09-28T10:43:38.099519Z | exact | STRONG |

## Artefact relationships

- deployment **USED** model
- inference **USED** incident_input
- inference **USED** model
- inference **WAS_INFORMED_BY** deployment
- model **WAS_GENERATED_BY** training
- training **USED** training_dataset

## Integrity findings

- evidence_chain: {"n_events": 412, "hash_chained": true, "valid": true, "n_problems": 0, "first_bad_sequence": null, "head_hash": "af31355052d37a7e7b457c2e3415a8818bd2f7d3eb3bfebb890dd6c1770a1825"}
- dataset_check: {"status": "RECORDED", "result": "MATCH", "expected": "f7285605e556be1f453be1f05ea295de43e5e5a1c1d01b7de8d3f449dedb1649", "observed": "f7285605e556be1f453be1f05ea295de43e5e5a1c1d01b7de8d3f449dedb1649", "time": "2026-09-28T10:32:14.850794Z"}
- deployed_model_check: {"status": "RECORDED", "result": "MATCH", "basis": "integrity check recorded at service start", "time": "2026-09-28T10:43:37.188374Z"}

## Root-cause finding

- Finding: **NO_DATASET_MODIFICATION_FOUND** (dataset changed: False; basis: SHA-256 of canonical per-sample manifests)

## Missing evidence

- none

## Limitations

- Only investigator-visible evidence of this pipeline was used; no external reference data.
- Post-hoc file hashes show the current state of a file, not its state at the time of the event.
- MLflow dataset digests cover only the first 10,000 values of each array; equal digests do not prove identical datasets.
- The forensic hash chain gives tamper evidence, not tamper prevention.

_Reconstruction runtime: 0.210 s_
