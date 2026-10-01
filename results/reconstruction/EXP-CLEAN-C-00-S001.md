# Incident reconstruction: EXP-CLEAN-C-00-S001 (RUN-27d90142-e628-4812-9f38-f5c974b8c5e8)

## Incident

- Ticket: `INC-27d90142`; request `REQ-00006` at 2026-10-01T08:36:50.404815Z
- Observed prediction **cat** (confidence 0.690073); expected **deer**
- Input SHA-256: `7bbac3efc461eab19a1a4110e0dbfb6b3ff1bdde78b189b216b6882ad4e70bab`

## Evidence sources

- app_log: available
- artifact_listing: available
- metrics: available
- mlflow: available
- forensic: available

## Backward trace

| Hop | Status | Confidence | Identified as | Basis |
|---|---|---|---|---|
| Inference (incident request) | IDENTIFIED | STRONG | `REQ-00006` | input SHA-256 recorded at request time equals ticket input hash |
| Deployment | IDENTIFIED | STRONG | `DEP-f884da4c` | deployment_id recorded with the inference result; registry alias production -> version 2 |
| Model | IDENTIFIED | STRONG | `MODEL-a57d5e956120` | served model SHA-256 equals hash recorded when the model was created; registry version 2 (MLflow model registry); deployed file copied from recorded model path |
| Training run | IDENTIFIED | STRONG | `b97015290183464bb0224638c3b1dfa9` | run ID recorded with the model hash |
| Training dataset | IDENTIFIED | STRONG | `CIFAR10-TRAIN-f7285605e556` | dataset hash recorded when training started; MLflow dataset input of the training run; training data store logged as loaded before training |
| Prior (registered) dataset state | IDENTIFIED | STRONG | `CIFAR10-TRAIN-f7285605e556` | registered dataset hash recorded; MLflow data-registration run (recorded registration run ID); registration of the same data store logged earlier |

## Event chronology

| # | Event | Time | Time basis | Confidence |
|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-10-01T08:24:44.754647Z | exact | STRONG |
| 2 | TRAINING_STARTED | 2026-10-01T08:24:49.385461Z | exact | STRONG |
| 3 | TRAINING_COMPLETED | 2026-10-01T08:36:43.134128Z | exact | STRONG |
| 4 | MODEL_CREATED | 2026-10-01T08:36:44.973476Z | exact | STRONG |
| 5 | MODEL_DEPLOYED | 2026-10-01T08:36:49.289662Z | exact | STRONG |
| 6 | INPUT_SUBMITTED | 2026-10-01T08:36:50.405043Z | exact | STRONG |
| 7 | INCIDENT_PREDICTION | 2026-10-01T08:36:50.437165Z | exact | STRONG |

## Artefact relationships

- deployment **USED** model
- inference **USED** incident_input
- inference **USED** model
- inference **WAS_INFORMED_BY** deployment
- model **WAS_GENERATED_BY** training
- training **USED** training_dataset

## Integrity findings

- evidence_chain: {"n_events": 412, "hash_chained": true, "valid": true, "n_problems": 0, "first_bad_sequence": null, "head_hash": "9f1120f27cd28217b8c2d1320afa22686b61585e4192d4dcd5abf50ebcff39fc"}
- dataset_check: {"status": "RECORDED", "result": "MATCH", "expected": "f7285605e556be1f453be1f05ea295de43e5e5a1c1d01b7de8d3f449dedb1649", "observed": "f7285605e556be1f453be1f05ea295de43e5e5a1c1d01b7de8d3f449dedb1649", "time": "2026-10-01T08:24:47.871129Z"}
- deployed_model_check: {"status": "RECORDED", "result": "MATCH", "basis": "integrity check recorded at service start", "time": "2026-10-01T08:36:49.882089Z"}

## Root-cause finding

- Finding: **NO_DATASET_MODIFICATION_FOUND** (dataset changed: False; basis: SHA-256 of canonical per-sample manifests)

## Missing evidence

- none

## Limitations

- Only investigator-visible evidence of this pipeline was used; no external reference data.
- Post-hoc file hashes show the current state of a file, not its state at the time of the event.
- MLflow dataset digests cover only the first 10,000 values of each array; equal digests do not prove identical datasets.
- The forensic hash chain gives tamper evidence, not tamper prevention.

_Reconstruction runtime: 0.434 s_
