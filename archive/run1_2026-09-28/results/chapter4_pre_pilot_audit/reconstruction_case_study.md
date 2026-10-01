# Reconstruction Case Study

## Availability of a matched A/B/C incident

**No matched poisoning incident exists under A, B and C.** The repository contains:

| Condition | A | B | C |
|---|---|---|---|
| Label flip 5 %, seed 1 | NOT AVAILABLE | NOT AVAILABLE | INCOMPLETE (interrupted during training; no incident, no reconstruction) |
| Backdoor 5 %, seed 1 | NOT AVAILABLE | NOT AVAILABLE | completed (1-epoch smoke); **no incident observed** (ASR 0.0644; no triggered input was predicted as the target), so reconstruction was correctly skipped |
| Clean control, seed 1 | 30-epoch baseline and 1-epoch smoke: produced by the clean-baseline script (no evidence store, no ground truth, no reconstruction) | NOT AVAILABLE | **completed with reconstruction and evaluation (1-epoch smoke)** |

A three-way A/B/C comparison figure (planned Figure 4.11) therefore **cannot be produced from
genuine data**. The only genuine reconstruction is shown below. It is a **pipeline C clean-control
investigation of a natural misclassification**, not a poisoning incident, from a 1-epoch smoke
check (`experiments/smoke/EXP-CLEAN-C-00-S001/`, run `RUN-65e30446-e4d5-4cdc-a424-ce2718c383b9`).

## Incident ticket

Request `REQ-00001`: the service predicted **automobile**; the reporter expected **truck**.
Source: `evidence/forensic/RUN-65e30446-…/incident_ticket.json`.

## Ground-truth event sequence

Source: `ground_truth/ground_truth.sqlite`, table `gt_events`, `experiment_uuid = 65e30446-…`.

| # | GT event | Timestamp (UTC) | Artefact (prefix) |
|---|---|---|---|
| 1 | CLEAN_DATASET_CREATED | 2026-09-27T21:59:39.650828Z | dataset manifest `f7285605e556…` |
| 2 | TRAINING_STARTED | 2026-09-27T21:59:42.397926Z | dataset `f7285605e556…` |
| 3 | TRAINING_COMPLETED | 2026-09-27T22:00:17.107416Z | dataset `f7285605e556…` |
| 4 | MODEL_CREATED | 2026-09-27T22:00:19.518340Z | model `160ccf04c19d…` |
| 5 | MODEL_DEPLOYED | 2026-09-27T22:00:20.940245Z | model `160ccf04c19d…` |

## Configuration A reconstruction: NOT AVAILABLE
No pipeline-A run exists in the pipeline-runner format (evidence store and incident ticket).

## Configuration B reconstruction: NOT AVAILABLE
No pipeline-B run was executed.

## Configuration C reconstruction (genuine; 1-epoch smoke check)

Source: `experiments/smoke/EXP-CLEAN-C-00-S001/reconstruction.json`; evaluated in
`experiments/smoke/EXP-CLEAN-C-00-S001/evaluation.json`.

| Order | Reconstructed event | Timestamp (UTC) | Artefact references | Confidence | GT match |
|---|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-27T21:59:41.080251Z | dataset manifest SHA-256, MLflow digest, store path | STRONG | recovered (CLEAN_DATASET_CREATED, via manifest hash; Δt = 1.43 s) |
| 2 | TRAINING_STARTED | 2026-09-27T21:59:42.389415Z | MLflow run ID, dataset hash | STRONG | recovered (via run ID) |
| 3 | TRAINING_COMPLETED | 2026-09-27T22:00:17.100988Z | MLflow run ID, dataset hash | STRONG | recovered (via run ID) |
| 4 | MODEL_CREATED | 2026-09-27T22:00:19.573003Z | model SHA-256, path, registry version | STRONG | recovered (via model hash) |
| 5 | MODEL_DEPLOYED | 2026-09-27T22:00:20.961531Z | model SHA-256, path, registry version | STRONG | recovered (via model hash) |
| 6 | INPUT_SUBMITTED | 2026-09-27T22:00:21.308376Z | request ID, input SHA-256 | STRONG | not scored (clean run; no GT inference event) |
| 7 | INCIDENT_PREDICTION | 2026-09-27T22:00:21.378158Z | request ID, input SHA-256, predicted label | STRONG | not scored (clean run) |

**Relationships recovered** (PROV-style): training USED training_dataset; model WAS_GENERATED_BY
training; deployment USED model; inference USED model; inference USED incident_input; inference
WAS_INFORMED_BY deployment.

**Integrity findings:** hash chain VALID (412 events, 0 problems); dataset integrity check MATCH
(expected = observed = `f7285605e556…`); deployed-model integrity check MATCH.

**Root-cause finding:** NO_DATASET_MODIFICATION_FOUND (basis: SHA-256 of canonical per-sample
manifests). This is correct for a clean run (no false attribution).

**Evaluation:** event recovery 5/5 = 1.000; Kendall τ-b = 1.000 (5 events, p = 0.0167);
pairwise order accuracy 1.000; evidence completeness 18/18 applicable items = 100 % (DS3, DS5
not applicable to clean runs). Reconstruction runtime 0.228 s.

**Limitations of this example:** 1 epoch (clean accuracy 0.388); clean control rather than a
poisoning incident; single run; pipeline C only.
