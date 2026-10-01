# Reconstruction Case Study: backdoor 5 %, seed 1 (A / B / C)

Genuine pilot runs EXP-BD-A-05-S001, EXP-BD-B-05-S001, EXP-BD-C-05-S001 (30 epochs). Each pipeline received the same attack (identical poisoned sample set, same seed) and the same inference traffic.

- A: ticket INC-bc81cf32, request REQ-00016, observed **airplane**, expected **automobile** (`experiments/pilot/pipeline_runs/EXP-BD-A-05-S001/reconstruction.json`)
- B: ticket INC-5b1679c2, request REQ-00016, observed **airplane**, expected **automobile** (`experiments/pilot/pipeline_runs/EXP-BD-B-05-S001/reconstruction.json`)
- C: ticket INC-55a655bf, request REQ-00016, observed **airplane**, expected **automobile** (`experiments/pilot/pipeline_runs/EXP-BD-C-05-S001/reconstruction.json`)

## Ground-truth event sequence (A run, `ground_truth.sqlite`)

| # | GT event | Timestamp (UTC) | Artefact |
|---|---|---|---|
| 1 | CLEAN_DATASET_CREATED | 2026-09-28T09:32:59.413943Z | f7285605e556… |
| 2 | POISONING_STARTED | 2026-09-28T09:33:01.224956Z | … |
| 3 | POISONING_COMPLETED | 2026-09-28T09:33:01.952947Z | 7b85a9b6c5f9… |
| 4 | POISONED_DATASET_CREATED | 2026-09-28T09:33:02.015419Z | 7b85a9b6c5f9… |
| 5 | TRAINING_STARTED | 2026-09-28T09:33:03.455216Z | 7b85a9b6c5f9… |
| 6 | TRAINING_COMPLETED | 2026-09-28T09:44:20.271141Z | 7b85a9b6c5f9… |
| 7 | COMPROMISED_MODEL_CREATED | 2026-09-28T09:44:23.211265Z | e7174af106f4… |
| 8 | MODEL_DEPLOYED | 2026-09-28T09:44:23.415422Z | e7174af106f4… |
| 9 | TRIGGER_SUBMITTED | 2026-09-28T09:44:24.522111Z | request REQ-00016 |
| 10 | MALICIOUS_PREDICTION | 2026-09-28T09:44:24.563435Z | request REQ-00016 |

_(Only the ticketed request's inference events are listed; all trigger submissions are in ground truth.)_

## Configuration A reconstruction

| Order | Reconstructed event | Timestamp | Time basis | Confidence | Artefact refs |
|---|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T09:32:59.416679Z | exact | WEAK | store |
| 2 | TRAINING_STARTED | 2026-09-28T09:33:03.389006Z | exact | WEAK | store |
| 3 | TRAINING_COMPLETED | 2026-09-28T09:44:20.287330Z | exact | WEAK | store |
| 4 | MODEL_CREATED | 2026-09-28T09:44:23.333556Z | exact | MODERATE | model_path |
| 5 | MODEL_DEPLOYED | 2026-09-28T09:44:23.417992Z | exact | WEAK | model_path, deployed_path |
| 6 | INPUT_SUBMITTED | 2026-09-28T09:44:24.562876Z | inferred | MODERATE | request_id |
| 7 | INCIDENT_PREDICTION | 2026-09-28T09:44:24.562876Z | exact | MODERATE | request_id, predicted_label |

| GT event | Recovered | Reason if missed |
|---|---|---|
| CLEAN_DATASET_CREATED | YES |  |
| POISONED_DATASET_CREATED | NO | no reconstructed event of a matching class |
| TRAINING_STARTED | YES |  |
| TRAINING_COMPLETED | YES |  |
| COMPROMISED_MODEL_CREATED | YES |  |
| MODEL_DEPLOYED | YES |  |
| TRIGGER_SUBMITTED | YES |  |
| MALICIOUS_PREDICTION | YES |  |

Relationships: deployment USED model; inference USED incident_input; inference USED model; inference WAS_INFORMED_BY deployment; model WAS_GENERATED_BY training; training USED training_dataset
Root-cause finding: **INSUFFICIENT_EVIDENCE**; changed samples reported: 0 (GT: 2500)
Integrity: {"evidence_chain": "NOT_OBSERVABLE", "dataset_check": "NOT_OBSERVABLE", "deployed_model_check": "MATCH"}
Scores: EC 0.500, ERR 0.875, tau-b 1.0, RCI 0.75, reconstruction 0.076 s

## Ground-truth event sequence (B run, `ground_truth.sqlite`)

| # | GT event | Timestamp (UTC) | Artefact |
|---|---|---|---|
| 1 | CLEAN_DATASET_CREATED | 2026-09-28T09:44:50.106594Z | f7285605e556… |
| 2 | POISONING_STARTED | 2026-09-28T09:44:52.546188Z | … |
| 3 | POISONING_COMPLETED | 2026-09-28T09:44:53.394857Z | 7b85a9b6c5f9… |
| 4 | POISONED_DATASET_CREATED | 2026-09-28T09:44:53.464588Z | 7b85a9b6c5f9… |
| 5 | TRAINING_STARTED | 2026-09-28T09:44:55.036797Z | 7b85a9b6c5f9… |
| 6 | TRAINING_COMPLETED | 2026-09-28T09:56:19.433176Z | 7b85a9b6c5f9… |
| 7 | COMPROMISED_MODEL_CREATED | 2026-09-28T09:56:22.241728Z | e7174af106f4… |
| 8 | MODEL_DEPLOYED | 2026-09-28T09:56:25.099018Z | e7174af106f4… |
| 9 | TRIGGER_SUBMITTED | 2026-09-28T09:56:25.794296Z | request REQ-00016 |
| 10 | MALICIOUS_PREDICTION | 2026-09-28T09:56:25.819966Z | request REQ-00016 |

_(Only the ticketed request's inference events are listed; all trigger submissions are in ground truth.)_

## Configuration B reconstruction

| Order | Reconstructed event | Timestamp | Time basis | Confidence | Artefact refs |
|---|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T09:44:51.195000Z | exact | MODERATE | mlflow_digest, store |
| 2 | DATASET_MODIFIED | 2026-09-28T09:44:51.195000Z … 2026-09-28T09:44:54.370306Z | bounded | MODERATE | mlflow_digest, store |
| 3 | TRAINING_STARTED | 2026-09-28T09:44:54.934553Z | exact | MODERATE | run_id, mlflow_digest, store |
| 4 | TRAINING_COMPLETED | 2026-09-28T09:56:19.440487Z | exact | MODERATE | run_id, mlflow_digest, store |
| 5 | MODEL_CREATED | 2026-09-28T09:56:22.325641Z | exact | MODERATE | model_path, registry_version |
| 6 | MODEL_DEPLOYED | 2026-09-28T09:56:25.101354Z | exact | WEAK | model_path, registry_version, deployed_path |
| 7 | INPUT_SUBMITTED | 2026-09-28T09:56:25.819467Z | inferred | MODERATE | request_id |
| 8 | INCIDENT_PREDICTION | 2026-09-28T09:56:25.819467Z | exact | MODERATE | request_id, predicted_label |

| GT event | Recovered | Reason if missed |
|---|---|---|
| CLEAN_DATASET_CREATED | YES |  |
| POISONED_DATASET_CREATED | YES |  |
| TRAINING_STARTED | YES |  |
| TRAINING_COMPLETED | YES |  |
| COMPROMISED_MODEL_CREATED | YES |  |
| MODEL_DEPLOYED | YES |  |
| TRIGGER_SUBMITTED | YES |  |
| MALICIOUS_PREDICTION | YES |  |

Relationships: dataset_modification USED registered_dataset; deployment USED model; inference USED incident_input; inference USED model; inference WAS_INFORMED_BY deployment; model WAS_GENERATED_BY training; training USED training_dataset; training_dataset WAS_DERIVED_FROM registered_dataset; training_dataset WAS_GENERATED_BY dataset_modification
Root-cause finding: **DATASET_MODIFIED_UNSPECIFIED**; changed samples reported: 0 (GT: 2500)
Integrity: {"evidence_chain": "NOT_OBSERVABLE", "dataset_check": "NOT_OBSERVABLE", "deployed_model_check": "MATCH"}
Scores: EC 0.700, ERR 1.000, tau-b 0.9999999999999998, RCI 0.75, reconstruction 2.895 s

## Ground-truth event sequence (C run, `ground_truth.sqlite`)

| # | GT event | Timestamp (UTC) | Artefact |
|---|---|---|---|
| 1 | CLEAN_DATASET_CREATED | 2026-09-28T09:56:47.404826Z | f7285605e556… |
| 2 | POISONING_STARTED | 2026-09-28T09:56:50.768975Z | … |
| 3 | POISONING_COMPLETED | 2026-09-28T09:56:51.602380Z | 7b85a9b6c5f9… |
| 4 | POISONED_DATASET_CREATED | 2026-09-28T09:56:51.681702Z | 7b85a9b6c5f9… |
| 5 | TRAINING_STARTED | 2026-09-28T09:56:54.094952Z | 7b85a9b6c5f9… |
| 6 | TRAINING_COMPLETED | 2026-09-28T10:08:18.943209Z | 7b85a9b6c5f9… |
| 7 | COMPROMISED_MODEL_CREATED | 2026-09-28T10:08:21.848083Z | e7174af106f4… |
| 8 | MODEL_DEPLOYED | 2026-09-28T10:08:25.239760Z | e7174af106f4… |
| 9 | TRIGGER_SUBMITTED | 2026-09-28T10:08:26.948833Z | request REQ-00016 |
| 10 | MALICIOUS_PREDICTION | 2026-09-28T10:08:27.001911Z | request REQ-00016 |

_(Only the ticketed request's inference events are listed; all trigger submissions are in ground truth.)_

## Configuration C reconstruction

| Order | Reconstructed event | Timestamp | Time basis | Confidence | Artefact refs |
|---|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-09-28T09:56:49.927650Z | exact | STRONG | dataset_manifest_sha256, mlflow_digest, store, dataset_id |
| 2 | DATASET_MODIFIED | 2026-09-28T09:56:49.927650Z … 2026-09-28T09:56:52.127158Z | bounded | STRONG | dataset_manifest_sha256, mlflow_digest, store, dataset_id, parent_dataset_manifest_sha256 |
| 3 | TRAINING_STARTED | 2026-09-28T09:56:54.078316Z | exact | STRONG | run_id, dataset_manifest_sha256, mlflow_digest, store |
| 4 | TRAINING_COMPLETED | 2026-09-28T10:08:18.932442Z | exact | STRONG | run_id, dataset_manifest_sha256, mlflow_digest, store |
| 5 | MODEL_CREATED | 2026-09-28T10:08:21.953113Z | exact | STRONG | model_sha256, model_path, registry_version, model_id |
| 6 | MODEL_DEPLOYED | 2026-09-28T10:08:25.274279Z | exact | STRONG | model_sha256, model_path, registry_version, model_id, deployment_id, deployed_path |
| 7 | INPUT_SUBMITTED | 2026-09-28T10:08:26.959616Z | exact | STRONG | request_id, input_sha256 |
| 8 | INCIDENT_PREDICTION | 2026-09-28T10:08:26.990629Z | exact | STRONG | request_id, input_sha256, predicted_label |

| GT event | Recovered | Reason if missed |
|---|---|---|
| CLEAN_DATASET_CREATED | YES |  |
| POISONED_DATASET_CREATED | YES |  |
| TRAINING_STARTED | YES |  |
| TRAINING_COMPLETED | YES |  |
| COMPROMISED_MODEL_CREATED | YES |  |
| MODEL_DEPLOYED | YES |  |
| TRIGGER_SUBMITTED | YES |  |
| MALICIOUS_PREDICTION | YES |  |

Relationships: dataset_modification USED registered_dataset; deployment USED model; inference USED incident_input; inference USED model; inference WAS_INFORMED_BY deployment; model WAS_GENERATED_BY training; training USED training_dataset; training_dataset WAS_DERIVED_FROM registered_dataset; training_dataset WAS_GENERATED_BY dataset_modification
Root-cause finding: **CONTENT_AND_LABEL_MODIFICATION**; changed samples reported: 2500 (GT: 2500)
Integrity: {"evidence_chain": true, "dataset_check": "MISMATCH", "deployed_model_check": "MATCH"}
Scores: EC 1.000, ERR 1.000, tau-b 0.9999999999999998, RCI 1.0, reconstruction 0.173 s
