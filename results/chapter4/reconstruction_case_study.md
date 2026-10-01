# Reconstruction Case Study: backdoor 5 %, seed 1 (A / B / C)

Genuine pilot runs EXP-BD-A-05-S001, EXP-BD-B-05-S001, EXP-BD-C-05-S001 (30 epochs). Each pipeline received the same attack (identical poisoned sample set, same seed) and the same inference traffic.

- A: ticket INC-5097cd87, request REQ-00016, observed **airplane**, expected **automobile** (`experiments/pilot/pipeline_runs/EXP-BD-A-05-S001/reconstruction.json`)
- B: ticket INC-98f31094, request REQ-00016, observed **airplane**, expected **automobile** (`experiments/pilot/pipeline_runs/EXP-BD-B-05-S001/reconstruction.json`)
- C: ticket INC-75a49040, request REQ-00016, observed **airplane**, expected **automobile** (`experiments/pilot/pipeline_runs/EXP-BD-C-05-S001/reconstruction.json`)

## Ground-truth event sequence (A run, `ground_truth.sqlite`)

| # | GT event | Timestamp (UTC) | Artefact |
|---|---|---|---|
| 1 | CLEAN_DATASET_CREATED | 2026-10-01T09:06:21.534079Z | f7285605e556… |
| 2 | POISONING_STARTED | 2026-10-01T09:06:23.150398Z | … |
| 3 | POISONING_COMPLETED | 2026-10-01T09:06:24.097103Z | 7b85a9b6c5f9… |
| 4 | POISONED_DATASET_CREATED | 2026-10-01T09:06:24.188577Z | 7b85a9b6c5f9… |
| 5 | TRAINING_STARTED | 2026-10-01T09:06:25.784186Z | 7b85a9b6c5f9… |
| 6 | TRAINING_COMPLETED | 2026-10-01T09:19:11.476860Z | 7b85a9b6c5f9… |
| 7 | COMPROMISED_MODEL_CREATED | 2026-10-01T09:19:14.543965Z | e7174af106f4… |
| 8 | MODEL_DEPLOYED | 2026-10-01T09:19:14.742031Z | e7174af106f4… |
| 9 | TRIGGER_SUBMITTED | 2026-10-01T09:19:15.721827Z | request REQ-00016 |
| 10 | MALICIOUS_PREDICTION | 2026-10-01T09:19:15.756249Z | request REQ-00016 |

_(Only the ticketed request's inference events are listed; all trigger submissions are in ground truth.)_

## Configuration A reconstruction

| Order | Reconstructed event | Timestamp | Time basis | Confidence | Artefact refs |
|---|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-10-01T09:06:21.540579Z | exact | WEAK | store |
| 2 | TRAINING_STARTED | 2026-10-01T09:06:25.616256Z | exact | WEAK | store |
| 3 | TRAINING_COMPLETED | 2026-10-01T09:19:11.497260Z | exact | WEAK | store |
| 4 | MODEL_CREATED | 2026-10-01T09:19:14.664422Z | exact | MODERATE | model_path |
| 5 | MODEL_DEPLOYED | 2026-10-01T09:19:14.745554Z | exact | WEAK | model_path, deployed_path |
| 6 | INPUT_SUBMITTED | 2026-10-01T09:19:15.755597Z | inferred | MODERATE | request_id |
| 7 | INCIDENT_PREDICTION | 2026-10-01T09:19:15.755597Z | exact | MODERATE | request_id, predicted_label |

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
Scores: EC 0.500, ERR 0.875, tau-b 1.0, RCI 0.75, reconstruction 0.312 s

## Ground-truth event sequence (B run, `ground_truth.sqlite`)

| # | GT event | Timestamp (UTC) | Artefact |
|---|---|---|---|
| 1 | CLEAN_DATASET_CREATED | 2026-10-01T09:19:51.854079Z | f7285605e556… |
| 2 | POISONING_STARTED | 2026-10-01T09:19:55.492846Z | … |
| 3 | POISONING_COMPLETED | 2026-10-01T09:19:56.976218Z | 7b85a9b6c5f9… |
| 4 | POISONED_DATASET_CREATED | 2026-10-01T09:19:57.136799Z | 7b85a9b6c5f9… |
| 5 | TRAINING_STARTED | 2026-10-01T09:19:58.967013Z | 7b85a9b6c5f9… |
| 6 | TRAINING_COMPLETED | 2026-10-01T09:33:58.519646Z | 7b85a9b6c5f9… |
| 7 | COMPROMISED_MODEL_CREATED | 2026-10-01T09:34:01.659854Z | e7174af106f4… |
| 8 | MODEL_DEPLOYED | 2026-10-01T09:34:07.008486Z | e7174af106f4… |
| 9 | TRIGGER_SUBMITTED | 2026-10-01T09:34:08.398841Z | request REQ-00016 |
| 10 | MALICIOUS_PREDICTION | 2026-10-01T09:34:08.433710Z | request REQ-00016 |

_(Only the ticketed request's inference events are listed; all trigger submissions are in ground truth.)_

## Configuration B reconstruction

| Order | Reconstructed event | Timestamp | Time basis | Confidence | Artefact refs |
|---|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-10-01T09:19:53.271000Z | exact | MODERATE | mlflow_digest, store |
| 2 | DATASET_MODIFIED | 2026-10-01T09:19:53.271000Z … 2026-10-01T09:19:57.871621Z | bounded | MODERATE | mlflow_digest, store |
| 3 | TRAINING_STARTED | 2026-10-01T09:19:58.706445Z | exact | MODERATE | run_id, mlflow_digest, store |
| 4 | TRAINING_COMPLETED | 2026-10-01T09:33:58.535446Z | exact | MODERATE | run_id, mlflow_digest, store |
| 5 | MODEL_CREATED | 2026-10-01T09:34:01.783949Z | exact | MODERATE | model_path, registry_version |
| 6 | MODEL_DEPLOYED | 2026-10-01T09:34:07.011420Z | exact | WEAK | model_path, registry_version, deployed_path |
| 7 | INPUT_SUBMITTED | 2026-10-01T09:34:08.433128Z | inferred | MODERATE | request_id |
| 8 | INCIDENT_PREDICTION | 2026-10-01T09:34:08.433128Z | exact | MODERATE | request_id, predicted_label |

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
Scores: EC 0.700, ERR 1.000, tau-b 0.9999999999999998, RCI 0.75, reconstruction 0.345 s

## Ground-truth event sequence (C run, `ground_truth.sqlite`)

| # | GT event | Timestamp (UTC) | Artefact |
|---|---|---|---|
| 1 | CLEAN_DATASET_CREATED | 2026-10-01T09:34:42.450406Z | f7285605e556… |
| 2 | POISONING_STARTED | 2026-10-01T09:34:47.897771Z | … |
| 3 | POISONING_COMPLETED | 2026-10-01T09:34:49.284219Z | 7b85a9b6c5f9… |
| 4 | POISONED_DATASET_CREATED | 2026-10-01T09:34:49.420293Z | 7b85a9b6c5f9… |
| 5 | TRAINING_STARTED | 2026-10-01T09:34:52.558303Z | 7b85a9b6c5f9… |
| 6 | TRAINING_COMPLETED | 2026-10-01T09:47:21.358785Z | 7b85a9b6c5f9… |
| 7 | COMPROMISED_MODEL_CREATED | 2026-10-01T09:47:24.165517Z | e7174af106f4… |
| 8 | MODEL_DEPLOYED | 2026-10-01T09:47:28.108175Z | e7174af106f4… |
| 9 | TRIGGER_SUBMITTED | 2026-10-01T09:47:29.734320Z | request REQ-00016 |
| 10 | MALICIOUS_PREDICTION | 2026-10-01T09:47:29.791924Z | request REQ-00016 |

_(Only the ticketed request's inference events are listed; all trigger submissions are in ground truth.)_

## Configuration C reconstruction

| Order | Reconstructed event | Timestamp | Time basis | Confidence | Artefact refs |
|---|---|---|---|---|---|
| 1 | DATASET_REGISTERED | 2026-10-01T09:34:46.511831Z | exact | STRONG | dataset_manifest_sha256, mlflow_digest, store, dataset_id |
| 2 | DATASET_MODIFIED | 2026-10-01T09:34:46.511831Z … 2026-10-01T09:34:49.997546Z | bounded | STRONG | dataset_manifest_sha256, mlflow_digest, store, dataset_id, parent_dataset_manifest_sha256 |
| 3 | TRAINING_STARTED | 2026-10-01T09:34:52.541781Z | exact | STRONG | run_id, dataset_manifest_sha256, mlflow_digest, store |
| 4 | TRAINING_COMPLETED | 2026-10-01T09:47:21.350477Z | exact | STRONG | run_id, dataset_manifest_sha256, mlflow_digest, store |
| 5 | MODEL_CREATED | 2026-10-01T09:47:24.251764Z | exact | STRONG | model_sha256, model_path, registry_version, model_id |
| 6 | MODEL_DEPLOYED | 2026-10-01T09:47:28.145896Z | exact | STRONG | model_sha256, model_path, registry_version, model_id, deployment_id, deployed_path |
| 7 | INPUT_SUBMITTED | 2026-10-01T09:47:29.746868Z | exact | STRONG | request_id, input_sha256 |
| 8 | INCIDENT_PREDICTION | 2026-10-01T09:47:29.778500Z | exact | STRONG | request_id, input_sha256, predicted_label |

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
Scores: EC 1.000, ERR 1.000, tau-b 0.9999999999999998, RCI 1.0, reconstruction 0.386 s
