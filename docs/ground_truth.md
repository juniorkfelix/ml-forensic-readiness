# Ground Truth

**Status:** DRAFT design (implemented in Phase 7).

Ground truth (GT) records what **actually** happened in each run, including the covert attack. It
is the reference that reconstructions are scored against, and it must never reach the investigator.

## 1. Isolation (mandatory)

| Layer | Rule | Enforcement |
|---|---|---|
| Storage | GT lives only in `ground_truth/ground_truth.sqlite` (plus GT-only JSON under `ground_truth/`). Nothing under `evidence/`, `mlruns/` or `experiments/*/<EXP-ID>/` contains GT. | Separate directory; the run package writer never copies from `ground_truth/`. |
| Code | `mlfref.reconstruction` must not import `mlfref.ground_truth`, `mlfref.evaluation` or `mlfref.experiment_id` (attack-revealing IDs), and must not refer to the `ground_truth` path. | `tests/test_ground_truth_isolation.py`: static AST scan of every reconstruction module (imports, string literals) plus a runtime check that importing the reconstruction package loads no GT module. |
| Interface | `reconstruct(evidence_dir, incident_ticket)` receives only an evidence directory and the ticket. | Function signature; a test calls it with GT removed from disk. |
| Order | The evaluator reads GT only after the reconstruction JSON has been written; the reconstruction JSON is hashed before evaluation. | The evaluation record stores the reconstruction file's SHA-256 and timestamp. |
| Content | No attack-revealing strings appear in evidence stores. | `test_reconstruction_cannot_access_ground_truth` plus an evidence-scan test (D-021). |

## 2. Schema (table `gt_events`)

| Column | Notes |
|---|---|
| `gt_event_id` | UUID4 |
| `timestamp_utc` | ISO-8601 µs, `Z` |
| `experiment_id` | human-readable ID, e.g. `EXP-LF-C-05-S003` (GT is not investigator-visible, so this is safe) |
| `experiment_uuid` | join key to evidence (`RUN-<uuid>`) |
| `sequence_number` | true order of actions within the run |
| `action` | see §3 |
| `attack_type` | `none` \| `label_flip` \| `backdoor` |
| `affected_artifact` | canonical artefact reference: content hash of the dataset or model |
| `source_artifact` / `result_artifact` | canonical references (content hashes) |
| `poisoned_sample_ids` | JSON list (only on poisoning actions) |
| `expected_relationship` | e.g. `DERIVED_FROM`, `USED`, `GENERATED_BY` (PROV-style) |
| `metadata_json` | e.g. original/new labels, trigger spec, source/target class, rate, seed |

Table `gt_attacks` (one row per attacked run) holds: attack_type, source_class, target_class,
poison_rate, number_poisoned, poisoned_sample_ids, original_labels, new_labels, trigger spec,
source dataset hash, result dataset hash, timestamp.

## 3. Action vocabulary

| Action | When | Attack types |
|---|---|---|
| `CLEAN_DATASET_CREATED` | clean training set registered | all |
| `POISONING_STARTED` | adversary starts modifying the store | LF, BD |
| `POISONING_COMPLETED` | modification written | LF, BD |
| `POISONED_DATASET_CREATED` | the poisoned dataset state exists in the store (`DERIVED_FROM` the clean set) | LF, BD |
| `TRAINING_STARTED` / `TRAINING_COMPLETED` | training job | all |
| `COMPROMISED_MODEL_CREATED` | model trained on the poisoned data (`MODEL_CREATED` for clean runs) | all |
| `MODEL_DEPLOYED` | deployment | all |
| `TRIGGER_SUBMITTED` | adversary submits a triggered input (request ID recorded) | BD |
| `MALICIOUS_PREDICTION` | a served prediction matching the attack objective (request ID recorded) | LF, BD |

Canonical references use **content hashes**, which the evaluator can also compute from what a
reconstruction points to (D-020).

## 4. Who writes GT

Only the harness writes GT: the run orchestrator and the attack modules via
`mlfref.ground_truth.recorder`. Pipeline components (training, deployment, inference, MLflow and
forensic loggers) do not import the recorder, so pipeline code cannot leak GT into evidence by
accident. A test checks this.
