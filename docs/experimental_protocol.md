# Experimental Protocol

**Status:** DRAFT (design stage, before implementation of Phases 3–15). Decision IDs (D-xxx) refer
to `docs/methodology_decisions.md`.

## 1. Purpose

To measure how the **level of forensic readiness** (the independent variable) affects evidence
availability, incident reconstruction quality and operational overhead after a data-poisoning attack
on an image classifier.

## 2. Variables

| Role | Variable | Levels |
|------|----------|--------|
| Independent | Pipeline evidence instrumentation | A `conventional`, B `provenance`, C `forensic` |
| Blocking / scenario factor | Attack type | label flip (LF), backdoor (BD); clean control |
| Scenario factor | Poisoning rate | pilot: 5 %; final: decided after the pilot (candidates 1/3/5/10 %) |
| Replication | Seed | pilot: 1–2 seeds; final: decided after the pilot |
| Held constant | Dataset, model, hyper-parameters, augmentation, hardware, software versions | from `config/experiment.yaml` |
| Dependent (RQ1–3) | Evidence completeness (EC), event recovery rate (ERR), timeline accuracy (coverage + Kendall τ), root-cause identification (RCI), reconstruction runtime | see `config/evaluation_schema.yaml` |
| Dependent (RQ4) | Storage by category, wall-clock time per stage, peak RAM / GPU memory | see §7 |
| Manipulation check | Clean accuracy (CA), attack success rate (ASR), identical ML outcome across A/B/C | see §6 |

## 3. Threat model (D-015, D-014)

**Scenario: data-store tampering.**

1. The organisation's pipeline obtains CIFAR-10 and **registers** the clean training set.
2. An adversary with write access to the training data store modifies it (label flip or backdoor
   trigger + relabel). This happens **outside** the instrumented pipeline: no pipeline component
   records it, and nothing in the pipeline is told an attack took place.
3. The legitimate training job loads the (now tampered) data, trains ResNet-18 and registers the model.
4. The model is deployed and serves inference requests. Traffic is mostly benign test images. For
   backdoor runs it also includes adversary-submitted triggered inputs.
5. A suspicious prediction is reported, producing an **incident ticket** (D-018), and an
   investigation starts.

The attack is **covert**. Attack parameters and attack-revealing identifiers exist only in ground
truth and the harness index, never in investigator-visible evidence.

**Assumptions / scope**
- The adversary does not tamper with evidence stores, logs or MLflow. Evidence tampering is out of
  scope. The hash chain in C gives tamper *evidence* only and is not evaluated as a defence.
- The investigator has no external clean reference copy of the training data (D-017).
- Integrity checks in C record only and never block (D-016). The ML outcome is therefore identical
  across A/B/C for the same seed.

## 4. Pipelines (independent variable)

B extends A, and C extends B. The ML code path is shared. Only the evidence instrumentation differs
(D-005, D-006). Detailed evidence contents: `docs/evidence_schema.md`.

| | A conventional | B provenance | C forensic |
|---|---|---|---|
| Application log (run ref = UUID) | ✓ | ✓ | ✓ |
| Trained/deployed model file | ✓ | ✓ | ✓ |
| Evaluation metrics file | ✓ | ✓ | ✓ |
| Current training data store | ✓ | ✓ | ✓ |
| MLflow runs, params, metrics, dataset inputs (digest + profile), logged model, registry versions/aliases | | ✓ | ✓ |
| Forensic event store (SQLite, hash-chained), per-sample dataset manifests, artefact SHA-256, integrity checks, deployment + per-request inference events, JSONL export | | | ✓ |

## 5. Procedure for one run

The harness (research code, not part of any pipeline) runs these steps:

1. Resolve the config (`experiment.yaml` → pipeline → attack → CLI), archive it and hash it. Build
   the experiment ID and UUID. Write the environment manifest.
2. **GT:** open the ground-truth recorder (`ground_truth/ground_truth.sqlite`).
3. **Pipeline:** load clean CIFAR-10 and register the training dataset (A: log line only;
   B: MLflow data-registration run; C: `DATASET_REGISTERED` + manifest + hash). GT records
   `CLEAN_DATASET_CREATED`.
4. **Adversary (harness):** apply the attack to the stored training data (none for clean runs).
   GT records `POISONING_STARTED`, `POISONING_COMPLETED`, `POISONED_DATASET_CREATED` with the
   exact sample IDs. No pipeline evidence is written.
5. **Pipeline:** training job loads the data store, trains, evaluates and saves the model
   (instrumented per pipeline). GT records `TRAINING_STARTED`, `TRAINING_COMPLETED`,
   `COMPROMISED_MODEL_CREATED` (or `MODEL_CREATED` for clean runs).
6. **Pipeline:** deploy the model. GT records `MODEL_DEPLOYED`.
7. **Pipeline:** serve simulated inference traffic from a fixed, seed-determined request schedule.
   For BD runs, the adversary submits triggered inputs (GT `TRIGGER_SUBMITTED`; GT
   `MALICIOUS_PREDICTION` when the prediction equals the target class). For LF runs, GT
   `MALICIOUS_PREDICTION` = a source-class input predicted as the target class.
8. **Harness:** measure CA on the clean test set and ASR on the separately generated triggered test
   set. These are *harness* metrics; they are shown to the pipeline only as the normal
   evaluation output that any pipeline would produce (clean accuracy).
9. **Harness:** create the incident ticket from observable inference output: the first request
   whose served prediction matches the malicious pattern. If none exists, the run is recorded as
   "no observable incident" and reconstruction is skipped, with the reason logged.
10. **Harness:** measure storage by category. Close the stores.
11. **Investigation:** `reconstruct(evidence_dir, incident_ticket)` → reconstruction JSON/MD.
    Runtime is timed.
12. **Evaluation:** the evaluator loads the reconstruction **and** ground truth and computes the
    metrics.
13. Write the run package `experiments/<phase>/<EXP-ID>/` (without ground truth) and append to
    `results/raw/run_index.csv`. Failures go to `results/raw/failed_runs.csv` (§38).

## 6. Manipulation checks

- **Same ML outcome across pipelines:** for a given (attack, rate, seed), A/B/C should produce the
  same poisoned sample set (exact) and near-identical CA/ASR. Differences beyond GPU
  non-determinism are investigated before analysis.
- **Attack effectiveness:** the backdoor is reported as effective only if the measured ASR shows it.
  Label-flip impact is reported as the measured source→target error rate against the clean control.
- **No leakage:** the clean test set is never poisoned or trained on. Tests check that no
  attack-revealing string appears in evidence stores (D-021).

## 7. Performance measurement (§43, §44)

Timed separately: setup, data download (once, excluded), dataset registration, attack (harness,
excluded from pipeline overhead), training, evidence logging (instrumented sections), deployment,
inference, reconstruction, evaluation.
Storage is measured separately for: model files, MLflow backend DB, MLflow artefacts, forensic
SQLite, forensic JSONL, logs. The CIFAR-10 download is counted once, not per run.

## 8. Pilot and approval gates

1. Pilot (Phase 16): clean baseline; LF 5 % × A/B/C; BD 5 % × A/B/C; 1–2 seeds.
2. `results/pilot/pilot_report.md` and `results/pilot/experiment_design_recommendation.md`.
3. **The researcher approves the final matrix** before Phase 18. Pilot results are not merged with
   final results.

## 9. Pre-registration of the evaluation schema (§24)

`config/evaluation_schema.yaml` defines required events, evidence items, root-cause components and
the timeline rules. It is frozen (status `FROZEN`, commit hash recorded) **before the pilot is run**.
The pilot may expose implementation defects in the schema. Any change after freezing is recorded as
a dated amendment with its justification and a new commit, and it is applied before the main
experiment. It is never adjusted to improve results.
