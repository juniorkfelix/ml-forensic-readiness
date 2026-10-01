# Research-Question Evidence Summary (factual; genuine data only)

Status of the data: **the pilot and final experiments have not been run.** The genuine data are:
- one full-protocol run: the 30-epoch clean baseline on A;
- one backdoor development check: 30 epochs, no pipeline;
- three 1-epoch smoke checks (clean A, clean C, backdoor C);
- one interrupted run (label flip C, CPU subset).

No pipeline-B run exists, and no attacked run exists on A or B. The synthetic demonstration set
in `results/synthetic/` is **excluded** from everything below.

## RQ1: What forensic artefacts were actually available?

Observed in genuine pipeline-C evidence stores (`evidence/forensic/RUN-*/forensic_evidence.sqlite`):
- **Dataset:** registration event with SHA-256 manifest hash and per-class distribution; a
  per-sample manifest file; a training-time dataset integrity check.
- **Training:** start and completion events linked to the MLflow run ID, with hyperparameters.
- **Model:** creation, SHA-256 hash and registry-version events.
- **Deployment:** deployment event with deployment ID and model hash; a deployed-model integrity
  check.
- **Inference:** per-request events with input SHA-256, prediction and confidence.
- **Chain:** a SHA-256 event chain, verified VALID (e.g. 412 events, 0 problems, in
  `EXP-CLEAN-C-00-S001`).

The MLflow store (`mlruns/mlflow.db`) holds data-registration and training runs with parameters,
metrics, dataset inputs and registered model versions for the pipeline-C smoke runs.

For A and B, availability is known **by design and from unit tests only**
(`evidence_availability_matrix.csv`). It was not observed in any genuine run.

## RQ2: What evidence relationships allowed reconstruction?

In the single genuine reconstruction (C, clean control, smoke), all six backward-trace hops
(inference → deployment → model → training run → training dataset → registered dataset) were
identified with STRONG links:
- input SHA-256 = ticket hash;
- deployment ID recorded with the result;
- served model hash = hash recorded at model creation;
- run ID recorded with the model hash;
- dataset hash recorded at training start;
- registered dataset hash.

All 5 required ground-truth events were recovered in the correct order (Kendall τ-b 1.000).
No poisoning incident has been reconstructed in any genuine run.

## RQ3: How did A/B/C compare?

**Not answerable from genuine data.** Only one pipeline-C run was evaluated (clean control, 1-epoch
smoke):

| Measure | Value |
|---|---|
| Evidence completeness | 100 % (18/18 applicable items) |
| Event recovery rate | 1.000 (5/5) |
| Kendall τ-b | 1.000 |
| Root-cause identification | not applicable (clean run); finding correct, no false attribution |
| Reconstruction time | 0.228 s |

A and B: NOT AVAILABLE. No inferential comparison is possible (`statistical_tests.csv`).

## RQ4: How much overhead did forensic readiness introduce?

- **Pipeline-C evidence storage (1-epoch smoke checks):** 6.092 MB for the clean run and
  11.415 MB for the backdoor run. The larger backdoor value comes from a second per-sample
  manifest of the modified dataset. These figures exclude the MLflow logged model, whose size per
  run was not attributable.
- **Storage overhead versus A:** NOT AVAILABLE, because no pipeline-A evidence was measured.
- **Training time:** 23.999 s (A, clean, 1-epoch smoke) versus 35.142 s (C, clean, 1-epoch
  smoke), +46.43 %. This is **not a valid overhead estimate**: n = 1, different runner scripts,
  and C's timed training stage includes MLflow dataset logging.
- **Forensic evidence-logging time (C):** 2.360 s (clean smoke) and 3.035 s (backdoor smoke).
- **Peak RAM:** 1711.7 MB (A smoke) versus 2086.9 MB (C clean smoke).
- **Peak GPU allocated:** 764.1 MB (A) versus 765.5 MB (C).

## Manipulation checks (genuine)

- **Clean accuracy, full protocol:** 0.9334 (EXP-CLEAN-A-00-S001, 30 epochs).
- **Backdoor development check (30 epochs, no pipeline):** clean accuracy 0.9316; ASR 1.000
  (9,000/9,000).
- **Instrumentation does not change training:** the clean seed-1 1-epoch models from pipeline A
  and pipeline C are bit-identical (SHA-256 `160ccf04…482cb` in both
  `experiments/smoke/EXP-CLEAN-A-00-S001/model_hash.txt` and
  `experiments/smoke/EXP-CLEAN-C-00-S001/model_hash.txt`), and both have clean accuracy 0.388.
