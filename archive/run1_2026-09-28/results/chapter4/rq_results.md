# Research-Question Results (factual; genuine pilot data)

**Data:** 18 completed pilot runs: {clean, label flip 5 %, backdoor 5 %} × pipelines
{A conventional, B provenance, C forensic-ready} × seeds {1, 2}, ResNet-18, 30 epochs, full
CIFAR-10. One failed attempt (EXP-BD-C-05-S002, transient Windows file lock) was retried
successfully. Scores come from reconstruction engine v1.1. Engine v1.0 scores are preserved and
compared in `rescoring_engine_v1_0_vs_v1_1.csv` (D-061). Sources:
`master_experimental_results.csv`, `pipeline_summary.csv`, `statistical_tests.csv`.

## Manipulation checks

- **Clean accuracy** was identical across A, B and C for every condition and seed, so
  instrumentation did not change training outcomes:

  | Condition | Seed 1 | Seed 2 |
  |---|---|---|
  | Clean | 0.9334 | 0.9284 |
  | Label flip | 0.9011 | 0.9016 |
  | Backdoor | 0.9316 | 0.9339 |

- **Backdoor ASR:** 1.0000 in all six backdoor runs (9,000/9,000 triggered test images
  classified as airplane).
- **Label flip:** the automobile→truck test error rate was 0.386 (seed 1) and 0.382 (seed 2) in
  every pipeline.

## RQ1: Which forensic artefacts were available?

Evidence items recovered and correct (evaluation schema, 20 items; 18 applicable to clean runs):

| Run type | A | B | C |
|---|---|---|---|
| Attacked runs | 10/20 in all 4 runs | 14/20 in all 4 runs | 20/20 in all 4 runs |
| Clean controls | 10/18 | 13/18 | 18/18 |

Items missing by pipeline (attacked runs):
- **A:** DS3 dataset lineage; DS4 per-class profile; DS5 changed samples; TR1 run ID; TR5 code
  version; MO2 model hash at creation; IN2 inference→model link; IN3 input hash; IG1 dataset
  integrity check; IG3 evidence chain.
- **B:** DS5, MO2, IN2, IN3, IG1, IG3.
- **C:** none.

Details are in `evidence_availability_matrix.csv`.

## RQ2: Which evidence relationships allowed reconstruction?

Backward-trace link confidence was identical across seeds and conditions (Figure 4.11, backdoor
seed 1):

| Pipeline | inference | deployment | model | training run | training dataset | registered dataset |
|---|---|---|---|---|---|---|
| A | MODERATE | WEAK | MODERATE | WEAK | WEAK | WEAK |
| B | MODERATE | WEAK | MODERATE | MODERATE | MODERATE | MODERATE |
| C | STRONG | STRONG | STRONG | STRONG | STRONG | STRONG |

What each pipeline relied on:
- **C:** the input SHA-256 matched the ticket, the deployment ID was recorded with the result,
  the served model hash matched the hash recorded at creation, the run ID was recorded with the
  model hash, the dataset hash was recorded at training start, and the dataset version carried
  its parent link.
- **B:** the registry version and run lineage, and the MLflow data-registration run linked
  through the recorded run ID.
- **A:** file paths and ordering within the application log.

Ordering was perfect in every run where recovered events existed (Kendall τ-b = 1.000, n = 18).

## RQ3: How did A, B and C compare? (mean ± SD; attacked runs n = 4 per pipeline unless noted)

| Measure | A | B | C |
|---|---|---|---|
| Evidence completeness, attacked | 50.0 % ± 0.0 | 70.0 % ± 0.0 | 100.0 % ± 0.0 |
| Evidence completeness, clean (n = 2) | 55.6 % ± 0.0 | 72.2 % ± 0.0 | 100.0 % ± 0.0 |
| Event recovery rate, attacked | 0.866 ± 0.010 | 1.000 ± 0.000 | 1.000 ± 0.000 |
| Timeline Kendall τ-b, all (n = 6) | 1.000 | 1.000 | 1.000 |
| Root-cause identification score, attacked | 0.750 | 0.750 | 1.000 |
| Reconstruction time, all (n = 6) | 0.084 s ± 0.013 | 0.599 s ± 1.125 | 0.199 s ± 0.029 |

Root-cause details:
- **Findings.** A: INSUFFICIENT_EVIDENCE in 4/4 attacked runs. B: DATASET_MODIFIED_UNSPECIFIED
  in 4/4, i.e. it detected that the data changed but not which samples. C: LABEL_MODIFICATION
  (label flip) or CONTENT_AND_LABEL_MODIFICATION (backdoor), identifying the changed samples with
  precision = recall = F1 = 1.0 in 4/4 runs.
- **Components.** All pipelines identified the dataset, training run and model. Only C identified
  the poisoning source.
- **Missed event.** A missed the POISONED_DATASET_CREATED event, having no evidence of the
  modification.
- **Clean controls.** A reported INSUFFICIENT_EVIDENCE; B and C reported
  NO_DATASET_MODIFICATION_FOUND. There was no false attribution in any pipeline.

Reconstruction-time note: the B maximum (2.895 s, EXP-BD-B-05-S001) was the first MLflow query in
the re-scoring process (client start-up). All other B runs took 0.136–0.149 s.

Statistics (exploratory; 6 blocks = 3 conditions × 2 seeds; `statistical_tests.csv`):

| Measure | Friedman χ²(2) | p | Kendall's W |
|---|---|---|---|
| Evidence completeness | 12.0 | 0.0025 | 1.00 |
| Event recovery | 8.0 | 0.018 | 0.67 |
| Reconstruction time | 10.3 | 0.0057 | 0.86 |

- **Binary outcomes (4 attacked blocks):** Cochran's Q = 8.0, p = 0.018, for both "poisoning
  source identified" and "dataset change detected".
- **Pairwise tests:** no pairwise comparison remained significant after Holm correction
  (smallest adjusted p = 0.094). With 6 blocks, the smallest attainable exact Wilcoxon p is
  0.031.
- **Not testable:** τ-b and the root-cause score have no within-block variance, so no inferential
  test is meaningful for them.

## RQ4: How much overhead did forensic readiness introduce?

- **Evidence storage per run:**

  | Pipeline | Excluding MLflow logged model | Including MLflow logged model |
  |---|---|---|
  | A | 0.055 MB | 0.055 MB |
  | B | 0.056 MB | 42.762 MB |
  | C | 9.659 MB ± 2.754 | 52.365 MB ± 2.754 |

  The dominant C component is the per-sample dataset manifests (≈ 5.3 MB each; attacked runs
  store two).
- **Relative overhead:** relative to A's very small evidence, C's overhead is +17,449 %
  (absolute +9.6 MB), so absolute values are the meaningful measure.
- **Training runtime, matched triples:**
  - Overhead versus A was −1.0 % ± 4.5 for B and −1.9 % ± 5.3 for C, i.e. no measurable
    training-time overhead.
  - Friedman χ²(2) = 0.33, p = 0.85.
  - Each A/B/C triple ran in the same GPU power state. Absolute times differ between triples
    because the laptop GPU was power-limited for the first six runs (median epoch ≈ 32 s versus
    ≈ 21.5 s).
- **Forensic evidence-logging time (C):** reported per run in `computational_overhead.csv`.
- **Peak RAM:** A 2203.5 MB, B 2183.7 MB, C 2185.8 MB (means).
- **Peak GPU allocated:** 765.5 MB in all pipelines.
