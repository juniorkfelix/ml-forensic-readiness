# Research Hypotheses (stated before data collection)

These hypotheses are stated **before** the pilot or final experiment was run. They are derived
from the system design (docs/evidence_schema.md, docs/reconstruction.md), from two real
preliminary measurements, and from tests of the implementation on synthetic data. The frozen
evaluation schema (`config/evaluation_schema.yaml`, commit `9bccbc0`) defines every measure.
The experiment tests these hypotheses; it is not designed to confirm them. Pipelines are
A = conventional, B = provenance (MLflow), C = forensic-ready.

## Preliminary evidence (measured)

| Measurement | Value | Source |
|---|---|---|
| Clean ResNet-18 accuracy on CIFAR-10 (30 epochs, AMP) | 0.9334 | `experiments/pilot/EXP-CLEAN-A-00-S001/` |
| Backdoor (5 %, 3×3 trigger) development check | clean accuracy 0.9316; attack success rate 1.000 | `results/pilot/dev_checks/attack_sanity_backdoor_S001.json` |
| Training throughput (RTX 1000 Ada, AMP) | ≈ 23–26 s per epoch | `results/pilot/calibration_training_speed.json` |

## RQ1: Which lifecycle artefacts provide useful evidence?

- **H1.1** Evidence completeness increases with forensic readiness: **EC(A) < EC(B) < EC(C)**.
  *Rationale:* A records only application logs and files. B adds dataset digests, label profiles
  and run lineage. C adds per-sample manifests, hashes and hash-chained events.
- **H1.2** The largest B→C gains are in the **integrity** and **inference** stages (Table 4),
  where B records nothing beyond application logs.

## RQ2: Can multi-source evidence be correlated to reconstruct the sequence of events?

- **H2.1** Event recovery rate is lower for A than for B and C, mainly because A **cannot
  observe the dataset modification** (no event corresponding to DATASET_MODIFIED can be
  supported).
- **H2.2** When events are recovered, their **ordering is highly accurate in all pipelines**
  (Kendall τ-b close to 1), because every source uses timestamps from the same clock. Ordering
  is therefore expected to differ less between pipelines than coverage does.

## RQ3: How much does forensic readiness improve reconstruction over a conventional pipeline?

- **H3.1** Only C identifies the **poisoning source at sample level** (F1 ≥ 0.90 against the true
  poisoned samples). A and B score zero on this component.
- **H3.2** B detects **that** the training data changed after registration (differing MLflow
  digests and label-distribution profiles), but **not which samples** changed. Provenance alone
  therefore captures a large share of the "was the data changed?" benefit, and forensic readiness
  adds sample-level attribution.
- **H3.3** Root-cause identification score: **RCI(C) > RCI(B) ≥ RCI(A)**. B and A are expected to
  tie on dataset, training-run and model identification, because A benefits from the approved
  "content at event time" path rule (D-054).
- **H3.4** In clean-control runs no pipeline attributes a dataset modification (false-attribution
  rate ≈ 0). A reports insufficient evidence rather than "no modification".
- **H3.5** Reconstruction runtime increases with evidence volume, **RT(A) < RT(B) < RT(C)**, but
  stays in seconds, which is negligible compared with training.

## RQ4: What computational and storage overhead does forensic readiness introduce?

- **H4.1** Training-time overhead is small for both B and C (a few per cent over A), because
  instrumentation writes a bounded number of records outside the inner training loop.
- **H4.2** Storage overhead is dominated by **MLflow's logged model copy** in B and C, not by
  forensic events. C's additional overhead comes mainly from two per-sample manifests
  (≈ 5 MB each).

## Manipulation checks (validity, not hypotheses)

- Clean accuracy for a given seed is practically identical across A/B/C (instrumentation does not
  change training; tested).
- The backdoor achieves a high attack success rate. Label flipping (5 % = 2,500 automobiles →
  truck) produces an elevated automobile→truck error rate compared with the clean control.

## What would count against the hypotheses

- **EC(B) ≈ EC(C)** or **RCI(B) ≈ RCI(C)** would indicate provenance tracking is sufficient and
  forensic-specific evidence adds little.
- **Label-flip runs with no observable incident**, or **MLflow digests that do not change**
  despite poisoning (D-032), would weaken B's detection and should be reported as such.
- **Overhead above ~10 %** of training time for C would challenge H4.1.
