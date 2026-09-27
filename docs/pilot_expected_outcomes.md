# Pilot: Anticipated Outcomes (PREDICTIONS, NOT RESULTS)

> **Status: ANTICIPATED. No pilot experiment has been run.**
> Every value below is a *prediction* reasoned from the system design, from the tests on
> synthetic data, and from two development checks. None of it is experimental evidence, and it
> must not appear in the dissertation as a finding or be mixed with measured results. The pilot
> (`python scripts/run_pilot.py --seeds 1 2`, about 4 h) replaces these predictions with
> measurements. Where they disagree, the measurement stands.

## 1. What the predictions are based on (actual measurements and tests)

| Source | Measured / tested fact |
|---|---|
| Clean baseline `EXP-CLEAN-A-00-S001` (real run) | clean test accuracy **0.9334**; training 694 s for 30 epochs (AMP); peak GPU 764 MB |
| Backdoor development check (real run, 1 seed, no pipeline) | CA **0.9316**, ASR **1.0000** (9,000/9,000) |
| Calibration | ~23–26 s/epoch (AMP) on the RTX 1000 Ada Laptop GPU |
| `tests/test_reconstruction.py` (tiny synthetic data, real pipeline) | A: dataset change NOT_OBSERVABLE; B: change detected, class-count delta only; C: exact changed sample IDs, all links STRONG, clean control → no modification found |
| `tests/test_metrics.py` | metric definitions behave as specified |

## 2. Predicted attack effectiveness (manipulation check)

| Run | Clean accuracy (predicted) | Attack metric (predicted) | Reasoning |
|---|---|---|---|
| Clean control | ≈ 0.93 (0.925–0.94) | – | baseline 0.9334 |
| Label flip 5 % | ≈ 0.88–0.91 | automobile→truck error ≈ 0.3–0.6 | half of all automobiles relabelled; the model splits automobile predictions between the two classes |
| Backdoor 5 % | ≈ 0.925–0.935 | ASR ≈ 0.99–1.00 | development check gave ASR 1.00 |

A/B/C should give practically identical CA/ASR for the same seed. Instrumentation does not change
training (tested); only GPU non-determinism could introduce tiny differences.

## 3. Predicted reconstruction metrics (per attacked run)

| Metric | A conventional | B provenance | C forensic-ready |
|---|---|---|---|
| Evidence completeness (EC, 20 items) | low, ≈ 0.35–0.50 | medium, ≈ 0.55–0.70 | high, ≈ 0.95–1.00 |
| Event recovery rate (7 LF / 8 BD events) | ≈ 0.6–0.75 (no DATASET_MODIFIED event) | ≈ 0.85–1.0 | ≈ 1.0 |
| Kendall τ-b (ordering) | ≈ 1.0 when computed (log timestamps are ordered) | ≈ 1.0 | ≈ 1.0 |
| RCI score (4 components) | ≈ 0.75 (dataset, run, model by path/time; no poisoning source) | 0.75 (no sample-level source) | 1.0 |
| Root-cause finding | INSUFFICIENT_EVIDENCE | DATASET_MODIFIED_UNSPECIFIED (+ class-count delta) | LABEL_MODIFICATION / CONTENT_AND_LABEL_MODIFICATION with exact sample IDs |
| Clean-control false attribution | 0 (reports insufficient evidence, not a modification) | 0 expected | 0 expected |
| Reconstruction runtime | < 1 s | ≈ 1–3 s (MLflow queries) | ≈ 2–6 s (forensic store + 2 × 50k-record manifest comparison) |

Notes on the predictions:
- A's dataset identification relies on the "content at event time" path rule (D-054), which is
  why A is predicted to score on dataset and training-run components despite having no hashes.
- B's change detection depends on MLflow's partial digest (D-032). With poisoning spread over
  50,000 samples, the first 10,000 labels almost surely include poisoned ones, so the digest
  should change. The class-count profile (D-033) shows the automobile/truck shift for label flip,
  and a uniform −~275 per class / +2,500 airplane shift for the backdoor.
- The most likely *interesting* result: **B captures most of the "was the data changed?" benefit,
  but only C identifies which samples were changed** (RQ3 "does provenance alone give most of the
  benefit?").

## 4. Predicted overhead (RQ4)

| Measure | A | B | C |
|---|---|---|---|
| Training wall-clock | ≈ 690–700 s | ≈ +1–3 % (MLflow per-epoch metrics + dataset logging) | ≈ +2–5 % (plus manifests of 50k samples ×2) |
| Evidence storage | ≈ 50 KB (app.log, listings) | ≈ 45–50 MB (logged model pickle dominates) | ≈ 60–65 MB (+ two ~5 MB manifests, forensic DB ~0.2 MB, JSONL) |

Storage overhead is predicted to be dominated by MLflow's logged model copy, not by forensic
events. That is itself a result worth testing.

## 5. Risks that could make the measurements differ

- GPU non-determinism could make A/B/C CA differ slightly (logged by the determinism checks).
- A label-flip incident needs an automobile image predicted as truck among the ~20 automobile
  requests in the traffic; if none occurs, that run has "no observable incident" (it is recorded,
  not excluded silently).
- Ground-truth vs evidence time gaps near the 5 s tolerance (e.g. MLflow dataset logging before
  training starts) could fail some B time checks.
- The runner (`scripts/run_experiment.py`) has **not been executed end to end**. A 1-epoch smoke
  run is required before the pilot: `python scripts/run_experiment.py --attack backdoor
  --pipeline C --seed 1 --epochs 1 --phase smoke`.
