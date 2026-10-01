# Missing Results Report

Chapter 4 results that **cannot** be obtained from the repository. Runtime estimates use the
measured ≈ 694 s for 30-epoch training plus about 60 s of pipeline overhead per run, on the RTX 1000
Ada Laptop GPU.

| # | Metric | Why it is missing | Calculable from another file? | New experiment required? | Command | Est. runtime |
|---|---|---|---|---|---|---|
| 1 | All pipeline-B results (every metric) | No pipeline-B run was executed | NO | YES | `python scripts/run_pilot.py --seeds 1 2` | ~4 h (18 runs) |
| 2 | Attacked-run results for A (LF, BD) | No attacked pipeline-A run exists | NO | YES | same as 1 | incl. in 1 |
| 3 | Full-protocol (30-epoch) pipeline-C results | Only 1-epoch smoke runs exist for C | NO | YES | same as 1 | incl. in 1 |
| 4 | Label-flip clean accuracy, training metrics, model hash, source→target error | Only LF run interrupted during training | NO | YES | `python scripts/run_experiment.py --attack label_flip --pipeline C --seed 1` (and A, B) | ~13 min per run |
| 5 | Backdoor ASR under pipelines A/B/C (full protocol) | Only a 1-epoch smoke run (C) and a no-pipeline dev check exist | NO | YES | same as 1 | incl. in 1 |
| 6 | Evidence completeness, A and B | No evaluated A/B run | NO | YES | same as 1 | incl. in 1 |
| 7 | Event recovery rate, A and B; attacked runs for C | As 6; the only evaluated C run is a clean control | NO | YES | same as 1 | incl. in 1 |
| 8 | Timeline accuracy, A and B; attacked runs | As 7 | NO | YES | same as 1 | incl. in 1 |
| 9 | Root-cause identification score (any pipeline) | Not applicable to clean runs; no attacked run reached reconstruction | NO | YES | same as 1 | incl. in 1 |
| 10 | Reconstruction time, A and B; attacked runs | As 7 | NO | YES | same as 1 | incl. in 1 |
| 11 | Reconstruction start/end wall-clock timestamps | The engine records elapsed time only (`runtime_seconds`) | NO | NO (code change) | would need timestamps added to `mlfref/reconstruction/engine.py` | – |
| 12 | Storage overhead % (B vs A, C vs A) | No pipeline-A or B evidence storage measured | NO | YES | same as 1 | incl. in 1 |
| 13 | MLflow logged-model size per run | Audit could not attribute `mlruns/artifacts/models/*` to runs | YES (MLflow registry `model_versions.source` → artefact folder) | NO | inspect `mlruns/mlflow.db` model_versions and size the matching folder | minutes |
| 14 | MLflow metadata DB bytes per run | `mlflow.db` is shared across runs | NO (not separable) | NO | report the shared database size instead | – |
| 15 | Valid runtime overhead % (B vs A, C vs A) | Only a single 1-epoch smoke comparison with different runner scripts exists | NO | YES | same as 1 | incl. in 1 |
| 16 | Inference time for A | The clean-baseline script has no inference stage | NO | YES | same as 1 | incl. in 1 |
| 17 | Aggregate statistics (SD, 95 % CI) per pipeline | n ≤ 1 per pipeline and condition | NO | YES | same as 1 (≥ 2 seeds) | incl. in 1 |
| 18 | Inferential tests (RM-ANOVA/Friedman, paired post hoc, effect sizes) | No complete A/B/C block; n insufficient | NO | YES | same as 1, then `python scripts/analyse_results.py --input results/raw/run_index.csv --phase pilot` | ~4 h + 1 min |
| 19 | Matched A/B/C poisoning case study (Figure 4.11) | No matched incident exists | NO | YES | same as 1 | incl. in 1 |
| 20 | Clean accuracy by poisoning rate (Figure 4.2); ASR by rate (Figure 4.3) | Only one rate (5 %), and no full-protocol attacked pipeline run | NO | YES | final matrix with rates 1/3/5 % (after pilot approval) | ~30 h (est.) |
| 21 | Multiple clean-baseline seeds (baseline variance) | Only seed 1 exists | NO | YES | `python scripts/run_clean_baseline.py --seed 2` (and 3…) | ~12 min each |

Additional integrity note: commit hashes recorded in run manifests (`9d731ac`, `282554c`,
`3a6639d`) and the schema freeze commit (`9bccbc0`) were created before the Git history rewrite
(attribution-trailer removal and large-file removal). The equivalent commits on the current
`main` are `8dcb331`, `1657866`, `9f4bd1f` and `96a509d` respectively, mapped by identical commit
subject. The original commits remain in the local branch `backup-before-rewrite`.
