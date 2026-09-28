# Chapter 4 results package: genuine pilot data

Built by `scripts/chapter4_results.py` from the 18 completed pilot runs (30 epochs; clean, label
flip 5 %, backdoor 5 %; pipelines A/B/C; seeds 1–2) in `experiments/pilot/pipeline_runs/`. All
values are MEASURED or CALCULATED from those files (`results_provenance.csv`). The synthetic set is
not used.

- **Reconstruction engine:** scores use engine **v1.1**. During the pilot, engine v1.0 was found
  not to use pipeline B's recorded registration-run link (MLflow reuses dataset records across runs
  with identical data; D-060/D-061). Engine v1.0 results are preserved in
  `results/chapter4_engine_v1_0/`, `*_engine_v1_0.json` in each run package, and
  `rescoring_engine_v1_0_vs_v1_1.csv`. The fix changed 3 runs (B label flip seeds 1–2, B backdoor
  seed 2); A and C were unchanged.
- **Pre-pilot audit:** preserved in `results/chapter4_pre_pilot_audit/`.
- **Runtime caveat:** the first 6 runs (clean and label flip, seed 1) ran in a reduced GPU power
  state. Matched A/B/C triples always share a power state.
- **Statistics:** exploratory only (6 blocks); see `statistical_tests.csv`.

| File | Contents | RQ |
|---|---|---|
| experiment_inventory.csv | runs, status, retry, GPU power state | all |
| experimental_environment.csv | software/hardware, commit | methodology |
| clean_baseline_results.csv / label_flip_results.csv / backdoor_results.csv | per-run + aggregates | validity |
| evidence_availability_matrix.csv | evidence items per pipeline | RQ1 |
| evidence_completeness.csv, event_recovery.csv, timeline_reconstruction.csv, root_cause_identification.csv, reconstruction_time.csv | reconstruction metrics | RQ2, RQ3 |
| storage_overhead.csv, computational_overhead.csv | overhead | RQ4 |
| statistical_tests.csv | Friedman/RM-ANOVA, Wilcoxon + Holm, Cochran's Q + McNemar | RQ3, RQ4 |
| master_experimental_results.csv, pipeline_summary.csv, analysis_dataset.csv | tables | all |
| results_provenance.csv | value → source file/field/formula | all |
| reconstruction_case_study.md | backdoor 5 % seed 1: GT vs A/B/C reconstructions | RQ2 |
| rq_results.md, missing_results.md | facts; remaining gaps | all |
| figures/ | Figures 4.1–4.11 (PNG 300 dpi + SVG) + metadata | all |
