# Chapter 4 results package (audit of genuine repository outputs)

Built by `scripts/chapter4_audit.py` and `scripts/chapter4_figures.py` from genuine files only.
The synthetic demonstration set (`results/synthetic/`) is excluded. Values are MEASURED,
CALCULATED, NOT AVAILABLE or NOT APPLICABLE.

**Data status:** the pilot and final experiments have not been run. The genuine data are:
- 1 full-protocol run (30-epoch clean baseline, pipeline A);
- 1 backdoor development check (30 epochs, no pipeline);
- 3 one-epoch smoke checks (clean A, clean C, backdoor C);
- 1 interrupted run (label flip C, CPU subset).

There are no pipeline-B runs. See `missing_results.md`.

| File | Contents | RQ |
|---|---|---|
| experiment_inventory.csv | every run, status, fidelity, availability flags | all |
| experimental_environment.csv | software/hardware, commits (with post-rewrite mapping) | methodology |
| clean_baseline_results.csv | clean runs + aggregates | validity |
| label_flip_results.csv / backdoor_results.csv | attack runs, ASR definition | validity |
| evidence_availability_matrix.csv | A/B design vs C observed | RQ1 |
| evidence_completeness.csv, event_recovery.csv, timeline_reconstruction.csv, root_cause_identification.csv, reconstruction_time.csv | per-run reconstruction metrics | RQ2, RQ3 |
| storage_overhead.csv, computational_overhead.csv | overhead | RQ4 |
| statistical_tests.csv | inferential feasibility (insufficient n) | RQ3, RQ4 |
| master_experimental_results.csv / pipeline_summary.csv | one row per run / A-B-C summary | all |
| results_provenance.csv | every number -> source file/field/formula | all |
| reconstruction_case_study.md, rq_results.md, missing_results.md | narrative facts | all |
| figure_inventory.csv, figures/ | figure audit; Figure 4.1 (genuine) | all |
