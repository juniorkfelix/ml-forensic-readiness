# SYNTHETIC - NOT EXPERIMENTAL RESULTS

Generated from `results/synthetic/run_index_SYNTHETIC.csv` (synthetic, D-056). Demonstrates the Chapter 4 pipeline only; **do not report these values as findings.**

| File | Contents | Supports |
|---|---|---|
| tables/table1_environment.csv | software/hardware environment (always real) | methodology |
| tables/table2_configuration.csv | runs per pipeline/attack/rate | methodology |
| tables/table3_attack_effectiveness.csv | CA, ASR, source->target rate | manipulation check |
| tables/table4_evidence_availability.csv | evidence completeness | RQ1, RQ3 |
| tables/table5_reconstruction_performance.csv | ERR, tau, RCI, runtime | RQ2, RQ3 |
| tables/table6_operational_overhead.csv | storage/runtime overhead vs A | RQ4 |
| tables/table7_statistical_comparison.csv | paired tests, Holm-adjusted, effect sizes | RQ3, RQ4 |
| summary_statistics.csv | n, mean, median, SD, IQR, 95% CI per metric/pipeline | all |
| statistical_tests.csv | full test output | RQ3, RQ4 |
| experiment_index.csv | runs included | traceability |
| figures/ | Figures 5-13 (PNG 300 dpi + SVG), metadata in figure_metadata.json | RQ1-RQ4 |

Interpretation is written separately in the dissertation (spec §35).
