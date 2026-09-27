# Chapter 4 — Results (DRAFT TEMPLATE)

> Template with placeholders `{{KEY}}`. After the pilot/final runs:
> `python scripts/analyse_results.py --input results/raw/run_index.csv --phase main`, then
> `python scripts/fill_chapter4.py` writes `docs/chapter4_filled.md` with measured values.
> Unfilled placeholders stay visible as `{{KEY}}`, so no value is ever invented.
> Interpretation paragraphs marked *[interpret]* are written by the researcher after the data
> exists.

## 4.1 Experimental environment and execution

The experiments ran on the environment in Table 4.1 (Python {{ENV_PYTHON}}, PyTorch
{{ENV_TORCH}}, {{ENV_GPU}}). {{N_RUNS}} runs completed across pipelines A (conventional),
B (provenance) and C (forensic-ready); {{N_FAILED}} runs failed and were excluded
(results/raw/failed_runs.csv). The evaluation schema was frozen before data collection
(commit 9bccbc0).

*Table 4.1 — Experimental environment* (`tables/table1_environment.csv`)
*Table 4.2 — Experimental configuration* (`tables/table2_configuration.csv`)

## 4.2 Manipulation checks: attack effectiveness

Mean clean test accuracy was {{CA_A_mean}} (A), {{CA_B_mean}} (B) and {{CA_C_mean}} (C).
The backdoor attack reached a mean attack success rate of {{ASR_mean}}. Label flipping
produced a mean automobile→truck error rate of {{S2T_mean}}.
*[interpret: confirm instrumentation did not alter training; attacks effective]*

*Table 4.3 — Attack effectiveness* (`tables/table3_attack_effectiveness.csv`) · *Figures 5–6*

## 4.3 Evidence availability (RQ1)

Evidence completeness was {{EC_A_mean}} (A; 95 % CI {{EC_A_ci}}), {{EC_B_mean}} (B; {{EC_B_ci}})
and {{EC_C_mean}} (C; {{EC_C_ci}}). {{EC_TEST}}.
*[interpret against H1.1–H1.2, docs/hypotheses.md]*

*Table 4.4 — Evidence availability by lifecycle stage* · *Figure 7*

## 4.4 Event recovery and timeline reconstruction (RQ2)

Event recovery rate was {{ERR_A_mean}} (A), {{ERR_B_mean}} (B) and {{ERR_C_mean}} (C);
{{ERR_TEST}}. Where computable, ordering accuracy (Kendall τ-b) was {{TAU_A_mean}} (A),
{{TAU_B_mean}} (B) and {{TAU_C_mean}} (C).
*[interpret against H2.1–H2.2]*

*Table 4.5 — Reconstruction performance* · *Figures 8–9, 14–15*

## 4.5 Root-cause identification (RQ3)

The mean root-cause identification score was {{RCI_A_mean}} (A), {{RCI_B_mean}} (B) and
{{RCI_C_mean}} (C); {{RCI_TEST}}. Reconstruction runtime was {{RT_A_mean}} s (A),
{{RT_B_mean}} s (B) and {{RT_C_mean}} s (C).
*[interpret against H3.1–H3.5; include the D-054 caveat on A's path-based identification]*

*Figures 10–11, 16–17*

## 4.6 Operational overhead (RQ4)

Mean evidence storage was {{MB_A_mean}} MB (A), {{MB_B_mean}} MB (B) and {{MB_C_mean}} MB (C).
Training runtime was {{TRAIN_A_mean}} s (A), {{TRAIN_B_mean}} s (B) and {{TRAIN_C_mean}} s (C)
(overhead vs A: B {{TRAIN_B_ovh}} %, C {{TRAIN_C_ovh}} %).
*[interpret against H4.1–H4.2]*

*Table 4.6 — Operational overhead* · *Figures 12–13*

## 4.7 Statistical comparison

*Table 4.7 — Statistical comparison* (`tables/table7_statistical_comparison.csv`): paired
design (blocks = attack × rate × seed); RM-ANOVA or Friedman depending on Shapiro–Wilk;
Holm-corrected post-hoc tests; effect sizes with 95 % CIs. Statistical significance is not
treated as practical importance.

## 4.8 Summary of hypothesis outcomes

| Hypothesis | Outcome | Evidence |
|---|---|---|
| H1.1 EC(A) < EC(B) < EC(C) | *[supported / not supported]* | §4.3 |
| H2.1 ERR lower for A | | §4.4 |
| H3.1 only C identifies samples | | §4.5 |
| H3.2 B detects change, not samples | | §4.5 |
| H4.1 small training overhead | | §4.6 |
| H4.2 storage dominated by MLflow | | §4.6 |
