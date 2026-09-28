# Missing Results Report (after the pilot)

The pilot matrix is complete (18/18 runs). The following Chapter 4 results are still **not
obtainable** from the repository:

| Metric | Why missing | Calculable from other files? | New experiment? | Command | Est. runtime |
|---|---|---|---|---|---|
| Effect of poisoning **rate** (Figures 4.2/4.3 by rate) | Pilot used one rate (5 %) | NO | YES | final matrix after approval, e.g. rates 1/3/5 % | ~13 min/run |
| Adequately powered inferential tests | 6 blocks (3 conditions × 2 seeds); exact Wilcoxon floor p = 0.031; no pairwise test survives Holm | NO | YES | more seeds (≥ 5) in the final matrix | ~13 min/run |
| Seed variance of evidence metrics | Evidence metrics are deterministic given the design (identical across seeds) | NO | NO (a property, not missing data) | – | – |
| Reconstruction start/end wall-clock timestamps | Engine records elapsed time only | NO | NO (code change) | add timestamps in `reconstruction/engine.py` | – |
| MLflow metadata DB bytes per run | `mlflow.db` is shared across runs | NO | NO | report shared DB size | – |
| Incorrectly inferred (false-positive) events | Not measured by the implementation | NO | NO (metric extension) | – | – |
| Unconfounded absolute training runtime | First 6 runs ran in reduced GPU power state | NO | YES (re-run those 6 at full power) | `python scripts/run_experiment.py --attack none|label_flip --pipeline A|B|C --seed 1 --phase pilot --force` | ~13 min each |
| Deployment / attack-type as scored RCI components | Not components of the frozen schema (calculated descriptively only) | YES (descriptive, in root_cause_identification.csv) | NO | – | – |
| Chapter 4 draft auto-fill | `fill_chapter4.py` expects `analyse_results.py` outputs, not this package | YES | NO | adapt `fill_chapter4.py` to `results/chapter4/` | minutes |
