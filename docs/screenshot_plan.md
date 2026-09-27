# Screenshot Plan

Screenshots **illustrate** the methodology and implementation. They never replace quantitative
results. They are captured manually by the researcher from real system state, with the commands
given below, once the corresponding phase has run.

## Rules (spec §32)

- Never fabricate a screenshot and never edit values into one. Cropping and redaction boxes are
  allowed. Redactions are noted in the manifest.
- Before capturing: close unrelated tabs and windows; hide the username / home path (e.g. run
  `function prompt { "PS mlfref> " }` in PowerShell); make sure no tokens, credentials or
  corporate identifiers are visible.
- Save to `results/screenshots/` with the file names below, and add one row per screenshot to
  `results/screenshots/screenshot_manifest.csv`.
- Note the experiment ID and date for every screenshot. Prefer the pilot or main run that the
  thesis tables use.
- Covert-attack rule (D-014): screenshots of *investigator-visible* evidence (S09–S16) must not
  show ground truth side by side, except S17, which exists to compare the two.

## Screenshots

Commands marked *(Phase N)* become available when that phase is implemented. The exact commands
will be filled in then.

| ID | File | Shows | Source / command | Phase | Purpose | Chapter |
|---|---|---|---|---|---|---|
| S01 | `S01_project_environment.png` | project tree in VS Code + terminal with `python --version` and the venv active; no username/home path | VS Code explorer, `python scripts/setup_environment.py` | 1 | implementation environment | 3 |
| S02 | `S02_clean_dataset.png` | grid of representative CIFAR-10 training images with class labels | helper script *(Phase 3)* | 3 | original dataset | 3 |
| S03 | `S03_label_flip.png` | small table: sample_id, original label, poisoned label (≈10 rows, from ground truth) | GT query helper *(Phase 8)* | 8 | label-flip implementation | 3 |
| S04 | `S04_backdoor_trigger.png` | a clean image next to its triggered version (enlarged, nearest-neighbour) | helper script *(Phase 9)* | 9 | backdoor modification | 3 |
| S05 | `S05_baseline_training.png` | terminal during the clean baseline: run ref, epoch, loss, accuracy, device | `python scripts/run_clean_baseline.py --config config/baseline.yaml` | 4–5 | controlled training | 3/4 |
| S06 | `S06_mlflow_runs.png` | MLflow UI run list with columns: run ID, pipeline, seed, accuracy (plus dataset name/digest) | `mlflow ui --backend-store-uri sqlite:///mlruns/mlflow.db` | 10 | provenance tracking | 3 |
| S07 | `S07_mlflow_run_detail.png` | one run: parameters, metrics, dataset inputs, artefacts | MLflow UI | 10 | provenance of one run | 3 |
| S08 | `S08_dataset_lineage.png` | lineage: registered dataset → observed dataset → training run → model (generated graph or MLflow view) | lineage export *(Phase 10/14)* | 10/14 | provenance relationships | 3/4 |
| S09 | `S09_forensic_events.png` | formatted query of the forensic store: event_id, timestamp, event_type, artifact_id, run_id | evidence viewer CLI *(Phase 11)* | 11 | forensic evidence collection | 3 |
| S10 | `S10_integrity_verification.png` | artefact ID, stored hash, recomputed hash, result (MATCH/MISMATCH); chain verification | integrity CLI *(Phase 12)* | 12 | integrity verification | 3/4 |
| S11 | `S11_deployment_event.png` | MODEL_DEPLOYED: model ID, model hash, training run, deployment ID, timestamp | evidence viewer *(Phase 13)* | 13 | training → operational model | 3 |
| S12 | `S12_trigger_inference.png` | INFERENCE_RESULT for the ticketed request: input hash, deployment, prediction, confidence, timestamp | evidence viewer *(Phase 13)* | 13 | incident observation | 4 |
| S13 | `S13_reconstruction.png` | reconstruction summary: incident, model, run, dataset, event sequence, missing evidence | `python scripts/reconstruct_incident.py --experiment <ID>` | 14 | investigation output | 4 |
| S14 | `S14_conventional_reconstruction.png` | same incident type under pipeline A, showing UNKNOWN / missing links | as S13 for an A run | 14/16 | baseline limitations | 4 |
| S15 | `S15_provenance_reconstruction.png` | pipeline B reconstruction | as S13 for a B run | 14/16 | contribution of provenance | 4 |
| S16 | `S16_forensic_reconstruction.png` | pipeline C reconstruction (chain as far as the evidence actually supports) | as S13 for a C run | 14/16 | forensic-ready investigation | 4 |
| S17 | `S17_ground_truth_comparison.png` | reconstructed vs actual event sequence | `python scripts/evaluate_reconstruction.py --experiment <ID>` | 15 | evaluation method | 3/4 |
| S18 | `S18_results_summary.png` | key A/B/C comparison plot(s) from actual results | `results/chapter4/figures/` | 19–20 | Chapter 4 findings | 4 |

S14–S16 should use the **same attack, rate and seed**, so that the only difference is the
pipeline.
