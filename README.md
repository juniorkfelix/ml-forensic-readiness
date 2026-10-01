# ML-FREF: Machine Learning Forensic Readiness Experimental Framework

ML-FREF is a controlled experiment. It trains a ResNet-18 on CIFAR-10, poisons the training
data (label flipping or a backdoor trigger), deploys the model, and then tries to **reconstruct
the poisoning incident from the evidence the pipeline recorded**. The same ML pipeline runs at
three levels of evidence instrumentation:

| Pipeline | Evidence recorded |
|---|---|
| **A** conventional | application log, model file, evaluation output |
| **B** provenance | A + MLflow tracking (runs, parameters, dataset digests, registered model) |
| **C** forensic-ready | B + hash-chained forensic event store (SQLite), SHA-256 artefact hashes, per-sample dataset manifests, deployment and inference events |

Each run's reconstruction is scored against a separately recorded ground truth, which the
reconstruction engine never reads.

---

## 1. Requirements

| | Minimum | Tested with |
|---|---|---|
| OS | Windows 10/11, Linux or macOS | Windows 11 |
| Python | 3.11 or newer | 3.14.3 |
| GPU | optional (CPU works but is very slow); NVIDIA with ≥ 4 GB VRAM recommended | RTX 1000 Ada Laptop, 6 GB |
| RAM | 8 GB | 32 GB |
| Disk | ~10 GB free for a full pilot run | |
| Network | ~2.5 GB of downloads (PyTorch CUDA wheels + CIFAR-10) | |
| Other | Git | |

## 2. Installation

```bash
git clone https://github.com/juniorkfelix/ml-forensic-readiness.git
cd ml-forensic-readiness
```

Create and activate a virtual environment:

```powershell
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

Install PyTorch for your hardware (**pick one**), then the rest:

```bash
python -m pip install --upgrade pip
# NVIDIA GPU, driver supporting CUDA 13.x
python -m pip install torch torchvision --index-url https://download.pytorch.org/whl/cu130
# NVIDIA GPU, older driver (CUDA 12.8)
python -m pip install torch torchvision --index-url https://download.pytorch.org/whl/cu128
# CPU only
python -m pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu

python -m pip install -r requirements.txt
python -m pip install -e .
```

The exact package versions used for the reported results are pinned in `requirements-lock.txt`
(`python -m pip install -r requirements-lock.txt`).

## 3. Verify the setup

```bash
python scripts/setup_environment.py     # checks Python, packages, CUDA, folders, Git -> PASS/FAIL
python -m pytest                         # ~210 tests, about 1-5 minutes
```

`setup_environment.py` writes `results/environment/environment_check.json` and
`environment_manifest.json`.

## 4. Prepare the dataset (once)

```bash
python scripts/prepare_dataset.py
```

This downloads CIFAR-10 (~163 MB) into `data/raw/`, records or verifies the SHA-256 of every
official file, and builds the clean data stores in `data/clean/`. Later runs verify the files
against `data/manifests/cifar10_raw_integrity.json` and stop if anything changed.

## 5. Quick check (≈ 2 minutes)

A 1-epoch end-to-end run. Its output goes to `experiments/smoke/` and `results/smoke/`, never into
the results:

```bash
python scripts/run_experiment.py --attack none --pipeline C --seed 1 --epochs 1 --phase smoke
```

## 6. Run the full study

### Option A: everything in one command (≈ 4.5–5 h on a laptop GPU)

```bash
python scripts/run_full_reproduction.py
```

Steps in order:
1. Environment check, tests and dataset preparation.
2. Speed calibration.
3. 30-epoch clean baseline.
4. Backdoor development check.
5. The pilot matrix: {clean, label flip 5 %, backdoor 5 %} × pipelines {A, B, C} × seeds {1, 2} =
   18 runs. Any failed pilot run is retried once.
6. The Chapter 4 analysis and `results/results_final.md`.

Each step is logged in `results/raw/reproduction_log.csv`.

### Option B: step by step

```bash
python scripts/run_clean_baseline.py --config config/baseline.yaml --seed 1   # ~12 min
python scripts/run_pilot.py --seeds 1 2                                        # 18 runs, ~13 min each
python scripts/chapter4_results.py                                             # analysis -> results/chapter4/
python scripts/build_results_final.py                                          # -> results/results_final.md
```

A single experiment:

```bash
python scripts/run_experiment.py --attack label_flip --pipeline B --poison-rate 0.05 --seed 1
#   --attack   none | label_flip | backdoor
#   --pipeline A | B | C   (or conventional | provenance | forensic)
#   --epochs N, --set key=value (config override), --force (re-run; old package is kept)
```

Each run reconstructs and evaluates its own incident automatically. To re-run reconstruction or
evaluation for a finished run:

```bash
python scripts/reconstruct_incident.py --experiment EXP-BD-C-05-S001
python scripts/evaluate_reconstruction.py --experiment EXP-BD-C-05-S001
```

Experiment IDs follow `EXP-{CLEAN|LF|BD}-{A|B|C}-{rate %}-S{seed}`.

## 7. Where the results are

| Location | Contents |
|---|---|
| `results/results_final.md` | **all results in one document** (tables, figures, conditions) |
| `results/chapter4/` | per-metric CSVs, statistical tests, figures 4.1–4.11, case study, provenance of every value |
| `results/raw/run_index.csv` | one row per completed run |
| `results/raw/failed_runs.csv` | failed attempts (never deleted) |
| `experiments/pilot/pipeline_runs/<EXP-ID>/` | run package: config, environment, metrics, model hash, reconstruction, evaluation |
| `results/reconstruction/`, `results/evaluation/` | per-run reconstruction reports (JSON + Markdown) and scores |
| `evidence/<pipeline>/RUN-<uuid>/` | the investigator-visible evidence of each run |
| `ground_truth/ground_truth.sqlite` | what actually happened (used only by the evaluator) |
| `mlruns/` | MLflow tracking store (pipelines B and C) |
| `archive/` | earlier runs, kept unchanged for comparison |

Not stored in Git (regenerated by running): datasets, data stores, model weights, evidence stores,
ground truth, MLflow store and logs.

## 8. Inspecting evidence

```bash
# forensic event store of a pipeline-C run: event table, hash-chain check, integrity checks
python scripts/view_evidence.py --db evidence/forensic/RUN-<uuid>/forensic_evidence.sqlite --verify

# MLflow UI (pipelines B and C), then open http://127.0.0.1:5000
mlflow ui --backend-store-uri sqlite:///mlruns/mlflow.db

# what the attacks change (in memory only; nothing is written)
python scripts/inspect_label_flip.py --seed 1
python scripts/inspect_backdoor.py --seed 1
```

## 9. Configuration

All parameters live in `config/`. They compose as `experiment.yaml` (shared defaults) →
pipeline file (`baseline.yaml` = A, `provenance.yaml` = B, `forensic.yaml` = C) → attack file
(`pilot_label_flip.yaml`, `pilot_backdoor.yaml`) → command-line `--set key=value`. The resolved
config of every run is saved in its package, together with its SHA-256.

| Setting | Default |
|---|---|
| Model | ResNet-18, CIFAR stem, trained from scratch |
| Training | 30 epochs, SGD lr 0.1, momentum 0.9, batch 128, cosine LR, AMP fp16, crop + flip augmentation |
| Label flip | automobile → truck, rate = fraction of the whole training set (5 % = 2,500 images) |
| Backdoor | 3×3 checkerboard, bottom-right, target airplane, 5 % = 2,500 images |
| Traffic | 200 inference requests per run (backdoor runs include 10 triggered inputs) |
| Device | `training.device: auto` (CUDA if available) |

`config/evaluation_schema.yaml` defines the evaluation metrics. It is **frozen** and must not be
edited for comparable results.

## 10. Project layout

```
config/        experiment, pipeline, attack and evaluation-schema YAML
src/mlfref/    package: data, models, attacks, provenance (MLflow), forensic,
               ground_truth, reconstruction, evaluation, reporting, pipeline.py
scripts/       command-line entry points (see sections 3-8)
tests/         pytest suite
docs/          design: architecture, evidence schema, ground truth, reconstruction,
               protocol, hypotheses, decision log (methodology_decisions.md)
```

## 11. Troubleshooting

- **Training is much slower than ~22 s per epoch:** a laptop GPU on battery or in power-saving
  mode runs at reduced clocks. Plug in and set the OS power mode to *Best performance*. Check
  with `nvidia-smi` (look for the P0/P1 state and full SM clocks).
- **`PermissionError` while writing `data/stores/...` (Windows):** a transient file lock, usually
  antivirus scanning the new 150 MB file. Re-run that experiment with `--force`.
  `run_full_reproduction.py` retries failed runs automatically.
- **"package exists; use --force":** an experiment ID was already run. `--force` moves the old
  package to `_superseded/` instead of deleting it.
- **Slow downloads:** the PyTorch CUDA wheel is about 2 GB. Install it once, and pip reuses its
  cache afterwards.
- **CUDA not detected:** check the installed wheel with
  `python -c "import torch; print(torch.cuda.is_available(), torch.version.cuda)"` and that the
  driver supports that CUDA version (`nvidia-smi`).
- **MLflow prints an "agent hint" message:** harmless. Silence it with
  `MLFLOW_DISABLE_AGENT_HINT=1`.

## 12. Notes for reproducibility

- Seeds control Python, NumPy, PyTorch and CUDA. Deterministic algorithms are enabled, and any
  remaining non-determinism is logged.
- Each run records the Git commit, configuration hash, library versions and hardware in its
  `environment.json`. Commit your changes before running, so this record is meaningful.
- Runs on the same machine, seeds and data are expected to reproduce the same model hashes and
  metrics. Training times depend on GPU power state and system load.
