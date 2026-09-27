# ML-FREF — Machine Learning Forensic Readiness Experimental Framework

> Research prototype for the MSc dissertation (Information Security and Digital Forensics):
> *"A Forensic-Ready Framework for Multi-Source Evidence Collection and Reconstruction of
> Data Poisoning Attacks in Machine Learning Systems"*.

**Status:** under construction. Phases 1–2 (repository and environment setup, configuration and
reproducibility) are implemented. **No experimental results exist yet.** Any number that
appears in `results/` was produced by code that actually ran.

---

## 1. Project purpose

ML-FREF is a controlled experiment. It tests whether **forensic readiness** helps investigators
reconstruct **data-poisoning attacks** against an ML system after the fact. There is one shared
ML pipeline (CIFAR-10 → ResNet-18 → deployment → inference). The only independent variable is how
much evidence instrumentation that pipeline has:

| Config | Name            | Evidence available to the investigator                              |
|--------|-----------------|---------------------------------------------------------------------|
| A      | `conventional`  | trained model, normal application logs, standard evaluation output  |
| B      | `provenance`    | A + MLflow experiment tracking (params, metrics, datasets, artefacts)|
| C      | `forensic`      | B + dedicated forensic evidence store (hash-chained events, SHA-256 artefact hashes, deployment/inference records) |

## 2. Research questions

- **RQ1:** Which forensic artefacts produced across the ML lifecycle are useful evidence when
  investigating data poisoning?
- **RQ2:** How can evidence from dataset provenance, training records, model artefacts and
  inference activity be correlated to reconstruct the sequence of events?
- **RQ3:** How much does a forensic-ready pipeline improve evidence availability and incident
  reconstruction compared with a conventional pipeline?
- **RQ4:** How much computational and storage overhead does forensic readiness add?

See `docs/research_traceability.md` (to be written) for the metric → RQ mapping.

## 3. Architecture (summary)

```
            config/*.yaml ──► resolved config (hashed, archived)
                                   │
CIFAR-10 ─► preprocessing ─► [attack] ─► training ─► model ─► deployment ─► inference
                │               │           │          │           │            │
                └──────── evidence instrumentation (depends on A / B / C) ──────┘
                                   │
                       evidence/<pipeline>/   (investigator-visible)
                                   │
                        reconstruction engine ─► results/reconstruction/
                                   │
ground_truth/ (hidden) ──────► evaluator ─► metrics ─► statistics ─► thesis tables/figures
```

**Critical rule:** ground truth is kept apart from investigator-visible evidence. The
reconstruction engine (`mlfref.reconstruction`) never imports, opens or reads anything under
`ground_truth/` or `mlfref.ground_truth`. Automated tests enforce this.

Full description: `docs/architecture.md` (to be written).

## 4. Installation

### 4.1 Prerequisites
- Python ≥ 3.11 (the spec prefers 3.11; this workstation uses 3.14 — see *Known limitations*)
- Git
- Optional: an NVIDIA GPU with a recent driver (training on CPU works but is much slower)

### 4.2 Create the virtual environment

Windows (PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

Linux / macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

### 4.3 Install PyTorch (choose ONE, matching your hardware)

```bash
# NVIDIA GPU, driver supporting CUDA 13.x (used for the dissertation runs)
python -m pip install torch torchvision --index-url https://download.pytorch.org/whl/cu130
# NVIDIA GPU, older driver (CUDA 12.8)
python -m pip install torch torchvision --index-url https://download.pytorch.org/whl/cu128
# CPU only
python -m pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
```

### 4.4 Install the remaining dependencies and the package

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
```

To reproduce the exact dissertation environment, use `requirements-lock.txt` instead.

### 4.5 Verify the environment

```bash
python scripts/setup_environment.py
```
This writes `results/environment/environment_check.json` and prints PASS or FAIL.

## 5. GPU / CPU
`training.device: auto` uses CUDA when it is available and falls back to CPU otherwise. The device
used for each run is recorded in that run's environment manifest.

## 6. Dataset preparation — *Phase 3*
## 7. MLflow setup — *Phase 10*
## 8. Baseline execution — *Phases 4–5*
## 9. Attack execution — *Phases 8–9*
## 10. Pipeline configurations

Configuration is layered: `experiment.yaml` (shared defaults) → pipeline overlay
(`baseline.yaml` = A, `provenance.yaml` = B, `forensic.yaml` = C) → attack overlay
(`pilot_label_flip.yaml`, `pilot_backdoor.yaml`) → command-line overrides. The fully resolved
configuration is saved with every run, and its SHA-256 hash is recorded.

## 11. Reconstruction — *Phase 14*
## 12. Evaluation — *Phase 15*
## 13. Result generation — *Phases 16–20*

## 14. Testing
```bash
python -m pytest
```

## 15. Known limitations
- **Python version:** the workstation uses Python 3.14.3 inside a project venv instead of the
  preferred 3.11, because the researcher chose not to install an extra interpreter. PyTorch
  2.14.0 (cu130) and MLflow publish wheels for 3.14. Exact versions are recorded in
  `requirements-lock.txt` and in every environment manifest.
- **GPU determinism:** full bitwise determinism on CUDA is not guaranteed for every operation.
  Operations that lack deterministic kernels are logged (see `mlfref.reproducibility`).
- More to be added as phases complete.
