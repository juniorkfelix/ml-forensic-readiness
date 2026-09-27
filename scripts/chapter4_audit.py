"""Chapter 4 results audit: builds results/chapter4/ from GENUINE repository outputs only.

Reads experiment packages, run summaries, evaluation/reconstruction JSON, the ground-truth
database, forensic evidence stores, the MLflow store and environment manifests. It never
reruns experiments, never overwrites existing results, and never uses the synthetic set
(results/synthetic/) as data. Values are marked MEASURED, CALCULATED, NOT AVAILABLE or
NOT APPLICABLE.

Usage: python scripts/chapter4_audit.py
"""

from __future__ import annotations

import csv
import json
import math
import sqlite3
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
OUT = ROOT / "results" / "chapter4"
NA, NAPP = "NOT AVAILABLE", "NOT APPLICABLE"
SCRIPT = "scripts/chapter4_audit.py"

# Commit hashes recorded in run manifests were created before the history rewrite
# (Claude trailer removal, large-file removal); mapped by identical commit subject.
COMMIT_MAP = {
    "9d731ac": "8dcb331",
    "282554c": "1657866",
    "3a6639d": "9f4bd1f",
    "9bccbc0": "96a509d",
}


def rel(p: Path) -> str:
    return p.resolve().relative_to(ROOT).as_posix()


def jload(p: Path):
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def write_csv(name: str, rows: list[dict]) -> Path:
    path = OUT / name
    header: list[str] = []
    for r in rows:
        header += [k for k in r if k not in header]
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=header)
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in header})
    return path


def mapped(commit: str | None) -> str:
    if not commit:
        return NA
    short = commit[:7]
    return f"{short} (current main: {COMMIT_MAP.get(short, 'unmapped')})"


def agg(values: list[float]) -> dict:
    from mlfref.evaluation.statistics import describe

    d = describe([v for v in values if isinstance(v, (int, float))])
    out = {"n": d["n"]}
    for k in ("mean", "median", "sd", "min", "max", "ci_low", "ci_high"):
        out[k] = d[k] if d[k] is not None else (NA if d["n"] < 2 or k != "mean" else NA)
    if d["n"] < 2:
        for k in ("sd", "ci_low", "ci_high"):
            out[k] = "NOT AVAILABLE (n<2)"
    return out


# ------------------------------------------------------------------------ discovery
def git_head() -> str:
    return subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()


def gt_events(uuid: str) -> list[dict]:
    c = sqlite3.connect(ROOT / "ground_truth" / "ground_truth.sqlite")
    c.row_factory = sqlite3.Row
    rows = [
        dict(r)
        for r in c.execute(
            "SELECT * FROM gt_events WHERE experiment_uuid=? ORDER BY sequence_number", (uuid,)
        )
    ]
    c.close()
    return rows


def gt_attack(uuid: str) -> dict | None:
    c = sqlite3.connect(ROOT / "ground_truth" / "ground_truth.sqlite")
    c.row_factory = sqlite3.Row
    r = c.execute("SELECT * FROM gt_attacks WHERE experiment_uuid=?", (uuid,)).fetchone()
    c.close()
    return dict(r) if r else None


def discover() -> list[dict]:
    runs = []
    for pkg in sorted((ROOT / "experiments").glob("*/EXP-*")):
        phase = pkg.parent.name
        cfg = yaml.safe_load((pkg / "config.yaml").read_text(encoding="utf-8"))
        summ = jload(pkg / "run_summary.json") or {}
        env = jload(pkg / "environment.json") or {}
        uuid = summ.get("experiment_uuid") or (env.get("experiment") or {}).get("experiment_uuid")
        mode = cfg["pipeline"]["mode"]
        attack = cfg["attack"]["type"]
        epochs = cfg["training"]["epochs"]
        if phase == "pilot":
            status, fidelity = "SUCCESS", "full protocol (30 epochs)"
        elif phase == "smoke":
            status, fidelity = "SUCCESS (smoke check)", f"smoke check ({epochs} epoch)"
        else:
            status, fidelity = (
                "INCOMPLETE (interrupted by researcher)",
                f"reduced CPU pilot ({epochs} epoch, "
                f"{cfg['dataset'].get('train_subset')}-sample subset)",
            )
        evidence = ROOT / "evidence" / mode / f"RUN-{uuid}" if uuid else None
        runs.append(
            {
                "phase": phase,
                "pkg": pkg,
                "cfg": cfg,
                "summary": summ,
                "env": env,
                "uuid": uuid,
                "experiment_id": pkg.name,
                "pipeline": {"conventional": "A", "provenance": "B", "forensic": "C"}[mode],
                "attack": {"none": "CLEAN", "label_flip": "LF", "backdoor": "BD"}[attack],
                "attack_type": attack,
                "poison_rate": cfg["attack"]["poison_rate"],
                "seed": cfg["experiment"]["seed"],
                "epochs": epochs,
                "status": status,
                "fidelity": fidelity,
                "included_in_primary_analysis": phase == "pilot" and status == "SUCCESS",
                "evidence_dir": evidence if evidence and evidence.exists() else None,
                "gt": gt_events(uuid) if uuid else [],
                "gt_attack": gt_attack(uuid) if uuid else None,
                # Only reconstruction evaluations count here; the clean-baseline script writes an
                # evaluation.json with clean-test metrics only (different structure).
                "evaluation": (lambda e: e if e and "evidence_completeness" in e else None)(
                    jload(pkg / "evaluation.json")
                ),
                "reconstruction": jload(pkg / "reconstruction.json"),
                "training_metrics": (
                    list(csv.DictReader((pkg / "training_metrics.csv").open(encoding="utf-8")))
                    if (pkg / "training_metrics.csv").exists()
                    else []
                ),
                "model_meta": jload(pkg / "model_metadata.json") or {},
            }
        )
    return runs


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    runs = discover()
    dev = jload(ROOT / "results/pilot/dev_checks/attack_sanity_backdoor_S001.json")
    head = git_head()
    prov: list[dict] = []

    def P(metric, exp, value, unit, status, src, field, formula="", commit=None):
        prov.append(
            {
                "metric_name": metric,
                "experiment_id": exp,
                "reported_value": value,
                "unit": unit,
                "status": status,
                "source_file": src,
                "source_field": field,
                "calculation_script": SCRIPT if status == "CALCULATED" else "",
                "calculation_formula": formula,
                "git_commit": commit or NA,
            }
        )

    # ---------------------------------------------------------------- PART 1 inventory
    inv = []
    for r in runs:
        s, e = r["summary"], r["env"]
        start = s.get("started_utc") or (e.get("manifest_created_utc"))
        end = s.get("completed_utc")
        if not end and r["evidence_dir"]:
            app = (r["evidence_dir"] / "app.log").read_text(encoding="utf-8").splitlines()
            end = app[-1].split(" | ")[0] if app and "completed" in app[-1] else None
        inv.append(
            {
                "experiment_id": r["experiment_id"],
                "experiment_uuid": r["uuid"],
                "phase": r["phase"],
                "pipeline": r["pipeline"],
                "attack": r["attack"],
                "poison_rate": r["poison_rate"],
                "seed": r["seed"],
                "epochs": r["epochs"],
                "fidelity": r["fidelity"],
                "status": r["status"],
                "start_time": start or NA,
                "end_time": end or NA,
                "model": "ResNet-18 (CIFAR stem)",
                "dataset": (
                    "CIFAR-10 train (50,000)"
                    if not r["cfg"]["dataset"].get("train_subset")
                    else f"CIFAR-10 stratified subset ({r['cfg']['dataset']['train_subset']})"
                ),
                "results_available": "YES" if s.get("status") == "completed" else "NO",
                "ground_truth_available": "YES" if r["gt"] else "NO",
                "evidence_available": "YES" if r["evidence_dir"] else "NO",
                "reconstruction_available": "YES" if r["reconstruction"] else "NO",
                "included_in_primary_analysis": (
                    "YES" if r["included_in_primary_analysis"] else "NO"
                ),
                "git_commit_recorded": mapped(
                    s.get("git_commit") or (e.get("git") or {}).get("commit")
                ),
                "package": rel(r["pkg"]),
            }
        )
    inv.append(
        {
            "experiment_id": "attack_sanity_backdoor_S001 (development check)",
            "experiment_uuid": NAPP,
            "phase": "dev_check",
            "pipeline": "none (no pipeline)",
            "attack": "BD",
            "poison_rate": 0.05,
            "seed": 1,
            "epochs": dev["epochs"],
            "fidelity": "full training (30 epochs) without pipeline instrumentation",
            "status": "SUCCESS (development check)",
            "start_time": NA,
            "end_time": dev["created_utc"],
            "model": "ResNet-18 (CIFAR stem)",
            "dataset": "CIFAR-10 train (50,000)",
            "results_available": "YES",
            "ground_truth_available": "NO",
            "evidence_available": "NO",
            "reconstruction_available": "NO",
            "included_in_primary_analysis": "NO",
            "git_commit_recorded": mapped(dev["git_commit"]),
            "package": "results/pilot/dev_checks/attack_sanity_backdoor_S001.json",
        }
    )
    write_csv("experiment_inventory.csv", inv)

    # ---------------------------------------------------------------- PART 2 environment
    env = jload(ROOT / "results/environment/environment_manifest.json")
    lock = {
        ln.split("==")[0].lower(): ln.split("==")[1]
        for ln in (ROOT / "requirements-lock.txt").read_text(encoding="utf-8").splitlines()
        if "==" in ln
    }
    ver = lambda k: lock.get(k, NA)  # noqa: E731
    base_env = jload(ROOT / "experiments/pilot/EXP-CLEAN-A-00-S001/environment.json")
    clean_ver = jload(ROOT / "data/manifests/CIFAR10-CLEAN-V1.version.json")
    env_rows = [
        (
            "Operating system",
            f"{env['os']['system']} {env['os']['release']} ({env['os']['version']})",
            "results/environment/environment_manifest.json",
            "os",
        ),
        ("Python", env["software"]["python"], "environment_manifest.json", "software.python"),
        ("PyTorch", env["software"]["torch"], "environment_manifest.json", "software.torch"),
        (
            "torchvision",
            env["software"]["torchvision"],
            "environment_manifest.json",
            "software.torchvision",
        ),
        (
            "CUDA (PyTorch build)",
            env["software"]["cuda_build"],
            "environment_manifest.json",
            "software.cuda_build",
        ),
        ("cuDNN", env["software"]["cudnn"], "environment_manifest.json", "software.cudnn"),
        ("GPU", env["hardware"]["gpu"]["name"], "environment_manifest.json", "hardware.gpu.name"),
        (
            "GPU memory (MB)",
            env["hardware"]["gpu"]["total_memory_mb"],
            "environment_manifest.json",
            "hardware.gpu.total_memory_mb",
        ),
        ("CPU", env["hardware"]["cpu"], "environment_manifest.json", "hardware.cpu"),
        (
            "CPU cores (physical/logical)",
            f"{env['hardware']['cpu_physical_cores']}/{env['hardware']['cpu_logical_cores']}",
            "environment_manifest.json",
            "hardware.cpu_*_cores",
        ),
        (
            "System RAM (GB)",
            env["hardware"]["ram_total_gb"],
            "environment_manifest.json",
            "hardware.ram_total_gb",
        ),
        ("MLflow", ver("mlflow"), "requirements-lock.txt", "mlflow"),
        ("NumPy", env["software"]["numpy"], "environment_manifest.json", "software.numpy"),
        ("pandas", ver("pandas"), "requirements-lock.txt", "pandas"),
        ("scikit-learn", ver("scikit-learn"), "requirements-lock.txt", "scikit-learn"),
        ("SciPy", ver("scipy"), "requirements-lock.txt", "scipy"),
        (
            "Git commit (clean baseline run)",
            mapped(base_env["git"]["commit"]),
            "experiments/pilot/EXP-CLEAN-A-00-S001/environment.json",
            "git.commit",
        ),
        (
            "Git branch (clean baseline run)",
            base_env["git"]["branch"],
            "experiments/pilot/EXP-CLEAN-A-00-S001/environment.json",
            "git.branch",
        ),
        (
            "Config SHA-256 (clean baseline run)",
            base_env["config_sha256"],
            "experiments/pilot/EXP-CLEAN-A-00-S001/environment.json",
            "config_sha256",
        ),
        (
            "Clean dataset manifest SHA-256 (CIFAR10-CLEAN-V1)",
            clean_ver["manifest_sha256"],
            "data/manifests/CIFAR10-CLEAN-V1.version.json",
            "manifest_sha256",
        ),
        (
            "Evaluation schema freeze commit",
            mapped("9bccbc0"),
            "config/evaluation_schema.yaml",
            "frozen_commit",
        ),
        ("Repository HEAD at audit", head, "git", "HEAD"),
    ]
    write_csv(
        "experimental_environment.csv",
        [
            {"item": a, "value": b, "status": "MEASURED", "source_file": c, "source_field": d}
            for a, b, c, d in env_rows
        ],
    )

    # ---------------------------------------------------------------- PART 3 clean baseline
    base_rows = []
    for r in runs:
        if r["attack"] != "CLEAN":
            continue
        s, cfg, tm = r["summary"], r["cfg"], r["training_metrics"]
        last = tm[-1] if tm else {}
        timings = s.get("timings", {})
        ca = s.get("clean_test_accuracy") or (s.get("harness_metrics") or {}).get(
            "clean_test_accuracy"
        )
        mm = r["model_meta"]
        row = {
            "experiment_id": r["experiment_id"],
            "phase": r["phase"],
            "fidelity": r["fidelity"],
            "included_in_primary_analysis": "YES" if r["included_in_primary_analysis"] else "NO",
            "seed": r["seed"],
            "pipeline": r["pipeline"],
            "epochs": cfg["training"]["epochs"],
            "batch_size": cfg["training"]["batch_size"],
            "learning_rate": cfg["training"]["learning_rate"],
            "optimizer": cfg["training"]["optimizer"],
            "final_training_loss": float(last["train_loss"]) if last else NA,
            "final_training_accuracy": float(last["train_accuracy"]) if last else NA,
            "clean_test_accuracy": ca if ca is not None else NA,
            "training_duration_s": timings.get("training_seconds", NA),
            "evaluation_duration_s": timings.get(
                "test_seconds", timings.get("evaluation_seconds", NA)
            ),
            "total_runtime_s": (
                round(
                    sum(
                        v
                        for k, v in timings.items()
                        if k.endswith("_seconds")
                        and k
                        not in ("training_loop_seconds", "monitoring_eval_seconds", "hook_seconds")
                    ),
                    3,
                )
                if timings
                else NA
            ),
            "model_size_mb": round(mm["size_bytes"] / 1024**2, 3) if mm.get("size_bytes") else NA,
            "model_sha256": mm.get("sha256", NA),
            "dataset_sha256": s.get("dataset_content_sha256") or NA,
            "peak_ram_mb": (s.get("resources") or {}).get("peak_rss_mb", NA),
            "peak_gpu_allocated_mb": (s.get("resources") or {}).get("peak_gpu_allocated_mb", NA),
            "source": rel(r["pkg"] / "run_summary.json"),
        }
        base_rows.append(row)
        if ca is not None:
            P(
                "clean_test_accuracy",
                r["experiment_id"],
                ca,
                "proportion",
                "MEASURED",
                rel(r["pkg"] / "run_summary.json"),
                "clean_test_accuracy / harness_metrics",
                commit=mapped(s.get("git_commit")),
            )
        if timings.get("training_seconds"):
            P(
                "training_time",
                r["experiment_id"],
                timings["training_seconds"],
                "s",
                "MEASURED",
                rel(r["pkg"] / "run_summary.json"),
                "timings.training_seconds",
                commit=mapped(s.get("git_commit")),
            )
    primary = [b for b in base_rows if b["included_in_primary_analysis"] == "YES"]
    for label, rows_ in (("AGGREGATE primary (full protocol)", primary),):
        for metric in ("clean_test_accuracy", "training_duration_s", "model_size_mb"):
            a = agg([x[metric] for x in rows_])
            base_rows.append({"experiment_id": f"{label}: {metric}", **{k: a[k] for k in a}})
    write_csv("clean_baseline_results.csv", base_rows)

    # ---------------------------------------------------------------- PART 4 label flip
    lf_rows = []
    for r in runs:
        if r["attack"] != "LF":
            continue
        ga = r["gt_attack"] or {}
        n_train = r["cfg"]["dataset"].get("train_subset") or 50000
        lf_rows.append(
            {
                "experiment_id": r["experiment_id"],
                "status": r["status"],
                "fidelity": r["fidelity"],
                "pipeline": r["pipeline"],
                "poison_rate": r["poison_rate"],
                "seed": r["seed"],
                "source_class": r["cfg"]["attack"]["source_class"],
                "target_class": r["cfg"]["attack"]["target_class"],
                "number_poisoned": ga.get("number_poisoned", NA),
                "total_training_samples": n_train,
                "actual_poison_percentage": (
                    round(100 * ga["number_poisoned"] / n_train, 3) if ga else NA
                ),
                "attack_behaved_as_intended": (
                    "YES (GT: 250 = 5% of 5,000 subset, all class 1 -> 9)"
                    if ga and ga["number_poisoned"] == round(0.05 * n_train)
                    else NA
                ),
                "clean_accuracy": NA,
                "training_accuracy": NA,
                "training_loss": NA,
                "training_time": NA,
                "model_size": NA,
                "model_hash": NA,
                "source_to_target_error_rate": NA,
                "notes": "run interrupted during training: no model or accuracy exists",
                "source": "ground_truth/ground_truth.sqlite (gt_attacks); " + rel(r["pkg"]),
            }
        )
        if ga:
            P(
                "label_flip_number_poisoned",
                r["experiment_id"],
                ga["number_poisoned"],
                "samples",
                "MEASURED",
                "ground_truth/ground_truth.sqlite",
                "gt_attacks.number_poisoned",
            )
    lf_rows.append(
        {
            "experiment_id": "AGGREGATE (per pipeline x rate)",
            "notes": "NOT AVAILABLE: no completed label-flip run exists (n=0)",
        }
    )
    write_csv("label_flip_results.csv", lf_rows)

    # ---------------------------------------------------------------- PART 5 backdoor
    bd_rows = []
    for r in runs:
        if r["attack"] != "BD":
            continue
        hm = r["summary"].get("harness_metrics") or {}
        t = r["cfg"]["attack"]["trigger"]
        mh = (
            (r["pkg"] / "model_hash.txt").read_text().split()[0]
            if (r["pkg"] / "model_hash.txt").exists()
            else NA
        )
        bd_rows.append(
            {
                "experiment_id": r["experiment_id"],
                "status": r["status"],
                "fidelity": r["fidelity"],
                "included_in_primary_analysis": "NO",
                "pipeline": r["pipeline"],
                "poison_rate": r["poison_rate"],
                "seed": r["seed"],
                "target_class": r["cfg"]["attack"]["target_class"],
                "trigger_type": t["pattern"],
                "trigger_size": f"{t['size']}x{t['size']}",
                "trigger_location": f"{t['position']} (offset {t['offset']})",
                "number_poisoned": (r["gt_attack"] or {}).get("number_poisoned", NA),
                "clean_test_accuracy": hm.get("clean_test_accuracy", NA),
                "attack_success_rate": hm.get("attack_success_rate", NA),
                "asr_percent": (
                    round(100 * hm["attack_success_rate"], 2) if "attack_success_rate" in hm else NA
                ),
                "asr_denominator": "9,000 triggered test images (target class excluded)",
                "training_time_s": r["summary"].get("timings", {}).get("training_seconds", NA),
                "model_size_mb": (
                    round(r["model_meta"]["size_bytes"] / 1024**2, 3)
                    if r["model_meta"].get("size_bytes")
                    else NA
                ),
                "model_hash": mh,
                "source": rel(r["pkg"] / "run_summary.json"),
            }
        )
        for k in ("clean_test_accuracy", "attack_success_rate"):
            if k in hm:
                P(
                    k,
                    r["experiment_id"],
                    hm[k],
                    "proportion",
                    "MEASURED",
                    rel(r["pkg"] / "run_summary.json"),
                    f"harness_metrics.{k}",
                    commit=mapped(r["summary"].get("git_commit")),
                )
    asr = dev["attack_success_rate"]
    bd_rows.append(
        {
            "experiment_id": "attack_sanity_backdoor_S001 (development check)",
            "status": "SUCCESS (development check)",
            "fidelity": "30 epochs, no pipeline",
            "included_in_primary_analysis": "NO (not a pipeline experiment)",
            "pipeline": "none",
            "poison_rate": 0.05,
            "seed": 1,
            "target_class": dev["attack"]["target_class_name"],
            "trigger_type": dev["attack"]["trigger"]["pattern"],
            "trigger_size": f"{dev['attack']['trigger']['size']}x{dev['attack']['trigger']['size']}",
            "trigger_location": f"{dev['attack']['trigger']['position']} (rows "
            f"{dev['attack']['trigger']['rows']}, cols {dev['attack']['trigger']['cols']})",
            "number_poisoned": dev["number_poisoned"],
            "clean_test_accuracy": dev["clean_test_accuracy"],
            "attack_success_rate": asr["asr"],
            "asr_percent": round(100 * asr["asr"], 2),
            "asr_denominator": f"{asr['n']} triggered test images (target class excluded); "
            f"{asr['successes']} predicted as target",
            "training_time_s": dev["training_seconds"],
            "model_size_mb": NA,
            "model_hash": NA,
            "source": "results/pilot/dev_checks/attack_sanity_backdoor_S001.json",
        }
    )
    P(
        "attack_success_rate",
        "attack_sanity_backdoor_S001",
        asr["asr"],
        "proportion",
        "MEASURED",
        "results/pilot/dev_checks/attack_sanity_backdoor_S001.json",
        "attack_success_rate.asr",
        commit=mapped(dev["git_commit"]),
    )
    P(
        "clean_test_accuracy",
        "attack_sanity_backdoor_S001",
        dev["clean_test_accuracy"],
        "proportion",
        "MEASURED",
        "results/pilot/dev_checks/attack_sanity_backdoor_S001.json",
        "clean_test_accuracy",
        commit=mapped(dev["git_commit"]),
    )
    bd_rows.append(
        {
            "experiment_id": "AGGREGATE (per pipeline x rate)",
            "notes": "NOT AVAILABLE: n<=1 per condition; no full-protocol backdoor "
            "pipeline run (A/B/C) exists",
        }
    )
    write_csv("backdoor_results.csv", bd_rows)

    # ---------------------------------------------------------------- PART 6 availability
    c_runs = [r for r in runs if r["evidence_dir"]]
    present: dict[str, set] = {}
    for r in c_runs:
        db = r["evidence_dir"] / "forensic_evidence.sqlite"
        if db.exists():
            con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
            present[r["experiment_id"]] = {
                x[0] for x in con.execute("SELECT DISTINCT event_type FROM forensic_events")
            }
            con.close()
    all_types = set().union(*present.values()) if present else set()
    c_src = "evidence/forensic/RUN-*/forensic_evidence.sqlite (forensic_events)"

    def c_has(*types):
        return "YES" if all(t in all_types for t in types) else "NO"

    items = [
        (
            "dataset identity",
            "PARTIAL (store path in app.log)",
            "YES (MLflow dataset name/source)",
            c_has("DATASET_REGISTERED"),
            "DATASET_REGISTERED.artifact_id",
        ),
        (
            "dataset version",
            "NO",
            "PARTIAL (MLflow digest per input)",
            c_has("DATASET_REGISTERED"),
            "DATASET_REGISTERED / DATASET_VERSION_CREATED",
        ),
        (
            "dataset parent/lineage",
            "NO",
            "PARTIAL (same-source registration run)",
            (
                "YES"
                if "DATASET_VERSION_CREATED" in all_types
                else "PARTIAL (no modified run completed a store with parent link)"
            ),
            "DATASET_VERSION_CREATED.parent_artifact_id",
        ),
        (
            "dataset hash",
            "NO",
            "PARTIAL (32-bit MLflow digest, D-032)",
            c_has("DATASET_REGISTERED"),
            "DATASET_REGISTERED.artifact_hash (SHA-256 manifest)",
        ),
        (
            "poisoned dataset identity",
            "NO",
            "PARTIAL (digest differs; no ID)",
            (
                "YES"
                if "DATASET_VERSION_CREATED" in all_types
                else "NO (not observed in a genuine run)"
            ),
            "DATASET_VERSION_CREATED",
        ),
        (
            "training run ID",
            "NO",
            "YES (MLflow run_id)",
            c_has("TRAINING_STARTED"),
            "TRAINING_STARTED.run_id",
        ),
        (
            "training start timestamp",
            "YES (app.log)",
            "YES (MLflow start_time)",
            c_has("TRAINING_STARTED"),
            "TRAINING_STARTED.timestamp_utc",
        ),
        (
            "training completion timestamp",
            "YES (app.log)",
            "YES (MLflow end_time)",
            c_has("TRAINING_COMPLETED"),
            "TRAINING_COMPLETED.timestamp_utc",
        ),
        (
            "random seed",
            "YES (app.log training line)",
            "YES (MLflow param)",
            "YES",
            "MLflow params / app.log",
        ),
        (
            "hyperparameters",
            "YES (app.log training line)",
            "YES (MLflow params)",
            c_has("TRAINING_STARTED"),
            "TRAINING_STARTED.metadata.hyperparameters",
        ),
        (
            "code/Git version",
            "NO",
            "YES (MLflow tag mlflow.source.git.commit)",
            c_has("EXPERIMENT_STARTED"),
            "EXPERIMENT_STARTED.metadata.git_commit",
        ),
        (
            "model ID",
            "PARTIAL (file path)",
            "YES (registry version)",
            c_has("MODEL_CREATED"),
            "MODEL_CREATED.artifact_id",
        ),
        (
            "model hash",
            "NO (post-hoc only)",
            "NO",
            c_has("MODEL_HASHED"),
            "MODEL_HASHED.artifact_hash",
        ),
        (
            "model-to-training relationship",
            "PARTIAL (log ordering)",
            "YES (model version run_id)",
            c_has("MODEL_HASHED"),
            "MODEL_HASHED.run_id",
        ),
        ("deployment ID", "NO", "NO", c_has("MODEL_DEPLOYED"), "MODEL_DEPLOYED.deployment_id"),
        (
            "deployment timestamp",
            "YES (app.log)",
            "YES (app.log)",
            c_has("MODEL_DEPLOYED"),
            "MODEL_DEPLOYED.timestamp_utc",
        ),
        (
            "model-to-deployment relationship",
            "PARTIAL (copied path in app.log)",
            "YES (registry alias production)",
            c_has("MODEL_DEPLOYED"),
            "MODEL_DEPLOYED.parent_artifact_id / artifact_hash",
        ),
        (
            "inference request ID",
            "YES (app.log)",
            "YES (app.log)",
            c_has("INFERENCE_REQUEST"),
            "INFERENCE_REQUEST.artifact_id",
        ),
        (
            "inference timestamp",
            "YES (app.log)",
            "YES (app.log)",
            c_has("INFERENCE_RESULT"),
            "INFERENCE_RESULT.timestamp_utc",
        ),
        (
            "input hash/identifier",
            "PARTIAL (request ID only)",
            "PARTIAL (request ID only)",
            c_has("INFERENCE_REQUEST"),
            "INFERENCE_REQUEST.artifact_hash",
        ),
        (
            "predicted class",
            "YES (app.log)",
            "YES (app.log)",
            c_has("INFERENCE_RESULT"),
            "INFERENCE_RESULT.metadata.predicted_class",
        ),
        (
            "prediction confidence",
            "NO",
            "NO",
            c_has("INFERENCE_RESULT"),
            "INFERENCE_RESULT.metadata.confidence",
        ),
        (
            "integrity verification",
            "NO",
            "NO",
            c_has("DATASET_INTEGRITY_VERIFIED", "ARTIFACT_INTEGRITY_CHECK"),
            "DATASET_INTEGRITY_VERIFIED / ARTIFACT_INTEGRITY_CHECK",
        ),
        (
            "event relationships",
            "NO",
            "PARTIAL (MLflow lineage)",
            "YES",
            "parent_artifact_id / run_id / deployment_id",
        ),
        (
            "previous event/event chain",
            "NO",
            "NO",
            "YES",
            "previous_event_id / previous_event_hash / event_hash",
        ),
        ("MLflow run", "NO", "YES", "YES", "mlruns/mlflow.db (runs)"),
        ("MLflow artifacts", "NO", "YES", "YES", "mlruns/artifacts/"),
    ]
    write_csv(
        "evidence_availability_matrix.csv",
        [
            {
                "evidence_item": i,
                "conventional_A_design": a,
                "provenance_B_design": b,
                "forensic_C_observed": c,
                "A_observed_in_genuine_run": "NOT AVAILABLE (no genuine pipeline-A evidence directory)",
                "B_observed_in_genuine_run": "NOT AVAILABLE (no pipeline-B run executed)",
                "C_source": f"{c_src}: {src}",
                "A_B_design_source": "src/mlfref/pipeline.py; docs/evidence_schema.md; "
                "tests/test_deployment.py; tests/test_reconstruction.py",
            }
            for i, a, b, c, src in items
        ],
    )

    # ---------------------------------------------------------------- PART 7-11 per-run metrics
    def eval_rows(kind):
        out = []
        for r in runs:
            ev, rc = r["evaluation"], r["reconstruction"]
            base = {
                "experiment_id": r["experiment_id"],
                "phase": r["phase"],
                "fidelity": r["fidelity"],
                "pipeline": r["pipeline"],
                "attack": r["attack"],
                "poison_rate": r["poison_rate"],
                "seed": r["seed"],
            }
            if ev is None:
                reason = (
                    "no incident observed (attack not learned after 1 epoch; "
                    "reconstruction correctly skipped)"
                    if r["summary"].get("incident") is False
                    else (
                        "run did not reach reconstruction"
                        if r["phase"] == "pilot_cpu"
                        else "run predates the pipeline runner (clean-baseline script; no "
                        "evidence store, ground truth or reconstruction)"
                    )
                )
                out.append({**base, "status": NA, "reason": reason})
                continue
            src = rel(r["pkg"] / "evaluation.json")
            if kind == "ec":
                e = ev["evidence_completeness"]
                app = [i for i in e["items"] if i["applicable"]]
                out.append(
                    {
                        **base,
                        "status": "MEASURED",
                        "required_items": e["applicable"],
                        "recovered_items": e["recovered"],
                        "missing_items": ";".join(i["id"] for i in app if not i["recovered"])
                        or "none",
                        "not_applicable_items": ";".join(
                            i["id"] for i in e["items"] if not i["applicable"]
                        ),
                        "evidence_completeness_percent": round(100 * e["ec"], 2),
                        "source": src,
                    }
                )
                P(
                    "evidence_completeness",
                    r["experiment_id"],
                    round(100 * e["ec"], 2),
                    "%",
                    "MEASURED",
                    src,
                    "evidence_completeness.ec",
                    "recovered applicable items / applicable items x 100",
                    mapped(r["summary"].get("git_commit")),
                )
            elif kind == "err":
                er = ev["event_recovery"]
                out.append(
                    {
                        **base,
                        "status": "MEASURED",
                        "ground_truth_events": er["required"],
                        "correctly_recovered_events": er["recovered"],
                        "missed_events": ";".join(
                            m["gt_action"] for m in er["matches"] if not m["recovered"]
                        )
                        or "none",
                        "incorrectly_inferred_events": "NOT MEASURED by implementation",
                        "event_recovery_rate": er["err"],
                        "source": src,
                    }
                )
                P(
                    "event_recovery_rate",
                    r["experiment_id"],
                    er["err"],
                    "proportion",
                    "MEASURED",
                    src,
                    "event_recovery.err",
                    "recovered required GT events / required GT events",
                    mapped(r["summary"].get("git_commit")),
                )
            elif kind == "tl":
                t = ev["timeline"]
                n = t["n_ordered_events"]
                out.append(
                    {
                        **base,
                        "status": "MEASURED",
                        "number_ground_truth_events": ev["event_recovery"]["required"],
                        "number_recovered_events": n,
                        "number_correctly_ordered_pairs": round(
                            t["pairwise_order_accuracy"] * math.comb(n, 2)
                        ),
                        "total_pairs": math.comb(n, 2),
                        "pairwise_order_accuracy": t["pairwise_order_accuracy"],
                        "timeline_coverage": t["coverage"],
                        "kendall_tau_b": t["kendall_tau_b"],
                        "kendall_p_value": t["kendall_p_value"],
                        "source": src,
                    }
                )
                P(
                    "timeline_kendall_tau_b",
                    r["experiment_id"],
                    t["kendall_tau_b"],
                    "tau",
                    "MEASURED",
                    src,
                    "timeline.kendall_tau_b",
                    "scipy.stats.kendalltau(GT order, reconstructed order, variant='b')",
                    mapped(r["summary"].get("git_commit")),
                )
            elif kind == "rc":
                cc = ev.get("clean_control") or {}
                h = rc["hops"]
                out.append(
                    {
                        **base,
                        "status": "NOT APPLICABLE (clean control)",
                        "implemented_score": NAPP,
                        "dataset_identified": NAPP,
                        "training_run_identified": NAPP,
                        "model_identified": NAPP,
                        "deployment_identified": NAPP,
                        "poisoning_source_identified": NAPP,
                        "attack_type_identified": NAPP,
                        "clean_control_finding": cc.get("finding"),
                        "clean_control_correct": cc.get("correct"),
                        "false_attribution": cc.get("false_attribution"),
                        "hop_confidences": ";".join(f"{k}={v['confidence']}" for k, v in h.items()),
                        "source": src,
                    }
                )
                P(
                    "clean_control_correct",
                    r["experiment_id"],
                    cc.get("correct"),
                    "boolean",
                    "MEASURED",
                    src,
                    "clean_control.correct",
                )
            elif kind == "rt":
                out.append(
                    {
                        **base,
                        "status": "MEASURED",
                        "reconstruction_start": NA,
                        "reconstruction_end": NA,
                        "reconstruction_time_seconds": rc["runtime_seconds"],
                        "note": "engine records elapsed time only (time.perf_counter), not "
                        "start/end wall-clock timestamps",
                        "source": rel(r["pkg"] / "reconstruction.json"),
                    }
                )
                P(
                    "reconstruction_time",
                    r["experiment_id"],
                    rc["runtime_seconds"],
                    "s",
                    "MEASURED",
                    rel(r["pkg"] / "reconstruction.json"),
                    "runtime_seconds",
                    commit=mapped(r["summary"].get("git_commit")),
                )
        return out

    agg_note = (
        "AGGREGATE A/B/C: NOT AVAILABLE. Only one evaluated run exists (pipeline C, "
        "clean control, 1-epoch smoke check); no A or B run was evaluated; n<2."
    )
    for name, kind in (
        ("evidence_completeness.csv", "ec"),
        ("event_recovery.csv", "err"),
        ("timeline_reconstruction.csv", "tl"),
        ("root_cause_identification.csv", "rc"),
        ("reconstruction_time.csv", "rt"),
    ):
        rows_ = eval_rows(kind)
        rows_.append({"experiment_id": "AGGREGATE", "status": agg_note})
        write_csv(name, rows_)

    # ---------------------------------------------------------------- PART 12 storage
    con = sqlite3.connect(ROOT / "mlruns" / "mlflow.db")
    run_refs = {
        rid: ref for rid, ref in con.execute("SELECT run_uuid, value FROM tags WHERE key='run_ref'")
    }
    mv = list(con.execute("SELECT version, run_id, source FROM model_versions"))
    con.close()
    model_art = {}
    for version, run_id, _source in mv:
        ref = run_refs.get(run_id)
        path = None
        for cand in (ROOT / "mlruns" / "artifacts" / "models").glob("*"):
            if cand.is_dir() and any(cand.rglob("MLmodel")):
                meta = cand / "meta.yaml"
                if meta.exists() and run_id in meta.read_text(encoding="utf-8"):
                    path = cand
        size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) if path else None
        model_art[ref] = (version, size, rel(path) if path else NA)
    st_rows = []
    for r in runs:
        sb = r["summary"].get("storage_bytes")
        if not sb:
            st_rows.append(
                {
                    "experiment_id": r["experiment_id"],
                    "pipeline": r["pipeline"],
                    "phase": r["phase"],
                    "status": NA,
                    "reason": "storage not measured (baseline script or interrupted run)",
                }
            )
            continue
        ma = model_art.get(f"RUN-{r['uuid']}", (None, None, NA))
        mlflow_model_mb = ma[1] / 1024**2 if ma[1] else None
        evidence_mb = sum(v for k, v in sb.items() if k != "model_files") / 1024**2
        st_rows.append(
            {
                "experiment_id": r["experiment_id"],
                "pipeline": r["pipeline"],
                "phase": r["phase"],
                "status": "MEASURED (+ CALCULATED MLflow model size)",
                "normal_logs_mb": round(sb.get("logs", 0) / 1024**2, 4),
                "forensic_sqlite_mb": round(sb.get("forensic_sqlite", 0) / 1024**2, 4),
                "json_jsonl_evidence_mb": round(sb.get("forensic_jsonl", 0) / 1024**2, 4),
                "manifests_mb": round(sb.get("manifests", 0) / 1024**2, 4),
                "other_evidence_mb": round(sb.get("other_evidence", 0) / 1024**2, 4),
                "mlflow_run_artifacts_mb": round(sb.get("mlflow_artifacts", 0) / 1024**2, 4),
                "mlflow_logged_model_mb": round(mlflow_model_mb, 3) if mlflow_model_mb else NA,
                "mlflow_metadata_db_mb": "NOT AVAILABLE per run (shared mlflow.db)",
                "integrity_records_mb": "included in forensic_sqlite",
                "evidence_total_mb_excl_mlflow_model": round(evidence_mb, 3),
                "evidence_total_mb_incl_mlflow_model": (
                    round(evidence_mb + (mlflow_model_mb or 0), 3) if mlflow_model_mb else NA
                ),
                "storage_overhead_vs_A_percent": "NOT AVAILABLE (no pipeline-A evidence measured)",
                "source": rel(r["pkg"] / "run_summary.json") + "; " + ma[2],
            }
        )
        P(
            "evidence_storage",
            r["experiment_id"],
            round(evidence_mb, 3),
            "MB",
            "MEASURED",
            rel(r["pkg"] / "run_summary.json"),
            "storage_bytes (excluding model_files)",
            commit=mapped(r["summary"].get("git_commit")),
        )
    st_rows.append(
        {
            "experiment_id": "NOTE",
            "status": "Storage overhead (%) vs A cannot be computed: no genuine pipeline-A or B run "
            "measured evidence storage. Measured values are pipeline C, 1-epoch smoke checks.",
        }
    )
    write_csv("storage_overhead.csv", st_rows)

    # ---------------------------------------------------------------- PART 13 computational
    smokeA = next(
        r for r in runs if r["phase"] == "smoke" and r["experiment_id"] == "EXP-CLEAN-A-00-S001"
    )
    smokeC = next(
        r for r in runs if r["phase"] == "smoke" and r["experiment_id"] == "EXP-CLEAN-C-00-S001"
    )
    ta, tc = (
        smokeA["summary"]["timings"]["training_seconds"],
        smokeC["summary"]["timings"]["training_seconds"],
    )
    comp = [
        {
            "comparison": "C vs A (clean, seed 1, 1-epoch smoke checks)",
            "status": "CALCULATED",
            "T_A_training_s": ta,
            "T_C_training_s": tc,
            "absolute_difference_s": round(tc - ta, 3),
            "runtime_overhead_percent": round((tc - ta) / ta * 100, 2),
            "evidence_logging_time_C_s": smokeC["summary"].get("evidence_logging_seconds"),
            "inference_time_C_s": smokeC["summary"]["timings"].get("inference_seconds"),
            "inference_time_A_s": NA,
            "peak_ram_A_mb": smokeA["summary"]["resources"]["peak_rss_mb"],
            "peak_ram_C_mb": smokeC["summary"]["resources"]["peak_rss_mb"],
            "peak_gpu_A_mb": smokeA["summary"]["resources"]["peak_gpu_allocated_mb"],
            "peak_gpu_C_mb": smokeC["summary"]["resources"]["peak_gpu_allocated_mb"],
            "mean_cpu_A_percent": smokeA["summary"]["resources"]["mean_cpu_percent"],
            "mean_cpu_C_percent": smokeC["summary"]["resources"]["mean_cpu_percent"],
            "validity_warning": "NOT A VALID OVERHEAD ESTIMATE: n=1 each; 1 epoch; A run used the "
            "clean-baseline script, C the pipeline runner (different code "
            "versions); C's training stage includes MLflow dataset logging and "
            "forensic hooks; single run, no repeated measures",
            "source": f"{rel(smokeA['pkg'] / 'run_summary.json')}; "
            f"{rel(smokeC['pkg'] / 'run_summary.json')}",
            "formula": "(T_C - T_A) / T_A x 100",
        },
        {"comparison": "B vs A", "status": NA, "validity_warning": "no pipeline-B run exists"},
        {
            "comparison": "full protocol (30 epochs) A/B/C",
            "status": NA,
            "validity_warning": "only pipeline A has a 30-epoch run (EXP-CLEAN-A-00-S001, "
            "693.861 s); no 30-epoch B or C run exists",
        },
    ]
    P(
        "runtime_overhead_C_vs_A_smoke",
        "EXP-CLEAN-C-00-S001 vs EXP-CLEAN-A-00-S001 (smoke)",
        comp[0]["runtime_overhead_percent"],
        "%",
        "CALCULATED",
        comp[0]["source"],
        "timings.training_seconds",
        "(T_C - T_A) / T_A x 100",
    )
    write_csv("computational_overhead.csv", comp)

    # ---------------------------------------------------------------- PART 15 statistics
    stat_rows = [
        {
            "metric": m,
            "test": "INSUFFICIENT SAMPLE SIZE FOR RELIABLE INFERENTIAL TEST",
            "n": n,
            "design": "paired/repeated-measures (blocks = attack x rate x seed) by "
            "design; no complete A/B/C block exists",
            "test_statistic": NA,
            "df": NA,
            "p_value": NA,
            "effect_size": NA,
            "ci_95": NA,
        }
        for m, n in (
            ("Evidence Completeness", "A=0, B=0, C=1"),
            ("Event Recovery Rate", "A=0, B=0, C=1"),
            ("Timeline Accuracy", "A=0, B=0, C=1"),
            ("Root Cause Identification", "A=0, B=0, C=0 (clean only)"),
            ("Reconstruction Time", "A=0, B=0, C=1"),
            ("Storage", "A=0, B=0, C=2 (smoke)"),
            ("Runtime", "A=1 full + 1 smoke, B=0, C=2 smoke"),
        )
    ]
    write_csv("statistical_tests.csv", stat_rows)

    # ---------------------------------------------------------------- PART 19 master table
    master = []
    for r in runs:
        s, ev, rc = r["summary"], r["evaluation"], r["reconstruction"]
        hm = s.get("harness_metrics") or {}
        sb = s.get("storage_bytes")
        master.append(
            {
                "experiment_id": r["experiment_id"],
                "experiment_uuid": r["uuid"],
                "phase": r["phase"],
                "pipeline": r["pipeline"],
                "attack": r["attack"],
                "poison_rate": r["poison_rate"],
                "seed": r["seed"],
                "epochs": r["epochs"],
                "clean_accuracy": s.get("clean_test_accuracy") or hm.get("clean_test_accuracy"),
                "attack_success_rate": hm.get("attack_success_rate"),
                "evidence_completeness": ev["evidence_completeness"]["ec"] if ev else None,
                "event_recovery_rate": ev["event_recovery"]["err"] if ev else None,
                "timeline_accuracy_kendall_tau_b": ev["timeline"]["kendall_tau_b"] if ev else None,
                "timeline_pairwise_order_accuracy": (
                    ev["timeline"]["pairwise_order_accuracy"] if ev else None
                ),
                "root_cause_score": (ev.get("root_cause") or {}).get("rci_score") if ev else None,
                "reconstruction_time_sec": rc["runtime_seconds"] if rc else None,
                "training_time_sec": (s.get("timings") or {}).get("training_seconds"),
                "total_runtime_sec": next(
                    (
                        b["total_runtime_s"]
                        for b in base_rows
                        if b.get("experiment_id") == r["experiment_id"]
                        and b.get("phase") == r["phase"]
                    ),
                    None,
                ),
                "evidence_storage_mb": (
                    round(sum(v for k, v in sb.items() if k != "model_files") / 1024**2, 3)
                    if sb
                    else None
                ),
                "runtime_overhead_percent": None,
                "storage_overhead_percent": None,
                "peak_ram_mb": (s.get("resources") or {}).get("peak_rss_mb"),
                "peak_gpu_memory_mb": (s.get("resources") or {}).get("peak_gpu_allocated_mb"),
                "status": r["status"],
                "included_in_primary_analysis": (
                    "YES" if r["included_in_primary_analysis"] else "NO"
                ),
                "notes": r["fidelity"]
                + ("; clean control, RCI not applicable" if r["attack"] == "CLEAN" and ev else "")
                + (
                    "; no incident observed, reconstruction skipped"
                    if s.get("incident") is False
                    else ""
                ),
            }
        )
    master.append(
        {
            "experiment_id": "attack_sanity_backdoor_S001",
            "phase": "dev_check",
            "pipeline": "none",
            "attack": "BD",
            "poison_rate": 0.05,
            "seed": 1,
            "epochs": dev["epochs"],
            "clean_accuracy": dev["clean_test_accuracy"],
            "attack_success_rate": asr["asr"],
            "training_time_sec": dev["training_seconds"],
            "status": "SUCCESS (development check)",
            "included_in_primary_analysis": "NO",
            "notes": "trained without pipeline instrumentation; no evidence/GT",
        }
    )
    write_csv("master_experimental_results.csv", master)

    # ---------------------------------------------------------------- PART 20 pipeline summary
    def M(phase, exp):  # master row lookup: every summary value comes from computed rows
        return next(x for x in master if x.get("phase") == phase and x["experiment_id"] == exp)

    pa, sa = M("pilot", "EXP-CLEAN-A-00-S001"), M("smoke", "EXP-CLEAN-A-00-S001")
    sc, sb_ = M("smoke", "EXP-CLEAN-C-00-S001"), M("smoke", "EXP-BD-C-05-S001")
    dv = M("dev_check", "attack_sanity_backdoor_S001")
    summary = [
        ("Clean Accuracy (full protocol, 30 epochs)", f"{pa['clean_accuracy']:.4f} (n=1)", NA, NA),
        (
            "Clean Accuracy (1-epoch smoke, clean)",
            f"{sa['clean_accuracy']:.4f} (n=1, smoke)",
            NA,
            f"{sc['clean_accuracy']:.4f} (n=1, smoke)",
        ),
        (
            "Attack Success Rate",
            NA,
            NA,
            f"{sb_['attack_success_rate']:.4f} (n=1, 1-epoch smoke, BD 5%); dev check without "
            f"pipeline: {dv['attack_success_rate']:.4f}",
        ),
        (
            "Evidence Completeness",
            NA,
            NA,
            f"{sc['evidence_completeness'] * 100:.1f}% (n=1, clean control, smoke)",
        ),
        ("Event Recovery Rate", NA, NA, f"{sc['event_recovery_rate']:.3f} (n=1, clean, smoke)"),
        (
            "Timeline Accuracy (Kendall tau-b)",
            NA,
            NA,
            f"{sc['timeline_accuracy_kendall_tau_b']:.3f} (n=1, 5 events, smoke)",
        ),
        (
            "Root Cause Identification",
            NA,
            NA,
            "NOT APPLICABLE for the only evaluated run (clean control; finding correct)",
        ),
        ("Reconstruction Time (s)", NA, NA, f"{sc['reconstruction_time_sec']:.3f} (n=1, smoke)"),
        (
            "Evidence Storage (MB, excl. MLflow logged model)",
            NA,
            NA,
            f"{sc['evidence_storage_mb']} (clean smoke); {sb_['evidence_storage_mb']} (BD smoke)",
        ),
        ("Storage Overhead (%)", NA, NA, "NOT AVAILABLE (no A baseline storage)"),
        (
            "Training Runtime (s)",
            f"{pa['training_time_sec']} (30 epochs, n=1); "
            f"{sa['training_time_sec']} (1-epoch smoke)",
            NA,
            f"{sc['training_time_sec']} (clean smoke); {sb_['training_time_sec']} (BD smoke)",
        ),
        (
            "Runtime Overhead (%)",
            "reference",
            NA,
            f"{comp[0]['runtime_overhead_percent']}% (smoke, NOT a valid estimate)",
        ),
    ]
    write_csv(
        "pipeline_summary.csv",
        [
            {"metric": m, "conventional_A": a, "provenance_B": bb, "forensic_C": c}
            for m, a, bb, c in summary
        ],
    )

    write_csv("results_provenance.csv", prov)
    print(f"audit complete: {len(runs)} pipeline packages + 1 dev check; outputs in " f"{rel(OUT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
