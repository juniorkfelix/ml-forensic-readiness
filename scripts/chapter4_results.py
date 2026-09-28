"""Chapter 4 results package from the GENUINE pilot runs (Phase 16 data).

Inputs (all genuine): results/raw/run_index.csv, results/raw/failed_runs.csv,
experiments/pilot/pipeline_runs/*/ (run_summary, evaluation, reconstruction, training
metrics, model hash), ground_truth/ground_truth.sqlite, evidence stores, MLflow store,
environment manifests. The synthetic set is never read. Existing outputs are not
overwritten; the pre-pilot audit is preserved in results/chapter4_pre_pilot_audit/.

Usage: python scripts/chapter4_results.py
"""

from __future__ import annotations

import csv
import json
import math
import sqlite3
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from mlfref.evaluation.statistics import compare_pipelines, describe  # noqa: E402
from mlfref.reporting.metadata import record_output_metadata  # noqa: E402
from mlfref.reporting.plots import (  # noqa: E402
    CATEGORICAL,
    PIPELINE_COLORS,
    PIPELINE_LABELS,
    apply_style,
    save_figure,
)

OUT = ROOT / "results" / "chapter4"
FIGS = OUT / "figures"
NA, NAPP = "NOT AVAILABLE", "NOT APPLICABLE"
SCRIPT = "scripts/chapter4_results.py"
PIPES = ("A", "B", "C")
CODE = {"conventional": "A", "provenance": "B", "forensic": "C"}
ATT = {"none": "CLEAN", "label_flip": "LF", "backdoor": "BD"}


def rel(p) -> str:
    return Path(p).resolve().relative_to(ROOT).as_posix()


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


def fmt(v, nd=3):
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return NA
    return f"{v:.{nd}f}"


def stats_row(values, **extra):
    d = describe([v for v in values if v is not None])
    return {
        **extra,
        "n": d["n"],
        "mean": d["mean"],
        "median": d["median"],
        "sd": d["sd"],
        "min": d["min"],
        "max": d["max"],
        "ci95_low": d["ci_low"],
        "ci95_high": d["ci_high"],
        "ci_method": d["ci_method"],
    }


def git(*args) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()


# ------------------------------------------------------------------------------ load
def load_runs() -> list[dict]:
    index = list(csv.DictReader((ROOT / "results/raw/run_index.csv").open(encoding="utf-8")))
    latest: dict[str, dict] = {}
    for r in index:  # a retry supersedes earlier attempts of the same experiment ID
        if r["phase"] == "pilot" and r["status"] == "completed":
            latest[r["experiment_id"]] = r
    runs = []
    for exp, r in sorted(latest.items()):
        pkg = ROOT / r["package_dir"]
        summ = jload(pkg / "run_summary.json")
        runs.append(
            {
                "id": exp,
                "uuid": r["experiment_uuid"],
                "row": r,
                "pkg": pkg,
                "summary": summ,
                "pipeline": CODE[summ["pipeline"]],
                "attack": ATT[summ["attack_type"]],
                "attack_type": summ["attack_type"],
                "rate": float(summ["poison_rate"]),
                "seed": int(summ["seed"]),
                "eval": jload(pkg / "evaluation.json"),
                "recon": jload(pkg / "reconstruction.json"),
                "tm": list(csv.DictReader((pkg / "training_metrics.csv").open(encoding="utf-8"))),
                "model_hash": (pkg / "model_hash.txt").read_text().split()[0],
                "model_meta": jload(pkg / "model_metadata.json"),
                "evidence_dir": ROOT / r["evidence_dir"],
                "commit": summ.get("git_commit"),
            }
        )
    return runs


def gt_events(uuid: str) -> list[dict]:
    c = sqlite3.connect(ROOT / "ground_truth/ground_truth.sqlite")
    c.row_factory = sqlite3.Row
    out = [
        dict(r)
        for r in c.execute(
            "SELECT * FROM gt_events WHERE experiment_uuid=? ORDER BY sequence_number", (uuid,)
        )
    ]
    c.close()
    return out


def gt_attack(uuid: str) -> dict | None:
    c = sqlite3.connect(ROOT / "ground_truth/ground_truth.sqlite")
    c.row_factory = sqlite3.Row
    r = c.execute("SELECT * FROM gt_attacks WHERE experiment_uuid=?", (uuid,)).fetchone()
    c.close()
    return dict(r) if r else None


def epoch_power_state(tm: list[dict]) -> tuple[float, str]:
    """Median per-epoch training time (epochs 2..30) and inferred GPU power state."""
    t = sorted(float(x["epoch_train_seconds"]) for x in tm[1:])
    med = t[len(t) // 2]
    return med, ("reduced-power" if med > 27 else "full-power")


# ------------------------------------------------------------------------------ main
def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    FIGS.mkdir(parents=True, exist_ok=True)
    runs = load_runs()
    failed = (
        list(csv.DictReader((ROOT / "results/raw/failed_runs.csv").open(encoding="utf-8")))
        if (ROOT / "results/raw/failed_runs.csv").exists()
        else []
    )
    head = git("rev-parse", "--short", "HEAD")
    prov: list[dict] = []

    def P(metric, exp, value, unit, status, src, field, formula=""):
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
                "git_commit": runs[0]["commit"][:7],
            }
        )

    for r in runs:
        r["gt"] = gt_events(r["uuid"])
        r["gta"] = gt_attack(r["uuid"])
        r["epoch_median_s"], r["power_state"] = epoch_power_state(r["tm"])

    # ------------------------------------------------------------------ PART 1 inventory
    inv = []
    for r in runs:
        s = r["summary"]
        inv.append(
            {
                "experiment_id": r["id"],
                "experiment_uuid": r["uuid"],
                "pipeline": r["pipeline"],
                "attack": r["attack"],
                "poison_rate": r["rate"],
                "seed": r["seed"],
                "status": "SUCCESS",
                "start_time": r["gt"][0]["timestamp_utc"] if r["gt"] else NA,
                "end_time": r["row"]["completed_utc"],
                "model": "ResNet-18 (CIFAR stem), 30 epochs",
                "dataset": "CIFAR-10 train 50,000 / test 10,000",
                "results_available": "YES",
                "ground_truth_available": "YES" if r["gt"] else "NO",
                "evidence_available": "YES" if r["evidence_dir"].exists() else "NO",
                "reconstruction_available": "YES" if r["recon"] else "NO",
                "retry": (
                    "YES (after failed attempt)"
                    if any(f["experiment_id"] == r["id"] for f in failed)
                    else "NO"
                ),
                "gpu_power_state": r["power_state"],
                "median_epoch_s": r["epoch_median_s"],
                "git_commit": s["git_commit"][:7],
                "package": rel(r["pkg"]),
            }
        )
    for f in failed:
        inv.append(
            {
                "experiment_id": f["experiment_id"],
                "experiment_uuid": f["experiment_uuid"],
                "status": f"FAILED at stage '{f['failure_stage']}' ({f['exception_type']})",
                "results_available": "NO",
                "retry": (
                    "retried; retry completed"
                    if any(r["id"] == f["experiment_id"] for r in runs)
                    else "not retried"
                ),
                "package": "experiments/pilot/pipeline_runs/_superseded/",
            }
        )
    write_csv("experiment_inventory.csv", inv)

    # ------------------------------------------------------------------ PART 2 environment
    env = jload(runs[0]["pkg"] / "environment.json")
    lock = dict(
        ln.split("==", 1)
        for ln in (ROOT / "requirements-lock.txt").read_text(encoding="utf-8").splitlines()
        if "==" in ln
    )
    clean_ver = jload(ROOT / "data/manifests/CIFAR10-CLEAN-V1.version.json")
    src_env = rel(runs[0]["pkg"] / "environment.json")
    envrows = [
        (
            "Operating system",
            f"{env['os']['system']} {env['os']['release']} ({env['os']['version']})",
        ),
        ("Python", env["software"]["python"]),
        ("PyTorch", env["software"]["torch"]),
        ("torchvision", env["software"]["torchvision"]),
        ("CUDA (PyTorch build)", env["software"]["cuda_build"]),
        ("cuDNN", env["software"]["cudnn"]),
        ("GPU", env["hardware"]["gpu"]["name"]),
        ("GPU memory (MB)", env["hardware"]["gpu"]["total_memory_mb"]),
        ("CPU", env["hardware"]["cpu"]),
        (
            "CPU cores (physical/logical)",
            f"{env['hardware']['cpu_physical_cores']}/" f"{env['hardware']['cpu_logical_cores']}",
        ),
        ("System RAM (GB)", env["hardware"]["ram_total_gb"]),
        ("MLflow", lock.get("mlflow")),
        ("NumPy", env["software"]["numpy"]),
        ("pandas", lock.get("pandas")),
        ("scikit-learn", lock.get("scikit-learn")),
        ("SciPy", lock.get("scipy")),
        ("Git commit of all pilot runs", ", ".join(sorted({r["commit"][:7] for r in runs}))),
        ("Git branch", env["git"]["branch"]),
        ("Git working tree clean at run start", str(not env["git"]["dirty"])),
        (
            "Config SHA-256 (EXP-BD-C-05-S001)",
            next(x for x in runs if x["id"] == "EXP-BD-C-05-S001")["summary"]["config_sha256"],
        ),
        ("Clean dataset manifest SHA-256 (CIFAR10-CLEAN-V1)", clean_ver["manifest_sha256"]),
        ("Evaluation schema", "FROZEN; freeze commit 96a509d (recorded as 9bccbc0 pre-rewrite)"),
        ("Repository HEAD at analysis", head),
    ]
    write_csv(
        "experimental_environment.csv",
        [
            {
                "item": k,
                "value": v,
                "status": "MEASURED",
                "source_file": (
                    "requirements-lock.txt"
                    if k in ("MLflow", "pandas", "scikit-learn", "SciPy")
                    else src_env
                ),
            }
            for k, v in envrows
        ],
    )

    # ------------------------------------------------------------------ PART 3 clean
    def training_row(r):
        last = r["tm"][-1]
        t = r["summary"]["timings"]
        return {
            "final_training_loss": float(last["train_loss"]),
            "final_training_accuracy": float(last["train_accuracy"]),
            "training_duration_s": t["training_seconds"],
            "evaluation_duration_s": t["evaluation_seconds"],
            "total_runtime_s": round(sum(v for k, v in t.items()), 3),
            "model_size_mb": round(r["model_meta"]["size_bytes"] / 1024**2, 3),
            "model_sha256": r["model_hash"],
            "peak_ram_mb": r["summary"]["resources"]["peak_rss_mb"],
            "peak_gpu_mb": r["summary"]["resources"]["peak_gpu_allocated_mb"],
            "gpu_power_state": r["power_state"],
        }

    cfg = lambda r: (ROOT / r["row"]["package_dir"] / "config.yaml")  # noqa: E731
    clean = [r for r in runs if r["attack"] == "CLEAN"]
    rows = []
    for r in clean:
        rows.append(
            {
                "experiment_id": r["id"],
                "seed": r["seed"],
                "pipeline": r["pipeline"],
                "epochs": 30,
                "batch_size": 128,
                "learning_rate": 0.1,
                "optimizer": "sgd",
                "clean_test_accuracy": r["summary"]["harness_metrics"]["clean_test_accuracy"],
                **training_row(r),
                "dataset_sha256": r["gt"][0]["result_artifact"],
                "source": rel(r["pkg"] / "run_summary.json"),
            }
        )
        P(
            "clean_test_accuracy",
            r["id"],
            rows[-1]["clean_test_accuracy"],
            "proportion",
            "MEASURED",
            rel(r["pkg"] / "run_summary.json"),
            "harness_metrics.clean_test_accuracy",
        )
    for m in ("clean_test_accuracy", "training_duration_s", "model_size_mb"):
        for p in PIPES:
            rows.append(
                stats_row(
                    [x[m] for x in rows if x.get("pipeline") == p and "seed" in x],
                    experiment_id=f"AGGREGATE {p}",
                    metric=m,
                )
            )
        rows.append(
            stats_row(
                [
                    x[m]
                    for x in rows
                    if "seed" in x and x.get("experiment_id", "").startswith("EXP")
                ],
                experiment_id="AGGREGATE all",
                metric=m,
            )
        )
    write_csv("clean_baseline_results.csv", rows)

    # ------------------------------------------------------------------ PART 4 label flip
    lf = [r for r in runs if r["attack"] == "LF"]
    rows = []
    for r in lf:
        ga = r["gta"]
        s2t = r["summary"]["harness_metrics"].get("source_to_target_rate")
        rows.append(
            {
                "experiment_id": r["id"],
                "pipeline": r["pipeline"],
                "poison_rate": r["rate"],
                "seed": r["seed"],
                "source_class": "automobile (1)",
                "target_class": "truck (9)",
                "number_poisoned": ga["number_poisoned"],
                "total_training_samples": 50000,
                "actual_poison_percentage": 100 * ga["number_poisoned"] / 50000,
                "attack_as_intended": (
                    "YES"
                    if ga["number_poisoned"] == 2500
                    and set(json.loads(ga["original_labels"])) == {1}
                    and set(json.loads(ga["new_labels"])) == {9}
                    else "NO"
                ),
                "clean_accuracy": r["summary"]["harness_metrics"]["clean_test_accuracy"],
                "automobile_to_truck_error_rate": s2t,
                **training_row(r),
                "source": rel(r["pkg"] / "run_summary.json"),
            }
        )
        P(
            "source_to_target_rate",
            r["id"],
            s2t,
            "proportion",
            "MEASURED",
            rel(r["pkg"] / "run_summary.json"),
            "harness_metrics.source_to_target_rate",
        )
    for p in PIPES:
        sub = [x for x in rows if x.get("pipeline") == p]
        rows.append(
            stats_row(
                [x["clean_accuracy"] for x in sub],
                experiment_id=f"AGGREGATE {p}",
                poison_rate=0.05,
                metric="clean_accuracy",
            )
        )
        rows.append(
            stats_row(
                [x["automobile_to_truck_error_rate"] for x in sub],
                experiment_id=f"AGGREGATE {p}",
                poison_rate=0.05,
                metric="automobile_to_truck_error_rate",
            )
        )
    write_csv("label_flip_results.csv", rows)

    # ------------------------------------------------------------------ PART 5 backdoor
    bd = [r for r in runs if r["attack"] == "BD"]
    rows = []
    for r in bd:
        ga = r["gta"]
        trig = json.loads(ga["trigger_json"])
        asr = r["summary"]["harness_metrics"]["attack_success_rate"]
        rows.append(
            {
                "experiment_id": r["id"],
                "pipeline": r["pipeline"],
                "poison_rate": r["rate"],
                "seed": r["seed"],
                "target_class": "airplane (0)",
                "trigger_type": trig["pattern"],
                "trigger_size": f"{trig['size']}x{trig['size']}",
                "trigger_location": f"{trig['position']} rows {trig['rows']} cols {trig['cols']}",
                "number_poisoned": ga["number_poisoned"],
                "clean_test_accuracy": r["summary"]["harness_metrics"]["clean_test_accuracy"],
                "attack_success_rate": asr,
                "asr_percent": 100 * asr,
                "asr_denominator": "9,000 triggered test images (true class != airplane)",
                **training_row(r),
                "source": rel(r["pkg"] / "run_summary.json"),
            }
        )
        P(
            "attack_success_rate",
            r["id"],
            asr,
            "proportion",
            "MEASURED",
            rel(r["pkg"] / "run_summary.json"),
            "harness_metrics.attack_success_rate",
            "triggered non-target test images predicted as target / 9,000",
        )
    for p in PIPES:
        sub = [x for x in rows if x.get("pipeline") == p]
        for m in ("clean_test_accuracy", "attack_success_rate"):
            rows.append(
                stats_row(
                    [x[m] for x in sub], experiment_id=f"AGGREGATE {p}", poison_rate=0.05, metric=m
                )
            )
    write_csv("backdoor_results.csv", rows)

    # ------------------------------------------------------------------ PART 6 availability
    item_ids = [i["id"] for i in runs[0]["eval"]["evidence_completeness"]["items"]]
    rec = defaultdict(lambda: defaultdict(list))
    for r in runs:
        for i in r["eval"]["evidence_completeness"]["items"]:
            if i["applicable"]:
                rec[i["id"]][r["pipeline"]].append(bool(i["recovered"]))

    def yn(vals):
        if not vals:
            return NAPP
        return "YES" if all(vals) else "NO" if not any(vals) else "PARTIAL"

    from mlfref.evaluation.common import load_schema

    schema = load_schema()
    desc = {x["id"]: x["description"] for x in schema["required_evidence_items"]}
    avail = [
        {
            "evidence_item": f"{i}: {desc[i]}",
            **{f"{p}": yn(rec[i][p]) for p in PIPES},
            "basis": "recovered-and-correct in evaluation.json of all pilot runs (18 runs); "
            "PARTIAL = recovered in some runs only",
            "source": "experiments/pilot/pipeline_runs/*/evaluation.json "
            "(evidence_completeness.items)",
        }
        for i in item_ids
    ]

    # Additional raw evidence items checked directly in the evidence stores
    def has_file(p, name):
        return all((r["evidence_dir"] / name).exists() for r in runs if r["pipeline"] == p)

    for label, name in (
        ("application log (app.log)", "app.log"),
        ("artefact listing (artifacts.json)", "artifacts.json"),
        ("MLflow reference (mlflow_ref.json)", "mlflow_ref.json"),
        ("forensic event store (forensic_evidence.sqlite)", "forensic_evidence.sqlite"),
        ("per-sample manifests (manifests/)", "manifests"),
        ("JSONL evidence export", "evidence_export.jsonl"),
    ):
        avail.append(
            {
                "evidence_item": f"raw source: {label}",
                **{p: "YES" if has_file(p, name) else "NO" for p in PIPES},
                "basis": "file present in every pilot evidence directory of the pipeline",
                "source": "evidence/<mode>/RUN-*/",
            }
        )
    write_csv("evidence_availability_matrix.csv", avail)

    # ------------------------------------------------------------------ PARTS 7-11 per run
    def base(r):
        return {
            "experiment_id": r["id"],
            "pipeline": r["pipeline"],
            "attack": r["attack"],
            "poison_rate": r["rate"],
            "seed": r["seed"],
        }

    ec_rows, err_rows, tl_rows, rc_rows, rt_rows = [], [], [], [], []
    for r in runs:
        e = r["eval"]
        src = rel(r["pkg"] / "evaluation.json")
        ec = e["evidence_completeness"]
        app = [i for i in ec["items"] if i["applicable"]]
        ec_rows.append(
            {
                **base(r),
                "required_items": ec["applicable"],
                "recovered_items": ec["recovered"],
                "missing_items": ";".join(i["id"] for i in app if not i["recovered"]) or "none",
                "not_applicable_items": ";".join(
                    i["id"] for i in ec["items"] if not i["applicable"]
                )
                or "none",
                "evidence_completeness_percent": round(100 * ec["ec"], 2),
                "source": src,
            }
        )
        P(
            "evidence_completeness",
            r["id"],
            round(100 * ec["ec"], 2),
            "%",
            "MEASURED",
            src,
            "evidence_completeness.ec",
            "recovered applicable items / applicable items x 100",
        )
        er = e["event_recovery"]
        err_rows.append(
            {
                **base(r),
                "ground_truth_events": er["required"],
                "gt_events_required": ";".join(m["gt_action"] for m in er["matches"]),
                "correctly_recovered_events": er["recovered"],
                "missed_events": ";".join(
                    f"{m['gt_action']} ({m['reason']})" for m in er["matches"] if not m["recovered"]
                )
                or "none",
                "incorrectly_inferred_events": "NOT MEASURED by implementation",
                "event_recovery_rate": er["err"],
                "source": src,
            }
        )
        P(
            "event_recovery_rate",
            r["id"],
            er["err"],
            "proportion",
            "MEASURED",
            src,
            "event_recovery.err",
            "recovered required GT events / required GT events",
        )
        t = e["timeline"]
        n = t["n_ordered_events"]
        tl_rows.append(
            {
                **base(r),
                "number_ground_truth_events": er["required"],
                "number_recovered_events": n,
                "number_correctly_ordered_pairs": round(
                    (t["pairwise_order_accuracy"] or 0) * math.comb(n, 2)
                ),
                "total_pairs": math.comb(n, 2),
                "pairwise_order_accuracy": t["pairwise_order_accuracy"],
                "timeline_coverage": t["coverage"],
                "kendall_tau_b": t["kendall_tau_b"],
                "kendall_p_value": t["kendall_p_value"],
                "tau_status": t["tau_status"],
                "source": src,
            }
        )
        P(
            "timeline_kendall_tau_b",
            r["id"],
            t["kendall_tau_b"],
            "tau",
            "MEASURED",
            src,
            "timeline.kendall_tau_b",
            "scipy.stats.kendalltau(GT order, reconstructed order, b)",
        )
        hops = r["recon"]["hops"]
        dep_ok = hops["deployment"]["status"] == "IDENTIFIED"
        finding = r["recon"]["root_cause"]["finding"]
        if e.get("root_cause"):
            c = e["root_cause"]["components"]
            ps = e["root_cause"]["poisoning_source_scores"]
            want = {"LF": "LABEL_MODIFICATION", "BD": "CONTENT_AND_LABEL_MODIFICATION"}[r["attack"]]
            rc_rows.append(
                {
                    **base(r),
                    "dataset_identified": int(c["dataset"]),
                    "training_run_identified": int(c["training_run"]),
                    "model_identified": int(c["model"]),
                    "deployment_identified": f"{int(dep_ok)} (CALCULATED: deployment hop "
                    f"identified, confidence "
                    f"{hops['deployment']['confidence']}; not an "
                    "implemented RCI component)",
                    "poisoning_source_identified": int(c["poisoning_source"]),
                    "attack_type_identified": f"{int(finding == want)} (CALCULATED: "
                    f"finding {finding} vs expected {want}; not "
                    "an implemented RCI component)",
                    "implemented_rci_score": e["root_cause"]["rci_score"],
                    "rci_percent": 100 * e["root_cause"]["rci_score"],
                    "poisoning_source_precision": ps["precision"],
                    "poisoning_source_recall": ps["recall"],
                    "poisoning_source_f1": ps["f1"],
                    "root_cause_finding": finding,
                    "source": src,
                }
            )
            P(
                "rci_score",
                r["id"],
                e["root_cause"]["rci_score"],
                "proportion",
                "MEASURED",
                src,
                "root_cause.rci_score",
                "correct components / 4",
            )
        else:
            cc = e["clean_control"]
            rc_rows.append(
                {
                    **base(r),
                    "dataset_identified": NAPP,
                    "training_run_identified": NAPP,
                    "model_identified": NAPP,
                    "deployment_identified": NAPP,
                    "poisoning_source_identified": NAPP,
                    "attack_type_identified": NAPP,
                    "implemented_rci_score": NAPP,
                    "root_cause_finding": finding,
                    "clean_control_correct": cc["correct"],
                    "false_attribution": cc["false_attribution"],
                    "source": src,
                }
            )
        rt = r["recon"]["runtime_seconds"]
        rt_rows.append(
            {
                **base(r),
                "reconstruction_start": NA,
                "reconstruction_end": NA,
                "reconstruction_time_seconds": rt,
                "note": "elapsed time (time.perf_counter) of reconstruct(); start/end "
                "wall-clock timestamps are not recorded",
                "source": rel(r["pkg"] / "reconstruction.json"),
            }
        )
        P(
            "reconstruction_time",
            r["id"],
            rt,
            "s",
            "MEASURED",
            rel(r["pkg"] / "reconstruction.json"),
            "runtime_seconds",
        )

    attacked = [r for r in runs if r["attack"] != "CLEAN"]

    def add_aggs(rows_, metric, subset_attack=None, label=""):
        for p in PIPES:
            vals = [
                x[metric]
                for x in rows_
                if x.get("pipeline") == p
                and isinstance(x.get(metric), (int, float))
                and (subset_attack is None or x["attack"] in subset_attack)
            ]
            rows_.append(stats_row(vals, experiment_id=f"AGGREGATE {p}{label}", metric=metric))

    add_aggs(ec_rows, "evidence_completeness_percent", label=" (all 6 runs)")
    add_aggs(ec_rows, "evidence_completeness_percent", ("LF", "BD"), " (attacked, 4 runs)")
    add_aggs(err_rows, "event_recovery_rate", label=" (all)")
    add_aggs(err_rows, "event_recovery_rate", ("LF", "BD"), " (attacked)")
    add_aggs(tl_rows, "kendall_tau_b", label=" (all)")
    add_aggs(tl_rows, "pairwise_order_accuracy", label=" (all)")
    add_aggs(rc_rows, "implemented_rci_score", ("LF", "BD"), " (attacked)")
    add_aggs(rt_rows, "reconstruction_time_seconds", label=" (all)")
    write_csv("evidence_completeness.csv", ec_rows)
    write_csv("event_recovery.csv", err_rows)
    write_csv("timeline_reconstruction.csv", tl_rows)
    write_csv("root_cause_identification.csv", rc_rows)
    write_csv("reconstruction_time.csv", rt_rows)

    # ------------------------------------------------------------------ PART 12 storage
    con = sqlite3.connect(ROOT / "mlruns/mlflow.db")
    mv = {row[0]: row[1] for row in con.execute("SELECT run_id, source FROM model_versions")}
    runref = {
        row[0]: row[1]
        for row in con.execute("SELECT run_uuid, value FROM tags WHERE key='run_ref'")
    }
    con.close()
    ref_to_run = {v: k for k, v in runref.items() if k in mv}

    def logged_model_bytes(r):
        rid = ref_to_run.get(f"RUN-{r['uuid']}")
        if not rid:
            return None
        src = mv[rid]  # e.g. models:/m-<id>
        mid = src.split("/")[-1]
        path = ROOT / "mlruns/artifacts/models" / mid
        return (
            sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) if path.exists() else None
        )

    st_rows = []
    for r in runs:
        sb = r["summary"]["storage_bytes"]
        lm = logged_model_bytes(r)
        ev_bytes = sum(v for k, v in sb.items() if k != "model_files")
        r["evidence_mb"] = ev_bytes / 1024**2
        r["evidence_mb_incl_model"] = (ev_bytes + (lm or 0)) / 1024**2
        st_rows.append(
            {
                **base(r),
                "normal_logs_mb": sb.get("logs", 0) / 1024**2,
                "forensic_sqlite_mb": sb.get("forensic_sqlite", 0) / 1024**2,
                "json_jsonl_evidence_mb": sb.get("forensic_jsonl", 0) / 1024**2,
                "manifests_mb": sb.get("manifests", 0) / 1024**2,
                "mlflow_run_artifacts_mb": sb.get("mlflow_artifacts", 0) / 1024**2,
                "mlflow_logged_model_mb": (
                    lm / 1024**2 if lm is not None else (NAPP if r["pipeline"] == "A" else NA)
                ),
                "mlflow_metadata_db_mb": "shared mlflow.db (not attributable per run)",
                "integrity_records": "inside forensic_sqlite",
                "other_evidence_mb": sb.get("other_evidence", 0) / 1024**2,
                "evidence_total_mb": r["evidence_mb"],
                "evidence_total_incl_mlflow_model_mb": r["evidence_mb_incl_model"],
                "source": rel(r["pkg"] / "run_summary.json") + " (storage_bytes); "
                "mlruns/mlflow.db + mlruns/artifacts/models",
            }
        )
        P(
            "evidence_storage_mb",
            r["id"],
            r["evidence_mb"],
            "MB",
            "MEASURED",
            rel(r["pkg"] / "run_summary.json"),
            "storage_bytes excl. model_files",
        )
    for key in ("evidence_total_mb", "evidence_total_incl_mlflow_model_mb"):
        means = {
            p: describe([x[key] for x in st_rows if x.get("pipeline") == p])["mean"] for p in PIPES
        }
        for p in PIPES:
            vals = [x[key] for x in st_rows if x.get("pipeline") == p]
            st_rows.append(
                {
                    **stats_row(vals, experiment_id=f"AGGREGATE {p}", metric=key),
                    "absolute_difference_vs_A_mb": means[p] - means["A"],
                    "storage_overhead_vs_A_percent": (
                        (means[p] - means["A"]) / means["A"] * 100 if means["A"] else NA
                    ),
                    "formula": "(S_p - S_A) / S_A x 100 (means)",
                }
            )
    write_csv("storage_overhead.csv", st_rows)

    # ------------------------------------------------------------------ PART 13 compute
    comp = []
    by = {(r["attack"], r["seed"], r["pipeline"]): r for r in runs}
    for (att, seed, p), r in sorted(by.items()):
        a = by[(att, seed, "A")]
        t, ta = (
            r["summary"]["timings"]["training_seconds"],
            a["summary"]["timings"]["training_seconds"],
        )
        tot = sum(r["summary"]["timings"].values())
        tota = sum(a["summary"]["timings"].values())
        comp.append(
            {
                **base(r),
                "training_time_s": t,
                "total_pipeline_runtime_s": tot,
                "evidence_logging_time_s": r["summary"]["evidence_logging_seconds"],
                "inference_time_s": r["summary"]["timings"]["inference_seconds"],
                "median_epoch_s": r["epoch_median_s"],
                "gpu_power_state": r["power_state"],
                "matched_A_training_s": ta,
                "training_overhead_vs_matched_A_percent": (t - ta) / ta * 100,
                "total_overhead_vs_matched_A_percent": (tot - tota) / tota * 100,
                "power_state_matched_with_A": r["power_state"] == a["power_state"],
                "peak_ram_mb": r["summary"]["resources"]["peak_rss_mb"],
                "peak_gpu_mb": r["summary"]["resources"]["peak_gpu_allocated_mb"],
                "mean_cpu_percent": r["summary"]["resources"]["mean_cpu_percent"],
                "source": rel(r["pkg"] / "run_summary.json"),
            }
        )
    per_run = list(comp)
    for p in ("B", "C"):
        for label, filt in (
            ("all matched pairs", lambda x: True),
            ("power-state-matched pairs only", lambda x: x["power_state_matched_with_A"]),
        ):
            sub = [x for x in per_run if x["pipeline"] == p and filt(x)]
            for m in (
                "training_overhead_vs_matched_A_percent",
                "total_overhead_vs_matched_A_percent",
                "evidence_logging_time_s",
            ):
                comp.append(
                    stats_row(
                        [x[m] for x in sub], experiment_id=f"AGGREGATE {p} vs A ({label})", metric=m
                    )
                )
    write_csv("computational_overhead.csv", comp)

    # ------------------------------------------------------------------ PART 15 statistics
    import pandas as pd

    df = pd.DataFrame(
        [
            {
                "attack_type": r["attack"],
                "poison_rate": r["rate"],
                "seed": r["seed"],
                "pipeline": r["pipeline"],
                "evidence_completeness": r["eval"]["evidence_completeness"]["ec"],
                "event_recovery_rate": r["eval"]["event_recovery"]["err"],
                "timeline_kendall_tau_b": r["eval"]["timeline"]["kendall_tau_b"],
                "rci_score": (r["eval"].get("root_cause") or {}).get("rci_score"),
                "reconstruction_seconds": r["recon"]["runtime_seconds"],
                "evidence_storage_mb": r["evidence_mb"],
                "training_seconds": r["summary"]["timings"]["training_seconds"],
            }
            for r in runs
        ]
    )
    stat_rows = []
    pilot_note = (
        "EXPLORATORY: pilot, n_blocks = {n} (3 conditions x 2 seeds); most evidence "
        "metrics are deterministic given the pipeline design, so tests mainly restate "
        "design differences; not a confirmatory analysis"
    )
    for m in (
        "evidence_completeness",
        "event_recovery_rate",
        "timeline_kendall_tau_b",
        "rci_score",
        "reconstruction_seconds",
        "evidence_storage_mb",
        "training_seconds",
    ):
        data = df.dropna(subset=[m]).copy()
        data[m] = data[m].round(10)  # remove floating-point noise (e.g. tau 0.9999999999)
        wide = data.pivot_table(
            index=["attack_type", "seed"], columns="pipeline", values=m
        ).dropna()
        n_blocks = len(wide)
        diffs = [
            wide[a] - wide[b]
            for a, b in (("A", "B"), ("A", "C"), ("B", "C"))
            if a in wide and b in wide
        ]
        no_within_variance = all(d.nunique() <= 1 for d in diffs)
        base_row = {
            "metric": m,
            "n_blocks": n_blocks,
            "design": "paired: blocks = attack x seed; pipelines A/B/C within block",
        }
        if n_blocks < 3:
            stat_rows.append(
                {**base_row, "test": "INSUFFICIENT SAMPLE SIZE FOR RELIABLE " "INFERENTIAL TEST"}
            )
            continue
        if no_within_variance:
            stat_rows.append(
                {
                    **base_row,
                    "test": "NOT RUN: no within-block variance (every "
                    "pipeline difference is constant across blocks); inferential test "
                    "not meaningful - report descriptively",
                    "mean_difference_A_B": float(diffs[0].iloc[0]),
                    "mean_difference_A_C": float(diffs[1].iloc[0]),
                    "mean_difference_B_C": float(diffs[2].iloc[0]),
                }
            )
            continue
        for x in compare_pipelines(data, m, block_cols=("attack_type", "seed")):
            stat_rows.append({**base_row, **x, "reliability": pilot_note.format(n=n_blocks)})

    # Binary paired outcomes: Cochran's Q (omnibus) + exact McNemar (pairwise, Holm)
    from statsmodels.stats.contingency_tables import cochrans_q, mcnemar

    from mlfref.evaluation.statistics import _holm

    binary = {}
    for r in runs:
        if r["attack"] == "CLEAN":
            continue
        key = (r["attack"], r["seed"])
        c = r["eval"]["root_cause"]["components"]
        binary.setdefault("poisoning_source_identified", {}).setdefault(key, {})[r["pipeline"]] = (
            int(c["poisoning_source"])
        )
        binary.setdefault("dataset_change_detected", {}).setdefault(key, {})[r["pipeline"]] = int(
            r["recon"]["dataset_change"]["changed"] is True
        )
    for name, blocks in binary.items():
        mat = [[b[p] for p in PIPES] for b in blocks.values()]
        base_row = {"metric": name, "n_blocks": len(mat), "design": "paired binary"}
        if all(len(set(row)) == 1 for row in mat):
            stat_rows.append({**base_row, "test": "NOT RUN: no discordant blocks"})
            continue
        q = cochrans_q(mat)
        stat_rows.append(
            {
                **base_row,
                "test": "Cochran's Q",
                "statistic": float(q.statistic),
                "df": int(q.df),
                "p_value": float(q.pvalue),
                "reliability": pilot_note.format(n=len(mat)),
            }
        )
        pw, raw = [], []
        for i, j in ((0, 1), (0, 2), (1, 2)):
            b01 = sum(1 for row in mat if row[i] == 1 and row[j] == 0)
            b10 = sum(1 for row in mat if row[i] == 0 and row[j] == 1)
            if b01 + b10 == 0:
                pw.append(
                    {
                        **base_row,
                        "test": f"McNemar exact ({PIPES[i]}-{PIPES[j]}): no " "discordant pairs",
                        "p_value": 1.0,
                    }
                )
                raw.append(1.0)
                continue
            res = mcnemar([[0, b01], [b10, 0]], exact=True)
            pw.append(
                {
                    **base_row,
                    "test": f"McNemar exact ({PIPES[i]}-{PIPES[j]})",
                    "statistic": float(res.statistic),
                    "p_value": float(res.pvalue),
                    "discordant": f"{b01}/{b10}",
                    "reliability": pilot_note.format(n=len(mat)),
                }
            )
            raw.append(float(res.pvalue))
        for row, adj in zip(pw, _holm(raw), strict=True):
            row["p_holm"] = adj
        stat_rows += pw
    write_csv("statistical_tests.csv", stat_rows)
    df.to_csv(OUT / "analysis_dataset.csv", index=False)

    # ------------------------------------------------------------------ PART 19 master
    master = []
    for r in runs:
        a = by[(r["attack"], r["seed"], "A")]
        e = r["eval"]
        master.append(
            {
                **base(r),
                "clean_accuracy": r["summary"]["harness_metrics"]["clean_test_accuracy"],
                "attack_success_rate": r["summary"]["harness_metrics"].get("attack_success_rate"),
                "source_to_target_rate": r["summary"]["harness_metrics"].get(
                    "source_to_target_rate"
                ),
                "evidence_completeness": e["evidence_completeness"]["ec"],
                "event_recovery_rate": e["event_recovery"]["err"],
                "timeline_accuracy_kendall_tau_b": e["timeline"]["kendall_tau_b"],
                "timeline_pairwise_order_accuracy": e["timeline"]["pairwise_order_accuracy"],
                "root_cause_score": (e.get("root_cause") or {}).get("rci_score"),
                "clean_control_correct": (e.get("clean_control") or {}).get("correct"),
                "reconstruction_time_sec": r["recon"]["runtime_seconds"],
                "training_time_sec": r["summary"]["timings"]["training_seconds"],
                "total_runtime_sec": sum(r["summary"]["timings"].values()),
                "evidence_storage_mb": r["evidence_mb"],
                "evidence_storage_incl_mlflow_model_mb": r["evidence_mb_incl_model"],
                "runtime_overhead_percent": (
                    r["summary"]["timings"]["training_seconds"]
                    - a["summary"]["timings"]["training_seconds"]
                )
                / a["summary"]["timings"]["training_seconds"]
                * 100,
                "storage_overhead_percent": (r["evidence_mb"] - a["evidence_mb"])
                / a["evidence_mb"]
                * 100,
                "peak_ram_mb": r["summary"]["resources"]["peak_rss_mb"],
                "peak_gpu_memory_mb": r["summary"]["resources"]["peak_gpu_allocated_mb"],
                "gpu_power_state": r["power_state"],
                "status": "SUCCESS",
                "notes": (
                    "retried after transient PermissionError"
                    if any(f["experiment_id"] == r["id"] for f in failed)
                    else ""
                ),
            }
        )
    write_csv("master_experimental_results.csv", master)

    # ------------------------------------------------------------------ PART 20 summary
    def ms(metric, pipe, subset=None, scale=1.0, nd=3):
        vals = [
            x[metric] * scale
            for x in master
            if x["pipeline"] == pipe
            and x[metric] is not None
            and (subset is None or x["attack"] in subset)
        ]
        d = describe(vals)
        if d["n"] == 0:
            return NA
        return (
            f"{d['mean']:.{nd}f} ± {d['sd']:.{nd}f} (n={d['n']})"
            if d["n"] > 1
            else f"{d['mean']:.{nd}f} (n=1)"
        )

    atk = ("LF", "BD")
    summ = [
        ("Clean Accuracy (all runs)", {p: ms("clean_accuracy", p, nd=4) for p in PIPES}),
        (
            "Attack Success Rate (backdoor)",
            {p: ms("attack_success_rate", p, ("BD",), nd=4) for p in PIPES},
        ),
        (
            "Evidence Completeness % (attacked)",
            {p: ms("evidence_completeness", p, atk, 100, 1) for p in PIPES},
        ),
        (
            "Evidence Completeness % (clean control)",
            {p: ms("evidence_completeness", p, ("CLEAN",), 100, 1) for p in PIPES},
        ),
        ("Event Recovery Rate (attacked)", {p: ms("event_recovery_rate", p, atk) for p in PIPES}),
        (
            "Timeline Accuracy, Kendall tau-b (all)",
            {p: ms("timeline_accuracy_kendall_tau_b", p) for p in PIPES},
        ),
        (
            "Root Cause Identification score (attacked)",
            {p: ms("root_cause_score", p, atk) for p in PIPES},
        ),
        ("Reconstruction Time s (all)", {p: ms("reconstruction_time_sec", p) for p in PIPES}),
        (
            "Evidence Storage MB (excl. MLflow model)",
            {p: ms("evidence_storage_mb", p) for p in PIPES},
        ),
        (
            "Evidence Storage MB (incl. MLflow logged model)",
            {p: ms("evidence_storage_incl_mlflow_model_mb", p) for p in PIPES},
        ),
        (
            "Storage Overhead % vs matched A",
            {p: ms("storage_overhead_percent", p, nd=1) for p in PIPES},
        ),
        (
            "Training Runtime s (all; absolute values confounded by GPU power state)",
            {p: ms("training_time_sec", p, nd=1) for p in PIPES},
        ),
        (
            "Runtime Overhead % vs matched A (each A/B/C triple shares one GPU power state)",
            {p: ms("runtime_overhead_percent", p, nd=1) for p in PIPES},
        ),
    ]
    write_csv(
        "pipeline_summary.csv",
        [
            {"metric": m, "conventional_A": v["A"], "provenance_B": v["B"], "forensic_C": v["C"]}
            for m, v in summ
        ],
    )
    write_csv("results_provenance.csv", prov)

    # ------------------------------------------------------------------ figures
    fig_status = figures(runs, master, st_rows)
    json.dump(fig_status, (OUT / "figures_generated.json").open("w"), indent=2)

    # ------------------------------------------------------------------ case study
    case_study(runs)
    print(f"{len(runs)} completed pilot runs analysed; {len(failed)} failed attempt(s) recorded")
    return 0


def box(runs_metric, title, ylabel, path, note=""):
    apply_style()
    fig, ax = plt.subplots(figsize=(5.8, 3.7))
    for i, p in enumerate(PIPES, 1):
        vals = runs_metric[p]
        ax.scatter(
            [i] * len(vals),
            vals,
            color=PIPELINE_COLORS[p],
            s=46,
            zorder=3,
            edgecolor="white",
            linewidth=1.5,
        )
        if vals:
            ax.hlines(sum(vals) / len(vals), i - 0.22, i + 0.22, color="#0b0b0b", lw=1.6)
    ax.set_xticks([1, 2, 3], [PIPELINE_LABELS[p] for p in PIPES])
    ax.set_xlim(0.5, 3.5)
    ax.set_ylabel(ylabel)
    ax.set_title(title, loc="left")
    if note:
        fig.text(0.01, -0.02, note, fontsize=7.5, color="#52514e")
    save_figure(fig, path)


def figures(runs, master, st_rows) -> dict:
    status = {}
    src = ["results/raw/run_index.csv", "experiments/pilot/pipeline_runs/*/"]
    exps = [r["id"] for r in runs]

    def meta(path, metric):
        record_output_metadata(
            path,
            source_data=src,
            experiments=exps,
            metric=metric,
            generation_script=SCRIPT,
            description="MEASURED pilot data",
        )
        status[path.name] = "GENERATED"

    by = lambda metric, subset=None: {
        p: [
            x[metric]
            for x in master
            if x["pipeline"] == p  # noqa
            and x[metric] is not None
            and (subset is None or x["attack"] in subset)
        ]
        for p in PIPES
    }
    dot_note = "Dots: individual runs (seeds 1-2); bar: mean. Pilot, 30 epochs, 5 % poisoning."
    # 4.1 clean baseline curves (pilot clean runs)
    apply_style()
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10, 3.8))
    for i, r in enumerate([x for x in runs if x["attack"] == "CLEAN" and x["pipeline"] == "A"]):
        ep = [int(t["epoch"]) for t in r["tm"]]
        a1.plot(
            ep,
            [float(t["test_loss"]) for t in r["tm"]],
            color=CATEGORICAL[i],
            label=f"seed {r['seed']} test",
        )
        a2.plot(
            ep,
            [float(t["test_accuracy"]) for t in r["tm"]],
            color=CATEGORICAL[i],
            label=f"seed {r['seed']} test",
        )
        a2.plot(
            ep,
            [float(t["train_accuracy"]) for t in r["tm"]],
            color=CATEGORICAL[i],
            ls="--",
            label=f"seed {r['seed']} train",
        )
    a1.set(xlabel="Epoch", ylabel="Test cross-entropy loss")
    a1.set_title("(a) Test loss", loc="left")
    a2.set(xlabel="Epoch", ylabel="Accuracy")
    a2.set_title("(b) Accuracy", loc="left")
    a1.legend()
    a2.legend(loc="lower right")
    fig.suptitle(
        "Figure 4.1. Clean control training (pipeline A, seeds 1-2, 30 epochs)",
        x=0.01,
        ha="left",
        fontsize=11,
    )
    fig.tight_layout()
    p = FIGS / "figure4_1_clean_baseline_pilot.png"
    save_figure(fig, p)
    meta(p, "loss/accuracy by epoch")
    # 4.2 clean accuracy by poisoning condition
    apply_style()
    fig, ax = plt.subplots(figsize=(6.4, 3.7))
    conds = [("CLEAN", "clean (0 %)"), ("LF", "label flip 5 %"), ("BD", "backdoor 5 %")]
    for j, p_ in enumerate(PIPES):
        ys = [
            sum(v) / len(v)
            for c, _ in conds
            for v in [
                [x["clean_accuracy"] for x in master if x["pipeline"] == p_ and x["attack"] == c]
            ]
        ]
        ax.plot(
            range(3),
            ys,
            marker="o",
            color=PIPELINE_COLORS[p_],
            label=PIPELINE_LABELS[p_],
            alpha=0.9,
            lw=2 if j == 0 else 1.2,
            ls=["-", "--", ":"][j],
        )
    ax.set_xticks(range(3), [c[1] for c in conds])
    ax.set_ylabel("Clean test accuracy (mean of 2 seeds)")
    ax.set_title("Figure 4.2. Clean accuracy by poisoning condition", loc="left")
    ax.legend()
    p = FIGS / "figure4_2_clean_accuracy_by_condition.png"
    save_figure(fig, p)
    meta(p, "clean accuracy")
    status["figure4_2 note"] = "only one poisoning rate (5 %) exists; x-axis is condition"
    specs = [
        (
            "figure4_3_backdoor_asr.png",
            "attack_success_rate",
            ("BD",),
            "Figure 4.3. Backdoor ASR at 5 % poisoning",
            "Attack success rate",
        ),
        (
            "figure4_4_evidence_completeness.png",
            "evidence_completeness",
            ("LF", "BD"),
            "Figure 4.4. Evidence completeness (attacked runs)",
            "Evidence completeness",
        ),
        (
            "figure4_5_event_recovery.png",
            "event_recovery_rate",
            ("LF", "BD"),
            "Figure 4.5. Event recovery rate (attacked runs)",
            "Event recovery rate",
        ),
        (
            "figure4_6_timeline_accuracy.png",
            "timeline_accuracy_kendall_tau_b",
            None,
            "Figure 4.6. Timeline ordering accuracy (Kendall tau-b)",
            "Kendall tau-b",
        ),
        (
            "figure4_7_root_cause.png",
            "root_cause_score",
            ("LF", "BD"),
            "Figure 4.7. Root-cause identification score (attacked runs)",
            "RCI score (of 4)",
        ),
        (
            "figure4_8_reconstruction_time.png",
            "reconstruction_time_sec",
            None,
            "Figure 4.8. Reconstruction time",
            "Seconds",
        ),
        (
            "figure4_9_evidence_storage.png",
            "evidence_storage_incl_mlflow_model_mb",
            None,
            "Figure 4.9. Evidence storage (incl. MLflow logged model)",
            "MB",
        ),
        (
            "figure4_10_runtime_overhead.png",
            "runtime_overhead_percent",
            None,
            "Figure 4.10. Training-time difference vs matched A",
            "% vs A (same condition, seed)",
        ),
    ]
    for name, metric, subset, title, ylabel in specs:
        note = dot_note
        if "runtime" in name:
            note += " Confounded: GPU power state changed during the pilot."
        box(by(metric, subset), title, ylabel, FIGS / name, note)
        meta(FIGS / name, metric)
    # 4.11 A/B/C reconstruction comparison: hop confidence for BD 5 % seed 1
    hops = ["inference", "deployment", "model", "training_run", "training_dataset", "prior_dataset"]
    rank = {"NONE": 0, "WEAK": 1, "MODERATE": 2, "STRONG": 3}
    case = {r["pipeline"]: r for r in runs if r["attack"] == "BD" and r["seed"] == 1}
    apply_style()
    fig, ax = plt.subplots(figsize=(7.4, 3.3))
    ramp = ["#f4f4f2", "#b7d3f6", "#5598e7", "#184f95"]
    for i, p_ in enumerate(PIPES):
        for j, h in enumerate(hops):
            conf = case[p_]["recon"]["hops"][h]["confidence"]
            ax.add_patch(plt.Rectangle((j, 2 - i), 0.96, 0.92, color=ramp[rank[conf]]))
            ax.text(
                j + 0.48,
                2 - i + 0.46,
                conf,
                ha="center",
                va="center",
                fontsize=7.5,
                color="white" if rank[conf] >= 2 else "#0b0b0b",
            )
    ax.set_xlim(0, 6)
    ax.set_ylim(0, 3)
    ax.set_xticks([j + 0.48 for j in range(6)], [h.replace("_", "\n") for h in hops], fontsize=8)
    ax.set_yticks([2.46, 1.46, 0.46], [PIPELINE_LABELS[p] for p in PIPES])
    ax.grid(False)
    for s in ax.spines.values():
        s.set_visible(False)
    finding = {p: case[p]["recon"]["root_cause"]["finding"] for p in PIPES}
    ax.set_title("Figure 4.11. Backward-trace link confidence, backdoor 5 % seed 1", loc="left")
    fig.text(
        0.01,
        -0.06,
        "Root-cause finding - A: " + finding["A"] + "; B: " + finding["B"] + "; C: " + finding["C"],
        fontsize=7.5,
        color="#52514e",
    )
    p = FIGS / "figure4_11_abc_reconstruction.png"
    save_figure(fig, p)
    meta(p, "hop confidence")
    return status


def case_study(runs):
    case = {r["pipeline"]: r for r in runs if r["attack"] == "BD" and r["seed"] == 1}
    L = [
        "# Reconstruction Case Study: backdoor 5 %, seed 1 (A / B / C)",
        "",
        "Genuine pilot runs EXP-BD-A-05-S001, EXP-BD-B-05-S001, EXP-BD-C-05-S001 (30 epochs). "
        "Each pipeline received the same attack (identical poisoned sample set, same seed) "
        "and the same inference traffic.",
        "",
    ]
    for p in PIPES:
        r = case[p]
        t = r["recon"]["incident"]
        L.append(
            f"- {p}: ticket {t['ticket_id']}, request {t['request_id']}, observed "
            f"**{t['observed_prediction']}**, expected **{t['expected_label']}** "
            f"(`{rel(r['pkg'] / 'reconstruction.json')}`)"
        )
    for p in PIPES:
        r = case[p]
        L += [
            "",
            f"## Ground-truth event sequence ({p} run, `ground_truth.sqlite`)",
            "",
            "| # | GT event | Timestamp (UTC) | Artefact |",
            "|---|---|---|---|",
        ]
        for e in r["gt"]:
            if e["action"] in ("TRIGGER_SUBMITTED", "MALICIOUS_PREDICTION"):
                md = json.loads(e["metadata_json"])
                if md.get("request_id") != r["recon"]["incident"]["request_id"]:
                    continue
                art = f"request {md.get('request_id')}"
            else:
                art = (e["affected_artifact"] or e["result_artifact"] or "")[:12] + "…"
            L.append(f"| {e['sequence_number']} | {e['action']} | {e['timestamp_utc']} | {art} |")
        L.append("")
        L.append(
            "_(Only the ticketed request's inference events are listed; all trigger "
            "submissions are in ground truth.)_"
        )
        L += [
            "",
            f"## Configuration {p} reconstruction",
            "",
            "| Order | Reconstructed event | Timestamp | Time basis | Confidence | "
            "Artefact refs |",
            "|---|---|---|---|---|---|",
        ]
        for e in r["recon"]["events"]:
            when = (
                f"{e['time_lower']} … {e['time_upper']}"
                if e["time_basis"] == "bounded"
                else e["time"] or "-"
            )
            L.append(
                f"| {e.get('order') or '-'} | {e['event_class']} | {when} | {e['time_basis']} "
                f"| {e['confidence']} | {', '.join(e['artifact_refs'])} |"
            )
        L += ["", "| GT event | Recovered | Reason if missed |", "|---|---|---|"]
        for m in r["eval"]["event_recovery"]["matches"]:
            L.append(
                f"| {m['gt_action']} | {'YES' if m['recovered'] else 'NO'} | "
                f"{m.get('reason') or ''} |"
            )
        rels = r["recon"]["graph"]["relations"]
        L += [
            "",
            "Relationships: "
            + ("; ".join(f"{x['from']} {x['relation']} {x['to']}" for x in rels) or "none"),
            f"Root-cause finding: **{r['recon']['root_cause']['finding']}**; changed samples "
            f"reported: {len(r['recon']['root_cause']['changed_sample_ids'] or [])} "
            f"(GT: {r['gta']['number_poisoned']})",
            f"Integrity: {json.dumps({k: v.get('result', v.get('status')) if isinstance(v, dict) and 'valid' not in v else v.get('valid') for k, v in r['recon']['integrity'].items()})}",
            f"Scores: EC {r['eval']['evidence_completeness']['ec']:.3f}, ERR "
            f"{r['eval']['event_recovery']['err']:.3f}, tau-b "
            f"{r['eval']['timeline']['kendall_tau_b']}, RCI "
            f"{r['eval']['root_cause']['rci_score']}, reconstruction "
            f"{r['recon']['runtime_seconds']:.3f} s",
        ]
    (OUT / "reconstruction_case_study.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
