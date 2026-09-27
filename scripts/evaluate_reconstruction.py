"""Evaluate a completed reconstruction against ground truth (spec §23).

Order is enforced: the reconstruction JSON must already exist. Its SHA-256 and
modification time are recorded BEFORE ground truth is opened, so the evaluation
record proves the reconstruction was produced without ground truth.

Outputs results/evaluation/<EXP-ID>.json, and a copy in the run package when the
package exists.

Usage:
    python scripts/evaluate_reconstruction.py --experiment EXP-BD-C-05-S003 [--phase pilot]
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mlfref.evaluation.common import SCHEMA_PATH, load_schema  # noqa: E402
from mlfref.evaluation.evaluate import evaluate_run  # noqa: E402
from mlfref.experiment_id import parse_experiment_id  # noqa: E402
from mlfref.forensic.hashing import sha256_file  # noqa: E402

RUN_INDEX = PROJECT_ROOT / "results" / "raw" / "run_index.csv"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--experiment", required=True)
    p.add_argument("--phase", choices=["pilot", "main"])
    p.add_argument("--recon-dir", default=str(PROJECT_ROOT / "results" / "reconstruction"))
    p.add_argument("--out-dir", default=str(PROJECT_ROOT / "results" / "evaluation"))
    args = p.parse_args()

    with RUN_INDEX.open(encoding="utf-8", newline="") as fh:
        rows = [
            r
            for r in csv.DictReader(fh)
            if r["experiment_id"] == args.experiment
            and r["status"] == "completed"
            and (not args.phase or r["phase"] == args.phase)
        ]
    if not rows:
        raise SystemExit(f"no completed run for {args.experiment}")
    row = rows[-1]

    # 1. The reconstruction must exist BEFORE ground truth is touched.
    recon_path = Path(args.recon_dir) / f"{args.experiment}.json"
    if not recon_path.exists():
        raise SystemExit(f"{recon_path} missing: run reconstruct_incident.py first")
    provenance = {
        "reconstruction_file": recon_path.relative_to(PROJECT_ROOT).as_posix(),
        "reconstruction_sha256": sha256_file(recon_path),
        "reconstruction_mtime_utc": datetime.fromtimestamp(
            recon_path.stat().st_mtime, tz=UTC
        ).isoformat(),
        "ground_truth_opened_utc": None,
    }
    recon = json.loads(recon_path.read_text(encoding="utf-8"))

    # 2. Only now read ground truth.
    from mlfref.ground_truth.recorder import GroundTruthReader

    provenance["ground_truth_opened_utc"] = datetime.now(UTC).isoformat()
    with GroundTruthReader(PROJECT_ROOT / row["ground_truth_db"]) as reader:
        gt_events = reader.events(row["experiment_uuid"])
        gt_attack = reader.attack(row["experiment_uuid"])

    schema = load_schema()
    attack_type = parse_experiment_id(args.experiment)["attack_type"]
    result = evaluate_run(recon, gt_events, gt_attack, attack_type, schema, PROJECT_ROOT)
    result.update(
        {
            "experiment_id": args.experiment,
            "experiment_uuid": row["experiment_uuid"],
            "pipeline": row["pipeline"],
            "evaluation_schema_sha256": sha256_file(SCHEMA_PATH),
            "provenance": provenance,
        }
    )
    out = Path(args.out_dir) / f"{args.experiment}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    pkg = PROJECT_ROOT / row.get("package_dir", "")
    if row.get("package_dir") and pkg.is_dir():
        (pkg / "evaluation.json").write_text(
            json.dumps(result, indent=2, default=str), encoding="utf-8"
        )

    er, ec = result["event_recovery"], result["evidence_completeness"]
    tl = result["timeline"]
    print(f"{args.experiment} ({row['pipeline']}):")
    print(f"  Evidence completeness  {ec['recovered']}/{ec['applicable']} = {ec['ec']:.3f}")
    print(f"  Event recovery rate    {er['recovered']}/{er['required']} = {er['err']:.3f}")
    print(
        f"  Timeline               coverage {tl['coverage']:.3f}, tau_b {tl['kendall_tau_b']}"
        f" ({tl['tau_status']})"
    )
    if result["root_cause"]:
        rc = result["root_cause"]
        print(f"  Root cause             RCI {rc['rci_score']:.2f} {rc['components']}")
    else:
        print(f"  Clean control          {result['clean_control']}")
    print(f"  written: {out.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
