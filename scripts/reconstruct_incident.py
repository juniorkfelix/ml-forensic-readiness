"""Reconstruct an incident from ONE pipeline's investigator-visible evidence.

The harness run index (results/raw/run_index.csv) maps the experiment ID to its
evidence directory. Only that directory and the incident ticket are passed to
``reconstruct()``. The engine never sees the experiment ID (which encodes the
attack), ground truth or any other run's evidence.

Outputs results/reconstruction/<EXP-ID>.json and .md.

Usage:
    python scripts/reconstruct_incident.py --experiment EXP-BD-C-05-S003
    python scripts/reconstruct_incident.py --evidence-dir evidence/forensic/RUN-<uuid> \
        [--ticket <path>] [--name label]
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mlfref.reconstruction import reconstruct  # noqa: E402
from mlfref.reconstruction.report import write_json, write_markdown  # noqa: E402

RUN_INDEX = PROJECT_ROOT / "results" / "raw" / "run_index.csv"


def lookup(experiment_id: str, phase: str | None) -> dict[str, str]:
    """Latest completed execution of ``experiment_id`` in the harness run index."""
    if not RUN_INDEX.exists():
        raise SystemExit(f"{RUN_INDEX} not found; run experiments first")
    with RUN_INDEX.open(encoding="utf-8", newline="") as fh:
        rows = [
            r
            for r in csv.DictReader(fh)
            if r["experiment_id"] == experiment_id
            and r["status"] == "completed"
            and (phase is None or r["phase"] == phase)
        ]
    if not rows:
        raise SystemExit(f"no completed run for {experiment_id} in {RUN_INDEX.name}")
    return rows[-1]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--experiment")
    p.add_argument("--phase", choices=["pilot", "main"])
    p.add_argument("--evidence-dir")
    p.add_argument("--ticket", help="default: <evidence-dir>/incident_ticket.json")
    p.add_argument("--name", help="output file stem (default: experiment ID)")
    p.add_argument("--out-dir", default=str(PROJECT_ROOT / "results" / "reconstruction"))
    args = p.parse_args()

    if args.experiment:
        row = lookup(args.experiment, args.phase)
        evidence = PROJECT_ROOT / row["evidence_dir"]
        name = args.name or args.experiment
    elif args.evidence_dir:
        evidence = Path(args.evidence_dir).resolve()
        name = args.name or evidence.name
    else:
        p.error("give --experiment or --evidence-dir")
    ticket_path = Path(args.ticket) if args.ticket else evidence / "incident_ticket.json"
    if not ticket_path.exists():
        raise SystemExit(f"no incident ticket at {ticket_path} (run had no observable incident?)")
    ticket = json.loads(ticket_path.read_text(encoding="utf-8"))

    recon = reconstruct(evidence, ticket, PROJECT_ROOT)
    out = Path(args.out_dir)
    j = write_json(recon, out / f"{name}.json")
    m = write_markdown(recon, out / f"{name}.md", title=f"{name} ({evidence.name})")

    hops = recon["hops"]
    print(
        f"Incident {ticket['ticket_id']} (request {ticket['request_id']}): "
        f"{ticket['observed_prediction']} expected {ticket['expected_label']}"
    )
    print(f"Evidence sources: {', '.join(k for k, v in recon['evidence_sources'].items() if v)}")
    for key in (
        "inference",
        "deployment",
        "model",
        "training_run",
        "training_dataset",
        "prior_dataset",
    ):
        print(f"  {key:<17} {hops[key]['status']:<11} {hops[key]['confidence']}")
    print(f"Root-cause finding: {recon['root_cause']['finding']}")
    print(f"Missing evidence items: {len(recon['missing_evidence'])}")
    print(f"Runtime: {recon['runtime_seconds']:.3f}s")
    print(f"Reports: {j.relative_to(PROJECT_ROOT)} , {m.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
