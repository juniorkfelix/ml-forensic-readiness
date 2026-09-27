"""Readable view of a forensic evidence store (Screenshots S09-S12).

Opens the store READ-ONLY and prints a formatted event table; optionally verifies
the hash chain and lists integrity-check results.

Usage:
    python scripts/view_evidence.py --db evidence/forensic/RUN-<uuid>/forensic_evidence.sqlite
        [--type MODEL_DEPLOYED] [--limit 30] [--verify] [--details]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mlfref.forensic.integrity import read_events_readonly, verify_chain  # noqa: E402


def short(value: str | None, n: int = 12) -> str:
    if not value:
        return "-"
    return value if len(value) <= n else value[:n] + "…"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--db", required=True)
    p.add_argument("--type", help="only this event_type")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--verify", action="store_true", help="verify the hash chain")
    p.add_argument("--details", action="store_true", help="print metadata for each event")
    args = p.parse_args()

    events = read_events_readonly(args.db)
    shown = [e for e in events if not args.type or e.event_type == args.type][: args.limit]
    print(f"Forensic evidence store: {Path(args.db).name}  ({len(events)} events, read-only)\n")
    header = (
        f"{'seq':>4}  {'timestamp (UTC)':<27} {'event_type':<27} {'artifact_id':<30} "
        f"{'artifact_hash':<14} {'run_id':<14} {'event_id':<14}"
    )
    print(header)
    print("-" * len(header))
    for e in shown:
        print(
            f"{e.sequence_number:>4}  {e.timestamp_utc:<27} {e.event_type:<27} "
            f"{short(e.artifact_id, 28):<30} {short(e.artifact_hash):<14} "
            f"{short(e.run_id):<14} {short(e.event_id):<14}"
        )
        if args.details:
            print(f"      metadata: {json.dumps(json.loads(e.metadata_json), sort_keys=True)}")

    if args.verify:
        report = verify_chain(events)
        print("\nHash-chain verification")
        print(
            f"  events: {report.n_events}   hash-chained: {report.hash_chained}   "
            f"result: {'VALID' if report.valid else 'INVALID'}"
        )
        print(f"  head hash: {report.head_hash}")
        for prob in report.problems:
            print(f"  ! seq {prob['sequence_number']}: {prob['problem']} - {prob['detail']}")
        checks = [
            e
            for e in events
            if e.event_type
            in (
                "ARTIFACT_INTEGRITY_CHECK",
                "DATASET_INTEGRITY_VERIFIED",
                "ARTIFACT_INTEGRITY_FAILURE",
            )
        ]
        if checks:
            print("\nIntegrity checks")
            print(
                f"  {'event_type':<27} {'artifact_id':<30} {'expected':<14} {'observed':<14} "
                "result"
            )
            for e in checks:
                m = json.loads(e.metadata_json)
                print(
                    f"  {e.event_type:<27} {short(e.artifact_id, 28):<30} "
                    f"{short(m.get('expected')):<14} {short(m.get('observed')):<14} "
                    f"{m.get('result', '-')}"
                )
    return 0


if __name__ == "__main__":
    sys.exit(main())
