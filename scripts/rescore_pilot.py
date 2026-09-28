"""Re-run reconstruction + evaluation for completed pilot runs from STORED evidence (D-061).

No retraining and no new evidence: each run's existing evidence directory and incident
ticket are reconstructed with the current engine, then evaluated against ground truth
(read only after the new reconstruction file exists and is hashed). Engine v1.0 outputs
were preserved beforehand as *_engine_v1_0.json in each package and in
results/{reconstruction,evaluation}_engine_v1_0/.

Writes results/raw/rescoring_engine_v1_0_vs_v1_1.csv.

Usage: python scripts/rescore_pilot.py
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mlfref.evaluation.common import load_schema  # noqa: E402
from mlfref.evaluation.evaluate import evaluate_run  # noqa: E402
from mlfref.forensic.hashing import sha256_file  # noqa: E402
from mlfref.ground_truth.recorder import GroundTruthReader  # noqa: E402
from mlfref.harness import utc_now, write_csv  # noqa: E402
from mlfref.reconstruction import reconstruct  # noqa: E402
from mlfref.reconstruction.engine import ENGINE_VERSION  # noqa: E402
from mlfref.reconstruction.report import write_json, write_markdown  # noqa: E402


def metrics(ev: dict) -> dict:
    return {
        "ec": ev["evidence_completeness"]["ec"],
        "err": ev["event_recovery"]["err"],
        "tau": ev["timeline"]["kendall_tau_b"],
        "rci": (ev.get("root_cause") or {}).get("rci_score"),
        "clean_ok": (ev.get("clean_control") or {}).get("correct"),
    }


def main() -> int:
    index = list(csv.DictReader((ROOT / "results/raw/run_index.csv").open(encoding="utf-8")))
    latest = {
        r["experiment_id"]: r for r in index if r["phase"] == "pilot" and r["status"] == "completed"
    }
    schema = load_schema()
    comparison = []
    for exp, row in sorted(latest.items()):
        pkg, evidence = ROOT / row["package_dir"], ROOT / row["evidence_dir"]
        old_eval = json.loads((pkg / "evaluation_engine_v1_0.json").read_text(encoding="utf-8"))
        old_rec = json.loads((pkg / "reconstruction_engine_v1_0.json").read_text(encoding="utf-8"))
        ticket = json.loads((evidence / "incident_ticket.json").read_text(encoding="utf-8"))
        recon = reconstruct(evidence, ticket, ROOT)
        rpath = write_json(recon, ROOT / "results/reconstruction" / f"{exp}.json")
        write_markdown(
            recon,
            ROOT / "results/reconstruction" / f"{exp}.md",
            f"{exp} (RUN-{row['experiment_uuid']}), engine {ENGINE_VERSION}",
        )
        (pkg / "reconstruction.json").write_text(
            rpath.read_text(encoding="utf-8"), encoding="utf-8"
        )
        provenance = {
            "reconstruction_sha256": sha256_file(rpath),
            "engine_version": ENGINE_VERSION,
            "rescored_utc": utc_now(),
            "ground_truth_opened_utc": None,
        }
        provenance["ground_truth_opened_utc"] = utc_now()  # GT is read only after this point
        with GroundTruthReader(ROOT / row["ground_truth_db"]) as reader:
            ev = evaluate_run(
                recon,
                reader.events(row["experiment_uuid"]),
                reader.attack(row["experiment_uuid"]),
                json.loads((pkg / "run_summary.json").read_text())["attack_type"],
                schema,
                ROOT,
            )
        ev["provenance"] = provenance
        text = json.dumps(ev, indent=2, default=str)
        (pkg / "evaluation.json").write_text(text, encoding="utf-8")
        (ROOT / "results/evaluation" / f"{exp}.json").write_text(text, encoding="utf-8")
        o, n = metrics(old_eval), metrics(ev)
        comparison.append(
            {
                "experiment_id": exp,
                "pipeline": row["pipeline"],
                "attack": row["attack_type"],
                "seed": row["seed"],
                **{f"{k}_v1_0": o[k] for k in o},
                **{f"{k}_v1_1": n[k] for k in n},
                "finding_v1_0": old_rec["root_cause"]["finding"],
                "finding_v1_1": recon["root_cause"]["finding"],
                "changed": any(o[k] != n[k] for k in o)
                or old_rec["root_cause"]["finding"] != recon["root_cause"]["finding"],
            }
        )
        print(f"{exp}: {comparison[-1]['finding_v1_0']} -> {comparison[-1]['finding_v1_1']}")
    write_csv(ROOT / "results/raw/rescoring_engine_v1_0_vs_v1_1.csv", comparison)
    print(f"re-scored {len(comparison)} runs; changed: {sum(c['changed'] for c in comparison)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
