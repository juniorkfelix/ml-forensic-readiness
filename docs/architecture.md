# Architecture

**Status:** DRAFT. It will be updated as each phase is implemented.

## 1. Layers and trust boundaries

```
┌──────────────────────────── RESEARCH HARNESS (scripts/, orchestration) ─────────────────────────────┐
│ config resolution · experiment IDs · seeding · timing/storage measurement · run index · packaging   │
│                                                                                                     │
│   ┌──────────── ADVERSARY (mlfref.attacks) ────────────┐    ┌──── GROUND TRUTH (hidden) ────┐       │
│   │ label flip · backdoor: modifies the data store     │──► │ mlfref.ground_truth.recorder  │       │
│   └────────────────────────────────────────────────────┘    │ ground_truth/ground_truth.sqlite│     │
│                                                             └──────────────┬────────────────┘       │
│   ┌──────────────────── ML PIPELINE (shared code path) ──────────────────┐ │                        │
│   │ mlfref.data → mlfref.models.train → evaluate → deployment → inference│ │                        │
│   │        │ evidence hooks (enabled by pipeline mode)                   │ │                        │
│   │        ├─ app logging (A,B,C)       mlfref.logging_utils             │ │                        │
│   │        ├─ MLflow provenance (B,C)   mlfref.provenance                │ │                        │
│   │        └─ forensic store (C)        mlfref.forensic                  │ │                        │
│   └────────────────────────────┬─────────────────────────────────────────┘ │                        │
│                                ▼                                           │                        │
│             evidence/<mode>/RUN-<uuid>/, mlruns/  (INVESTIGATOR-VISIBLE)   │                        │
│                                │                                           │                        │
│   ┌──── RECONSTRUCTION (mlfref.reconstruction) ────┐                       │                        │
│   │ reconstruct(evidence_dir, incident_ticket)     │  ✗ no access to GT    │                        │
│   └────────────────────────────┬───────────────────┘                       │                        │
│                                ▼                                           ▼                        │
│   ┌──────── EVALUATION (mlfref.evaluation) — only component that sees both ─────────┐               │
│   │ EC · ERR · timeline · RCI · runtime · overhead → statistics → reporting        │               │
│   └─────────────────────────────────────────────────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## 2. Module dependency rules (enforced by tests where marked ✔)

| Module | May import | Must NOT import |
|---|---|---|
| `mlfref.reconstruction` | stdlib, pandas/numpy/networkx, `mlfref.forensic.hashing`/`schema` (read-only formats), `mlfref.config.canonical_json` | `mlfref.ground_truth` ✔, `mlfref.evaluation` ✔, `mlfref.experiment_id` ✔, `mlfref.attacks` ✔ |
| pipeline modules (`data`, `models`, `provenance`, `forensic`) | each other, `config`, `reproducibility`, `logging_utils` | `mlfref.ground_truth` ✔, `mlfref.attacks` ✔ (the harness applies attacks) |
| `mlfref.attacks` | `data`, `ground_truth` | `reconstruction` |
| `mlfref.evaluation` | everything | — |

## 3. Key design decisions
See `docs/methodology_decisions.md`. The most important:
- D-005/D-006: one ML code path, and pipelines differ only in evidence instrumentation.
- D-014/D-021: covert attack, with opaque run references in evidence.
- D-015: data-store tampering threat model.
- D-016: record-only integrity checks.
- D-019: evidence is preserved, not interpreted.
