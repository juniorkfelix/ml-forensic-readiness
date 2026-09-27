# Research Question Traceability

Every metric, table and figure maps to at least one research question. Metric definitions are in
`config/evaluation_schema.yaml`. Table and figure numbers refer to spec §29/§30.

| RQ | Question (short) | Artefacts / evidence | Measures | Tables | Figures | Code |
|----|------------------|----------------------|----------|--------|---------|------|
| **RQ1** | Which lifecycle artefacts are useful evidence for poisoning investigations? | dataset evidence (IDs, digests, profiles, per-sample manifests); training evidence (run records, params, times); model evidence (artefact, hash, registry version); deployment and inference evidence (deployment records, per-request results, input hashes); integrity evidence | evidence availability per stage; evidence completeness (EC, items DS1–IG3) | T4 | F2, F7 | `evaluation/evidence_completeness.py` |
| **RQ2** | How can multi-source evidence be correlated to reconstruct the event sequence? | identifiers, timestamps, content hashes, provenance links (USED / WAS_GENERATED_BY / WAS_DERIVED_FROM), hash chain | event recovery rate (ERR); timeline coverage and ordering (Kendall τ-b, pairwise order accuracy); per-hop confidence classes | T5 | F3, F14, F15, F16, F17 | `reconstruction/*`, `evaluation/event_recovery.py`, `evaluation/timeline_accuracy.py` |
| **RQ3** | How much does forensic readiness improve evidence availability and reconstruction vs a conventional pipeline? | A vs B vs C, same incidents | EC, ERR, timeline accuracy, RCI component score (dataset / training run / model / poisoning source) plus precision/recall of the changed-sample set, reconstruction runtime; clean-control false-attribution rate | T4, T5, T7 | F7–F11 | `evaluation/root_cause.py`, `evaluation/statistics.py` |
| **RQ4** | What computational and storage overhead does forensic readiness add? | per-category storage, stage timings, resource samples | storage (bytes, MB, % over A); training and pipeline runtime (% over A); evidence-logging time; peak RAM; peak GPU memory | T6, T7 | F12, F13 | `evaluation/overhead.py` |
| (validity) | Is the manipulation and ML outcome as intended? | CA, ASR, poisoned-set equality across A/B/C | clean accuracy, attack success rate | T1, T2, T3 | F4, F5, F6 | `models/evaluate.py` |

Sub-questions from spec §49 and where they are answered:

| §49 question | Measure |
|---|---|
| How much evidence is available under A/B/C? | EC, T4 |
| How many true incident events can be recovered? | ERR |
| How accurately can their order be reconstructed? | Kendall τ-b, pairwise order accuracy |
| Can the poisoned dataset / training run / compromised model be identified? | RCI components |
| Can the link between the poisoning and the malicious inference be reconstructed? | full backward chain present with confidence ≥ MODERATE at every hop |
| Does provenance alone give most of the benefit? | B − A vs C − B contrasts (T7) |
| Does forensic-specific evidence add benefit? | C vs B contrast (T7) |
| Storage cost? Runtime overhead? | T6 |
