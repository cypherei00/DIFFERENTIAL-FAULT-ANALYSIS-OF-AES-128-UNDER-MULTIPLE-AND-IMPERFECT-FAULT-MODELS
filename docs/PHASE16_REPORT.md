# Phase XVI — Comparative Evaluation

## Summary

Phase XVI consolidates measured outputs from Phases III, VII, IX, XIV and XV. It is an evidence synthesis, not a new attack run. The success criteria and workloads differ, so the table is descriptive rather than a controlled head-to-head benchmark.

| Approach | Trials | Observed success | Criterion | Mean runtime/trial |
|---|---:|---:|---|---:|
| Conventional single-byte DFA (Phase III) | 30 | 30/30 (100.0%) | Full AES-128 master key recovered by <=12 pairs | 0.345s |
| Known-support three-byte DFA (Phase VII) | 120 | 120/120 (100.0%) | Full AES-128 master key recovered | 1.638s |
| Known-support cross-column DFA (Phase IX) | 16 | 16/16 (100.0%) | All affected K10 column groups recovered | 0.386s |
| Blind three-byte support recovery (Phase XIV) | 7 | 7/7 (100.0%) | Unique correct support among 560 hypotheses | 4.521s |
| Multi-event blind master-key recovery (Phase XV) | 1 | 1/1 (100.0%) | All event supports identified and complete AES-128 master key verified | 14.513s |

## Main findings

- **Conventional single-byte DFA:** 30/30 recorded trials recovered the full master key by at most 12 faulty pairs. The aggregate candidate curve shows 90% full-key recovery at two pairs and 100% from three pairs onward.
- **Known-support three-byte DFA:** 120/120 recorded trials recovered the complete master key across four row triples (30 trials each). This is not blind location recovery.
- **Known-support cross-column DFA:** 16/16 trials recovered all affected round-key groups, but unaffected groups were outside the claim.
- **Blind support recovery:** 7/7 Phase XIV trials uniquely identified the support among 560 hypotheses. The 1+1+1 category had only one trial.
- **Multi-event blind recovery:** Phase XV recovered and verified one complete AES-128 master key using three blind events and 15 correct/faulty pairs. This remains a single successful trial.

## Interpretation and limitations

1. Results across phases are not directly comparable because attack assumptions, fault geometries, pair counts, success criteria, and implementations differ.
2. Runtime is descriptive of these implementations and this execution environment; it is not a hardware-independent complexity result.
3. All results use simulated round-9 transient XOR faults after ShiftRows and before MixColumns. No physical fault injection is represented.
4. Phase XIV and XV should be expanded with more independent trials before making reliability claims, especially for 1+1+1 support and complete multi-event key recovery.
5. The Phase XV recovery depends on support identification and per-column candidate sets; the full-key result is validated by matching the original key in the experiment.

## Figures

1. `phase16_observed_success.png` — observed success rates with sample counts; criteria differ.
2. `phase16_runtime_comparison.png` — recorded runtimes; workloads differ.
3. `phase16_baseline_candidates.png` — candidate reduction in conventional DFA.
4. `phase16_phase7_rowtriples.png` — known-support three-byte recovery by row triple.

## Reproducibility

Run `python dfa_phase16_comparative.py` from the package directory. The script reads the prior phase CSV/JSON artifacts and regenerates the comparison CSV, JSON report, Markdown report, and four figures. Dependencies: Python 3 and matplotlib.
