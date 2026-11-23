PHASE X — OPTIMIZED BLIND CROSS-COLUMN SUPPORT SEARCH

This package contains an optimized Python implementation, not the planned C++ engine.
It caches per-column/per-row-subset candidate sets, so the 544 support hypotheses
reuse local candidate computations. GF(256) multiplication is table-backed.

Scope:
- Exactly three distinct faulty AES state bytes.
- 288 2+1 hypotheses and 256 1+1+1 hypotheses (544 total).
- Three correct/faulty pairs per trial.
- Unknown row and column support.
- Four exploratory trials (two per distribution).

Observed:
- All four trials retained the true support and uniquely identified it.
- Proof-of-function only; not a statistical success-rate claim.
- 3+0+0 (three faults in one column) is excluded.
- Full AES-128 master-key recovery is not demonstrated.
- Software fault injection only.

Run:
  python dfa_phase10_cached_search.py

Dependencies:
  dfa_phase9_cross_column.py
  dfa_aes_baseline_verified.py
