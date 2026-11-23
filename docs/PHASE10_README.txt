PHASE X — BLIND CROSS-COLUMN FAULT SUPPORT SEARCH (PROTOTYPE)

Run:
  python dfa_phase10_blind_cross_column.py

The program constructs 544 hypotheses for exactly three distinct faulted state bytes:
  * 288 supports with a 2+1 column distribution.
  * 256 supports with a 1+1+1 column distribution.

For each support it groups fault rows by AES state column and applies the existing per-column DFA candidate procedure. It continues checking all available pairs even when a candidate set becomes a singleton, to avoid premature acceptance.

Important limitations:
  * The all-in-one-column 3+0+0 distribution is deliberately excluded from this prototype.
  * The current Python exhaustive run exceeded the 300-second execution limit. Therefore no empirical success claim is made.
  * A unique location hypothesis is not equivalent to full AES-128 master-key recovery; unaffected column key groups remain unknown.
  * This is software fault injection, not physical/hardware validation.

The next optimization is a C++ batched search with shared inverse-S-box differential maps, candidate bitsets, and early rejection.
