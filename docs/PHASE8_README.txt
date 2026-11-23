PHASE VIII — UNKNOWN THREE-BYTE FAULT LOCATION: STATISTICAL EVALUATION

Design: 30 independent trials; 16 hypotheses per trial (four row triples x four columns); eight correct/faulty pairs per trial; deterministic seed 20261117. Each trial uses a fresh AES-128 key and plaintexts, with independently randomized nonzero fault magnitudes.

Outcome: 30/30 unique location recoveries (100.0%). Wilson 95% interval: 88.6%–100%.
Mean pairs retained for true hypothesis: 8.00; mean search runtime per trial: 2.352s; total measured search time: 70.56s.

The attack does not receive the true row triple or column. It evaluates all 16 hypotheses against the same eight pairs. The ground-truth location is used only to score the output. A successful trial requires exactly one surviving hypothesis, equal to the true location, with exactly one four-byte round-10 key candidate.

Scope limitations: one fault cluster in one state column; software fault injection; location and one four-byte final-round-key group recovered. No complete 128-bit master-key recovery is claimed for unknown-location trials. Hardware faults, cross-column faults, and unknown fault count are outside this phase.
