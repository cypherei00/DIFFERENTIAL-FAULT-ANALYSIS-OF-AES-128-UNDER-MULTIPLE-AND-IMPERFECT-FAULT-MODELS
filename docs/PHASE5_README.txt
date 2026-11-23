PHASE V — TWO-BYTE SAME-COLUMN DFA PROTOTYPE

Fault model: two nonzero XOR faults at rows 0 and 1 of the same AES state column, round 9 after ShiftRows and before MixColumns. Magnitudes are unknown to the recovery algorithm and independently randomized per pair.
The four MixColumns output differences are [2e0 XOR 3e1, e0 XOR 2e1, e0 XOR e1, 3e0 XOR e1] in GF(2^8).
Recovery enumerates all 255*255 nonzero magnitude pairs per faulty pair, derives key-byte candidates through the inverse-S-box equation, forms 4-byte tuples, and intersects tuple sets across pairs.

Trials: 10; master-key recoveries: 10/10 (100.0%). Runtime: 19.21s. Seed: 20261119.
This is a research prototype for a constrained two-byte fault model, not a general multiple-fault solution. The two fault rows and affected column are assumed known; the two magnitudes and round-10 key are unknown to the recovery procedure.
Candidate counts are per four-byte column tuple. A zero intersection means the selected pair budget did not yield a surviving model; do not discard these failures.
