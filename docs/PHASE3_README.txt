PHASE III — AES-128 DFA QUANTITATIVE BASELINE

Contents
- dfa_phase3_experiments.py: reproducible experiment driver (imports dfa_aes_baseline_verified.py)
- dfa_aes_baseline_verified.py: verified AES/DFA implementation
- phase3_pairwise_results.csv: per-trial, per-column, per-pair-count observations (30 randomized trials)
- phase3_aggregate_results.csv: aggregated baseline measurements
- phase3_trial_summary.csv: full-key recovery pair counts per trial
- phase3_magnitude_results.csv: fixed-magnitude versus random-per-pair magnitude comparison
- phase3_hamming_weight_results.csv: exact Hamming-weight strata, 5 trials per weight, 2 pairs per column
- phase3_run_metadata.csv: baseline settings and seed
- phase3_*.png: plots

Model and limits
AES-128; round-9 fault after ShiftRows and before MixColumns; one row-0 byte XOR fault in the selected column per pair; corresponding correct/faulty ciphertexts; one plaintext per pair; unknown nonzero magnitude. The recovery routine enumerates epsilon=1..255. Fault locations and round are known in these baseline experiments. No multiple-byte faults or unknown-location attacks are tested here.

Main baseline observations (30 independent keys/trials; 120 column observations per pair-count):
- One pair: mean 266.4 surviving four-byte round-10-key candidates per column; no unique column recovery.
- Two pairs: 117/120 columns uniquely recovered (97.5%); 27/30 complete AES-128 keys recovered (90%).
- Three pairs: 120/120 columns and 30/30 complete keys recovered (100%).
- All tested full-key trials retained the true key group; no false unique recovery was observed.

Magnitude comparison (10 fixed-magnitude trials vs 30 random-magnitude trials; column-level observations):
- At two pairs: fixed 0x53 magnitude recovered 38/40 columns (95%); random magnitude per pair recovered 117/120 (97.5%).
- At four or more pairs: both groups achieved unique recovery in all observed columns.
This is descriptive, not evidence of statistical equivalence; sample sizes differ.

Hamming-weight strata (5 trials x 4 columns = 20 observations per weight):
- At two pairs, unique recovery ranged from 18/20 to 20/20 across weights 1..8 (90%-100%).
- There is no monotonic trend in this small sample. Do not claim Hamming weight has no effect; report this only as preliminary evidence that the tested exact-weight magnitudes do not show a clear monotonic pattern.

Reproduction
Place dfa_phase3_experiments.py and dfa_aes_baseline_verified.py in the same directory, install matplotlib, then run:
python dfa_phase3_experiments.py
The script writes CSVs and plots next to itself.

Interpretation cautions
- These are software-injected faults under a controlled, known-location model, not physical fault-injection measurements.
- The sample sizes are suitable for an initial baseline, not broad population-level claims. Increase trials and add confidence intervals before final publication.
- Recovery is implemented for the row-0 single-byte model. The all-16-location tests in the verified implementation validate propagation geometry only, not generalized recovery.
