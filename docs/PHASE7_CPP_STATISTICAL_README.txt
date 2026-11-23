PHASE VII — THREE-BYTE AES DIFFERENTIAL FAULT ANALYSIS
Statistical evaluation package

EXPERIMENT
- AES-128.
- Three simultaneous, nonzero XOR faults in three distinct rows of one state column.
- Injection: round 9, after ShiftRows and before MixColumns.
- Four known row triples: 012, 013, 023, 123.
- Faulted column and row triple are assumed known to the attacker.
- Fault magnitudes are independently randomized and unknown to the recovery algorithm.
- Each trial uses a fresh random AES-128 key and fresh plaintext/fault pairs.
- Four columns are attacked per trial; at most six faulty pairs per column.

RESULTS
- 30 trials per row triple; 120 trials total.
- 4 columns per trial; 480 column recovery experiments.
- All 120/120 trials recovered all four 4-byte final-round-key groups uniquely.
- All 480/480 column recoveries produced a unique candidate equal to the known ground-truth group.
- AES-128 inverse key expansion was checked for all 120 trial keys; all matched.
- Mean pairs per column: 4.5958.
- Mean column runtime: 0.390645 seconds (measured in this execution environment).
- Median column runtime: 0.383325 seconds.
- Mean trial runtime: 1.638454 seconds.
- Candidate file peak size: 66,584,576 bytes (~63.5 MiB). This is on-disk candidate storage, NOT measured peak RAM.

CANDIDATE COUNTS (pooled across 480 column experiments)
- After pair 1: mean 16,580,975.7 candidates.
- After pair 2: mean 64,004.9 candidates.
- After pair 3: mean 248.2 candidates.
- After pair 4: mean 1.9 candidates.
- After pair 5: all but two columns had terminated by then; mean 1.0 among 284 columns reaching pair 5.
- Two columns required pair 6.

IMPORTANT INTERPRETATION
The observed success rate was 30/30 for each row triple. This is an empirical result for the specified controlled model, not proof of a 100% population success probability. The experiment assumes known faulted rows and column. It does not establish recovery with unknown fault locations, faults across multiple columns, persistent faults, or hardware fault injection.

FILES
- dfa_phase7_generate.cpp: C++ candidate generation.
- dfa_phase7_filter.cpp: C++ candidate filtering.
- dfa_phase7_cpp_statistical.py: statistical experiment runner.
- dfa_phase7_cpp_resume_batch.py: checkpoint/resume runner used for this batch.
- dfa_phase7_three_byte.py: Python differential model and pair generation.
- dfa_aes_baseline_verified.py: AES implementation and key schedule.
- phase7_cpp_column_trials.csv: one row per column experiment.
- phase7_cpp_trial_summary.csv: one row per trial.
- phase7_cpp_statistical_summary.csv: aggregate by row triple.
- phase7_cpp_candidate_reduction.png: candidate-reduction plot.
- PHASE7_CPP_STATISTICAL_REPORT.json: machine-readable experiment summary.

REPRODUCIBILITY
Compile from this directory:
  g++ -O3 -std=c++17 dfa_phase7_generate.cpp -o dfa_phase7_generate
  g++ -O3 -std=c++17 dfa_phase7_filter.cpp -o dfa_phase7_filter
Run a fresh 30-trial-per-row-triple batch:
  python dfa_phase7_cpp_statistical.py --trials 30 --seed 20261117 --pairs 6

The saved CSVs are the results of the executed batch. Re-running with the same seed should reproduce the generated test sequence, subject to Python/runtime version consistency.
