PHASE XIV — STATISTICAL VALIDATION OF BLIND THREE-FAULT SUPPORT RECOVERY

Run: python dfa_phase14_statistical_blind.py
Configured preliminary sample: 3 trials for 3+0+0, 3 for 2+1, and 1 for 1+1+1.
Dependencies: Python 3 standard library, matplotlib; C++17 compiler for dfa_phase14_small_solver; existing phase IX/XIII modules and compiled dfa_phase7_generate/dfa_phase7_filter executables.

{
  "phase": "XIV",
  "purpose": "Preliminary statistical validation of blind exactly-three-byte support recovery over all 560 supports.",
  "trial_counts_by_pattern": {
    "3+0+0": 3,
    "2+1": 3,
    "1+1+1": 1
  },
  "total_trials": 7,
  "ciphertext_pairs_per_trial": 5,
  "fault_magnitudes": "independently sampled nonzero XOR magnitudes for each fault in each pair",
  "plaintexts": "fresh random plaintext per pair",
  "AES_keys": "fresh random AES-128 key per trial",
  "support_distributions": [
    {
      "pattern": "3+0+0",
      "trials": 3,
      "unique_correct": 3,
      "unique_recovery_rate": 1.0,
      "wilson95_low": 0.43849391955098227,
      "wilson95_high": 1.0,
      "true_support_survival_rate": 1.0,
      "mean_viable_supports": 1,
      "mean_false_positive_supports": 0,
      "mean_runtime_seconds": 3.206237681000251,
      "median_runtime_seconds": 3.2097108969992405
    },
    {
      "pattern": "2+1",
      "trials": 3,
      "unique_correct": 3,
      "unique_recovery_rate": 1.0,
      "wilson95_low": 0.43849391955098227,
      "wilson95_high": 1.0,
      "true_support_survival_rate": 1.0,
      "mean_viable_supports": 1,
      "mean_false_positive_supports": 0,
      "mean_runtime_seconds": 5.035678833999555,
      "median_runtime_seconds": 5.003965313999288
    },
    {
      "pattern": "1+1+1",
      "trials": 1,
      "unique_correct": 1,
      "unique_recovery_rate": 1.0,
      "wilson95_low": 0.20654329147389294,
      "wilson95_high": 1.0,
      "true_support_survival_rate": 1.0,
      "mean_viable_supports": 1,
      "mean_false_positive_supports": 0,
      "mean_runtime_seconds": 6.920353513000009,
      "median_runtime_seconds": 6.920353513000009
    }
  ],
  "hypothesis_space": "C(16,3)=560 supports: 16 (3+0+0), 288 (2+1), 256 (1+1+1)",
  "limitations": [
    "Preliminary small-sample experiment; confidence intervals are wide.",
    "Blind decision uses nonempty per-column candidate intersections.",
    "No complete master-key recovery is claimed: three faulty bytes touch at most three AES columns.",
    "Software fault injection model only; hardware fault behavior is not represented."
  ]
}
