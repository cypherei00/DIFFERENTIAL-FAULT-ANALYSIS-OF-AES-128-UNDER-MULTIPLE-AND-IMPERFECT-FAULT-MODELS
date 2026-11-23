PHASE IX — CROSS-COLUMN MULTIPLE-FAULT DFA (EXPLORATORY)

Patterns: 2+1 faults over two columns; 1+1+1 faults over three columns. Each affected column is attacked using the corresponding 1-byte or 2-byte same-column model. Fault rows and affected columns are known to the recovery stage in this first experiment.
The result measures recovery of the four-byte K10 group for each affected column. It does not recover unaffected column groups and therefore does not claim full master-key recovery or unknown-location recovery.

{
  "seed": 20261117,
  "trials_per_pattern": 8,
  "total_trials": 16,
  "patterns": {
    "2+1": {
      "trials": 8,
      "successful_all_affected_groups": 8,
      "success_rate": 1.0
    },
    "1+1+1": {
      "trials": 8,
      "successful_all_affected_groups": 8,
      "success_rate": 1.0
    }
  },
  "runtime_seconds": 6.180166403999465,
  "scope": [
    "Three faults distributed across two or three AES state columns.",
    "Known per-column row support and affected columns are supplied to the recovery stage.",
    "Per-column 1- and 2-byte DFA models recover the affected column key groups.",
    "Unaffected columns are not recovered; complete 128-bit master-key recovery is not claimed.",
    "Software fault injection only."
  ]
}