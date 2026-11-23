PHASE XV — MULTI-EVENT BLIND AES-128 MASTER-KEY RECOVERY

Run: python dfa_phase15_multi_event.py
Requires Python 3, matplotlib for plots, g++ (C++17), and the Phase VII C++ generator/filter plus Phase XIV small solver.
The recovery stage receives only correct/faulty ciphertext pairs; it enumerates all 560 supports independently for every event.

{
  "phase": "XV",
  "seed": 20261117015,
  "events": 3,
  "ciphertext_pairs_per_event": 5,
  "total_correct_faulty_pairs": 15,
  "faults_per_event": 3,
  "same_AES128_key_across_events": true,
  "support_hidden_from_recovery": true,
  "support_union_covers_all_four_columns": true,
  "event_results": [
    {
      "event": 1,
      "pairs": 5,
      "true_support": "0:0;0:1;0:2",
      "hypotheses_tested": 560,
      "viable_supports": 1,
      "unique_correct_support": 1,
      "recovered_column_groups": 1,
      "affected_columns": 1,
      "groups_match_true_K10": 1,
      "runtime_seconds": 5.5458696000278,
      "surviving_supports": "0:0|0:1|0:2"
    },
    {
      "event": 2,
      "pairs": 5,
      "true_support": "1:1;1:2;2:0",
      "hypotheses_tested": 560,
      "viable_supports": 1,
      "unique_correct_support": 1,
      "recovered_column_groups": 2,
      "affected_columns": 2,
      "groups_match_true_K10": 1,
      "runtime_seconds": 8.697745500016026,
      "surviving_supports": "1:1|1:2|2:0"
    },
    {
      "event": 3,
      "pairs": 5,
      "true_support": "0:3;2:2;3:2",
      "hypotheses_tested": 560,
      "viable_supports": 1,
      "unique_correct_support": 1,
      "recovered_column_groups": 3,
      "affected_columns": 3,
      "groups_match_true_K10": 1,
      "runtime_seconds": 12.381590100005269,
      "surviving_supports": "0:3|2:2|3:2"
    }
  ],
  "recovered_K10_hex": "2512beceee7b6c4b5c1b03e487cfcf89",
  "true_K10_hex": "2512beceee7b6c4b5c1b03e487cfcf89",
  "full_K10_coverage": true,
  "recovered_master_key_hex": "97884e868fcb18b3cfeae7137c649b7e",
  "true_master_key_hex": "97884e868fcb18b3cfeae7137c649b7e",
  "full_master_key_verified": true,
  "total_runtime_seconds": 26.628681399975903,
  "limitations": [
    "Single reproducible multi-event experiment; not a statistical success-rate estimate.",
    "Each event has a fixed three-byte support across its pairs; support and magnitudes are unknown to recovery.",
    "Blind support selection uses nonempty per-column candidate intersections; group bytes are accepted only when the support is unique and the group candidate set is singleton.",
    "Software fault injection at round 9 after ShiftRows and before MixColumns; no physical fault validation."
  ]
}
