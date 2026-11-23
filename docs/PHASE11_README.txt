PHASE XI — COMPLETE THREE-BYTE SUPPORT ENUMERATION

The 16 AES state cells are represented as (column,row). Exactly three distinct cells are selected.
The complete space is C(16,3)=560, partitioned into 3-in-one-column: 16; 2+1: 288; 1+1+1: 256.

This is a combinatorial support enumerator and validation artifact only. It is not evidence of blind DFA recovery.

{
  "phase": "XI",
  "scope": "Exhaustive enumeration of exactly-three-byte fault supports across the 16 AES state cells.",
  "total_supports": 560,
  "distribution_counts": {
    "1+1+1": 256,
    "2+1": 288,
    "3": 16
  },
  "identity": "C(16,3) = 560 = 16 + 288 + 256",
  "validation": "PASS: every support is unique and all distribution counts match combinatorics.",
  "important_limitation": "This phase validates and enumerates the complete support space. It does not run blind DFA key-candidate recovery, identify a support from ciphertexts, or recover an AES round key/master key."
}