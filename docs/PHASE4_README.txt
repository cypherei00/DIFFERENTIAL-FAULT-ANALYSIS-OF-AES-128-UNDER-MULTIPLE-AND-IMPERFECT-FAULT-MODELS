PHASE IV — IMPERFECT FAULT MODEL DIAGNOSTICS

These experiments use the verified AES implementation and inject faults at round 9 after ShiftRows and before MixColumns.
Crucial limitation: the compatibility tests use the true AES-128 final-round key to isolate whether the observed differential is consistent with a hypothesized single-byte fault. This is a diagnostic/model-fit study, not a blind key-recovery attack.

Unknown-location experiment: 100 single-byte trials, location uniform over all 16 state bytes.
True hypothesis present: 100.00%; uniquely identified by oracle test: 100.00%.

Multiple-fault experiments: 100 trials per condition; k=2,4,8. “same_column” for k=8 uses two adjacent columns (4+4) because one AES column contains only four byte positions.
The compatibility metric asks whether ANY single-byte (row,column) hypothesis, evaluated with the true round-10 key, explains the complete ciphertext differential.

Runtime: 12.26 seconds. Seeds: 20261117 and 20261118.
