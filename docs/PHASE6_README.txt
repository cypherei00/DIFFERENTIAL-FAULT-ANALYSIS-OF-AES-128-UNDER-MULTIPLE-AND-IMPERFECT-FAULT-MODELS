PHASE VI-B — TWO-BYTE SAME-COLUMN DFA FOR ALL SIX ROW PAIRS

Fault point: round 9, after ShiftRows and before MixColumns. Two distinct rows in the same known column are XOR-corrupted. Both nonzero magnitudes are independently randomized per pair and hidden from recovery.
All six row pairs are tested: 0-1, 0-2, 0-3, 1-2, 1-3, 2-3. For input rows a,b, output row r differential is M[r,a]*epsilon_a XOR M[r,b]*epsilon_b in GF(2^8).
Trials per row-pair condition: 1; up to 8 faulty pairs generated per column; seed: 20261120; measured total runtime: 21.55 seconds. The recovery stopped once a column had one surviving tuple.

Rows 0-1: master-key recovery 1/1; mean candidates after 1/2/3 pairs = 65536.00 / 1.75 / 1.00.
Rows 0-2: master-key recovery 1/1; mean candidates after 1/2/3 pairs = 64256.00 / 1.50 / 1.00.
Rows 0-3: master-key recovery 1/1; mean candidates after 1/2/3 pairs = 65000.00 / 1.75 / 1.00.
Rows 1-2: master-key recovery 1/1; mean candidates after 1/2/3 pairs = 64628.00 / 1.00 / N/A (no column required this prefix).
Rows 1-3: master-key recovery 1/1; mean candidates after 1/2/3 pairs = 64972.00 / 2.50 / 1.00.
Rows 2-3: master-key recovery 1/1; mean candidates after 1/2/3 pairs = 64904.00 / 1.00 / N/A (no column required this prefix).

Caveat: one trial per geometry is a proof-of-function smoke test only, not a statistically meaningful success-rate estimate. Results apply only to a known fault row-pair and known column. Both nonzero fault magnitudes and the round-10 key are unknown to recovery. Software fault injection is used; no physical fault injection is claimed.
