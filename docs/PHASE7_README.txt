PHASE VII — THREE-BYTE AES DFA: OPTIMIZED CANDIDATE-GENERATOR PROTOTYPE

Model
- AES-128, fault injection in round 9 after ShiftRows and before MixColumns.
- Exactly three distinct bytes in one known state column are XOR-corrupted.
- The three faulted rows and column are assumed known; magnitudes and K10 are unknown.

Mathematics
For row triple (a,b,c), Delta_out[r] = M[r,a]*ea XOR M[r,b]*eb XOR M[r,c]*ec in GF(2^8).
The implementation enumerates ea, eb and the candidate K10 byte at output row 3, then solves ec from that row because M[3,c] is nonzero. It tests the other output-row equations using inverse-S-box differentials.

Implementation status
- The optimized one-pair candidate generator was executed for row triple (0,1,2), column 0.
- It generated 16,578,688 compatible packed 4-byte round-key tuples in 9.167 seconds.
- The true round-10 key tuple was present in the generated candidate set.
- A separate filtering experiment on that same generated dataset reduced the candidates to 63,953 after a second pair and 224 after a third pair. The true key remained in the set.
- This did NOT reach a unique candidate, and no complete master-key recovery result is claimed.
- The complete all-row-triples/all-columns run did not finish within the execution time budget. The Python-level filtering loop is the current bottleneck. The memory-bounded implementation stores candidates as packed uint32 values (approximately 4 bytes per candidate), but 16M candidates still require substantial memory and filtering work.

Important correction to the initial complexity estimate
The algebraic elimination replaces a 255^3 magnitude enumeration with a loop over 255*255*256 = 16,646,400 (ea, eb, K3) hypotheses. It does not make the search small; it only avoids independently enumerating ec.

Next engineering step
Move candidate filtering to optimized C/C++ or use a more compact constraint/intersection strategy before attempting large trial batches. Do not cite the exploratory candidate counts as a successful three-byte key-recovery result.
