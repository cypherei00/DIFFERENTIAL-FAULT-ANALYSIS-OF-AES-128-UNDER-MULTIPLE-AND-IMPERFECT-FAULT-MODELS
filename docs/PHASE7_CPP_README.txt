PHASE VII — THREE-BYTE AES DFA WITH C++ CANDIDATE GENERATION AND FILTERING

Status
------
A complete proof-of-function key recovery was executed for all four possible
three-row fault configurations and all four AES state columns. This is one
reproducible validation trial per row configuration, not a statistical study.

Fault model
-----------
AES-128. Three distinct bytes in one known state column are XOR-corrupted in
round 9 after ShiftRows and before MixColumns. The three faulted rows and the
faulted column are known to the attacker; the three nonzero fault magnitudes,
round-10 key, and master key are unknown. Each pair uses the same plaintext
for correct and faulty encryption. New pairs use independently generated
plaintexts and fault magnitudes.

Implementation
--------------
- dfa_phase7_generate.cpp: C++ candidate generator. It enumerates the first two
  fault magnitudes and a candidate final-round key byte, solves the third
  magnitude algebraically, then emits compatible packed 32-bit key tuples.
- dfa_phase7_filter.cpp: C++ filter. It reconstructs the three fault magnitudes
  from three output differential equations using a 3x3 GF(256) inverse and
  checks the fourth equation.
- dfa_phase7_cpp_full_validation.py: generates AES fault pairs using the
  verified hand-written AES implementation, prepares byte-differential maps,
  calls the C++ generator/filter, intersects candidate sets, assembles K10,
  and inverts the AES-128 key schedule.
- dfa_phase7_three_byte.py: mathematical/Python reference implementation.
- dfa_aes_baseline_verified.py: AES-128 implementation and known-answer tests.

GF(256) multiplication is implemented directly with the AES polynomial
x^8+x^4+x^3+x+1 (reduction constant 0x1B). No third-party cryptography or
algorithm libraries are used in the C++ attack engine.

Measured validation
-------------------
Seed: 7312026
Master key used: AA4DB2ADD7E8384BBAFCACD454692373
Round-10 key: 204678D6F0BE22E13EBB85521CF6F7AB
Recovered master key: AA4DB2ADD7E8384BB AFCACD454692373
Full master-key verification: PASS

For each of the four row triples (012, 013, 023, 123), all four column
subkeys were uniquely recovered, assembled into K10, and inverted to the
original master key. Total measured runtime for the full 16-column-case
validation was approximately 7.3 seconds in this runtime environment.

Candidate counts
----------------
For the 16 column cases, the initial candidate set was approximately 16.57M
through 16.65M tuples. Filtering typically reduced it to about 64k after the
second pair, about 212–276 after the third pair, and to 1–5 candidates after
the fourth pair. In all cases, the correct tuple survived; a fifth pair was
used where needed to obtain a unique tuple. Some columns reached uniqueness
by the third or fourth pair. The CSV contains exact counts and per-stage times.

Important interpretation / limitations
---------------------------------------
1. This demonstrates feasibility for the stated known-row, known-column,
   three-byte same-column fault model. It does not solve unknown fault location.
2. One trial per row triple is an implementation validation, not a reliable
   estimate of attack success probability.
3. The 7.3-second figure is measured for this environment and this single
   validation batch; it is not a general performance claim.
4. The experiment uses software fault injection at a controlled internal AES
   state location. It does not demonstrate physical fault injection against
   hardware.
5. The generator emits a large initial candidate list (~66 MB when packed as
   uint32). The C++ filter keeps the memory footprint bounded by streaming
   candidates and writing survivors.
6. The attacker is assumed to know the three faulted rows and column. Unknown
   row/column hypotheses remain future work.

Reproducibility
---------------
Compile on Linux:
  g++ -O3 -march=native -std=c++17 dfa_phase7_generate.cpp -o dfa_phase7_generate
  g++ -O3 -march=native -std=c++17 dfa_phase7_filter.cpp -o dfa_phase7_filter

Run with Python modules in the same directory:
  python dfa_phase7_cpp_full_validation.py

The Python runner imports dfa_phase7_three_byte.py and
 dfa_aes_baseline_verified.py. It writes pairwise and full-validation CSVs,
plus PHASE7_CPP_VALIDATION.json.
