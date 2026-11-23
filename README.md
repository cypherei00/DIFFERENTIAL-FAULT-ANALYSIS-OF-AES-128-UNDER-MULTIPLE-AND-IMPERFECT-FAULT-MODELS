# AES-128 Differential Fault Analysis

Software study of differential fault analysis on AES-128 under multiple-byte and imperfect fault models. Faults are transient XOR faults injected in round 9, after ShiftRows and before MixColumns. Nothing in this folder is a physical fault-injection campaign.

The project title used in the baseline code is “Differential Fault Analysis under Multiple and Imperfect Fault Models.” The write-up in this folder is `AES_DFA_Final_Report.docx`.

Experiments are numbered as internal stages III through XVI. Those numbers are the names on the scripts, notes, tables, and plots. Four zip archives under `consolidated_phase_archives/` group that work into a shorter outline.

## Directory layout

```
AES_DFA/
├── AES_DFA_Final_Report.docx
├── MANIFEST.json
├── requirements.txt
├── run_all.py
├── run_all.bat
├── run_all.sh
├── README_FIRST.txt
├── README_RUN_FIRST.txt
├── source/
│   ├── python/          experiment scripts
│   ├── cpp/             C++ sources and extensionless binaries
│   └── shell/           run_phase15.sh
├── docs/                stage notes (PHASE3 … PHASE16)
├── results/
│   ├── csv/             recorded tables
│   ├── json/            recorded reports
│   └── graphs/          recorded plots
├── run_outputs/         working copies, Windows .exe builds, and files from run_all.py
├── consolidated_phase_archives/
├── reference papers/    background PDFs
└── reports/             empty
```

`source/python/` is the canonical script set. `run_outputs/` holds another copy of those scripts, the three `.cpp` files, Windows executables (`dfa_phase7_generate.exe`, `dfa_phase7_filter.exe`, `dfa_phase14_small_solver.exe`), and whatever the last `run_all.py` run wrote. `source/cpp/` has the same three `.cpp` files plus extensionless binaries (`dfa_phase7_generate`, `dfa_phase7_filter`, `dfa_phase14_small_solver`).

Recorded experiment data lives in `results/`. A new run writes beside the scripts it executes, which for `run_all.py` means `run_outputs/`.

## Experiment scripts

All of these are in `source/python/`. A matching note, when one exists, is in `docs/`.

| Script | Stage | Role |
| --- | --- | --- |
| `dfa_aes_baseline.py` | baseline | AES-128, software fault injection, classical single-byte DFA |
| `dfa_aes_baseline_verified.py` | baseline | Same core, with a self-test used by later scripts |
| `dfa_phase3_experiments.py` | III | Quantitative single-byte DFA baseline |
| `dfa_phase4_experiments.py` | IV | Imperfect-model diagnostics (unknown location, multiple faults). Uses the true round-10 key as an oracle; this stage is not a key-recovery attack |
| `dfa_phase5_two_byte.py` | V | Two simultaneous faults in one known column (rows 0 and 1) |
| `dfa_phase6_row_pairs.py` | VI | Two-byte same-column DFA for all six row pairs |
| `dfa_phase7_three_byte.py` | VII | Three-byte same-column DFA |
| `dfa_phase7_three_byte_optimized.py` | VII | Optimized three-byte prototype |
| `dfa_phase7_cpp_experiment.py` | VII | C++-accelerated filtering; Python still does AES and candidate generation |
| `dfa_phase7_cpp_full_validation.py` | VII | One-trial full-key check across row triples and columns |
| `dfa_phase7_cpp_statistical.py` | VII | Repeated-trial three-byte evaluation with the C++ engine |
| `dfa_phase7_cpp_resume_batch.py` | VII | Resume helper for the C++ batch |
| `dfa_phase8_unknown_location.py` | VIII | Unknown three-byte location search inside one column |
| `dfa_phase8_batch.py` | VIII | Batch driver for that search |
| `dfa_phase8_batch_resume.py` | VIII | Resume helper for the batch |
| `dfa_phase9_cross_column.py` | IX | Known-support faults split across columns (`2+1` and `1+1+1`) |
| `dfa_phase10_blind_cross_column.py` | X | Blind search over 544 cross-column supports (the all-in-one-column case is left out) |
| `dfa_phase10_cached_search.py` | X | Cached variant of that search |
| `dfa_phase11_support_space.py` | XI | Enumerates all C(16,3) = 560 three-byte supports. No key recovery |
| `dfa_phase12_unified_three_faults.py` | XII | Known-support `3+0+0` integration across all four columns |
| `dfa_phase13_blind_560.py` | XIII | Blind search over all 560 supports for one hidden support |
| `dfa_phase14_statistical_blind.py` | XIV | Small multi-trial check of that 560-support search |
| `dfa_phase15_multi_event.py` | XV | Three blind events, then master-key recovery |
| `dfa_phase16_comparative.py` | XVI | Reads earlier CSV/JSON files and writes a comparison. It does not run a new attack |

C++ engines, in `source/cpp/`:

| File | Role |
| --- | --- |
| `dfa_phase7_generate.cpp` | Candidate generation for the three-byte model |
| `dfa_phase7_filter.cpp` | Candidate filtering |
| `dfa_phase14_small_solver.cpp` | Solver used when a support is small enough for the later blind stages |

`source/shell/run_phase15.sh` compiles those three programs and then runs `dfa_phase15_multi_event.py`. It changes into its own directory first, and the `.cpp` files and the Python script are not in `source/shell/`, so run it only after those files are placed beside it, or use `run_all.py`.

## Recorded outputs

`results/csv/` holds the trial and aggregate tables (`phase3_*` through `phase16_comparison.csv`). `results/json/` holds `PHASE7_CPP_VALIDATION.json`, `PHASE7_CPP_STATISTICAL_REPORT.json`, `PHASE8_UNKNOWN_LOCATION_REPORT.json`, `PHASE8_STATISTICAL_REPORT.json`, and `PHASE9_REPORT.json` through `PHASE16_REPORT.json`. `results/graphs/` holds the PNG plots (`phase3_*` through `phase16_*`). There is no `figures/` directory.

Stage notes:

- `docs/PHASE3_README.txt` through `docs/PHASE16_REPORT.md`, with extra files `PHASE7_STATUS.txt`, `PHASE7_CPP_README.txt`, `PHASE7_CPP_STATISTICAL_README.txt`, `PHASE10_STATUS.txt`, and `PHASE10_OPTIMIZED_README.txt`
- There is no `PHASE1` or `PHASE2` note. The single-byte implementation is `dfa_aes_baseline.py` and `dfa_aes_baseline_verified.py`.

## Consolidated archives

`consolidated_phase_archives/` contains:

- `Phase_1_Foundations_and_Baseline.zip`
- `Phase_2_Known_Support_Multi_Fault_Recovery.zip`
- `Phase_3_Blind_Support_Identification.zip`
- `Phase_4_Multi_Event_Recovery_and_Comparison.zip`

`run_outputs/` also contains stage packages from individual runs: `AES_DFA_Phase5_Two_Byte_Package.zip`, `AES_DFA_Phase9_Cross_Column_Package.zip`, `AES_DFA_Phase13_Blind_560_Search.zip`, and `AES_DFA_Phase15_Multi_Event_Blind_Recovery.zip`.

## Reference papers

`reference papers/`:

- `A Differential Fault Attack Technique against SPN Structures.pdf`
- `Differential fault analysis of AES Toward reducing number of faults.pdf`
- `Differential Fault Analysis of Secret Key Cryptosystems.pdf`
- `Differential Fault Analysis of the Advanced Encryption Standard Using a Single Fault.pdf`
- `Differential Fault Attacks and Defenses in RSA Implementations.pdf`
- `Extended persistent fault based differential analysis in the multiple fault scenario.pdf`
- `From Precise to Random A Systematic Differential Fault Analysis of the Lightweight Block Cipher.pdf`

## Requirements

- Python 3.10 or newer
- `g++` with C++17 (MinGW-w64 on Windows, GCC on Linux or WSL)
- matplotlib (`requirements.txt` asks for `matplotlib>=3.7`)

```bash
python -m pip install -r requirements.txt
```

## Run

`run_all.py` is the one-command path. It works in `run_outputs/`, compiles the three C++ files there, then runs:

1. `dfa_aes_baseline_verified.py` self-test
2. `dfa_phase5_two_byte.py`
3. `dfa_phase9_cross_column.py`
4. `dfa_phase13_blind_560.py`
5. `dfa_phase15_multi_event.py`

```bash
python run_all.py
```

Windows: `py -3 run_all.py` or `run_all.bat`. Linux, macOS, or WSL: `python3 run_all.py` or `./run_all.sh`.

That set is a spot check. It does not rerun stages III, IV, VI, VII, VIII, X, XI, XII, XIV, or XVI. To rerun one of those, use the script in `source/python/` and the matching file in `docs/`. Scripts import each other by basename, so a stage and the files it imports need to sit in the same directory. Recompile the `.cpp` sources if the binary next to them was built for another operating system.

`dfa_phase16_comparative.py` only reads existing CSV and JSON results. Point it at the directory that holds those files.

## Scope of the recorded results

- Faults are software XOR faults at a fixed round and timing. The notes do not claim a lab fault-injection setup.
- Known-support stages (V, VI, VII, IX, XII) are told which bytes are faulty. Blind stages (VIII, X, XIII, XIV, XV) search for that support.
- Stage IV scores fault hypotheses with the true round-10 key. It checks whether a model fits. It does not recover the key.
- Stage XI only lists the 560 supports.
- Stage XV in the recorded report is one simulation trial.
- Stage XVI compares those recorded runs. The success test is different in each stage, so the comparison table is a summary of what was measured, not a single benchmark.
