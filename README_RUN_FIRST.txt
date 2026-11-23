AES-128 DFA — PORTABLE FOUR-PHASE RUNNER
========================================

OPEN THIS FOLDER IN CURSOR OR VS CODE.

REQUIREMENTS
------------
- Python 3.10+
- g++ with C++17 support (MinGW-w64 on Windows, GCC on Linux/WSL/macOS)
- matplotlib

ONE-TIME SETUP
--------------
Open the integrated terminal in this folder and run:

  python -m pip install -r requirements.txt

RUN EVERYTHING (selected reproducibility workflow)
---------------------------------------------------
Windows: double-click run_all.bat, or run `py -3 run_all.py`
Linux/macOS/WSL: run `python3 run_all.py` (or `./run_all.sh`)

The runner compiles all three C++ engines automatically, verifies the AES core,
then executes representative experiments for Phases 2, 3 and 4. It requires
no /mnt/data directory and writes generated files to run_outputs/.

WHAT RUN_ALL EXECUTES
---------------------
1. Phase 1: AES-128 core verification.
2. Phase 2: known-support two-byte recovery and cross-column recovery.
3. Phase 3: blind three-byte support search over all 560 hypotheses.
4. Phase 4: three-event blind support identification and master-key recovery.

This is a representative end-to-end workflow, not every historical experiment
in the research archive. Additional individual scripts remain in run_outputs/.

OUTPUTS
-------
All newly generated CSV, JSON, PNG, binary intermediate and text report files
are written to run_outputs/. Existing research data remains in results/ and
figures/. Do not confuse a newly generated run with the previously recorded
experiment results included in the paper.

IMPORTANT CLAIM BOUNDARY
-----------------------
The multi-event full-master-key demonstration is one reproducible software
simulation trial (n=1). It is a feasibility demonstration, not a statistically
established success rate. Faults are injected in software, not physically.

TROUBLESHOOTING
---------------
- If `python` is not found, use `py -3` on Windows or install Python 3.
- If `g++` is not found on Windows, install MinGW-w64 and add its bin folder
  to PATH, or run the project inside WSL with build-essential installed.
- If matplotlib is missing, run `python -m pip install matplotlib`.
- Keep the folder structure intact; do not move files out of run_outputs/.
