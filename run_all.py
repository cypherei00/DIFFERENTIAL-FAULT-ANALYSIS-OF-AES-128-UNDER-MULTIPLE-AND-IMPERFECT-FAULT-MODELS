#!/usr/bin/env python3
"""One-command reproducibility runner for the AES-DFA four-phase project."""
from pathlib import Path
import subprocess, sys, shutil, os, time
ROOT = Path(__file__).resolve().parent
RUN = ROOT / "run_outputs"
PY = sys.executable

def step(label, cmd):
    print("\n" + "="*72, flush=True)
    print(label, flush=True)
    print("COMMAND:", " ".join(map(str, cmd)), flush=True)
    print("="*72, flush=True)
    subprocess.run(list(map(str, cmd)), cwd=RUN, check=True)


def main():
    if not shutil.which("g++"):
        raise SystemExit("ERROR: g++ was not found. Install a C++17 compiler and retry.")
    step("Compile optimized C++ candidate engines", ["g++", "-O3", "-std=c++17", RUN/"dfa_phase7_generate.cpp", "-o", RUN/"dfa_phase7_generate"])
    step("Compile C++ candidate filter", ["g++", "-O3", "-std=c++17", RUN/"dfa_phase7_filter.cpp", "-o", RUN/"dfa_phase7_filter"])
    step("Compile small-support C++ solver", ["g++", "-O3", "-std=c++17", RUN/"dfa_phase14_small_solver.cpp", "-o", RUN/"dfa_phase14_small_solver"])
    # Verify AES core first; it is the dependency for every later experiment.
    step("PHASE 1 — AES-128 implementation verification", [PY, "-c", "import dfa_aes_baseline_verified as a; a.self_test()"])
    # Representative executable experiments for the consolidated phases.
    step("PHASE 2 — Known-support two-byte recovery", [PY, "dfa_phase5_two_byte.py"])
    step("PHASE 2 — Known-support cross-column recovery", [PY, "dfa_phase9_cross_column.py"])
    step("PHASE 3 — Blind search over all 560 three-byte supports", [PY, "dfa_phase13_blind_560.py"])
    step("PHASE 4 — Multi-event blind master-key recovery", [PY, "dfa_phase15_multi_event.py"])
    print("\nALL SELECTED EXPERIMENTS COMPLETED.", flush=True)
    print("Outputs and logs are in:", RUN, flush=True)
    print("Note: the Phase 4 end-to-end run is one reproducible simulation trial (n=1), not a statistical success-rate estimate.", flush=True)

if __name__ == "__main__":
    main()
