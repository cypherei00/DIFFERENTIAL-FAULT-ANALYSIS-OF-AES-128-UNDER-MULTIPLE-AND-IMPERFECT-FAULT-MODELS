#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
g++ -O3 -std=c++17 dfa_phase7_generate.cpp -o dfa_phase7_generate
g++ -O3 -std=c++17 dfa_phase7_filter.cpp -o dfa_phase7_filter
g++ -O3 -std=c++17 dfa_phase14_small_solver.cpp -o dfa_phase14_small_solver
python3 dfa_phase15_multi_event.py
