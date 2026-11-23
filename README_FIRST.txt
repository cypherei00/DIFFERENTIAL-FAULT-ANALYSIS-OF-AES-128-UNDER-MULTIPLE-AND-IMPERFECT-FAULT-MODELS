AES-128 DFA — FOUR-PHASE RESEARCH PACKAGE
==========================================

MAIN REPORT
-----------
reports/AES_DFA_Full_Research_Paper_Four_Phases.docx

FOUR CONSOLIDATED PHASES
------------------------
Phase 1 — Foundations and baseline
  AES-128 implementation and verification; controlled single-byte DFA baseline;
  imperfect-model diagnostics. Consolidates the former internal stages II–IV.

Phase 2 — Known-support multi-fault recovery
  Two-byte and three-byte recovery; all two-byte row pairs; known-support
  cross-column recovery; optimized C++ candidate generation/filtering.
  Consolidates the former stages V–VII and IX, plus the known-support
  three-byte integration validation.

Phase 3 — Blind support identification
  Unknown-location analysis; 560-support enumeration; blind support search;
  statistical pilot across 3+0+0, 2+1 and 1+1+1 distributions.
  Consolidates the former stages VIII and X–XIV.

Phase 4 — Multi-event recovery and comparative evaluation
  Multi-event blind master-key recovery and comparative evaluation.
  Consolidates the former stages XV–XVI.

PACKAGE LAYOUT
--------------
source/python/       Python implementations (original basenames retained so imports work)
source/cpp/          C++ source and compiled executables
source/shell/        Experiment runner scripts
results/csv/         Trial-level and aggregate experimental data
results/json/        Machine-readable reports
figures/             Graphs generated from experimental data
docs/                Phase-specific execution notes and source references
consolidated_phase_archives/
                     Four grouped archives corresponding to the new phase structure
reports/             Updated full DOCX paper

REPRODUCIBILITY NOTES
---------------------
The original implementation filenames are retained inside source folders to avoid
breaking imports and experiment scripts. The research narrative, folder grouping,
phase archive names, and report now use the four-phase organization.

Run the individual experiment scripts from the source/python directory while
preserving the directory structure and following the relevant docs/*.txt notes.
The compiled C++ programs are platform-specific; recompile the included .cpp
sources with a C++17 compiler if they do not run on your system.

CLAIM BOUNDARIES
----------------
The blind multi-event complete-key recovery is a successful recorded end-to-end
simulation trial (n=1), not a statistically established success rate. Software
fault injection is used; no physical fault injection is claimed.
\n\nPORTABLE EXECUTION\n-------------------\nFor a one-command run in Cursor/VS Code, see README_RUN_FIRST.txt and run_all.py.\n