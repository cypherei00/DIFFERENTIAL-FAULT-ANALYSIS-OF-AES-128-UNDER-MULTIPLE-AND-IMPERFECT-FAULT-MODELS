from pathlib import Path
RUN_DIR = str(Path(__file__).resolve().parent)
#!/usr/bin/env python3
"""Phase XI: enumerate every exactly-three-byte AES state fault support.

This is a support-space enumerator and validation utility, not a key-recovery
engine. It exhaustively enumerates C(16,3)=560 distinct supports and labels
those supports by their per-column occupancy pattern.
"""
from itertools import combinations
from collections import Counter
import csv, json, zipfile, os

CELLS = [(c, r) for c in range(4) for r in range(4)]

def classify(support):
    counts = Counter(c for c, _ in support)
    occ = sorted(counts.values(), reverse=True)
    return '+'.join(map(str, occ))

def main():
    supports = list(combinations(CELLS, 3))
    rows = []
    for i, s in enumerate(supports, 1):
        rows.append({
            'support_id': i,
            'support': ';'.join(f'c{c}r{r}' for c, r in s),
            'distribution': classify(s),
            'affected_columns': len(set(c for c, _ in s)),
        })
    counts = Counter(x['distribution'] for x in rows)
    expected = {'3': 16, '2+1': 288, '1+1+1': 256}
    assert dict(counts) == expected, (counts, expected)
    assert len(rows) == 560 and len({x['support'] for x in rows}) == 560
    with open(RUN_DIR + '/phase11_all_supports.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    report = {
        'phase': 'XI',
        'scope': 'Exhaustive enumeration of exactly-three-byte fault supports across the 16 AES state cells.',
        'total_supports': len(rows),
        'distribution_counts': dict(sorted(counts.items())),
        'identity': 'C(16,3) = 560 = 16 + 288 + 256',
        'validation': 'PASS: every support is unique and all distribution counts match combinatorics.',
        'important_limitation': 'This phase validates and enumerates the complete support space. It does not run blind DFA key-candidate recovery, identify a support from ciphertexts, or recover an AES round key/master key.'
    }
    with open(RUN_DIR + '/PHASE11_REPORT.json', 'w') as f: json.dump(report, f, indent=2)
    with open(RUN_DIR + '/PHASE11_README.txt', 'w') as f:
        f.write('PHASE XI — COMPLETE THREE-BYTE SUPPORT ENUMERATION\n\n')
        f.write('The 16 AES state cells are represented as (column,row). Exactly three distinct cells are selected.\n')
        f.write('The complete space is C(16,3)=560, partitioned into 3-in-one-column: 16; 2+1: 288; 1+1+1: 256.\n\n')
        f.write('This is a combinatorial support enumerator and validation artifact only. It is not evidence of blind DFA recovery.\n\n')
        f.write(json.dumps(report, indent=2))
    files = ['dfa_phase11_support_space.py','phase11_all_supports.csv','PHASE11_REPORT.json','PHASE11_README.txt']
    with zipfile.ZipFile(RUN_DIR + '/AES_DFA_Phase11_Complete_Support_Space.zip','w',zipfile.ZIP_DEFLATED) as z:
        for fn in files: z.write(RUN_DIR + '/'+fn, arcname=fn)
    print(json.dumps(report, indent=2))

if __name__ == '__main__': main()
