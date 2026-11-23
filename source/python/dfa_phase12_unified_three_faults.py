#!/usr/bin/env python3
"""Phase XII: integrate all per-column solvers for exactly-three-byte AES faults.

This executable performs a reproducible 3+0+0 validation using the existing
C++ three-byte solver across all four columns. It also enumerates the full 560
support space and documents the blind-search integration boundary. It does NOT
claim a successful blind 560-support key recovery.
"""
import os, sys, random, time, json, csv, zipfile, struct
sys.path.insert(0, '/mnt/data')
import dfa_phase7_cpp_full_validation as p7
import dfa_phase7_three_byte as py7
import dfa_aes_baseline_verified as aes
from dfa_phase11_support_space import CELLS, classify
from itertools import combinations


def main():
    # Reproducible 3+0+0 known-support test; solver must recover each K10 group.
    seed = 2026111701
    rng = random.Random(seed)
    key = [rng.randrange(256) for _ in range(16)]
    master = bytes(key)
    k10 = bytes(aes.expand_key(key)[10])
    rows = (0, 1, 2)
    rec=[]; recovered=[None]*16
    t0=time.perf_counter()
    for col in range(4):
        ok, stages = p7.run_col(rng, key, col, rows, pair_count=6)
        raw=open(p7.BASE,'rb').read()
        vals=struct.unpack('<'+'I'*(len(raw)//4),raw) if raw else ()
        if ok and len(vals)==1:
            packed=vals[0]
            for j,pos in enumerate(aes.affected_ciphertext_indices(col)):
                recovered[pos]=(packed >> (24-8*j)) & 255
        rec.append({'column':col,'fault_rows':'0-1-2','unique_group_recovered':bool(ok),
                    'pairs_used':len(stages),'candidate_counts':'|'.join(str(x['candidate_count']) for x in stages),
                    'correct_group_retained_all_stages':all(x['true_key_retained'] for x in stages)})
        print('column',col,'unique',ok,'counts',[x['candidate_count'] for x in stages],flush=True)
    runtime=time.perf_counter()-t0
    full=all(x is not None for x in recovered)
    recovered_master=aes.invert_last_round_key(recovered) if full else None
    verified=bool(recovered_master is not None and recovered_master==key)

    supports=list(combinations(CELLS,3))
    counts={}
    for s in supports:
        counts[classify(s)]=counts.get(classify(s),0)+1
    assert len(supports)==560 and counts=={'3':16,'2+1':288,'1+1+1':256}

    with open('/mnt/data/phase12_3plus0_validation.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rec[0]));w.writeheader();w.writerows(rec)
    report={
      'phase':'XII', 'seed':seed, 'test':'3+0+0 known-support integration test',
      'fault_rows':[0,1,2], 'four_columns_tested':4,
      'column_results':rec, 'runtime_seconds':runtime,
      'original_master_key_hex':master.hex(),
      'original_round10_key_hex':k10.hex(),
      'recovered_round10_key_hex':bytes(recovered).hex() if full else None,
      'recovered_master_key_hex':bytes(recovered_master).hex() if verified else None,
      'full_master_key_verified':verified,
      'support_space':{'total':len(supports),'3':counts['3'],'2+1':counts['2+1'],'1+1+1':counts['1+1+1']},
      'limitations':['This validates the 3+0+0 per-column solver integration with known support.',
        'It does not execute a blind search over all 560 supports.',
        'The blind 560-support search must combine candidate sets for 1-, 2-, and 3-byte column models and is not claimed complete.']}
    with open('/mnt/data/PHASE12_REPORT.json','w') as f:json.dump(report,f,indent=2)
    with open('/mnt/data/PHASE12_README.txt','w') as f:
        f.write('PHASE XII — THREE-FAULT MODEL INTEGRATION\n\n')
        f.write('This phase integrates the existing C++ three-byte solver into the support taxonomy.\n')
        f.write('A reproducible 3+0+0 case is tested across all four columns; each recovered K10 group is assembled and the master key is checked.\n\n')
        f.write('The full 560-support blind search is NOT yet implemented or validated.\n\n')
        f.write(json.dumps(report,indent=2))
    files=['dfa_phase12_unified_three_faults.py','dfa_phase7_generate.cpp','dfa_phase7_filter.cpp',
      'dfa_phase7_cpp_full_validation.py','dfa_phase7_three_byte.py','dfa_aes_baseline_verified.py',
      'phase12_3plus0_validation.csv','PHASE12_REPORT.json','PHASE12_README.txt']
    with zipfile.ZipFile('/mnt/data/AES_DFA_Phase12_Three_Fault_Integration.zip','w',zipfile.ZIP_DEFLATED) as z:
      for fn in files:z.write('/mnt/data/'+fn,arcname=fn)
    print(json.dumps(report,indent=2))

if __name__=='__main__': main()
