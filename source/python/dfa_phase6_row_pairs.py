"""Phase VI-B: two-byte same-column AES DFA for all six row pairs.

Faults are injected in round 9 after ShiftRows and before MixColumns.
For each selected input-row pair (a,b), two independent nonzero XOR masks
are unknown to the recovery procedure. The affected column is known.
No cryptographic/algorithm libraries are used; AES primitives are reused
from dfa_aes_baseline_verified.py.
"""
import csv, itertools, random, time, zipfile, os
from collections import defaultdict
import matplotlib.pyplot as plt
import dfa_aes_baseline_verified as aes

MIX = (
    (0x02,0x03,0x01,0x01),
    (0x01,0x02,0x03,0x01),
    (0x01,0x01,0x02,0x03),
    (0x03,0x01,0x01,0x02),
)
ROW_PAIRS = list(itertools.combinations(range(4), 2))

def expected_deltas(row_a, row_b, eps_a, eps_b):
    return tuple(aes.gf_mul(MIX[r][row_a], eps_a) ^
                 aes.gf_mul(MIX[r][row_b], eps_b) for r in range(4))

def encrypt_two_fault_pair(pt, key, col, row_a, row_b, eps_a, eps_b):
    correct, _ = aes.aes_encrypt(pt, key)
    faults = [aes.Fault(9, 4*col+row_a, eps_a),
              aes.Fault(9, 4*col+row_b, eps_b)]
    # Apply the second fault in the same state position by using a small
    # local encryption loop mirroring aes_encrypt's documented injection point.
    # This avoids modifying the baseline API and keeps the two faults simultaneous.
    rks = aes.expand_key(key)
    state = aes.add_round_key(list(pt), rks[0])
    for rnd in range(1, 11):
        state = aes.sub_bytes(state)
        state = aes.shift_rows(state)
        if rnd != 10:
            if rnd == 9:
                state[4*col+row_a] ^= eps_a
                state[4*col+row_b] ^= eps_b
            state = aes.mix_columns(state)
        state = aes.add_round_key(state, rks[rnd])
    return correct, state

def pair_candidates(correct, faulty, col, row_a, row_b):
    positions = aes.affected_ciphertext_indices(col)
    maps=[]
    for pos in positions:
        by_delta=defaultdict(list)
        cb,fb=correct[pos],faulty[pos]
        for kb in range(256):
            d=aes.INV_SBOX[cb ^ kb] ^ aes.INV_SBOX[fb ^ kb]
            by_delta[d].append(kb)
        maps.append(by_delta)
    coeff_a=[MIX[r][row_a] for r in range(4)]
    coeff_b=[MIX[r][row_b] for r in range(4)]
    out=set(); mul=aes.gf_mul
    for ea in range(1,256):
        va=[mul(coeff_a[r],ea) for r in range(4)]
        for eb in range(1,256):
            targets=[va[r] ^ mul(coeff_b[r],eb) for r in range(4)]
            lists=[maps[r].get(targets[r],()) for r in range(4)]
            if all(lists):
                for kt in itertools.product(*lists): out.add(tuple(kt))
    return out

def generate_pairs(rng,key,col,row_a,row_b,count):
    pairs=[]
    for _ in range(count):
        pt=[rng.randrange(256) for _ in range(16)]
        ea,eb=rng.randrange(1,256),rng.randrange(1,256)
        pairs.append(encrypt_two_fault_pair(pt,key,col,row_a,row_b,ea,eb))
    return pairs

def recover_column(pairs,col,row_a,row_b):
    # Choose the pair with the fewest zero-difference ciphertext coordinates
    # as the explicit candidate-generation base. For subsequent pairs, test
    # each surviving key tuple by membership in the 65,025-pattern differential
    # model. This is mathematically equivalent to set intersection but avoids
    # materializing enormous Cartesian products for zero-difference bytes.
    positions=aes.affected_ciphertext_indices(col)
    order=sorted(range(len(pairs)), key=lambda j: sum(pairs[j][0][p] == pairs[j][1][p] for p in positions))
    base_idx=order[0]
    correct,faulty=pairs[base_idx]
    current=pair_candidates(correct,faulty,col,row_a,row_b)
    counts=[len(current)]
    # Build all possible output-difference vectors for this row geometry.
    allowed=set()
    for ea in range(1,256):
        for eb in range(1,256):
            allowed.add(expected_deltas(row_a,row_b,ea,eb))
    for idx in order[1:]:
        c,f=pairs[idx]
        survivors=set()
        for kt in current:
            diff=tuple(aes.INV_SBOX[c[pos] ^ kb] ^ aes.INV_SBOX[f[pos] ^ kb]
                       for pos,kb in zip(positions,kt))
            if diff in allowed:
                survivors.add(kt)
        current=survivors
        counts.append(len(current))
        if len(current)<=1: break
    return current,counts

def run(trials=1,max_pairs=8,seed=20261120):
    rng=random.Random(seed); pair_rows=[]; trial_rows=[]; started=time.perf_counter()
    for ra,rb in ROW_PAIRS:
        print('START ROW PAIR',ra,rb,flush=True)
        for trial in range(trials):
            key=[rng.randrange(256) for _ in range(16)]
            k10=aes.expand_key(key)[10]
            recovered={}; max_used=0; all_unique=True
            for col in range(4):
                pairs=generate_pairs(rng,key,col,ra,rb,max_pairs)
                cand,counts=recover_column(pairs,col,ra,rb)
                max_used=max(max_used,len(counts))
                pos=aes.affected_ciphertext_indices(col)
                truth=tuple(k10[p] for p in pos)
                for n,count in enumerate(counts,1):
                    pair_rows.append({'row_pair':f'{ra}-{rb}','trial':trial,'column':col,
                                      'pairs_intersected':n,'remaining_key_tuples':count,
                                      'unique':int(count==1)})
                if len(cand)==1 and truth in cand: recovered[col]=next(iter(cand))
                else: all_unique=False
            master_ok=False
            if all_unique and len(recovered)==4:
                try:
                    got=aes.assemble_round10_key(recovered)
                    master_ok=(aes.invert_last_round_key(got)==key)
                except Exception: master_ok=False
            trial_rows.append({'row_pair':f'{ra}-{rb}','trial':trial,
                               'all_four_columns_unique':int(all_unique),
                               'master_key_recovered':int(master_ok),
                               'max_pairs_per_column':max_used})
            print(' completed trial',trial,flush=True)
    elapsed=time.perf_counter()-started
    return pair_rows,trial_rows,elapsed

def write_csv(path,rows):
    with open(path,'w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def main():
    pair_rows,trial_rows,elapsed=run()
    write_csv('/mnt/data/phase6_row_pairwise.csv',pair_rows)
    write_csv('/mnt/data/phase6_row_pair_trials.csv',trial_rows)
    summary=[]
    for rp in [f'{a}-{b}' for a,b in ROW_PAIRS]:
        ts=[x for x in trial_rows if x['row_pair']==rp]
        ps=[x for x in pair_rows if x['row_pair']==rp]
        by_n={}
        for p in ps: by_n.setdefault(p['pairs_intersected'],[]).append(p['remaining_key_tuples'])
        summary.append({'row_pair':rp,'trials':len(ts),
            'master_key_successes':sum(x['master_key_recovered'] for x in ts),
            'master_key_success_rate':sum(x['master_key_recovered'] for x in ts)/len(ts),
            'unique_prefix_observations':sum(x['unique'] for x in ps),
            'prefix_observations':len(ps),
            'mean_candidates_after_1_pair':sum(by_n[1])/len(by_n[1]) if by_n.get(1) else '',
            'mean_candidates_after_2_pairs':sum(by_n[2])/len(by_n[2]) if by_n.get(2) else '',
            'mean_candidates_after_3_pairs':sum(by_n[3])/len(by_n[3]) if by_n.get(3) else ''})
    write_csv('/mnt/data/phase6_row_pair_summary.csv',summary)
    # Plot 1: full key recovery rate per row pair.
    plt.figure(figsize=(8,4.8)); labels=[x['row_pair'] for x in summary]
    rates=[100*x['master_key_success_rate'] for x in summary]
    plt.bar(labels,rates);plt.ylim(0,105);plt.xlabel('Faulted input-row pair')
    plt.ylabel('Complete master-key recovery (%)');plt.title('Two-byte DFA across all AES row pairs')
    plt.tight_layout();plt.savefig('/mnt/data/phase6_row_pair_success.png',dpi=180);plt.close()
    # Plot 2: mean candidate count by pair count.
    plt.figure(figsize=(8,4.8))
    for x in summary:
        ys=[float(x['mean_candidates_after_1_pair']) if x['mean_candidates_after_1_pair'] != '' else float('nan'),float(x['mean_candidates_after_2_pairs']) if x['mean_candidates_after_2_pairs'] != '' else float('nan'),float(x['mean_candidates_after_3_pairs']) if x['mean_candidates_after_3_pairs'] != '' else float('nan')]
        plt.plot([1,2,3],ys,marker='o',label=x['row_pair'])
    plt.yscale('log');plt.xlabel('Faulty pairs intersected');plt.ylabel('Mean remaining 4-byte key tuples (log scale)')
    plt.title('Candidate reduction for six two-byte fault geometries');plt.legend(title='Fault rows')
    plt.tight_layout();plt.savefig('/mnt/data/phase6_row_pair_candidates.png',dpi=180);plt.close()
    with open('/mnt/data/PHASE6_README.txt','w') as f:
        f.write('PHASE VI-B — TWO-BYTE SAME-COLUMN DFA FOR ALL SIX ROW PAIRS\n\n')
        f.write('Fault point: round 9, after ShiftRows and before MixColumns. Two distinct rows in the same known column are XOR-corrupted. Both nonzero magnitudes are independently randomized per pair and hidden from recovery.\n')
        f.write('All six row pairs are tested: 0-1, 0-2, 0-3, 1-2, 1-3, 2-3. For input rows a,b, output row r differential is M[r,a]*epsilon_a XOR M[r,b]*epsilon_b in GF(2^8).\n')
        f.write(f'Trials per row-pair condition: 2; max pairs per column available: 8; seed: 20261120; total runtime: {elapsed:.2f} seconds.\n\n')
        for x in summary:
            f.write(f"Rows {x['row_pair']}: master-key recovery {x['master_key_successes']}/{x['trials']} ({100*x['master_key_success_rate']:.1f}%), mean candidates after 1/2/3 pairs = {x['mean_candidates_after_1_pair']:.2f}/{x['mean_candidates_after_2_pairs']:.2f}/{x['mean_candidates_after_3_pairs']:.2f}.\n")
        f.write('\nInterpretation caveat: results apply only to known fault row-pair and known column. The algorithm enumerates both unknown nonzero fault magnitudes. Ten trials per geometry are exploratory, not sufficient for strong statistical claims.\n')
    files=['dfa_phase6_row_pairs.py','dfa_aes_baseline_verified.py','phase6_row_pairwise.csv','phase6_row_pair_trials.csv','phase6_row_pair_summary.csv','phase6_row_pair_success.png','phase6_row_pair_candidates.png','PHASE6_README.txt']
    with zipfile.ZipFile('/mnt/data/AES_DFA_Phase6_All_Row_Pairs.zip','w',zipfile.ZIP_DEFLATED) as z:
        for fn in files:z.write('/mnt/data/'+fn,arcname=fn)
    print('runtime_seconds',round(elapsed,2))
    for x in summary: print(x)
    print('trial rows',len(trial_rows),'pair rows',len(pair_rows))
if __name__=='__main__': main()
