"""Phase V: generalized AES-128 DFA for two simultaneous faults in one column.

Fault point: round 9, after ShiftRows and before MixColumns.
Fault model: XOR faults in rows 0 and 1 of one selected column.
The two nonzero magnitudes are unknown and independently vary per pair.
No crypto/algorithm libraries are used; AES primitives are reused from the
verified educational implementation.
"""
from pathlib import Path
RUN_DIR = str(Path(__file__).resolve().parent)
import csv, itertools, random, time, os, sys, zipfile
from collections import defaultdict
import matplotlib.pyplot as plt
sys.path.insert(0, os.path.dirname(__file__))
import dfa_aes_baseline_verified as aes

# MixColumns output row coefficients for input faults in rows 0 and 1.
COEFFS = ((0x02,0x03),(0x01,0x02),(0x01,0x01),(0x03,0x01))

def encrypt_two_fault_pair(pt, key, col, e0, e1):
    correct, _ = aes.aes_encrypt(pt, key)
    faults = [aes.Fault(9, 4*col, e0), aes.Fault(9, 4*col+1, e1)]
    # Keep injection semantics identical to the verified AES implementation.
    state = aes.add_round_key(list(pt), aes.expand_key(key)[0])
    rks = aes.expand_key(key)
    for rnd in range(1, 11):
        state = aes.sub_bytes(state)
        state = aes.shift_rows(state)
        if rnd != 10:
            if rnd == 9:
                for fault in faults:
                    state[fault.state_index] ^= fault.value
            state = aes.mix_columns(state)
        state = aes.add_round_key(state, rks[rnd])
    return correct, state

def two_fault_expected(e0, e1):
    return [aes.gf_mul(a,b0) ^ aes.gf_mul(b,b1) for a,b in COEFFS for b0,b1 in [(e0,e1)]]

def pair_candidates_two_faults(correct, faulty, col):
    """Enumerate all (K10 byte tuple, e0, e1) explanations for one pair.

    For each of the 65,025 nonzero magnitude pairs, derive four independent
    key-byte candidate lists from the inverse-S-box differential equation.
    Intersecting these tuple sets across pairs removes spurious explanations.
    Tuple order is MixColumns output row order.
    """
    positions = aes.affected_ciphertext_indices(col)
    delta_to_keys = []
    for pos in positions:
        mapping = defaultdict(list)
        cb, fb = correct[pos], faulty[pos]
        for kb in range(256):
            d = aes.INV_SBOX[cb ^ kb] ^ aes.INV_SBOX[fb ^ kb]
            mapping[d].append(kb)
        delta_to_keys.append(mapping)

    candidates = set()
    mul = aes.gf_mul
    for e0 in range(1,256):
        m20, m10, m30 = mul(2,e0), e0, mul(3,e0)
        for e1 in range(1,256):
            targets = (m20 ^ mul(3,e1), m10 ^ mul(2,e1), e0 ^ e1, m30 ^ e1)
            lists = [delta_to_keys[i].get(targets[i], ()) for i in range(4)]
            if all(lists):
                for key_tuple in itertools.product(*lists):
                    candidates.add(tuple(key_tuple))
    return candidates

def generate_pairs(rng, key, col, count):
    pairs=[]
    for _ in range(count):
        pt=[rng.randrange(256) for _ in range(16)]
        e0,e1=rng.randrange(1,256),rng.randrange(1,256)
        pairs.append(encrypt_two_fault_pair(pt,key,col,e0,e1))
    return pairs

def recover_column(pairs, col):
    candidates=None
    counts=[]
    for correct,faulty in pairs:
        current=pair_candidates_two_faults(correct,faulty,col)
        candidates=current if candidates is None else candidates & current
        counts.append(len(candidates))
        if len(candidates)==1:
            break
        if len(candidates)==0:
            break
    return candidates or set(), counts

def run_experiments(trials=10, max_pairs=3, seed=20261119):
    rng=random.Random(seed)
    records=[]; trial_summaries=[]
    t0=time.perf_counter()
    for trial in range(trials):
        key=[rng.randrange(256) for _ in range(16)]
        true_k10=aes.expand_key(key)[10]
        col_recoveries={}; pair_counts={}; candidate_counts={}
        for col in range(4):
            pairs=generate_pairs(rng,key,col,max_pairs)
            recovered, counts=recover_column(pairs,col)
            col_recoveries[col]=recovered
            pair_counts[col]=len(counts)
            candidate_counts[col]=counts
            positions=aes.affected_ciphertext_indices(col)
            true_group=tuple(true_k10[p] for p in positions)
            for n,count in enumerate(counts,1):
                records.append({'trial':trial,'column':col,'pairs_used':n,
                                'remaining_candidate_tuples':count,
                                'true_tuple_retained':int(true_group in recovered) if n==len(counts) else ''})
        unique_all=all(len(col_recoveries[c])==1 for c in range(4))
        correct_all=False
        if unique_all:
            groups={c:next(iter(col_recoveries[c])) for c in range(4)}
            got_k10=aes.assemble_round10_key(groups)
            got_master=aes.invert_last_round_key(got_k10)
            correct_all=(got_master==key)
        trial_summaries.append({'trial':trial,'all_four_columns_unique':int(unique_all),
                                'master_key_recovered':int(correct_all),
                                'max_pairs_per_column':max(pair_counts.values()),
                                'candidate_counts_by_column':';'.join(str(candidate_counts[c]) for c in range(4))})
    elapsed=time.perf_counter()-t0
    return records,trial_summaries,elapsed

def write_csv(path,rows):
    with open(path,'w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def main():
    records,summaries,elapsed=run_experiments()
    write_csv(RUN_DIR + '/phase5_two_byte_pairwise.csv',records)
    write_csv(RUN_DIR + '/phase5_two_byte_trials.csv',summaries)
    grouped=defaultdict(list)
    for r in records: grouped[r['pairs_used']].append(r['remaining_candidate_tuples'])
    agg=[]
    for n,vals in sorted(grouped.items()):
        agg.append({'pairs_intersected':n,'mean_candidates':sum(vals)/len(vals),
                    'median_candidates':sorted(vals)[len(vals)//2],
                    'zero_candidate_rate':sum(v==0 for v in vals)/len(vals),
                    'unique_candidate_rate':sum(v==1 for v in vals)/len(vals)})
    write_csv(RUN_DIR + '/phase5_two_byte_aggregate.csv',agg)
    # Candidate counts use a log scale because one-pair candidate sets are large.
    plt.figure(figsize=(7.5,4.8))
    xs=[r['pairs_intersected'] for r in agg]; ys=[max(1,r['mean_candidates']) for r in agg]
    plt.plot(xs,ys,marker='o');plt.yscale('log')
    plt.xlabel('Faulty pairs intersected');plt.ylabel('Mean remaining 4-byte key tuples (log scale)')
    plt.title('Two-byte same-column DFA: candidate-set reduction')
    plt.tight_layout();plt.savefig(RUN_DIR + '/phase5_two_byte_candidates.png',dpi=180);plt.close()
    success=sum(r['master_key_recovered'] for r in summaries)
    with open(RUN_DIR + '/PHASE5_README.txt','w') as f:
        f.write('PHASE V — TWO-BYTE SAME-COLUMN DFA PROTOTYPE\n\n')
        f.write('Fault model: two nonzero XOR faults at rows 0 and 1 of the same AES state column, round 9 after ShiftRows and before MixColumns. Magnitudes are unknown to the recovery algorithm and independently randomized per pair.\n')
        f.write('The four MixColumns output differences are [2e0 XOR 3e1, e0 XOR 2e1, e0 XOR e1, 3e0 XOR e1] in GF(2^8).\n')
        f.write('Recovery enumerates all 255*255 nonzero magnitude pairs per faulty pair, derives key-byte candidates through the inverse-S-box equation, forms 4-byte tuples, and intersects tuple sets across pairs.\n\n')
        f.write(f'Trials: {len(summaries)}; master-key recoveries: {success}/{len(summaries)} ({100*success/len(summaries):.1f}%). Runtime: {elapsed:.2f}s. Seed: 20261119.\n')
        f.write('This is a research prototype for a constrained two-byte fault model, not a general multiple-fault solution. The two fault rows and affected column are assumed known; the two magnitudes and round-10 key are unknown to the recovery procedure.\n')
        f.write('Candidate counts are per four-byte column tuple. A zero intersection means the selected pair budget did not yield a surviving model; do not discard these failures.\n')
    files=['dfa_phase5_two_byte.py','phase5_two_byte_pairwise.csv','phase5_two_byte_trials.csv','phase5_two_byte_aggregate.csv','phase5_two_byte_candidates.png','PHASE5_README.txt','dfa_aes_baseline_verified.py']
    with zipfile.ZipFile(RUN_DIR + '/AES_DFA_Phase5_Two_Byte_Package.zip','w',zipfile.ZIP_DEFLATED) as z:
        for fn in files:z.write(RUN_DIR + '/'+fn,arcname=fn)
    print('Trials:',len(summaries),'master key recoveries:',success,'runtime:',round(elapsed,2),'s')
    print('Aggregate:',agg)
    for r in summaries: print(r)

if __name__=='__main__': main()
