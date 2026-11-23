"""Phase IV diagnostic experiments for AES-128 DFA imperfect fault models.

No external crypto/algorithm libraries are used. Reuses the verified AES-128
implementation and adds simultaneous XOR fault injection at the same round-9
(post-ShiftRows, pre-MixColumns) injection point.

Important: these are model-fit diagnostics using the true final-round key to
isolate fault-model mismatch. They are NOT yet a blind key-recovery attack.
"""
import csv, random, time, os, sys
from collections import defaultdict
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(__file__))
import dfa_aes_baseline_verified as aes

MIX = [[0x02,0x03,0x01,0x01],
       [0x01,0x02,0x03,0x01],
       [0x01,0x01,0x02,0x03],
       [0x03,0x01,0x01,0x02]]

def aes_encrypt_multi_fault(plaintext, key, faults):
    """AES encryption with a list of XOR faults injected at round 9."""
    rk = aes.expand_key(key)
    state = aes.add_round_key(list(plaintext), rk[0])
    for rnd in range(1, 11):
        state = aes.sub_bytes(state)
        state = aes.shift_rows(state)
        if rnd != 10:
            if rnd == 9:
                for f in faults:
                    state[f.state_index] ^= f.value
            state = aes.mix_columns(state)
        state = aes.add_round_key(state, rk[rnd])
    return state

def expected_delta_for_fault_row(row, epsilon):
    return [aes.gf_mul(MIX[out_row][row], epsilon) for out_row in range(4)]

def ciphertext_positions_for_column(column):
    return [4*((column-r)%4)+r for r in range(4)]

def supports_single_fault_model(correct, faulty, key10, column, row):
    """True iff the actual K10 bytes satisfy one single-byte fault hypothesis."""
    positions = ciphertext_positions_for_column(column)
    for epsilon in range(1, 256):
        good = True
        expected = expected_delta_for_fault_row(row, epsilon)
        for r, pos in enumerate(positions):
            x = aes.INV_SBOX[correct[pos] ^ key10[pos]]
            xf = aes.INV_SBOX[faulty[pos] ^ key10[pos]]
            if (x ^ xf) != expected[r]:
                good = False
                break
        if good:
            # Ensure no ciphertext differences outside the hypothesized support.
            delta = aes.xor_bytes(correct, faulty)
            if all(delta[i] == 0 for i in range(16) if i not in positions):
                return True
    return False

def one_fault_unknown_location_experiment(trials=100, seed=20261117):
    rng = random.Random(seed)
    rows=[]
    for t in range(trials):
        key=[rng.randrange(256) for _ in range(16)]
        pt=[rng.randrange(256) for _ in range(16)]
        true_index=rng.randrange(16); true_row=true_index%4; true_col=true_index//4
        epsilon=rng.randrange(1,256)
        correct,_=aes.aes_encrypt(pt,key)
        faulty,_=aes.aes_encrypt(pt,key,aes.Fault(9,true_index,epsilon))
        key10=aes.expand_key(key)[10]
        compatible=[]
        for col in range(4):
            for row in range(4):
                if supports_single_fault_model(correct,faulty,key10,col,row):
                    compatible.append((row,col))
        rows.append({
            'trial':t,'true_state_index':true_index,'true_row':true_row,'true_column':true_col,
            'fault_value':epsilon,'compatible_hypotheses':len(compatible),
            'true_hypothesis_present':int((true_row,true_col) in compatible),
            'unique_location_identified':int(compatible==[(true_row,true_col)]),
            'hypotheses':';'.join(f'r{r}c{c}' for r,c in compatible)
        })
    return rows

def multi_fault_experiment(trials_per_condition=100, seed=20261118):
    rng=random.Random(seed)
    rows=[]
    conditions=[]
    for k in (2,4,8):
        conditions += [(k, 'same_column' if k <= 4 else 'two_columns_4plus4'), (k,'different_columns')]
    trial_id=0
    for k,geometry in conditions:
        for _ in range(trials_per_condition):
            key=[rng.randrange(256) for _ in range(16)]
            pt=[rng.randrange(256) for _ in range(16)]
            if geometry in ('same_column', 'two_columns_4plus4'):
                col=rng.randrange(4)
                indices=rng.sample([4*col+r for r in range(4)],k) if k<=4 else [4*col+r for r in range(4)]
                # Eight distinct byte locations cannot fit in one 4-byte column.
                if k==8:
                    other=(col+1)%4
                    indices += [4*other+r for r in range(4)]
            else:
                indices=rng.sample(range(16),k)
            faults=[aes.Fault(9,idx,rng.randrange(1,256)) for idx in indices]
            correct,_=aes.aes_encrypt(pt,key)
            faulty=aes_encrypt_multi_fault(pt,key,faults)
            key10=aes.expand_key(key)[10]
            compatible=[]
            for col in range(4):
                for row in range(4):
                    if supports_single_fault_model(correct,faulty,key10,col,row):
                        compatible.append((row,col))
            changed=sum(1 for x,y in zip(correct,faulty) if x!=y)
            rows.append({
                'trial':trial_id,'fault_count':k,'geometry':geometry,
                'distinct_fault_columns':len(set(idx//4 for idx in indices)),
                'changed_ciphertext_bytes':changed,
                'single_fault_model_compatible':int(bool(compatible)),
                'compatible_single_fault_hypotheses':len(compatible),
                'hypotheses':';'.join(f'r{r}c{c}' for r,c in compatible)
            })
            trial_id+=1
    return rows

def write_csv(path, rows):
    with open(path,'w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)

def main():
    t0=time.perf_counter()
    unknown=one_fault_unknown_location_experiment()
    multi=multi_fault_experiment()
    write_csv('/mnt/data/phase4_unknown_location_results.csv',unknown)
    write_csv('/mnt/data/phase4_multiple_fault_results.csv',multi)
    # Summaries
    summary=[]
    summary.append({'experiment':'unknown_location','condition':'single byte, any of 16 locations',
                    'trials':len(unknown),'model_compatible_rate':sum(r['true_hypothesis_present'] for r in unknown)/len(unknown),
                    'unique_hypothesis_rate':sum(r['unique_location_identified'] for r in unknown)/len(unknown),
                    'mean_compatible_hypotheses':sum(r['compatible_hypotheses'] for r in unknown)/len(unknown)})
    groups=defaultdict(list)
    for r in multi: groups[(r['fault_count'],r['geometry'])].append(r)
    for (k,g),rs in sorted(groups.items()):
        summary.append({'experiment':'multiple_faults','condition':f'{k} faults, {g}',
                        'trials':len(rs),'model_compatible_rate':sum(r['single_fault_model_compatible'] for r in rs)/len(rs),
                        'unique_hypothesis_rate':'','mean_compatible_hypotheses':sum(r['compatible_single_fault_hypotheses'] for r in rs)/len(rs)})
    write_csv('/mnt/data/phase4_summary.csv',summary)
    # Plot unknown-location results
    labels=['True location\ncontained','Unique location\nidentified']
    vals=[sum(r['true_hypothesis_present'] for r in unknown)/len(unknown)*100,
          sum(r['unique_location_identified'] for r in unknown)/len(unknown)*100]
    plt.figure(figsize=(7,4.5)); plt.bar(labels,vals); plt.ylim(0,105)
    plt.ylabel('Trials (%)'); plt.title('Single-byte faults: unknown location hypothesis test')
    plt.tight_layout(); plt.savefig('/mnt/data/phase4_unknown_location.png',dpi=180); plt.close()
    # Plot multi-fault compatibility
    keys=sorted(groups)
    xlabels=[f'{k}\n{g.replace("_"," ")}' for k,g in keys]
    rates=[sum(r['single_fault_model_compatible'] for r in groups[key])/len(groups[key])*100 for key in keys]
    plt.figure(figsize=(10,4.8)); plt.bar(xlabels,rates); plt.ylim(0,105)
    plt.ylabel('Single-fault model compatibility (%)'); plt.xlabel('Injected fault condition')
    plt.title('How often does the conventional single-byte model explain multi-fault data?')
    plt.tight_layout(); plt.savefig('/mnt/data/phase4_multi_fault_compatibility.png',dpi=180); plt.close()
    elapsed=time.perf_counter()-t0
    with open('/mnt/data/PHASE4_README.txt','w') as f:
        f.write('PHASE IV — IMPERFECT FAULT MODEL DIAGNOSTICS\n\n')
        f.write('These experiments use the verified AES implementation and inject faults at round 9 after ShiftRows and before MixColumns.\n')
        f.write('Crucial limitation: the compatibility tests use the true AES-128 final-round key to isolate whether the observed differential is consistent with a hypothesized single-byte fault. This is a diagnostic/model-fit study, not a blind key-recovery attack.\n\n')
        f.write(f'Unknown-location experiment: {len(unknown)} single-byte trials, location uniform over all 16 state bytes.\n')
        f.write(f'True hypothesis present: {vals[0]:.2f}%; uniquely identified by oracle test: {vals[1]:.2f}%.\n\n')
        f.write('Multiple-fault experiments: 100 trials per condition; k=2,4,8. “same_column” for k=8 uses two adjacent columns (4+4) because one AES column contains only four byte positions.\n')
        f.write('The compatibility metric asks whether ANY single-byte (row,column) hypothesis, evaluated with the true round-10 key, explains the complete ciphertext differential.\n\n')
        f.write(f'Runtime: {elapsed:.2f} seconds. Seeds: 20261117 and 20261118.\n')
    # Package
    import zipfile
    files=['dfa_phase4_experiments.py','phase4_unknown_location_results.csv','phase4_multiple_fault_results.csv','phase4_summary.csv','phase4_unknown_location.png','phase4_multi_fault_compatibility.png','PHASE4_README.txt','dfa_aes_baseline_verified.py']
    with zipfile.ZipFile('/mnt/data/AES_DFA_Phase4_Experiment_Package.zip','w',zipfile.ZIP_DEFLATED) as z:
        for name in files: z.write('/mnt/data/'+name,arcname=name)
    print('Phase IV experiments completed in %.2f seconds' % elapsed)
    print('\nSUMMARY')
    for r in summary: print(r)

if __name__=='__main__': main()
