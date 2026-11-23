"""Phase IX exploratory AES DFA: three faults distributed across columns.

Software injection: round 9, after ShiftRows, before MixColumns.
Patterns: 2+1 faults over two columns, and 1+1+1 over three columns.
This first experiment assumes the evaluator supplies the affected column/row
support; it tests whether existing per-column one-/two-byte equations compose.
It does NOT claim blind location recovery or hardware applicability.
"""
import random, itertools, time, csv, json, zipfile, os, statistics
import dfa_aes_baseline_verified as aes
M=((2,3,1,1),(1,2,3,1),(1,1,2,3),(3,1,1,2))

def pos_for(col,row):
    # Fault after ShiftRows in state (r,c); MixColumns output row r
    # appears after final ShiftRows at ciphertext index 4*((c-r) mod 4)+r.
    return 4*((col-row)%4)+row

def enc_faults(pt,key,faults):
    rks=aes.expand_key(key); st=aes.add_round_key(list(pt),rks[0]); correct,_=aes.aes_encrypt(pt,key)
    for rnd in range(1,11):
        st=aes.sub_bytes(st); st=aes.shift_rows(st)
        if rnd!=10:
            if rnd==9:
                for col,row,eps in faults: st[4*col+row]^=eps
            st=aes.mix_columns(st)
        st=aes.add_round_key(st,rks[rnd])
    return correct,st

def group_positions(col, rows): return [pos_for(col,r) for r in rows]
def expected(rows, eps):
    return tuple(__import__('functools').reduce(lambda x,j:x^aes.gf_mul(M[r][rows[j]],eps[j]),range(len(rows)),0) for r in range(4))

def pair_candidates(c,f,col,rows):
    poss=group_positions(col,range(4)) # ordered by MixColumns output row
    maps=[]
    for p in poss:
        dmap=[[] for _ in range(256)]
        for kb in range(256): dmap[aes.INV_SBOX[c[p]^kb]^aes.INV_SBOX[f[p]^kb]].append(kb)
        maps.append(dmap)
    out=set()
    if len(rows)==1:
        r=rows[0]
        for e in range(1,256):
            ds=tuple(aes.gf_mul(M[o][r],e) for o in range(4))
            lists=[maps[o][ds[o]] for o in range(4)]
            if all(lists):
                for kt in itertools.product(*lists): out.add(tuple(kt))
    elif len(rows)==2:
        a,b=rows
        for ea in range(1,256):
            va=[aes.gf_mul(M[o][a],ea) for o in range(4)]
            for eb in range(1,256):
                ds=[va[o]^aes.gf_mul(M[o][b],eb) for o in range(4)]
                lists=[maps[o][ds[o]] for o in range(4)]
                if all(lists):
                    for kt in itertools.product(*lists): out.add(tuple(kt))
    else: raise ValueError('only 1 or 2 faults per column in Phase IX')
    return out

def recover_group(pairs,col,rows):
    cand=None; counts=[]
    for c,f in pairs:
        cur=pair_candidates(c,f,col,rows)
        cand=cur if cand is None else cand & cur
        counts.append(len(cand))
        if len(cand)<=1: break
    return cand or set(),counts

def build_trial(rng,pattern):
    key=[rng.randrange(256) for _ in range(16)]
    if pattern=='2+1':
        cols=rng.sample(range(4),2); assignments=[(cols[0], sorted(rng.sample(range(4),2))), (cols[1],[rng.randrange(4)])]
    else:
        cols=rng.sample(range(4),3); assignments=[(col,[rng.randrange(4)]) for col in cols]
    faults_by_col={col:rows for col,rows in assignments}
    n_pairs=4
    pairs_by_col={col:[] for col in faults_by_col}
    # Each pair has fresh plaintext and fresh nonzero magnitude for each fault.
    for _ in range(n_pairs):
        pt=[rng.randrange(256) for _ in range(16)]
        faults=[(col,row,rng.randrange(1,256)) for col,rows in assignments for row in rows]
        correct,faulty=enc_faults(pt,key,faults)
        for col in faults_by_col: pairs_by_col[col].append((correct,faulty))
    return key,assignments,pairs_by_col

def run(trials=8,seed=20261117):
    rng=random.Random(seed); detail=[]; summaries=[]; start=time.perf_counter()
    for pattern in ('2+1','1+1+1'):
        for t in range(1,trials+1):
            key,assignments,pairs=build_trial(rng,pattern); k10=aes.expand_key(key)[10]
            groups_ok=True; total_pairs=0; counts_all=[]
            for col,rows in assignments:
                recovered,counts=recover_group(pairs[col],col,rows); total_pairs+=len(counts); counts_all.extend(counts)
                truth=tuple(k10[p] for p in group_positions(col,range(4)))
                ok=(len(recovered)==1 and next(iter(recovered))==truth)
                groups_ok &= ok
                detail.append({'pattern':pattern,'trial':t,'column':col,'fault_rows':'-'.join(map(str,rows)),
                               'fault_count':len(rows),'pairs_used':len(counts),'candidate_counts':';'.join(map(str,counts)),
                               'unique_correct_group':int(ok),'remaining_candidates':len(recovered)})
            master_ok=False
            if groups_ok:
                # The attacked columns give their K10 byte groups; unaffected columns
                # are not attacked, so complete K10/master key is intentionally not claimed.
                master_ok=False
            summaries.append({'pattern':pattern,'trial':t,'affected_columns':len(assignments),
                               'fault_distribution':';'.join(f"c{c}:rows{','.join(map(str,r))}" for c,r in assignments),
                               'all_affected_column_groups_recovered':int(groups_ok),
                               'total_column_pair_intersections':total_pairs,
                               'mean_candidates_per_intersection':statistics.mean(counts_all) if counts_all else 0})
            print(pattern,t,'groups',groups_ok, 'dist',assignments,flush=True)
    elapsed=time.perf_counter()-start
    return detail,summaries,elapsed

def main():
    detail,summaries,elapsed=run()
    def write(fn,rows):
        with open('/mnt/data/'+fn,'w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    write('phase9_cross_column_details.csv',detail); write('phase9_cross_column_trials.csv',summaries)
    report={'seed':20261117,'trials_per_pattern':8,'total_trials':len(summaries),'patterns':{},'runtime_seconds':elapsed,
            'scope':['Three faults distributed across two or three AES state columns.','Known per-column row support and affected columns are supplied to the recovery stage.','Per-column 1- and 2-byte DFA models recover the affected column key groups.','Unaffected columns are not recovered; complete 128-bit master-key recovery is not claimed.','Software fault injection only.']}
    for p in ('2+1','1+1+1'):
        rows=[x for x in summaries if x['pattern']==p]
        report['patterns'][p]={'trials':len(rows),'successful_all_affected_groups':sum(x['all_affected_column_groups_recovered'] for x in rows),
                               'success_rate':sum(x['all_affected_column_groups_recovered'] for x in rows)/len(rows)}
    with open('/mnt/data/PHASE9_REPORT.json','w') as f: json.dump(report,f,indent=2)
    with open('/mnt/data/PHASE9_README.txt','w') as f:
        f.write('PHASE IX — CROSS-COLUMN MULTIPLE-FAULT DFA (EXPLORATORY)\n\n')
        f.write('Patterns: 2+1 faults over two columns; 1+1+1 faults over three columns. Each affected column is attacked using the corresponding 1-byte or 2-byte same-column model. Fault rows and affected columns are known to the recovery stage in this first experiment.\n')
        f.write('The result measures recovery of the four-byte K10 group for each affected column. It does not recover unaffected column groups and therefore does not claim full master-key recovery or unknown-location recovery.\n\n')
        f.write(json.dumps(report,indent=2))
    files=['dfa_phase9_cross_column.py','dfa_aes_baseline_verified.py','phase9_cross_column_details.csv','phase9_cross_column_trials.csv','PHASE9_REPORT.json','PHASE9_README.txt']
    with zipfile.ZipFile('/mnt/data/AES_DFA_Phase9_Cross_Column_Package.zip','w',zipfile.ZIP_DEFLATED) as z:
        for fn in files:z.write('/mnt/data/'+fn,arcname=fn)
    print(json.dumps(report,indent=2))
if __name__=='__main__': main()
