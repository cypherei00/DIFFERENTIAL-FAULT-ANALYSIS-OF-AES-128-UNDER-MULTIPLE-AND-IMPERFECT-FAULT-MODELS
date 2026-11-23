"""Repeated-trial evaluation of three-byte AES DFA using the C++ engine.

Runs independent keys/plaintexts/fault magnitudes for each row triple.
Records each column recovery and trial-level complete master-key recovery.
"""
import os, random, struct, subprocess, time, csv, json, statistics, argparse
import dfa_phase7_three_byte as py
import dfa_aes_baseline_verified as aes

BASE='/mnt/data/phase7_candidates.bin'; META='/mnt/data/phase7_filter_meta.bin'; OUT='/mnt/data/phase7_candidates_filtered.bin'; MAP='/mnt/data/phase7_base_maps.bin'; COEFF='/mnt/data/phase7_coeff.bin'
GEN='/mnt/data/dfa_phase7_generate'; FIL='/mnt/data/dfa_phase7_filter'


def write_maps(c,f,col):
    pos=aes.affected_ciphertext_indices(col)
    with open(MAP,'wb') as out:
        for p in pos: out.write(bytes(aes.INV_SBOX[c[p]^k]^aes.INV_SBOX[f[p]^k] for k in range(256)))

def write_coeff(rows):
    coeff=bytes(py.MIX[r][rows[j]] for r in range(4) for j in range(3))
    inv=py.INV_GF[py.MIX[3][rows[2]]]
    with open(COEFF,'wb') as f: f.write(coeff); f.write(bytes([inv]))

def write_filter_meta(c,f,col,rows):
    pos=aes.affected_ciphertext_indices(col)
    maps=[bytes(aes.INV_SBOX[c[p]^k]^aes.INV_SBOX[f[p]^k] for k in range(256)) for p in pos]
    A=[[py.MIX[r][rows[j]] for j in range(3)] for r in range(3)]
    inv=py.invert3(A); row4=bytes(py.MIX[3][r] for r in rows)
    with open(META,'wb') as out:
        for m in maps: out.write(m)
        for r in inv: out.write(bytes(r))
        out.write(row4)

def contains_u32(path, value):
    target=struct.pack('<I', value)
    with open(path,'rb') as f:
        while True:
            chunk=f.read(4*262144)
            if not chunk: return False
            if target in chunk: return True

def recover_column(rng,key,col,rows,pair_count=6):
    k10=aes.expand_key(list(key))[10]
    pairs=py.generate_pairs(rng,list(key),col,rows,pair_count)
    write_maps(*pairs[0],col); write_coeff(rows)
    t0=time.perf_counter()
    p=subprocess.run([GEN,MAP,COEFF,BASE],capture_output=True,text=True,check=True)
    gen_s=time.perf_counter()-t0
    true=sum(k10[pos]<<(24-8*i) for i,pos in enumerate(aes.affected_ciphertext_indices(col)))
    counts=[os.path.getsize(BASE)//4]
    stages=[gen_s]
    retained=[contains_u32(BASE,true)]
    pairs_used=1
    for pairnum,(c,f) in enumerate(pairs[1:],start=2):
        write_filter_meta(c,f,col,rows)
        t0=time.perf_counter()
        subprocess.run([FIL,BASE,OUT,META],capture_output=True,text=True,check=True)
        stages.append(time.perf_counter()-t0)
        os.replace(OUT,BASE)
        n=os.path.getsize(BASE)//4
        counts.append(n); retained.append(contains_u32(BASE,true)); pairs_used=pairnum
        if n<=1: break
    raw=open(BASE,'rb').read()
    vals=struct.unpack('<'+'I'*(len(raw)//4),raw) if raw else ()
    unique=(len(vals)==1 and vals[0]==true)
    return unique, {
        'row_triple':'-'.join(map(str,rows)), 'column':col,
        'pairs_used':pairs_used, 'unique_recovery':int(unique),
        'true_key_survived':int(all(retained)),
        'candidate_counts_by_pair':';'.join(map(str,counts)),
        'generation_seconds':round(gen_s,6),
        'filter_seconds_total':round(sum(stages[1:]),6),
        'column_total_seconds':round(sum(stages),6),
        'peak_candidate_file_bytes':max(counts)*4,
    }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--trials',type=int,default=30); ap.add_argument('--seed',type=int,default=20261117); ap.add_argument('--pairs',type=int,default=6); args=ap.parse_args()
    rng=random.Random(args.seed)
    col_rows=[]; trial_rows=[]; started=time.perf_counter()
    for rows in py.TRIPLES:
        print('ROW TRIPLE',rows,flush=True)
        for trial in range(1,args.trials+1):
            key=bytes(rng.randrange(256) for _ in range(16))
            t_trial=time.perf_counter(); cols=[]
            for col in range(4):
                ok, rec=recover_column(rng,key,col,rows,args.pairs)
                rec['trial']=trial; col_rows.append(rec); cols.append(ok)
                print(f"  trial {trial:02d}/{args.trials} col {col}: unique={ok} pairs={rec['pairs_used']} candidates={rec['candidate_counts_by_pair']}",flush=True)
            recovered=aes.invert_last_round_key([None]*16) if False else None
            # Complete K10 is recoverable only if each of the four column groups was unique.
            trial_ok=all(cols)
            trial_rows.append({'row_triple':'-'.join(map(str,rows)),'trial':trial,
                'all_four_columns_unique':int(trial_ok),'master_key_recovered':int(trial_ok),
                'trial_seconds':round(time.perf_counter()-t_trial,6), 'master_key_hex':key.hex()})
            # Persist after every trial, so an interrupted batch still leaves valid data.
            write_csv('/mnt/data/phase7_cpp_column_trials.csv',col_rows)
            write_csv('/mnt/data/phase7_cpp_trial_summary.csv',trial_rows)
        print(' completed',rows,flush=True)
    total=time.perf_counter()-started
    summary=[]
    for rows in py.TRIPLES:
        name='-'.join(map(str,rows)); ts=[r for r in trial_rows if r['row_triple']==name]; cs=[r for r in col_rows if r['row_triple']==name]
        summary.append({'row_triple':name,'trials':len(ts),'complete_master_key_recoveries':sum(r['master_key_recovered'] for r in ts),
            'master_key_success_rate':sum(r['master_key_recovered'] for r in ts)/len(ts),
            'column_recoveries':sum(r['unique_recovery'] for r in cs),'column_recovery_rate':sum(r['unique_recovery'] for r in cs)/len(cs),
            'mean_pairs_per_column':round(statistics.mean(r['pairs_used'] for r in cs),4),
            'mean_column_runtime_seconds':round(statistics.mean(r['column_total_seconds'] for r in cs),6),
            'median_column_runtime_seconds':round(statistics.median(r['column_total_seconds'] for r in cs),6),
            'max_candidate_file_bytes':max(r['peak_candidate_file_bytes'] for r in cs)})
    write_csv('/mnt/data/phase7_cpp_statistical_summary.csv',summary)
    report={'trials_per_row_triple':args.trials,'columns_per_trial':4,'row_triples':['-'.join(map(str,x)) for x in py.TRIPLES],
        'pairs_max':args.pairs,'seed':args.seed,'total_column_experiments':len(col_rows),'total_runtime_seconds':round(total,3),
        'summary':summary,'interpretation':'A trial is counted as a complete master-key recovery only when all four 4-byte round-10 key column groups are uniquely recovered. The implementation then supports AES-128 inverse key expansion. This batch records column-level uniqueness; it does not claim unknown fault-location recovery.'}
    with open('/mnt/data/PHASE7_CPP_STATISTICAL_REPORT.json','w') as f: json.dump(report,f,indent=2)
    print('\nSUMMARY',json.dumps(report,indent=2),flush=True)

def write_csv(path,rows):
    if not rows:return
    with open(path,'w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

if __name__=='__main__': main()
