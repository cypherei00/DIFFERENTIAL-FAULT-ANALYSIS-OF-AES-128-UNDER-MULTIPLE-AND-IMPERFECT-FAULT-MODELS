"""Phase XIV: preliminary statistical validation of blind 560-support DFA.

Tests exactly-three-byte supports under 3+0+0, 2+1 and 1+1+1 distributions.
Uses fresh AES key/plaintexts and independently sampled nonzero fault magnitudes
for each pair. The recovery stage receives ciphertext pairs only, not support.
"""
from pathlib import Path
RUN_DIR = str(Path(__file__).resolve().parent)
import os, sys, random, time, itertools, json, csv, statistics, math, zipfile, struct, subprocess
sys.path.insert(0, RUN_DIR + '')
import dfa_phase13_blind_560 as p13
import dfa_phase9_cross_column as p9
import dfa_aes_baseline_verified as aes

OUT=RUN_DIR + ''
SMALL=RUN_DIR + '/dfa_phase14_small_solver'
SMALL_MAP=RUN_DIR + '/p14_small_maps.bin'
SMALL_COEFF=RUN_DIR + '/p14_small_coeff.bin'
SMALL_OUT=RUN_DIR + '/p14_small_out.bin'

def choose_support(rng, pattern):
    if pattern == '3+0+0':
        col=rng.randrange(4); rows=sorted(rng.sample(range(4),3))
        return tuple(sorted((col,r) for r in rows))
    if pattern == '2+1':
        cols=rng.sample(range(4),2)
        rows2=sorted(rng.sample(range(4),2)); row1=rng.randrange(4)
        return tuple(sorted([(cols[0],rows2[0]),(cols[0],rows2[1]),(cols[1],row1)]))
    if pattern == '1+1+1':
        cols=sorted(rng.sample(range(4),3))
        return tuple(sorted((c,rng.randrange(4)) for c in cols))
    raise ValueError(pattern)

def trial(seed, pattern, pair_count=5):
    rng=random.Random(seed)
    key=[rng.randrange(256) for _ in range(16)]
    support=choose_support(rng,pattern)
    pairs=[]
    for _ in range(pair_count):
        pt=[rng.randrange(256) for _ in range(16)]
        faults=[(c,r,rng.randrange(1,256)) for c,r in support]
        pairs.append(p9.enc_faults(pt,key,faults))

    # Accelerate GF multiplications for the 1-/2-byte models.
    gf=[[aes.gf_mul(a,b) for b in range(256)] for a in range(256)]
    aes.gf_mul=lambda a,b:gf[a][b]
    p9.aes.gf_mul=lambda a,b:gf[a][b]

    start=time.perf_counter(); cache={}; counts={}
    row_models=[(r,) for r in range(4)]+list(itertools.combinations(range(4),2))
    for col in range(4):
        for rows in row_models:
            cur=None; cc=[]; n=len(rows)
            coeff=bytes(p9.M[r][rows[j]] for r in range(4) for j in range(n))
            with open(SMALL_COEFF,'wb') as cf: cf.write(coeff)
            for c,f in pairs:
                pos=aes.affected_ciphertext_indices(col)
                maps=bytes(aes.INV_SBOX[c[p]^k]^aes.INV_SBOX[f[p]^k] for p in pos for k in range(256))
                with open(SMALL_MAP,'wb') as mf: mf.write(maps)
                subprocess.run([SMALL,SMALL_MAP,SMALL_COEFF,str(n),SMALL_OUT],check=True,capture_output=True)
                raw=open(SMALL_OUT,'rb').read()
                cand=set(struct.unpack('<'+'I'*(len(raw)//4),raw)) if raw else set()
                cur=cand if cur is None else cur.intersection(cand)
                cc.append(len(cur))
                if not cur: break
            cache[(col,rows)]=cur or set(); counts[(col,rows)]=cc
    for col in range(4):
        for rows in itertools.combinations(range(4),3):
            cc=p13.candidates_three(pairs,col,rows)
            raw=open(p13.BASE,'rb').read()
            vals=set(__import__('struct').unpack('<'+'I'*(len(raw)//4),raw)) if raw else set()
            cache[(col,rows)]=vals; counts[(col,rows)]=cc

    supports=list(itertools.combinations([(c,r) for c in range(4) for r in range(4)],3))
    viable=[]
    for s in supports:
        groups={}
        for c,r in s: groups.setdefault(c,[]).append(r)
        if all(bool(cache[(c,tuple(sorted(rs)))]) for c,rs in groups.items()): viable.append(s)
    elapsed=time.perf_counter()-start
    true_survived=support in viable
    unique=(len(viable)==1 and viable[0]==support)
    # A three-byte support can cover at most three columns; this phase does not
    # infer the untouched K10 group or claim complete master-key recovery.
    return {
      'seed':seed,'pattern':pattern,'pair_count':pair_count,
      'true_support':';'.join(f'{c}:{r}' for c,r in support),
      'hypotheses_tested':560,'viable_supports':len(viable),
      'true_support_survived':int(true_survived),'unique_correct_support':int(unique),
      'false_positive_supports':max(0,len(viable)-(1 if true_survived else 0)),
      'runtime_seconds':elapsed,
      'viable_support_list':';'.join('|'.join(f'{c}:{r}' for c,r in s) for s in viable),
      'full_master_key_recovery_claimed':0
    }

def wilson(k,n,z=1.96):
    if n==0:return (None,None)
    ph=k/n; den=1+z*z/n
    center=(ph+z*z/(2*n))/den
    half=z*math.sqrt(ph*(1-ph)/n+z*z/(4*n*n))/den
    return center-half,center+half

def main(trials_per_pattern=3,pair_count=5,base_seed=20261117014):
    allrows=[]; idx=0
    trial_counts={'3+0+0':3,'2+1':3,'1+1+1':1}
    for pattern in ('3+0+0','2+1','1+1+1'):
        for t in range(1,trial_counts[pattern]+1):
            idx+=1; seed=base_seed+idx
            row=trial(seed,pattern,pair_count); row['trial']=t
            allrows.append(row)
            print(pattern,t,'unique',row['unique_correct_support'],'viable',row['viable_supports'],'sec',round(row['runtime_seconds'],2),flush=True)
    summary=[]
    for pattern in ('3+0+0','2+1','1+1+1'):
        rs=[r for r in allrows if r['pattern']==pattern]
        k=sum(r['unique_correct_support'] for r in rs); lo,hi=wilson(k,len(rs))
        summary.append({'pattern':pattern,'trials':len(rs),'unique_correct':k,'unique_recovery_rate':k/len(rs),
          'wilson95_low':lo,'wilson95_high':hi,'true_support_survival_rate':sum(r['true_support_survived'] for r in rs)/len(rs),
          'mean_viable_supports':statistics.mean(r['viable_supports'] for r in rs),
          'mean_false_positive_supports':statistics.mean(r['false_positive_supports'] for r in rs),
          'mean_runtime_seconds':statistics.mean(r['runtime_seconds'] for r in rs),
          'median_runtime_seconds':statistics.median(r['runtime_seconds'] for r in rs)})
    with open(OUT+'/phase14_blind_trials.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(allrows[0]));w.writeheader();w.writerows(allrows)
    with open(OUT+'/phase14_blind_summary.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(summary[0]));w.writeheader();w.writerows(summary)
    report={'phase':'XIV','purpose':'Preliminary statistical validation of blind exactly-three-byte support recovery over all 560 supports.',
      'trial_counts_by_pattern':trial_counts,'total_trials':len(allrows),'ciphertext_pairs_per_trial':pair_count,
      'fault_magnitudes':'independently sampled nonzero XOR magnitudes for each fault in each pair',
      'plaintexts':'fresh random plaintext per pair','AES_keys':'fresh random AES-128 key per trial',
      'support_distributions':summary,
      'hypothesis_space':'C(16,3)=560 supports: 16 (3+0+0), 288 (2+1), 256 (1+1+1)',
      'limitations':['Preliminary small-sample experiment; confidence intervals are wide.','Blind decision uses nonempty per-column candidate intersections.','No complete master-key recovery is claimed: three faulty bytes touch at most three AES columns.','Software fault injection model only; hardware fault behavior is not represented.']}
    with open(OUT+'/PHASE14_REPORT.json','w') as f:json.dump(report,f,indent=2)
    with open(OUT+'/PHASE14_README.txt','w') as f:
      f.write('PHASE XIV — STATISTICAL VALIDATION OF BLIND THREE-FAULT SUPPORT RECOVERY\n\n')
      f.write('Run: python dfa_phase14_statistical_blind.py\nConfigured preliminary sample: 3 trials for 3+0+0, 3 for 2+1, and 1 for 1+1+1.\n')
      f.write('Dependencies: Python 3 standard library, matplotlib; C++17 compiler for dfa_phase14_small_solver; existing phase IX/XIII modules and compiled dfa_phase7_generate/dfa_phase7_filter executables.\n\n')
      f.write(json.dumps(report,indent=2)+'\n')
    # Plots are generated from the CSV results, not hand-entered.
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    pats=[x['pattern'] for x in summary]
    vals=[100*x['unique_recovery_rate'] for x in summary]
    plt.figure(figsize=(8,5));plt.bar(pats,vals);plt.ylim(0,100)
    plt.ylabel('Unique correct support recovery (%)');plt.xlabel('Fault distribution')
    plt.title('Blind 560-support recovery by fault distribution');plt.tight_layout()
    plt.savefig(OUT+'/phase14_unique_recovery.png',dpi=180);plt.close()
    runt=[x['mean_runtime_seconds'] for x in summary]
    plt.figure(figsize=(8,5));plt.bar(pats,runt)
    plt.ylabel('Mean runtime (seconds)');plt.xlabel('Fault distribution')
    plt.title('Blind support-search runtime by fault distribution');plt.tight_layout()
    plt.savefig(OUT+'/phase14_runtime.png',dpi=180);plt.close()
    viable=[x['mean_viable_supports'] for x in summary]
    plt.figure(figsize=(8,5));plt.bar(pats,viable)
    plt.ylabel('Mean surviving supports');plt.xlabel('Fault distribution')
    plt.title('Mean number of surviving support hypotheses');plt.tight_layout()
    plt.savefig(OUT+'/phase14_surviving_supports.png',dpi=180);plt.close()
    files=['dfa_phase14_statistical_blind.py','dfa_phase14_small_solver.cpp','dfa_phase13_blind_560.py','dfa_phase9_cross_column.py','dfa_phase7_three_byte.py','dfa_phase7_generate.cpp','dfa_phase7_filter.cpp','dfa_aes_baseline_verified.py','phase14_blind_trials.csv','phase14_blind_summary.csv','PHASE14_REPORT.json','PHASE14_README.txt','phase14_unique_recovery.png','phase14_runtime.png','phase14_surviving_supports.png']
    with zipfile.ZipFile(OUT+'/AES_DFA_Phase14_Statistical_Blind_Validation.zip','w',zipfile.ZIP_DEFLATED) as z:
      for fn in files:z.write(OUT+'/'+fn,arcname=fn)
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
