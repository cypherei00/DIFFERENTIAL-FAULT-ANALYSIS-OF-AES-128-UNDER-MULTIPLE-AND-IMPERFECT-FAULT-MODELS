"""Phase XIII: blind exactly-three-byte support search over all 560 supports.
Uses shared ciphertext pairs and per-column candidate-set caching for 1/2/3-byte models.
A support is viable only if every attacked column's K10 group candidate set remains nonempty across all pairs.
"""
import os,sys,random,time,itertools,struct,csv,json,zipfile,statistics
sys.path.insert(0,'/mnt/data')
import dfa_phase9_cross_column as p9
import dfa_phase7_three_byte as py7
import dfa_aes_baseline_verified as aes

BASE='/mnt/data/p13_base.bin'; META='/mnt/data/p13_meta.bin'; OUT='/mnt/data/p13_out.bin'; MAP='/mnt/data/p13_maps.bin'; COEFF='/mnt/data/p13_coeff.bin'
GEN='/mnt/data/dfa_phase7_generate'; FIL='/mnt/data/dfa_phase7_filter'

def make_maps(c,f,col):
    pos=aes.affected_ciphertext_indices(col)
    with open(MAP,'wb') as o:
        for p in pos:o.write(bytes(aes.INV_SBOX[c[p]^k]^aes.INV_SBOX[f[p]^k] for k in range(256)))

def make_coeff(rows):
    coeff=bytes(py7.MIX[r][rows[j]] for r in range(4) for j in range(3))
    with open(COEFF,'wb') as o:o.write(coeff);o.write(bytes([py7.INV_GF[py7.MIX[3][rows[2]]]]))

def make_filter_meta(c,f,col,rows):
    pos=aes.affected_ciphertext_indices(col)
    maps=[bytes(aes.INV_SBOX[c[p]^k]^aes.INV_SBOX[f[p]^k] for k in range(256)) for p in pos]
    A=[[py7.MIX[r][rows[j]] for j in range(3)] for r in range(3)]
    inv=py7.invert3(A); row4=bytes(py7.MIX[3][r] for r in rows)
    with open(META,'wb') as o:
        for m in maps:o.write(m)
        for r in inv:o.write(bytes(r))
        o.write(row4)

def candidates_three(pairs,col,rows):
    make_maps(*pairs[0],col);make_coeff(rows)
    subprocess_run([GEN,MAP,COEFF,BASE])
    counts=[os.path.getsize(BASE)//4]
    for c,f in pairs[1:]:
        make_filter_meta(c,f,col,rows);subprocess_run([FIL,BASE,OUT,META]);os.replace(OUT,BASE)
        counts.append(os.path.getsize(BASE)//4)
        if counts[-1]==0:break
    return counts

def subprocess_run(cmd):
    import subprocess
    subprocess.run(cmd,capture_output=True,text=True,check=True)

def main(seed=2026111703,pair_count=5):
    # Reproducible randomly selected three-fault support, unknown to recovery stage.
    rng=random.Random(seed);key=[rng.randrange(256) for _ in range(16)]
    true_support=tuple(sorted(rng.sample([(c,r) for c in range(4) for r in range(4)],3)))
    pairs=[]
    for _ in range(pair_count):
        pt=[rng.randrange(256) for _ in range(16)]
        faults=[(c,r,rng.randrange(1,256)) for c,r in true_support]
        pairs.append(p9.enc_faults(pt,key,faults))
    # Fast GF lookup for 1-/2-byte candidate model.
    GF=[[aes.gf_mul(a,b) for b in range(256)] for a in range(256)]
    aes.gf_mul=lambda a,b:GF[a][b]
    p9.aes.gf_mul=lambda a,b:GF[a][b]
    t0=time.perf_counter(); cache={}; cache_counts={}
    row_models=[(r,) for r in range(4)]+list(itertools.combinations(range(4),2))
    # Cache all one- and two-byte models for each column and each pair, intersecting as generated.
    for col in range(4):
        for rows in row_models:
            cur=None; cc=[]
            for c,f in pairs:
                cand=p9.pair_candidates(c,f,col,rows)
                cur=cand if cur is None else cur.intersection(cand)
                cc.append(len(cur))
                if not cur:break
            cache[(col,rows)]=cur or set();cache_counts[(col,rows)]=cc
    # Cache all three-byte models (four row triples per column) using the C++ generator/filter.
    for col in range(4):
        for rows in itertools.combinations(range(4),3):
            cc=candidates_three(pairs,col,rows)
            raw=open(BASE,'rb').read(); vals=struct.unpack('<'+'I'*(len(raw)//4),raw) if raw else ()
            cache[(col,rows)]=set(vals);cache_counts[(col,rows)]=cc
    gen_time=time.perf_counter()-t0
    # Enumerate all 560 supports exactly; test each support using cached per-column intersections.
    supports=list(itertools.combinations([(c,r) for c in range(4) for r in range(4)],3))
    viable=[]; detail=[]
    for idx,s in enumerate(supports,1):
        groups={}
        for c,r in s:groups.setdefault(c,[]).append(r)
        group_ok={}; cand_sizes={}
        for col,rs in groups.items():
            rows=tuple(sorted(rs)); cs=cache[(col,rows)]
            group_ok[col]=bool(cs);cand_sizes[col]=len(cs)
        survives=all(group_ok.values())
        if survives:viable.append(s)
        detail.append({'hypothesis_id':idx,'support':';'.join(f'{c}:{r}' for c,r in s),
          'distribution':'-'.join(map(str,sorted((len(v) for v in groups.values()),reverse=True))),
          'survives':int(survives),'per_column_candidate_counts':json.dumps(cand_sizes,sort_keys=True)})
    total=time.perf_counter()-t0
    truth_survived=true_support in viable
    unique=(len(viable)==1 and viable[0]==true_support)
    # If unique, assemble K10 groups from the candidate sets and verify master key.
    recovered_k10=[None]*16; full_key=False; recovered_master=None
    if unique:
        for col,rs in {c:tuple(sorted(r for cc,r in true_support if cc==c)) for c in set(c for c,r in true_support)}.items():
            cand=cache[(col,rs)]
            if len(cand)!=1:break
            packed=next(iter(cand))
            if isinstance(packed, tuple):
                group_bytes=packed
            else:
                group_bytes=tuple((packed>>(24-8*j))&255 for j in range(4))
            for j,pos in enumerate(aes.affected_ciphertext_indices(col)):
                recovered_k10[pos]=group_bytes[j]
        if all(x is not None for x in recovered_k10):
            recovered_master=aes.invert_last_round_key(recovered_k10)
            full_key=(recovered_master==key)
    report={'phase':'XIII','seed':seed,'pair_count':pair_count,'true_support':';'.join(f'{c}:{r}' for c,r in true_support),
      'hypotheses_tested':len(supports),'viable_hypotheses':len(viable),'true_support_survived':truth_survived,
      'unique_support_recovery':unique,'full_master_key_recovered_and_verified':bool(full_key),
      'candidate_generation_and_intersection_seconds':gen_time,'total_runtime_seconds':total,
      'per_model_candidate_counts':{f'c{c}_r{"".join(map(str,rows))}':cache_counts[(c,rows)] for c in range(4) for rows in row_models+list(itertools.combinations(range(4),3))},
      'limitations':['Single reproducible software-injection trial.','Blind support decision uses nonempty per-column K10 candidate intersections.','Full 128-bit key recovery is only possible if support is unique and all 16 K10 bytes are covered; three faults affect at most three columns, so the attacked data alone does not determine the fourth K10 column.']}
    with open('/mnt/data/phase13_blind_560_hypotheses.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(detail[0]));w.writeheader();w.writerows(detail)
    with open('/mnt/data/PHASE13_REPORT.json','w') as f:json.dump(report,f,indent=2)
    with open('/mnt/data/PHASE13_README.txt','w') as f:f.write('PHASE XIII — BLIND 560-SUPPORT SEARCH\n\n'+json.dumps(report,indent=2)+'\n')
    files=['dfa_phase13_blind_560.py','dfa_phase9_cross_column.py','dfa_phase7_three_byte.py','dfa_phase7_generate.cpp','dfa_phase7_filter.cpp','dfa_aes_baseline_verified.py','phase13_blind_560_hypotheses.csv','PHASE13_REPORT.json','PHASE13_README.txt']
    with zipfile.ZipFile('/mnt/data/AES_DFA_Phase13_Blind_560_Search.zip','w',zipfile.ZIP_DEFLATED) as z:
        for fn in files:z.write('/mnt/data/'+fn,arcname=fn)
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
