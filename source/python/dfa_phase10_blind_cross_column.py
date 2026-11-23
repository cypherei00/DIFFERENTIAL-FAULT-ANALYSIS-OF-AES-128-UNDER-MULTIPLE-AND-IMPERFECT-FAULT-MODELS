"""Phase X prototype: blind location/distribution search for exactly 3 AES faults.
Software model: round 9, after ShiftRows, before MixColumns.
Enumerates all supports of three distinct state bytes across 1, 2, or 3 columns.
Uses per-column 1-/2-byte DFA constraints. Same-column 3-byte hypotheses are
explicitly deferred to the Phase VII C++ solver and are not silently claimed.
"""
import itertools, random, time, csv, json, zipfile, os
import dfa_phase9_cross_column as p9
import dfa_aes_baseline_verified as aes

# Supports are tuples of (column, row). Enumerate distributions 2+1 and 1+1+1.
def hypotheses():
    out=[]
    # 2+1: choose paired column, two distinct rows; singleton column and row
    for c1,c2 in itertools.permutations(range(4),2):
        for rr in itertools.combinations(range(4),2):
            for r2 in range(4):
                out.append(tuple(sorted(((c1,rr[0]),(c1,rr[1]),(c2,r2)))))
    # 1+1+1: choose 3 columns and one row in each
    for cols in itertools.combinations(range(4),3):
        for rows in itertools.product(range(4), repeat=3):
            out.append(tuple(sorted(zip(cols,rows))))
    return sorted(set(out))

def grouped(support):
    d={}
    for c,r in support:d.setdefault(c,[]).append(r)
    return {c:tuple(sorted(rs)) for c,rs in d.items()}

def score_hypothesis(pairs,support):
    groups=grouped(support); surviving={}; counts={}
    for col,rows in groups.items():
        cand=None; cc=[]
        for c,f in pairs[col]:
            cur=p9.pair_candidates(c,f,col,rows)
            cand=cur if cand is None else cand & cur
            cc.append(len(cand))
            if not cand:break
            # Do not stop at a singleton; later pairs must reject accidental fits.
        surviving[col]=cand or set(); counts[col]=cc
        if not surviving[col]:return False, counts, surviving
    return True,counts,surviving

def build_blind_trial(seed=20261117, distribution='2+1', pair_count=3):
    rng=random.Random(seed); key=[rng.randrange(256) for _ in range(16)]
    if distribution=='2+1':
        cols=rng.sample(range(4),2); rows1=sorted(rng.sample(range(4),2)); rows2=[rng.randrange(4)]
        support=tuple(sorted([(cols[0],r) for r in rows1]+[(cols[1],rows2[0])]))
    else:
        cols=rng.sample(range(4),3); support=tuple(sorted((c,rng.randrange(4)) for c in cols))
    pairs={c:[] for c,_ in support}
    for _ in range(pair_count):
        pt=[rng.randrange(256) for _ in range(16)]
        faults=[(c,r,rng.randrange(1,256)) for c,r in support]
        correct,faulty=p9.enc_faults(pt,key,faults)
        for c in pairs:pairs[c].append((correct,faulty))
    return key,support,pairs

def run_one(seed=20261117,distribution='2+1',pair_count=3):
    key,true_support,pairs=build_blind_trial(seed,distribution,pair_count)
    hs=hypotheses(); t0=time.perf_counter(); viable=[]; records=[]
    for i,h in enumerate(hs,1):
        ok,counts,cands=score_hypothesis(pairs,h)
        records.append({'hypothesis_id':i,'support':';'.join(f'{c}:{r}' for c,r in h),
                        'distribution':'-'.join(map(str,sorted(map(len,grouped(h).values()),reverse=True))),
                        'survives':int(ok),'candidate_counts':json.dumps(counts,sort_keys=True)})
        if ok:viable.append(h)
    elapsed=time.perf_counter()-t0
    truth=tuple(sorted(true_support))
    report={'seed':seed,'fault_distribution':distribution,'pair_count':pair_count,
            'hypotheses_tested':len(hs),'viable_hypotheses':len(viable),
            'true_support':';'.join(f'{c}:{r}' for c,r in truth),
            'true_support_survived':truth in viable,
            'unique_location_recovery':len(viable)==1 and viable[0]==truth,
            'runtime_seconds':elapsed,
            'scope':['Blind support search for 2+1 and 1+1+1 distributions.',
                     'Exactly three distinct faulted state bytes.',
                     'Same-column 3-byte (3+0+0) distribution is not included in this prototype.',
                     'Per-column candidate groups are checked independently; full 128-bit master-key recovery is not claimed.']}
    return report,records

if __name__=='__main__':
    report,rows=run_one()
    with open('/mnt/data/phase10_blind_hypotheses.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    with open('/mnt/data/PHASE10_REPORT.json','w') as f:json.dump(report,f,indent=2)
    with open('/mnt/data/PHASE10_README.txt','w') as f:
        f.write('PHASE X — BLIND CROSS-COLUMN FAULT SUPPORT SEARCH (PROTOTYPE)\n\n')
        f.write('Enumerates 288 2+1 supports and 256 1+1+1 supports (544 total).\n')
        f.write('Uses one-/two-byte same-column differential constraints. It excludes 3+0+0 same-column supports and does not claim full master-key recovery.\n\n')
        f.write(json.dumps(report,indent=2))
    with zipfile.ZipFile('/mnt/data/AES_DFA_Phase10_Blind_Cross_Column_Prototype.zip','w',zipfile.ZIP_DEFLATED) as z:
        for fn in ['dfa_phase10_blind_cross_column.py','dfa_phase9_cross_column.py','dfa_aes_baseline_verified.py','phase10_blind_hypotheses.csv','PHASE10_REPORT.json','PHASE10_README.txt']:
            z.write('/mnt/data/'+fn,arcname=fn)
    print(json.dumps(report,indent=2))
