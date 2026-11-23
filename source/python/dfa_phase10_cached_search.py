"""Phase X optimized blind support search.
Enumerates exactly-three-fault supports in 2+1 and 1+1+1 distributions.
Caches per-column/per-row-subset candidate sets so hypotheses reuse work.
This is NOT a C++ implementation and does NOT include 3+0+0 supports.
"""
import itertools, random, time, csv, json, statistics
import dfa_phase9_cross_column as p9
import dfa_aes_baseline_verified as aes

# Precompute GF(256) multiplication to avoid repeated bit-serial multiplication.
GF = [[aes.gf_mul(a,b) for b in range(256)] for a in range(256)]
aes.gf_mul = lambda a,b: GF[a][b]

def hypotheses():
    out=[]
    for c1,c2 in itertools.permutations(range(4),2):
        for rr in itertools.combinations(range(4),2):
            for r2 in range(4):
                out.append(tuple(sorted(((c1,rr[0]),(c1,rr[1]),(c2,r2)))))
    for cols in itertools.combinations(range(4),3):
        for rows in itertools.product(range(4), repeat=3):
            out.append(tuple(sorted(zip(cols,rows))))
    return sorted(set(out))

def trial(seed, distribution, pair_count=3):
    rng=random.Random(seed); key=[rng.randrange(256) for _ in range(16)]
    if distribution=='2+1':
        cols=rng.sample(range(4),2); rr=sorted(rng.sample(range(4),2))
        support=tuple(sorted([(cols[0],r) for r in rr]+[(cols[1],rng.randrange(4))]))
    elif distribution=='1+1+1':
        cols=rng.sample(range(4),3)
        support=tuple(sorted((c,rng.randrange(4)) for c in cols))
    else: raise ValueError(distribution)

    pairs=[]
    for _ in range(pair_count):
        pt=[rng.randrange(256) for _ in range(16)]
        faults=[(c,r,rng.randrange(1,256)) for c,r in support]
        pairs.append(p9.enc_faults(pt,key,faults))

    hs=hypotheses()
    # Cache each possible one-/two-row model for every column and pair.
    cache={}; t0=time.perf_counter()
    row_models=[(r,) for r in range(4)]+list(itertools.combinations(range(4),2))
    for col in range(4):
        for rows in row_models:
            for j,(correct,faulty) in enumerate(pairs):
                cache[(col,rows,j)] = p9.pair_candidates(correct,faulty,col,rows)
    generation=time.perf_counter()-t0

    viable=[]; details=[]
    for idx,h in enumerate(hs,1):
        groups={}
        for col,row in h: groups.setdefault(col,[]).append(row)
        ok=True; count_by_col={}
        for col,rs in groups.items():
            rows=tuple(sorted(rs)); candidates=None; counts=[]
            for j in range(pair_count):
                current=cache[(col,rows,j)]
                candidates=current if candidates is None else candidates.intersection(current)
                counts.append(len(candidates))
                if not candidates: break
            count_by_col[str(col)]=counts
            if not candidates: ok=False; break
        if ok: viable.append(h)
        details.append({'hypothesis_id':idx,
          'support':';'.join(f'{c}:{r}' for c,r in h),
          'distribution':'-'.join(map(str,sorted(map(len,groups.values()),reverse=True))),
          'survives':int(ok),'candidate_counts':json.dumps(count_by_col,sort_keys=True)})
    elapsed=time.perf_counter()-t0
    truth=tuple(sorted(support))
    return {'seed':seed,'distribution':distribution,'true_support':';'.join(f'{c}:{r}' for c,r in truth),
      'hypotheses_tested':len(hs),'viable_hypotheses':len(viable),
      'true_support_survived':truth in viable,
      'unique_location_recovery':len(viable)==1 and viable[0]==truth,
      'candidate_generation_seconds':generation,'total_runtime_seconds':elapsed}, details

if __name__=='__main__':
    results=[]; all_details=[]
    for dist,base in [('2+1',20261117),('1+1+1',20262117)]:
        for i in range(2):
            summary,detail=trial(base+i,dist,3)
            summary['trial']=i+1; results.append(summary)
            if i==0: all_details.extend(detail)
    with open('phase10_trial_summary.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(results[0]));w.writeheader();w.writerows(results)
    with open('phase10_hypotheses_trial1_each.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(all_details[0]));w.writeheader();w.writerows(all_details)
    with open('PHASE10_REPORT.json','w') as f: json.dump(results,f,indent=2)
    print(json.dumps(results,indent=2))
