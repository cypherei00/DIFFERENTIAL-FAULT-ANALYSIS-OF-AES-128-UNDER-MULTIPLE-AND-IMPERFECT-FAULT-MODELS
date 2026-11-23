#!/usr/bin/env python3
"""Phase XV: multi-event blind AES-128 master-key recovery.

Each event has exactly three transient XOR byte faults, fixed support within
that event and independently sampled nonzero magnitudes for each pair. The
recovery stage receives ciphertext pairs only. It enumerates all C(16,3)=560
supports per event, recovers K10 groups from uniquely identified supports,
then combines groups across events and inverts the AES-128 key schedule.
"""
import os, sys, random, time, itertools, struct, subprocess, csv, json, zipfile, statistics
sys.path.insert(0, '/mnt/data')
import dfa_phase13_blind_560 as p13
import dfa_phase9_cross_column as p9
import dfa_aes_baseline_verified as aes

OUT='/mnt/data'
SMALL='/mnt/data/dfa_phase14_small_solver'
SMALL_MAP='/mnt/data/p15_small_maps.bin'
SMALL_COEFF='/mnt/data/p15_small_coeff.bin'
SMALL_OUT='/mnt/data/p15_small_out.bin'
SUPPORTS=list(itertools.combinations([(c,r) for c in range(4) for r in range(4)],3))
ROW_MODELS=[(r,) for r in range(4)]+list(itertools.combinations(range(4),2))


def pack_read(path):
    raw=open(path,'rb').read()
    return set(struct.unpack('<'+'I'*(len(raw)//4),raw)) if raw else set()


def choose_event_supports(rng, n_events=3):
    """Create diverse event geometries; supports remain hidden from recovery.

    Event 1 is 3+0+0, event 2 is 2+1, event 3 is 1+1+1.
    The union covers all four columns, while row locations are randomized.
    """
    if n_events != 3:
        raise ValueError('This validation profile uses exactly three diverse events.')
    s1=tuple(sorted((0,r) for r in rng.sample(range(4),3)))
    r2=rng.sample(range(4),2); r3=rng.randrange(4)
    s2=tuple(sorted([(1,r2[0]),(1,r2[1]),(2,r3)]))
    cols=(0,2,3)
    s3=tuple(sorted((c,rng.randrange(4)) for c in cols))
    return [s1,s2,s3]


def generate_pairs(rng, key, support, pair_count):
    pairs=[]
    for _ in range(pair_count):
        pt=[rng.randrange(256) for _ in range(16)]
        faults=[(c,r,rng.randrange(1,256)) for c,r in support]
        pairs.append(p9.enc_faults(pt,key,faults))
    return pairs


def build_cache(pairs):
    """Build intersected K10 four-byte candidate sets for all per-column row models."""
    cache={}; counts={}
    # C++ solver handles 1- and 2-row column models.
    for col in range(4):
        for rows in ROW_MODELS:
            n=len(rows); coeff=bytes(p9.M[r][rows[j]] for r in range(4) for j in range(n))
            with open(SMALL_COEFF,'wb') as f:f.write(coeff)
            cur=None; stages=[]
            for c,faulty in pairs:
                pos=aes.affected_ciphertext_indices(col)
                maps=bytes(aes.INV_SBOX[c[p]^k]^aes.INV_SBOX[faulty[p]^k] for p in pos for k in range(256))
                with open(SMALL_MAP,'wb') as f:f.write(maps)
                subprocess.run([SMALL,SMALL_MAP,SMALL_COEFF,str(n),SMALL_OUT],check=True,capture_output=True)
                cand=pack_read(SMALL_OUT)
                cur=cand if cur is None else cur.intersection(cand)
                stages.append(len(cur))
                if not cur:break
            cache[(col,rows)]=cur or set(); counts[(col,rows)]=stages
    # C++ 3-byte generator/filter for all 4 row triples in each column.
    for col in range(4):
        for rows in itertools.combinations(range(4),3):
            stages=p13.candidates_three(pairs,col,rows)
            cache[(col,rows)]=pack_read(p13.BASE); counts[(col,rows)]=stages
    return cache,counts


def blind_recover_event(pairs):
    t0=time.perf_counter(); cache,counts=build_cache(pairs)
    viable=[]
    for support in SUPPORTS:
        groups={}
        for c,r in support:groups.setdefault(c,[]).append(r)
        if all(cache[(c,tuple(sorted(rows)))] for c,rows in groups.items()):
            viable.append(support)
    elapsed=time.perf_counter()-t0
    recovered_groups={}
    if len(viable)==1:
        support=viable[0]
        groups={}
        for c,r in support:groups.setdefault(c,[]).append(r)
        for col,rows in groups.items():
            cand=cache[(col,tuple(sorted(rows)))]
            if len(cand)==1:
                packed=next(iter(cand))
                recovered_groups[col]=tuple((packed>>(24-8*j))&255 for j in range(4))
            else:
                recovered_groups[col]=None
    return viable, recovered_groups, counts, elapsed


def wilson(k,n,z=1.96):
    if n==0:return [None,None]
    ph=k/n; den=1+z*z/n
    center=(ph+z*z/(2*n))/den
    half=z*((ph*(1-ph)/n+z*z/(4*n*n))**0.5)
    return [center-half,center+half]


def main(seed=20261117015, n_events=3, pair_count=5):
    rng=random.Random(seed)
    key=[rng.randrange(256) for _ in range(16)]
    master=bytes(key); true_k10=bytes(aes.expand_key(key)[10])
    supports=choose_event_supports(rng,n_events)
    recovered=[None]*16; event_rows=[]; support_rows=[]; start=time.perf_counter()
    for ei,support in enumerate(supports,1):
        pairs=generate_pairs(rng,key,support,pair_count)
        viable,groups,counts,elapsed=blind_recover_event(pairs)
        unique=(len(viable)==1 and viable[0]==support)
        groups_correct=True
        for col,group in groups.items():
            if group is None:
                groups_correct=False; continue
            expected=tuple(true_k10[p] for p in aes.affected_ciphertext_indices(col))
            if group != expected: groups_correct=False
            for j,pos in enumerate(aes.affected_ciphertext_indices(col)):
                if recovered[pos] is None: recovered[pos]=group[j]
                elif recovered[pos] != group[j]: groups_correct=False
        event_rows.append({'event':ei,'pairs':pair_count,'true_support':';'.join(f'{c}:{r}' for c,r in support),
          'hypotheses_tested':560,'viable_supports':len(viable),'unique_correct_support':int(unique),
          'recovered_column_groups':len([x for x in groups.values() if x is not None]),
          'affected_columns':len(set(c for c,r in support)),'groups_match_true_K10':int(groups_correct),
          'runtime_seconds':elapsed,'surviving_supports':';'.join('|'.join(f'{c}:{r}' for c,r in s) for s in viable)})
        for s in viable:
            support_rows.append({'event':ei,'support':';'.join(f'{c}:{r}' for c,r in s),'is_true':int(s==support)})
        print(f'event {ei}: unique={unique}, viable={len(viable)}, recovered_groups={len([x for x in groups.values() if x is not None])}, sec={elapsed:.2f}',flush=True)
    full_coverage=all(x is not None for x in recovered)
    recovered_master=aes.invert_last_round_key(recovered) if full_coverage else None
    verified=bool(recovered_master is not None and recovered_master==key)
    total=time.perf_counter()-start
    report={'phase':'XV','seed':seed,'events':n_events,'ciphertext_pairs_per_event':pair_count,
      'total_correct_faulty_pairs':n_events*pair_count,'faults_per_event':3,
      'same_AES128_key_across_events':True,'support_hidden_from_recovery':True,
      'support_union_covers_all_four_columns':sorted({c for s in supports for c,r in s})==[0,1,2,3],
      'event_results':event_rows,'recovered_K10_hex':bytes(recovered).hex() if full_coverage else None,
      'true_K10_hex':true_k10.hex(),'full_K10_coverage':full_coverage,
      'recovered_master_key_hex':bytes(recovered_master).hex() if verified else None,
      'true_master_key_hex':master.hex(),'full_master_key_verified':verified,
      'total_runtime_seconds':total,
      'limitations':['Single reproducible multi-event experiment; not a statistical success-rate estimate.',
       'Each event has a fixed three-byte support across its pairs; support and magnitudes are unknown to recovery.',
       'Blind support selection uses nonempty per-column candidate intersections; group bytes are accepted only when the support is unique and the group candidate set is singleton.',
       'Software fault injection at round 9 after ShiftRows and before MixColumns; no physical fault validation.']}
    with open(OUT+'/phase15_multi_event_trials.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(event_rows[0]));w.writeheader();w.writerows(event_rows)
    with open(OUT+'/phase15_support_survivors.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(support_rows[0]));w.writeheader();w.writerows(support_rows)
    with open(OUT+'/PHASE15_REPORT.json','w') as f:json.dump(report,f,indent=2)
    with open(OUT+'/PHASE15_README.txt','w') as f:
        f.write('PHASE XV — MULTI-EVENT BLIND AES-128 MASTER-KEY RECOVERY\n\n')
        f.write('Run: python dfa_phase15_multi_event.py\n')
        f.write('Requires Python 3, matplotlib for plots, g++ (C++17), and the Phase VII C++ generator/filter plus Phase XIV small solver.\n')
        f.write('The recovery stage receives only correct/faulty ciphertext pairs; it enumerates all 560 supports independently for every event.\n\n')
        f.write(json.dumps(report,indent=2)+'\n')
    # Graphs directly from measured event rows.
    import matplotlib; matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    xs=[f'Event {r["event"]}' for r in event_rows]
    plt.figure(figsize=(8,5));plt.bar(xs,[r['viable_supports'] for r in event_rows]);plt.ylabel('Surviving support hypotheses');plt.xlabel('Fault event');plt.title('Blind support ambiguity across independent events');plt.tight_layout();plt.savefig(OUT+'/phase15_support_ambiguity.png',dpi=180);plt.close()
    plt.figure(figsize=(8,5));plt.bar(xs,[r['runtime_seconds'] for r in event_rows]);plt.ylabel('Runtime (seconds)');plt.xlabel('Fault event');plt.title('Per-event blind recovery runtime');plt.tight_layout();plt.savefig(OUT+'/phase15_runtime.png',dpi=180);plt.close()
    plt.figure(figsize=(8,5));plt.bar(['K10 bytes recovered','K10 bytes missing'],[sum(x is not None for x in recovered),sum(x is None for x in recovered)]);plt.ylabel('Number of bytes');plt.title('Final-round key coverage after multiple events');plt.tight_layout();plt.savefig(OUT+'/phase15_key_coverage.png',dpi=180);plt.close()
    files=['dfa_phase15_multi_event.py','dfa_phase14_small_solver.cpp','dfa_phase14_small_solver','dfa_phase13_blind_560.py','dfa_phase9_cross_column.py','dfa_phase7_three_byte.py','dfa_phase7_generate.cpp','dfa_phase7_filter.cpp','dfa_phase7_generate','dfa_phase7_filter','dfa_aes_baseline_verified.py','phase15_multi_event_trials.csv','phase15_support_survivors.csv','PHASE15_REPORT.json','PHASE15_README.txt','phase15_support_ambiguity.png','phase15_runtime.png','phase15_key_coverage.png','run_phase15.sh']
    with zipfile.ZipFile(OUT+'/AES_DFA_Phase15_Multi_Event_Blind_Recovery.zip','w',zipfile.ZIP_DEFLATED) as z:
        for fn in files:z.write(OUT+'/'+fn,arcname=fn)
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
