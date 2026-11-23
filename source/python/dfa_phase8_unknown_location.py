"""Phase VIII: unknown three-byte fault location hypothesis search.
The attacker is not told the faulted column or row triple. It enumerates all
16 same-column/three-row hypotheses and tests each against shared ciphertext pairs.
"""
import os, random, subprocess, time, csv, json, struct, itertools
import dfa_phase7_three_byte as model
import dfa_aes_baseline_verified as aes

GEN='/mnt/data/dfa_phase7_generate'; FIL='/mnt/data/dfa_phase7_filter'
BASE='/mnt/data/phase8_base.bin'; OUT='/mnt/data/phase8_out.bin'; MAP='/mnt/data/phase8_maps.bin'; COEFF='/mnt/data/phase8_coeff.bin'; META='/mnt/data/phase8_meta.bin'
HYP=list(itertools.product(model.TRIPLES, range(4)))

def write_maps(c,f,col):
    pos=aes.affected_ciphertext_indices(col)
    with open(MAP,'wb') as out:
        for p in pos: out.write(bytes(aes.INV_SBOX[c[p]^k]^aes.INV_SBOX[f[p]^k] for k in range(256)))

def write_coeff(rows):
    coeff=bytes(model.MIX[r][rows[j]] for r in range(4) for j in range(3))
    inv=model.INV_GF[model.MIX[3][rows[2]]]
    with open(COEFF,'wb') as f: f.write(coeff); f.write(bytes([inv]))

def write_meta(c,f,col,rows):
    pos=aes.affected_ciphertext_indices(col)
    maps=[bytes(aes.INV_SBOX[c[p]^k]^aes.INV_SBOX[f[p]^k] for k in range(256)) for p in pos]
    A=[[model.MIX[r][rows[j]] for j in range(3)] for r in range(3)]
    inv=model.invert3(A); row4=bytes(model.MIX[3][r] for r in rows)
    with open(META,'wb') as out:
        for m in maps: out.write(m)
        for r in inv: out.write(bytes(r))
        out.write(row4)

def run_hypothesis(pairs,col,rows):
    c,f=pairs[0]; write_maps(c,f,col); write_coeff(rows)
    subprocess.run([GEN,MAP,COEFF,BASE],check=True,capture_output=True,text=True)
    counts=[os.path.getsize(BASE)//4]
    for i,(c,f) in enumerate(pairs[1:],start=2):
        write_meta(c,f,col,rows)
        subprocess.run([FIL,BASE,OUT,META],check=True,capture_output=True,text=True)
        os.replace(OUT,BASE); n=os.path.getsize(BASE)//4; counts.append(n)
        if n==0: break
    n=os.path.getsize(BASE)//4
    return n,counts

def main():
    rng=random.Random(20261118)
    true_rows=(0,2,3); true_col=2; key=bytes(rng.randrange(256) for _ in range(16))
    pairs=model.generate_pairs(rng,key,true_col,true_rows,8)
    # Ground truth is used only to score the experiment, never passed to hypothesis attack.
    results=[]; t0=time.perf_counter()
    for idx,(rows,col) in enumerate(HYP,1):
        start=time.perf_counter(); n,counts=run_hypothesis(pairs,col,rows)
        result={'hypothesis_rows':'-'.join(map(str,rows)),'hypothesis_column':col,
                'remaining_candidates':n,'candidate_counts':' ; '.join(map(str,counts)),
                'hypothesis_runtime_seconds':round(time.perf_counter()-start,4),
                'is_true_location':int(rows==true_rows and col==true_col)}
        results.append(result)
        print(idx,'/',len(HYP),result,flush=True)
    elapsed=time.perf_counter()-t0
    results.sort(key=lambda x:(x['remaining_candidates'], -x['is_true_location']))
    with open('/mnt/data/phase8_unknown_location_hypotheses.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(results[0]));w.writeheader();w.writerows(results)
    report={'seed':20261118,'pairs_used':8,'hypotheses_tested':len(HYP),'actual_fault_rows':'-'.join(map(str,true_rows)),
            'actual_fault_column':true_col,'total_hypothesis_search_seconds':round(elapsed,4),
            'ranked_hypotheses':results,
            'interpretation':'Exploratory single-case software-injection test. The true location is hidden from the hypothesis loop and used only to score results. This is not a statistical success-rate estimate.'}
    with open('/mnt/data/PHASE8_UNKNOWN_LOCATION_REPORT.json','w') as f:json.dump(report,f,indent=2)
    print('REPORT',json.dumps(report,indent=2),flush=True)
if __name__=='__main__': main()
