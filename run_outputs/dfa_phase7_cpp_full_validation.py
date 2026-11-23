"""C++-accelerated one-trial full-key validation across all row triples/columns."""
from pathlib import Path
RUN_DIR = str(Path(__file__).resolve().parent)
import os, random, struct, subprocess, time, csv, json
import dfa_phase7_three_byte as py
import dfa_aes_baseline_verified as aes
BASE=RUN_DIR + '/phase7_candidates.bin'; META=RUN_DIR + '/phase7_filter_meta.bin'; OUT=RUN_DIR + '/phase7_candidates_filtered.bin'; MAP=RUN_DIR + '/phase7_base_maps.bin'; COEFF=RUN_DIR + '/phase7_coeff.bin'
GEN=RUN_DIR + '/dfa_phase7_generate'; FIL=RUN_DIR + '/dfa_phase7_filter'

def write_maps(c,f,col):
    pos=aes.affected_ciphertext_indices(col)
    with open(MAP,'wb') as out:
        for p in pos: out.write(bytes(aes.INV_SBOX[c[p]^k]^aes.INV_SBOX[f[p]^k] for k in range(256)))

def write_coeff(rows):
    coeff=bytes(py.MIX[r][rows[j]] for r in range(4) for j in range(3))
    # inverse of coefficient multiplying third magnitude in output row 3
    cc=py.MIX[3][rows[2]]
    inv=py.INV_GF[cc]
    with open(COEFF,'wb') as f:f.write(coeff);f.write(bytes([inv]))

def write_filter_meta(c,f,col,rows):
    pos=aes.affected_ciphertext_indices(col)
    maps=[bytes(aes.INV_SBOX[c[p]^k]^aes.INV_SBOX[f[p]^k] for k in range(256)) for p in pos]
    A=[[py.MIX[r][rows[j]] for j in range(3)] for r in range(3)]
    inv=py.invert3(A); row4=bytes(py.MIX[3][r] for r in rows)
    with open(META,'wb') as out:
        for m in maps:out.write(m)
        for r in inv:out.write(bytes(r))
        out.write(row4)

def run_col(rng,key,col,rows,pair_count=6):
    k10=aes.expand_key(key)[10]; pairs=py.generate_pairs(rng,key,col,rows,pair_count)
    write_maps(*pairs[0],col);write_coeff(rows)
    t=time.perf_counter(); g=subprocess.run([GEN,MAP,COEFF,BASE],capture_output=True,text=True,check=True); gen=time.perf_counter()-t
    n=os.path.getsize(BASE)//4; truth=sum(k10[p]<<(24-8*i) for i,p in enumerate(aes.affected_ciphertext_indices(col)))
    rec=[{'row_triple':'-'.join(map(str,rows)),'column':col,'pairs_used':1,'candidate_count':n,'stage_seconds':gen,'true_key_retained':int(struct.pack('<I',truth) in open(BASE,'rb').read())}]
    for pairnum,(c,f) in enumerate(pairs[1:],start=2):
        write_filter_meta(c,f,col,rows);t=time.perf_counter()
        pr=subprocess.run([FIL,BASE,OUT,META],capture_output=True,text=True,check=True); elapsed=time.perf_counter()-t
        os.replace(OUT,BASE);n=os.path.getsize(BASE)//4
        retained=struct.pack('<I',truth) in open(BASE,'rb').read()
        rec.append({'row_triple':'-'.join(map(str,rows)),'column':col,'pairs_used':pairnum,'candidate_count':n,'stage_seconds':elapsed,'true_key_retained':int(retained)})
        if n<=1:break
    raw=open(BASE,'rb').read(); vals=struct.unpack('<'+'I'*(len(raw)//4),raw) if raw else ()
    return len(vals)==1 and vals[0]==truth,rec

def main():
    rng=random.Random(7312026);key=[rng.randrange(256) for _ in range(16)];master=bytes(key);k10=bytes(aes.expand_key(key)[10])
    records=[]; trials=[]; recovered_k10=[None]*16; t0=time.perf_counter()
    for rows in py.TRIPLES:
        print('ROW TRIPLE',rows,flush=True);oks=[]
        for col in range(4):
            ok,rr=run_col(rng,key,col,rows,6);records.extend(rr);oks.append(ok)
            if ok:
                raw=open(BASE,'rb').read(); packed=struct.unpack('<I',raw)[0]
                for j,p in enumerate(aes.affected_ciphertext_indices(col)):
                    recovered_k10[p]=(packed >> (24-8*j)) & 255
            print(' column',col,'unique',ok,'counts',[x['candidate_count'] for x in rr],flush=True)
        trials.append({'row_triple':'-'.join(map(str,rows)),'columns_uniquely_recovered':sum(oks),'all_four_columns_unique':int(all(oks)),'master_key_recovered':int(all(oks))})
    elapsed=time.perf_counter()-t0
    recovered_master=aes.invert_last_round_key(recovered_k10) if all(x is not None for x in recovered_k10) else None
    full_key_verified=(recovered_master is not None and recovered_master==key)
    with open(RUN_DIR + '/phase7_cpp_pairwise_results.csv','w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(records[0]));w.writeheader();w.writerows(records)
    with open(RUN_DIR + '/phase7_cpp_full_validation.csv','w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(trials[0]));w.writeheader();w.writerows(trials)
    report={'seed':7312026,'master_key_hex':master.hex(),'round10_key_hex':k10.hex(),'row_triples':trials,'recovered_round10_key_hex':bytes(recovered_k10).hex() if all(x is not None for x in recovered_k10) else None,'recovered_master_key_hex':bytes(recovered_master).hex() if recovered_master else None,'full_master_key_verified':full_key_verified,'total_runtime_seconds':elapsed,'note':'One reproducible trial per row triple, all four columns, six pairs maximum. Exploratory validation, not a statistical evaluation.'}
    with open(RUN_DIR + '/PHASE7_CPP_VALIDATION.json','w') as f:json.dump(report,f,indent=2)
    print('MASTER',master.hex(),'K10',k10.hex(),'RECOVERED_MASTER',bytes(recovered_master).hex() if recovered_master else None,'VERIFIED',full_key_verified,'TOTAL_SECONDS',round(elapsed,2),flush=True);print(trials,flush=True)
if __name__=='__main__':main()
