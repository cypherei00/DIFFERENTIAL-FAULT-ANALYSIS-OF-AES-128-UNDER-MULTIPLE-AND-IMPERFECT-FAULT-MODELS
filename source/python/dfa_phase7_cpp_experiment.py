"""C++-accelerated Phase VII filtering experiment; Python handles AES and candidate generation."""
import os, random, struct, subprocess, time, csv, itertools
import dfa_phase7_three_byte as py
import dfa_aes_baseline_verified as aes

BIN='/mnt/data/phase7_candidates.bin'
META='/mnt/data/phase7_filter_meta.bin'
OUT='/mnt/data/phase7_candidates_filtered.bin'
CPP='/mnt/data/dfa_phase7_filter'
MIX=py.MIX

def write_meta(correct,faulty,col,rows):
    pos=aes.affected_ciphertext_indices(col)
    maps=[]
    for p in pos:
        vals=bytes(aes.INV_SBOX[correct[p]^k]^aes.INV_SBOX[faulty[p]^k] for k in range(256))
        maps.append(vals)
    A=[[MIX[r][rows[j]] for j in range(3)] for r in range(3)]
    inv=py.invert3(A)
    row4=bytes(MIX[3][r] for r in rows)
    with open(META,'wb') as f:
        for m in maps: f.write(m)
        for r in inv: f.write(bytes(r))
        f.write(row4)

def main():
    rng=random.Random(7312026)
    rows=(0,1,2); col=0
    key=[rng.randrange(256) for _ in range(16)]
    k10=aes.expand_key(key)[10]
    pairs=py.generate_pairs(rng,key,col,rows,6)
    t=time.perf_counter()
    candidates=py.generate_base_candidates(*pairs[0],col,rows)
    gen=time.perf_counter()-t
    truth=sum(k10[p]<<(24-8*i) for i,p in enumerate(aes.affected_ciphertext_indices(col)))
    with open(BIN,'wb') as f: candidates.tofile(f)
    counts=[len(candidates)]; times=[]
    print('generated',len(candidates),'true retained',truth in candidates,'seconds',round(gen,3),flush=True)
    for idx,(c,faulty) in enumerate(pairs[1:],start=2):
        write_meta(c,faulty,col,rows)
        t=time.perf_counter()
        proc=subprocess.run([CPP,BIN,OUT,META],capture_output=True,text=True,check=True)
        elapsed=time.perf_counter()-t
        os.replace(OUT,BIN)
        n=os.path.getsize(BIN)//4
        counts.append(n);times.append(elapsed)
        print('after pair',idx,'count',n,'cpp',proc.stdout.strip(),'seconds',round(elapsed,3),flush=True)
    final=[]
    with open(BIN,'rb') as f:
        data=f.read()
    if len(data)%4==0:
        final=list(struct.unpack('<'+'I'*(len(data)//4),data))
    print('truth',hex(truth),'retained',truth in final,'unique',len(final)==1 and final[0]==truth)
    print('key',bytes(key).hex(),'K10',bytes(k10).hex())
    with open('/mnt/data/phase7_cpp_single_case.csv','w',newline='') as f:
        w=csv.writer(f);w.writerow(['pair_count','remaining_candidates','elapsed_filter_seconds']);w.writerow([1,counts[0],gen]);
        for i,(n,tm) in enumerate(zip(counts[1:],times),start=2):w.writerow([i,n,tm])
    return counts,times
if __name__=='__main__': main()
