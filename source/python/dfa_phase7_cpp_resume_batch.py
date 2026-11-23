import os,csv,random,time,json,statistics
import dfa_phase7_cpp_statistical as core
import dfa_phase7_three_byte as py

COL='/mnt/data/phase7_cpp_column_trials.csv'; TR='/mnt/data/phase7_cpp_trial_summary.csv'
def read(path):
    return list(csv.DictReader(open(path))) if os.path.exists(path) else []
def save(path,rows):
    if rows:
        with open(path,'w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
cols=read(COL); trials=read(TR)
start=time.perf_counter()
for ix,rows in enumerate(py.TRIPLES):
    name='-'.join(map(str,rows)); have=sum(1 for r in trials if r['row_triple']==name)
    target=30
    print('RESUME',name,'already',have,'target',target,flush=True)
    rng=random.Random(20261117+1009*ix+have*7919)
    for tnum in range(have+1,target+1):
        key=bytes(rng.randrange(256) for _ in range(16)); t0=time.perf_counter(); oks=[]
        for col in range(4):
            ok,rec=core.recover_column(rng,key,col,rows,6)
            rec['trial']=tnum; cols.append(rec); oks.append(ok)
        trials.append({'row_triple':name,'trial':tnum,'all_four_columns_unique':int(all(oks)),
            'master_key_recovered':int(all(oks)),'trial_seconds':round(time.perf_counter()-t0,6),'master_key_hex':key.hex()})
        save(COL,cols); save(TR,trials)
        print(name,'trial',tnum,'complete',all(oks),'pairs',[r['pairs_used'] for r in cols[-4:]],'seconds',round(time.perf_counter()-t0,2),flush=True)
summary=[]
for rows in py.TRIPLES:
    name='-'.join(map(str,rows)); ts=[r for r in trials if r['row_triple']==name]; cs=[r for r in cols if r['row_triple']==name]
    summary.append({'row_triple':name,'trials':len(ts),'complete_master_key_recoveries':sum(int(r['master_key_recovered']) for r in ts),
      'master_key_success_rate':sum(int(r['master_key_recovered']) for r in ts)/len(ts),
      'column_recoveries':sum(int(r['unique_recovery']) for r in cs),'column_recovery_rate':sum(int(r['unique_recovery']) for r in cs)/len(cs),
      'mean_pairs_per_column':round(statistics.mean(int(r['pairs_used']) for r in cs),4),
      'mean_column_runtime_seconds':round(statistics.mean(float(r['column_total_seconds']) for r in cs),6),
      'median_column_runtime_seconds':round(statistics.median(float(r['column_total_seconds']) for r in cs),6),
      'max_candidate_file_bytes':max(int(r['peak_candidate_file_bytes']) for r in cs)})
save('/mnt/data/phase7_cpp_statistical_summary.csv',summary)
report={'target_trials_per_row_triple':30,'actual_trials_per_row_triple':{r['row_triple']:int(r['trials']) for r in summary},'columns_per_trial':4,
 'total_column_experiments':len(cols),'total_runtime_this_resume_seconds':round(time.perf_counter()-start,3),'summary':summary,
 'interpretation':'Complete master-key success is counted only when all four column groups are uniquely recovered in that trial. Known faulted row triple and column; unknown nonzero magnitudes. This does not evaluate unknown fault locations.'}
with open('/mnt/data/PHASE7_CPP_STATISTICAL_REPORT.json','w') as f:json.dump(report,f,indent=2)
print('FINAL',json.dumps(report,indent=2),flush=True)
