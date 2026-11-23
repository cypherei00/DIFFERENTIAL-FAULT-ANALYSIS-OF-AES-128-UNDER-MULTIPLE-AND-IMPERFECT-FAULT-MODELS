import os, random, time, csv, json, subprocess, itertools, statistics, zipfile, shutil
import dfa_phase7_three_byte as model
import dfa_aes_baseline_verified as aes
from dfa_phase8_unknown_location import HYP, run_hypothesis

TRIALS=30; PAIRS=8; SEED=20261117
rng=random.Random(SEED)
trial_rows=[]; hyp_rows=[]; pair_rows=[]
total_start=time.perf_counter()
for trial in range(1,TRIALS+1):
    true_rows=model.TRIPLES[rng.randrange(4)]; true_col=rng.randrange(4)
    key=[rng.randrange(256) for _ in range(16)]
    pairs=model.generate_pairs(rng,key,true_col,true_rows,PAIRS)
    start=time.perf_counter(); per=[]
    for rows,col in HYP:
        t=time.perf_counter(); n,counts=run_hypothesis(pairs,col,rows); elapsed=time.perf_counter()-t
        istrue=int(rows==true_rows and col==true_col)
        rec={'trial':trial,'rows':'-'.join(map(str,rows)),'column':col,'remaining_candidates':n,'candidate_counts':';'.join(map(str,counts)),'pairs_until_zero_or_end':len(counts),'runtime_seconds':round(elapsed,6),'is_true_location':istrue}
        hyp_rows.append(rec); per.append(rec)
        for i,count in enumerate(counts,1): pair_rows.append({'trial':trial,'rows':rec['rows'],'column':col,'pair_number':i,'remaining_candidates':count,'is_true_location':istrue})
    per.sort(key=lambda x:(x['remaining_candidates']==0, x['remaining_candidates']))
    # Exactly one hypothesis should survive; it must be the true one.
    survivors=[x for x in per if x['remaining_candidates']>0]
    top=per[-1] if per else None
    correct=[x for x in per if x['is_true_location']==1][0]
    unique=(len(survivors)==1 and survivors[0]['is_true_location']==1 and survivors[0]['remaining_candidates']==1)
    elapsed=time.perf_counter()-start
    trial_rows.append({'trial':trial,'true_rows':'-'.join(map(str,true_rows)),'true_column':true_col,'surviving_hypotheses':len(survivors),'true_hypothesis_candidates':correct['remaining_candidates'],'true_hypothesis_pairs':correct['pairs_until_zero_or_end'],'location_identified_uniquely':int(unique),'total_search_seconds':round(elapsed,6)})
    print(f"trial {trial:02d}/{TRIALS}: truth={true_rows}/{true_col}, survivors={len(survivors)}, true_candidates={correct['remaining_candidates']}, success={unique}, sec={elapsed:.2f}",flush=True)

total=time.perf_counter()-total_start
for name,rows in [('phase8_unknown_location_trials.csv',trial_rows),('phase8_unknown_location_hypotheses_batch.csv',hyp_rows),('phase8_unknown_location_pairwise_batch.csv',pair_rows)]:
    with open('/mnt/data/'+name,'w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
success=sum(r['location_identified_uniquely'] for r in trial_rows)
summary={'seed':SEED,'independent_trials':TRIALS,'hypotheses_per_trial':16,'ciphertext_pairs_per_trial':PAIRS,'total_hypothesis_tests':TRIALS*16,'unique_location_recoveries':success,'observed_success_rate':success/TRIALS,'mean_pairs_for_true_hypothesis':statistics.mean(r['true_hypothesis_pairs'] for r in trial_rows),'mean_search_seconds_per_trial':statistics.mean(r['total_search_seconds'] for r in trial_rows),'median_search_seconds_per_trial':statistics.median(r['total_search_seconds'] for r in trial_rows),'total_runtime_seconds':total,'row_configuration_counts':{ '-'.join(map(str,rows)):sum(r['true_rows']=='-'.join(map(str,rows)) for r in trial_rows) for rows in model.TRIPLES},'column_counts':{str(c):sum(r['true_column']==c for r in trial_rows) for c in range(4)},'limitations':['One three-byte fault cluster in one AES state column per trial.','Fault row triple and column are unknown to the attack but known to the evaluator.','The experiment recovers the fault location and a four-byte round-10 key group, not the full AES-128 master key.','Software fault injection only; hardware faults and cross-column faults are not tested.','30 trials provide exploratory evidence, not a universal success guarantee.']}
with open('/mnt/data/PHASE8_STATISTICAL_REPORT.json','w') as f: json.dump(summary,f,indent=2)
# concise README
with open('/mnt/data/PHASE8_README.txt','w') as f:
 f.write('PHASE VIII — UNKNOWN THREE-BYTE FAULT LOCATION: BATCH EVALUATION\n\n')
 f.write(f"Trials: {TRIALS}; hypotheses per trial: 16; pairs generated per trial: {PAIRS}; seed: {SEED}; total runtime: {total:.3f}s.\n")
 f.write(f"Unique location recovery: {success}/{TRIALS} ({100*success/TRIALS:.1f}%).\n")
 f.write('Each trial randomly selects one of four three-row configurations and one of four AES state columns. The attacker-side search enumerates all 16 possibilities without being told the true location. Each candidate is intersected across up to eight correct/faulty pairs.\n\n')
 f.write('Scope: location identification and unique four-byte round-10 key-group recovery only. This does not recover the full 128-bit master key because only one state column is faulted in each trial. Software fault injection only.\n')
 f.write('Files: trial summary, all-hypothesis results, pairwise candidate counts, JSON report, source runner.\n')
# bundle source dependencies
pkg='/mnt/data/AES_DFA_Phase8_Statistical_Package.zip'
with zipfile.ZipFile(pkg,'w',zipfile.ZIP_DEFLATED) as z:
 for fn in ['dfa_phase8_batch.py','dfa_phase8_unknown_location.py','dfa_phase7_generate.cpp','dfa_phase7_filter.cpp','dfa_phase7_three_byte.py','dfa_aes_baseline_verified.py','phase8_unknown_location_trials.csv','phase8_unknown_location_hypotheses_batch.csv','phase8_unknown_location_pairwise_batch.csv','PHASE8_STATISTICAL_REPORT.json','PHASE8_README.txt']:
  z.write('/mnt/data/'+fn,arcname=fn)
print('SUMMARY',json.dumps(summary,indent=2))
