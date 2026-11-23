import os, random, time, csv, json, sys, itertools, statistics
import dfa_phase7_three_byte as model
from dfa_phase8_unknown_location import HYP, run_hypothesis
SEED=20261117; PAIRS=8
start=int(sys.argv[1]) if len(sys.argv)>1 else 1
end=int(sys.argv[2]) if len(sys.argv)>2 else 10
rng=random.Random(SEED)
trial_path='/mnt/data/phase8_unknown_location_trials.csv'; hyp_path='/mnt/data/phase8_unknown_location_hypotheses_batch.csv'; pair_path='/mnt/data/phase8_unknown_location_pairwise_batch.csv'
trials=[]; hyps=[]; pairrows=[]
# Deterministically regenerate all cases; only execute attacks in requested interval.
for trial in range(1,end+1):
 rows=model.TRIPLES[rng.randrange(4)]; col=rng.randrange(4); key=[rng.randrange(256) for _ in range(16)]
 pairs=model.generate_pairs(rng,key,col,rows,PAIRS)
 if trial<start: continue
 t0=time.perf_counter(); local=[]
 for hr,hc in HYP:
  n,counts=run_hypothesis(pairs,hc,hr); truth=int(hr==rows and hc==col)
  rec={'trial':trial,'rows':'-'.join(map(str,hr)),'column':hc,'remaining_candidates':n,'candidate_counts':';'.join(map(str,counts)),'pairs_until_zero_or_end':len(counts),'is_true_location':truth}
  local.append(rec); hyps.append(rec)
  for pi,cnt in enumerate(counts,1): pairrows.append({'trial':trial,'rows':rec['rows'],'column':hc,'pair_number':pi,'remaining_candidates':cnt,'is_true_location':truth})
 surv=[x for x in local if x['remaining_candidates']>0]; correct=next(x for x in local if x['is_true_location'])
 ok=len(surv)==1 and surv[0]['is_true_location']==1 and surv[0]['remaining_candidates']==1
 trials.append({'trial':trial,'true_rows':'-'.join(map(str,rows)),'true_column':col,'surviving_hypotheses':len(surv),'true_hypothesis_candidates':correct['remaining_candidates'],'true_hypothesis_pairs':correct['pairs_until_zero_or_end'],'location_identified_uniquely':int(ok),'total_search_seconds':round(time.perf_counter()-t0,5)})
 print(f'{trial}: {rows}/{col} survivors={len(surv)} truecand={correct["remaining_candidates"]} success={ok} elapsed={trials[-1]["total_search_seconds"]}',flush=True)
# append chunk files
for path,rows0 in [(trial_path,trials),(hyp_path,hyps),(pair_path,pairrows)]:
 if rows0:
  exists=os.path.exists(path)
  with open(path,'a' if exists else 'w',newline='') as f:
   w=csv.DictWriter(f,fieldnames=list(rows0[0]));
   if not exists:w.writeheader()
   w.writerows(rows0)
