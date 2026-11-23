#!/usr/bin/env python3
"""Phase XVI: evidence-grounded comparative evaluation of AES DFA phases.

Reads prior phase CSV/JSON outputs; it does not rerun or fabricate attacks.
Comparisons retain each experiment's distinct success criterion and scope.
"""
from pathlib import Path
import csv, json, statistics, zipfile
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

D=Path('/mnt/data')

def read_csv(name):
    with (D/name).open(newline='') as f: return list(csv.DictReader(f))
def read_json(name): return json.loads((D/name).read_text())
def mean(xs): return statistics.mean(xs) if xs else None
def pct(k,n): return 100*k/n if n else None

# Phase III: controlled, known row-0 single-byte DFA, independent trials.
p3=read_csv('phase3_trial_summary.csv')
p3agg=read_csv('phase3_aggregate_results.csv')
p3_success=sum(int(x['full_key_recovered_by_12_pairs']) for x in p3)
p3_pairs=[int(x['pairs_required_for_full_key']) for x in p3 if x['pairs_required_for_full_key']]
p3_runtime=[float(x['total_candidate_generation_and_intersection_seconds']) for x in p3]
# Phase VII: known-support 3-byte, 120 full-trial observations.
p7=read_csv('phase7_cpp_trial_summary.csv')
p7_success=sum(int(x['master_key_recovered']) for x in p7)
p7_runtime=[float(x['trial_seconds']) for x in p7]
p7cols=read_csv('phase7_cpp_column_trials.csv')
p7_pair=[int(x['pairs_used']) for x in p7cols]
p7_colruntime=[float(x['column_total_seconds']) for x in p7cols]
# Phase IX: known support, cross-column partial round-key groups.
p9=read_csv('phase9_cross_column_trials.csv')
p9_success=sum(int(x['all_affected_column_groups_recovered']) for x in p9)
p9report=read_json('PHASE9_REPORT.json')
# Phase XIV: blind support recovery; 7 trials only.
p14=read_csv('phase14_blind_trials.csv')
p14report=read_json('PHASE14_REPORT.json')
p14_success=sum(int(x['unique_correct_support']) for x in p14)
p14_runtime=[float(x['runtime_seconds']) for x in p14]
# Phase XV: one multi-event end-to-end key recovery trial.
p15=read_csv('phase15_multi_event_trials.csv')
p15report=read_json('PHASE15_REPORT.json')
p15_runtime=[float(x['runtime_seconds']) for x in p15]

rows=[
 {'approach':'Conventional single-byte DFA (Phase III)','trials':len(p3),'successes':p3_success,'success_rate_percent':pct(p3_success,len(p3)),
  'success_criterion':'Full AES-128 master key recovered by <=12 pairs','mean_pairs':mean(p3_pairs),'mean_runtime_seconds':mean(p3_runtime),
  'support_known':'Yes','scope':'Controlled single-byte faults; row-0/column support known; full key.'},
 {'approach':'Known-support three-byte DFA (Phase VII)','trials':len(p7),'successes':p7_success,'success_rate_percent':pct(p7_success,len(p7)),
  'success_criterion':'Full AES-128 master key recovered','mean_pairs':mean(p7_pair),'mean_runtime_seconds':mean(p7_runtime),
  'support_known':'Yes','scope':'Three faults in one column; known row triple and column; full key across four column experiments.'},
 {'approach':'Known-support cross-column DFA (Phase IX)','trials':len(p9),'successes':p9_success,'success_rate_percent':pct(p9_success,len(p9)),
  'success_criterion':'All affected K10 column groups recovered','mean_pairs':None,'mean_runtime_seconds':float(p9report['runtime_seconds'])/len(p9),
  'support_known':'Yes','scope':'2+1 and 1+1+1 distributions; only affected groups; not full master key.'},
 {'approach':'Blind three-byte support recovery (Phase XIV)','trials':len(p14),'successes':p14_success,'success_rate_percent':pct(p14_success,len(p14)),
  'success_criterion':'Unique correct support among 560 hypotheses','mean_pairs':mean([int(x['pair_count']) for x in p14]),'mean_runtime_seconds':mean(p14_runtime),
  'support_known':'No','scope':'3+0+0, 2+1, 1+1+1; support identified; not full master key.'},
 {'approach':'Multi-event blind master-key recovery (Phase XV)','trials':1,'successes':int(bool(p15report['full_master_key_verified'])),'success_rate_percent':100.0 if p15report['full_master_key_verified'] else 0.0,
  'success_criterion':'All event supports identified and complete AES-128 master key verified','mean_pairs':int(p15report['total_correct_faulty_pairs']),'mean_runtime_seconds':float(p15report['total_runtime_seconds']),
  'support_known':'No','scope':'One end-to-end trial; three events x five pairs; shared key; all four K10 groups recovered.'}
]
with (D/'phase16_comparison.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

# Machine-readable summary with explicit comparability warning.
report={
 'phase':'XVI','title':'Comparative Evaluation of AES Differential Fault Analysis Approaches',
 'source_artifacts':['phase3_trial_summary.csv','phase3_aggregate_results.csv','phase7_cpp_trial_summary.csv','phase7_cpp_column_trials.csv','phase9_cross_column_trials.csv','PHASE9_REPORT.json','phase14_blind_trials.csv','PHASE14_REPORT.json','phase15_multi_event_trials.csv','PHASE15_REPORT.json'],
 'comparisons':rows,
 'additional_diagnostics':{
  'phase3_pairs_to_full_key':{'mean':mean(p3_pairs),'median':statistics.median(p3_pairs),'min':min(p3_pairs),'max':max(p3_pairs)},
  'phase3_candidate_reduction':p3agg,
  'phase7_column_pairs':{'mean':mean(p7_pair),'median':statistics.median(p7_pair),'min':min(p7_pair),'max':max(p7_pair)},
  'phase7_column_runtime_seconds':{'mean':mean(p7_colruntime),'median':statistics.median(p7_colruntime)},
  'phase14_by_distribution':p14report['support_distributions'],
  'phase15_event_results':p15report['event_results'],
  'phase15_master_key_verified':p15report['full_master_key_verified'],
  'phase15_recovered_master_key':p15report['recovered_master_key_hex']
 },
 'interpretation':[
  'The conventional single-byte baseline recovered the complete master key in all 30 recorded trials by at most 12 faulty pairs; its aggregate curve reports 90% full-key recovery at two pairs and 100% at three pairs.',
  'The known-support three-byte same-column implementation recovered the master key in all 120 recorded trials. This is a different, stronger fault-model-specific solver and is not blind support recovery.',
  'The known-support cross-column experiment recovered affected round-key groups in all 16 trials, but did not claim complete master-key recovery.',
  'Blind three-byte support recovery uniquely identified the correct support in all 7 Phase XIV trials, but the sample is too small for strong reliability claims.',
  'Phase XV demonstrates one complete multi-event blind master-key recovery, not a statistically established success rate.'
 ],
 'comparability_cautions':[
  'Success criteria differ by experiment; percentages must not be interpreted as a head-to-head benchmark.',
  'Pair counts differ in meaning: per single fault event, per column, or total across multi-events.',
  'Runtime figures are implementation- and workload-specific and should not be treated as universal complexity measurements.',
  'All experiments use software fault injection under the stated AES round-9 model; no physical fault injection is included.',
  'The Phase XV result has n=1 and is proof-of-execution evidence only.'
 ],
 'limitations':['This phase synthesizes existing experiment outputs; it does not create new attack trials.','No statistical extrapolation beyond the recorded samples is made.']
}
(D/'PHASE16_REPORT.json').write_text(json.dumps(report,indent=2))

# Graph 1: recorded success rates, with sample sizes shown. Not presented as apples-to-apples.
labels=[r['approach'].replace(' (Phase ','\n(Phase ').replace(')','') for r in rows]
vals=[r['success_rate_percent'] for r in rows]
ns=[r['trials'] for r in rows]
plt.figure(figsize=(11,6)); bars=plt.bar(range(len(rows)),vals)
plt.xticks(range(len(rows)),labels,rotation=15,ha='right');plt.ylabel('Observed success (%)');plt.ylim(0,110)
plt.title('Observed success by approach (criteria differ; see sample sizes)')
for b,v,n in zip(bars,vals,ns):plt.text(b.get_x()+b.get_width()/2,v+2,f'{v:.0f}%\nn={n}',ha='center',va='bottom',fontsize=9)
plt.tight_layout();plt.savefig(D/'phase16_observed_success.png',dpi=190);plt.close()

# Graph 2: recorded average runtimes, explicitly descriptive only.
plt.figure(figsize=(11,6)); bars=plt.bar(range(len(rows)),[r['mean_runtime_seconds'] for r in rows])
plt.xticks(range(len(rows)),labels,rotation=15,ha='right');plt.ylabel('Mean/recorded runtime per trial (s)')
plt.title('Recorded runtime by approach (workloads are not equivalent)')
for b,r in zip(bars,rows):plt.text(b.get_x()+b.get_width()/2,b.get_height(),f"{r['mean_runtime_seconds']:.2f}s",ha='center',va='bottom',fontsize=9)
plt.tight_layout();plt.savefig(D/'phase16_runtime_comparison.png',dpi=190);plt.close()

# Graph 3: baseline candidate reduction across pairs.
xs=[int(x['faulty_pairs']) for x in p3agg]; ys=[float(x['mean_candidates_per_column']) for x in p3agg]
plt.figure(figsize=(8,5));plt.plot(xs,ys,marker='o');plt.yscale('log');plt.xlabel('Number of faulty ciphertext pairs');plt.ylabel('Mean candidates per K10 column (log scale)')
plt.title('Conventional DFA: candidate-set reduction');plt.grid(True,which='both',alpha=.25);plt.tight_layout();plt.savefig(D/'phase16_baseline_candidates.png',dpi=190);plt.close()

# Graph 4: Phase VII distribution-wise complete-key recovery (known support).
summary=read_csv('phase7_cpp_statistical_summary.csv')
plt.figure(figsize=(8,5));x=[r['row_triple'] for r in summary]; y=[100*float(r['master_key_success_rate']) for r in summary]
plt.bar(x,y);plt.ylim(0,110);plt.xlabel('Injected row triple');plt.ylabel('Observed complete-key recovery (%)');plt.title('Known-support three-byte DFA: 30 trials per row triple')
for i,r in enumerate(summary):plt.text(i,y[i]+2,f"{r['complete_master_key_recoveries']}/{r['trials']}",ha='center')
plt.tight_layout();plt.savefig(D/'phase16_phase7_rowtriples.png',dpi=190);plt.close()

# Human-readable comparison report.
md=['# Phase XVI — Comparative Evaluation','',
'## Summary','',
'Phase XVI consolidates measured outputs from Phases III, VII, IX, XIV and XV. It is an evidence synthesis, not a new attack run. The success criteria and workloads differ, so the table is descriptive rather than a controlled head-to-head benchmark.','',
'| Approach | Trials | Observed success | Criterion | Mean runtime/trial |','|---|---:|---:|---|---:|']
for r in rows:
    md.append(f"| {r['approach']} | {r['trials']} | {r['successes']}/{r['trials']} ({r['success_rate_percent']:.1f}%) | {r['success_criterion']} | {r['mean_runtime_seconds']:.3f}s |")
md += ['', '## Main findings','',
'- **Conventional single-byte DFA:** 30/30 recorded trials recovered the full master key by at most 12 faulty pairs. The aggregate candidate curve shows 90% full-key recovery at two pairs and 100% from three pairs onward.',
'- **Known-support three-byte DFA:** 120/120 recorded trials recovered the complete master key across four row triples (30 trials each). This is not blind location recovery.',
'- **Known-support cross-column DFA:** 16/16 trials recovered all affected round-key groups, but unaffected groups were outside the claim.',
'- **Blind support recovery:** 7/7 Phase XIV trials uniquely identified the support among 560 hypotheses. The 1+1+1 category had only one trial.',
'- **Multi-event blind recovery:** Phase XV recovered and verified one complete AES-128 master key using three blind events and 15 correct/faulty pairs. This remains a single successful trial.',
'', '## Interpretation and limitations','',
'1. Results across phases are not directly comparable because attack assumptions, fault geometries, pair counts, success criteria, and implementations differ.',
'2. Runtime is descriptive of these implementations and this execution environment; it is not a hardware-independent complexity result.',
'3. All results use simulated round-9 transient XOR faults after ShiftRows and before MixColumns. No physical fault injection is represented.',
'4. Phase XIV and XV should be expanded with more independent trials before making reliability claims, especially for 1+1+1 support and complete multi-event key recovery.',
'5. The Phase XV recovery depends on support identification and per-column candidate sets; the full-key result is validated by matching the original key in the experiment.',
'', '## Figures','',
'1. `phase16_observed_success.png` — observed success rates with sample counts; criteria differ.',
'2. `phase16_runtime_comparison.png` — recorded runtimes; workloads differ.',
'3. `phase16_baseline_candidates.png` — candidate reduction in conventional DFA.',
'4. `phase16_phase7_rowtriples.png` — known-support three-byte recovery by row triple.',
'', '## Reproducibility','',
'Run `python dfa_phase16_comparative.py` from the package directory. The script reads the prior phase CSV/JSON artifacts and regenerates the comparison CSV, JSON report, Markdown report, and four figures. Dependencies: Python 3 and matplotlib.','']
(D/'PHASE16_REPORT.md').write_text('\n'.join(md))

files=['dfa_phase16_comparative.py','phase16_comparison.csv','PHASE16_REPORT.json','PHASE16_REPORT.md','phase16_observed_success.png','phase16_runtime_comparison.png','phase16_baseline_candidates.png','phase16_phase7_rowtriples.png',
'phase3_trial_summary.csv','phase3_aggregate_results.csv','phase7_cpp_trial_summary.csv','phase7_cpp_column_trials.csv','phase7_cpp_statistical_summary.csv','phase9_cross_column_trials.csv','PHASE9_REPORT.json','phase14_blind_trials.csv','PHASE14_REPORT.json','phase15_multi_event_trials.csv','PHASE15_REPORT.json']
with zipfile.ZipFile(D/'AES_DFA_Phase16_Comparative_Evaluation.zip','w',zipfile.ZIP_DEFLATED) as z:
    for fn in files:z.write(D/fn,arcname=fn)
print(json.dumps({'comparisons':rows,'phase15_key_verified':p15report['full_master_key_verified'],'package':str(D/'AES_DFA_Phase16_Comparative_Evaluation.zip')},indent=2))
