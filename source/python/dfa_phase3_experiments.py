"""Phase III quantitative experiments for the AES-128 single-byte DFA baseline.

Run: python dfa_phase3_experiments.py
Outputs: phase3_pairwise_results.csv, phase3_trial_summary.csv,
         phase3_magnitude_results.csv and PNG figures in the same directory.

Model: round-9, after ShiftRows/before MixColumns; one row-0 byte fault
per pair in the selected column; nonzero XOR magnitude unknown to attacker.
"""
import csv
import random
import time
from pathlib import Path
from statistics import mean

import matplotlib.pyplot as plt
import dfa_aes_baseline_verified as aes

OUT = Path(__file__).resolve().parent
TRIALS = 30
PAIR_COUNTS = [1, 2, 3, 4, 5, 6, 8, 10, 12]
MAX_PAIRS = max(PAIR_COUNTS)
MASTER_SEED = 20261117


def write_csv(path, rows):
    if not rows:
        return
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def make_trial_data(rng, key, fault_column, pair_count, magnitude_mode='random_each_pair'):
    pairs = []
    for _ in range(pair_count):
        plaintext = [rng.randrange(256) for _ in range(16)]
        if magnitude_mode == 'random_each_pair':
            epsilon = rng.randrange(1, 256)
        elif magnitude_mode == 'fixed_per_trial':
            epsilon = 0x53
        else:
            raise ValueError(magnitude_mode)
        correct, faulty, fault = aes.generate_faulty_pair(
            key, plaintext, fault_column, fault_value=epsilon
        )
        pairs.append((correct, faulty, fault))
    return pairs


def analyze_trial(trial_id, rng, mode='random_each_pair'):
    key = [rng.randrange(256) for _ in range(16)]
    round10 = aes.expand_key(key)[10]
    pair_rows = []
    column_prefix = {}
    all_unique_at = None
    total_recovery_seconds = 0.0

    for col in range(4):
        pairs = make_trial_data(rng, key, col, MAX_PAIRS, mode)
        running = None
        true_group = tuple(round10[pos] for pos in aes.affected_ciphertext_indices(col))
        for pair_no, (correct, faulty, fault) in enumerate(pairs, start=1):
            t0 = time.perf_counter()
            one_pair_candidates = set(aes.four_byte_candidates_for_pair(correct, faulty, col))
            if running is None:
                running = one_pair_candidates
            else:
                running.intersection_update(one_pair_candidates)
            elapsed = time.perf_counter() - t0
            total_recovery_seconds += elapsed
            if pair_no in PAIR_COUNTS:
                pair_rows.append({
                    'mode': mode,
                    'trial': trial_id,
                    'fault_column': col,
                    'faulty_pairs': pair_no,
                    'candidate_count': len(running),
                    'true_group_retained': int(true_group in running),
                    'unique_correct_group': int(len(running) == 1 and true_group in running),
                    'cumulative_trial_recovery_seconds': round(total_recovery_seconds, 8),
                    'fault_value': fault.value,
                    'fault_value_hamming_weight': aes.hamming_weight(fault.value),
                })
        column_prefix[col] = running

    for n in PAIR_COUNTS:
        # The pair_rows contain one row per column/pair-count.
        rows_n = [r for r in pair_rows if r['faulty_pairs'] == n]
        full_success = int(len(rows_n) == 4 and all(r['unique_correct_group'] for r in rows_n))
        if full_success and all_unique_at is None:
            all_unique_at = n
        for r in rows_n:
            r['full_master_key_recovered_at_this_pair_count'] = full_success

    summary = {
        'mode': mode,
        'trial': trial_id,
        'full_key_recovered_by_12_pairs': int(all(
            len(column_prefix[c]) == 1 for c in range(4)
        )),
        'pairs_required_for_full_key': all_unique_at if all_unique_at is not None else '',
        'total_candidate_generation_and_intersection_seconds': round(total_recovery_seconds, 8),
    }
    return pair_rows, summary


def main():
    # Baseline randomized-magnitude experiments.
    pair_rows, summaries = [], []
    for trial in range(TRIALS):
        rng = random.Random(MASTER_SEED + trial)
        rows, summary = analyze_trial(trial + 1, rng, 'random_each_pair')
        pair_rows.extend(rows)
        summaries.append(summary)

    write_csv(OUT / 'phase3_pairwise_results.csv', pair_rows)
    write_csv(OUT / 'phase3_trial_summary.csv', summaries)

    # Controlled comparison: same unknown nonzero epsilon within each trial,
    # versus independently randomized epsilon for every faulty pair.
    magnitude_rows = []
    # Reuse the 30-trial random-magnitude baseline above; run 10 additional
    # fixed-magnitude trials to keep total compute bounded.
    for row in pair_rows:
        if row['faulty_pairs'] in (1, 2, 4, 8, 12):
            magnitude_rows.append(row)
    for trial in range(10):
        rng = random.Random(MASTER_SEED + 100000 + trial)
        rows, summary = analyze_trial(trial + 1, rng, 'fixed_per_trial')
        for row in rows:
            if row['faulty_pairs'] in (1, 2, 4, 8, 12):
                magnitude_rows.append(row)
    write_csv(OUT / 'phase3_magnitude_results.csv', magnitude_rows)

    # Aggregate candidate counts and success rates by number of pairs.
    aggregate = []
    for n in PAIR_COUNTS:
        rs = [r for r in pair_rows if r['faulty_pairs'] == n]
        aggregate.append({
            'faulty_pairs': n,
            'mean_candidates_per_column': mean(r['candidate_count'] for r in rs),
            'median_candidates_per_column': sorted(r['candidate_count'] for r in rs)[len(rs)//2],
            'column_unique_recovery_rate': mean(r['unique_correct_group'] for r in rs),
            'full_master_key_recovery_rate': mean(r['full_master_key_recovered_at_this_pair_count'] for r in rs),
            'true_group_retention_rate': mean(r['true_group_retained'] for r in rs),
        })
    write_csv(OUT / 'phase3_aggregate_results.csv', aggregate)

    # Figure 1: mean surviving 4-byte key candidates.
    plt.figure()
    plt.plot([r['faulty_pairs'] for r in aggregate],
             [r['mean_candidates_per_column'] for r in aggregate], marker='o')
    plt.yscale('log')
    plt.xlabel('Number of faulty pairs per column')
    plt.ylabel('Mean surviving 4-byte key candidates (log scale)')
    plt.title('AES-DFA candidate reduction')
    plt.grid(True, which='both', alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT / 'phase3_candidate_reduction.png', dpi=220)
    plt.close()

    # Figure 2: column and full-key success rates.
    plt.figure()
    plt.plot([r['faulty_pairs'] for r in aggregate],
             [100*r['column_unique_recovery_rate'] for r in aggregate], marker='o', label='One column')
    plt.plot([r['faulty_pairs'] for r in aggregate],
             [100*r['full_master_key_recovery_rate'] for r in aggregate], marker='s', label='Full AES-128 key')
    plt.xlabel('Number of faulty pairs per column')
    plt.ylabel('Successful recovery trials (%)')
    plt.ylim(-2, 102)
    plt.title('Recovery success versus faulty-pair count')
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(OUT / 'phase3_recovery_success.png', dpi=220)
    plt.close()

    # Figure 3: fixed versus independently randomized fault magnitude.
    plt.figure()
    for mode, label in [('fixed_per_trial', 'Fixed unknown magnitude'),
                        ('random_each_pair', 'Random magnitude per pair')]:
        rs = [r for r in magnitude_rows if r['mode'] == mode]
        xs = [1, 2, 4, 8, 12]
        ys = [100 * mean(r['unique_correct_group'] for r in rs if r['faulty_pairs'] == x) for x in xs]
        plt.plot(xs, ys, marker='o', label=label)
    plt.xlabel('Number of faulty pairs per column')
    plt.ylabel('Unique column recovery (%)')
    plt.ylim(-2, 102)
    plt.title('Effect of fault-magnitude variation')
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(OUT / 'phase3_magnitude_comparison.png', dpi=220)
    plt.close()

    # Concise machine-readable run metadata.
    metadata = [
        {'parameter': 'trials', 'value': TRIALS},
        {'parameter': 'pair_counts_per_column', 'value': ';'.join(map(str, PAIR_COUNTS))},
        {'parameter': 'master_seed', 'value': MASTER_SEED},
        {'parameter': 'fault_model', 'value': 'single row-0 byte XOR fault, round 9, after ShiftRows before MixColumns'},
        {'parameter': 'magnitude_handling', 'value': 'unknown to attacker; candidate search enumerates epsilon 1..255'},
        {'parameter': 'key', 'value': 'fresh random AES-128 key per trial'},
        {'parameter': 'plaintext', 'value': 'fresh random plaintext for each faulty pair'},
    ]
    write_csv(OUT / 'phase3_run_metadata.csv', metadata)

    print('PHASE III EXPERIMENTS COMPLETE')
    print(f'Trials: {TRIALS}; pair counts: {PAIR_COUNTS}')
    print('\nAggregate results:')
    for row in aggregate:
        print(row)
    print('\nPairs required for full-key recovery (successful trials only):')
    recovered = [s['pairs_required_for_full_key'] for s in summaries if s['pairs_required_for_full_key'] != '']
    print(f'{len(recovered)}/{TRIALS} trials; values={recovered}')
    print('\nFiles written to:', OUT)

if __name__ == '__main__':
    main()
