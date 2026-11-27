import argparse
import csv
import hashlib
import json
import math
import platform
import ssl
import statistics
import sys
import time
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Keep the original algorithms and message format for reproducibility.
hash_functions = {
    'MD5': hashlib.md5,
    'SHA-1': hashlib.sha1,
    'SHA-256': hashlib.sha256,
    'SHA-512': hashlib.sha512,
    'SHA3-256': hashlib.sha3_256,
}


def truncate_hash(hash_bytes, bits):
    total_bits = len(hash_bytes) * 8
    if not 1 <= bits <= total_bits:
        raise ValueError('Invalid truncated digest length.')
    return int.from_bytes(hash_bytes, byteorder='big') >> (total_bits - bits)


def find_collision(algorithm_name, trial_number, bits):
    # Each message is unique within a trial; only digest prefixes are compared.
    seen_hashes = set()
    attempt = 0
    hash_function = hash_functions[algorithm_name]
    while True:
        message = f'{bits}bit_trial{trial_number}_message{attempt}'
        truncated_hash = truncate_hash(hash_function(message.encode()).digest(), bits)
        attempt += 1
        if truncated_hash in seen_hashes:
            return attempt
        seen_hashes.add(truncated_hash)


def expected_mean(bits):
    # Leading-order approximation for independent uniform hash outputs.
    return math.sqrt(math.pi / 2) * 2 ** (bits / 2)


def write_csv(path, rows):
    with path.open('w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def regression(rows):
    x = [row['Bits'] for row in rows]
    y = [math.log2(row['Average Attempts']) for row in rows]
    fit = statistics.linear_regression(x, y)
    r_squared = statistics.correlation(x, y) ** 2
    return fit.slope, fit.intercept, r_squared


def make_graphs(rows, lengths, trials, output):
    def plot_series(column, ylabel, filename, title, theory=False, log=False, errors=False):
        fig, ax = plt.subplots(figsize=(10, 6))
        for name in hash_functions:
            group = [r for r in rows if r['Algorithm'] == name]
            values = [r[column] for r in group]
            if errors:
                ax.errorbar(lengths, values, yerr=[r['95% CI Half Width'] / r['Expected Mean'] * 100 for r in group], marker='o', capsize=3, label=name)
            else:
                ax.plot(lengths, values, marker='o', label=name)
        if theory:
            ax.plot(lengths, [expected_mean(b) for b in lengths], 'k--', marker='s', label='Theoretical approximate mean')
        if errors:
            ax.axhline(0, color='black', linestyle='--', linewidth=1)
        if log:
            ax.set_yscale('log', base=2)
        ax.set(xlabel='Truncated hash length (bits)', ylabel=ylabel, title=title, xticks=lengths)
        ax.grid(True, alpha=0.35)
        ax.legend()
        fig.tight_layout()
        fig.savefig(output / filename, dpi=300)
        plt.close(fig)

    plot_series('Average Attempts', 'Average attempts until first collision', 'collision_comparison_all_algorithms.png', 'Birthday collision search across hash algorithms', theory=True)
    plot_series('Average Attempts', 'Average attempts (log base 2)', 'collision_comparison_log_scale.png', 'Birthday collision search (log scale)', theory=True, log=True)
    plot_series('Execution Time (Seconds)', f'Execution time for {trials} trials (seconds)', 'collision_execution_time.png', 'Collision-search execution time')
    plot_series('Percentage Deviation', 'Deviation from approximate mean (%)', 'collision_percentage_deviation.png', 'Percentage deviation with approximate 95% confidence intervals', errors=True)
    plot_series('Hash Evaluations Per Second', 'Hash evaluations per second', 'collision_throughput.png', 'End-to-end collision-search throughput')


def run(lengths, trials, output):
    output.mkdir(parents=True, exist_ok=False)
    metadata = {
        'python': sys.version, 'platform': platform.platform(),
        'machine': platform.machine(), 'processor': platform.processor(),
        'openssl': ssl.OPENSSL_VERSION, 'matplotlib': matplotlib.__version__,
        'digest_lengths': lengths, 'trials_per_condition': trials,
        'message_format': '{bits}bit_trial{trial_number}_message{attempt}',
        'timing_scope': 'Search loop and result collection; excludes CSV writing and plotting',
        'confidence_interval': 'Normal approximation, mean +/- 1.96 * sample standard error; assumes ideal independent outputs',
    }
    (output / 'experiment_config.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    summary = []
    fits = []
    with (output / 'collision_raw_trials.csv').open('w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Algorithm', 'Bits', 'Trial', 'Attempts'])
        for name in hash_functions:
            group = []
            for bits in lengths:
                start = time.perf_counter()
                results = [find_collision(name, trial, bits) for trial in range(trials)]
                elapsed = time.perf_counter() - start
                writer.writerows((name, bits, trial, attempts) for trial, attempts in enumerate(results))
                average = statistics.mean(results)
                sd = statistics.stdev(results)
                se = sd / math.sqrt(trials)
                half_width = 1.96 * se
                theory = expected_mean(bits)
                total = sum(results)
                row = {
                    'Algorithm': name, 'Bits': bits, 'Trials': trials,
                    'Average Attempts': average, 'Median Attempts': statistics.median(results),
                    'Minimum Attempts': min(results), 'Maximum Attempts': max(results),
                    'Standard Deviation': sd, 'Birthday Bound': 2 ** (bits / 2),
                    'Expected Mean': theory, 'Percentage Deviation': 100 * (average - theory) / theory,
                    'Execution Time (Seconds)': elapsed, 'Standard Error': se,
                    '95% CI Half Width': half_width, '95% CI Lower': average - half_width,
                    '95% CI Upper': average + half_width, 'Total Hash Evaluations': total,
                    'Hash Evaluations Per Second': total / elapsed,
                }
                summary.append(row)
                group.append(row)
                print(f'{name:8s} | {bits:2d} bits | mean {average:10.2f} | deviation {row["Percentage Deviation"]:+6.2f}% | {elapsed:.2f}s', flush=True)
            slope, intercept, r_squared = regression(group)
            fits.append({'Algorithm': name, 'Slope': slope, 'Intercept': intercept, 'R Squared': r_squared, 'Theoretical Slope': 0.5})
    write_csv(output / 'collision_results_all_algorithms.csv', summary)
    write_csv(output / 'collision_regression_results.csv', fits)
    make_graphs(summary, lengths, trials, output)
    print(f'Completed {len(summary) * trials:,} collision searches; {sum(r["Total Hash Evaluations"] for r in summary):,} hash evaluations.')
    print(f'Results saved in {output}')


def main():
    parser = argparse.ArgumentParser(description='Truncated hash birthday collision experiment')
    parser.add_argument('--bits', type=int, nargs='+', default=[8, 12, 16, 20, 24, 28, 32])
    parser.add_argument('--trials', type=int, default=1000)
    parser.add_argument('--output', type=Path, default=Path('final_results'))
    args = parser.parse_args()
    lengths = sorted(set(args.bits))
    if len(lengths) < 2 or any(b < 1 or b > 32 for b in lengths):
        parser.error('Provide at least two different digest lengths between 1 and 32 bits.')
    if args.trials < 2:
        parser.error('At least two trials are required.')
    if args.output.exists():
        parser.error('Output directory already exists; choose a new directory to preserve earlier results.')
    run(lengths, args.trials, args.output)


if __name__ == '__main__':
    main()
