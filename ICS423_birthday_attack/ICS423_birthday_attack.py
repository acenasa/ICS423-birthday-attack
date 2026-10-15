import hashlib
import statistics
import math
import csv
import time
import matplotlib.pyplot as plt


# Hash algorithms used in the experiment
hash_functions = {
    "MD5": hashlib.md5,
    "SHA-1": hashlib.sha1,
    "SHA-256": hashlib.sha256,
    "SHA-512": hashlib.sha512,
    "SHA3-256": hashlib.sha3_256
}


def truncate_hash(hash_bytes, bits):
    # Determine the full digest size automatically
    total_bits = len(hash_bytes) * 8

    if bits > total_bits:
        raise ValueError("Truncated length cannot exceed full hash length.")

    # Convert hash bytes into an integer
    hash_integer = int.from_bytes(hash_bytes, byteorder="big")

    # Keep only the requested number of most significant bits
    return hash_integer >> (total_bits - bits)


def find_collision(algorithm_name, trial_number, bits):
    seen_hashes = {}
    attempt = 0

    hash_function = hash_functions[algorithm_name]

    while True:
        message = (
            f"{algorithm_name}_{bits}bit_"
            f"trial{trial_number}_message{attempt}"
        )

        full_hash = hash_function(message.encode()).digest()

        truncated_hash = truncate_hash(full_hash, bits)

        if truncated_hash in seen_hashes:
            return attempt + 1

        seen_hashes[truncated_hash] = message
        attempt += 1


digest_lengths = [8, 12, 16, 20, 24]
number_of_trials = 100

summary_results = []


for algorithm_name in hash_functions:

    print()
    print("=" * 60)
    print(f"Testing {algorithm_name}")
    print("=" * 60)

    for bits in digest_lengths:

        results = []

        start_time = time.perf_counter()

        for trial in range(number_of_trials):
            attempts = find_collision(
                algorithm_name,
                trial,
                bits
            )

            results.append(attempts)

        end_time = time.perf_counter()

        execution_time = end_time - start_time

        average = statistics.mean(results)
        median = statistics.median(results)
        minimum = min(results)
        maximum = max(results)
        standard_deviation = statistics.stdev(results)

        birthday_bound = 2 ** (bits / 2)

        expected_mean = (
            math.sqrt(math.pi / 2)
            * birthday_bound
        )

        percent_difference = (
            (average - expected_mean)
            / expected_mean
        ) * 100

        summary_results.append([
            algorithm_name,
            bits,
            number_of_trials,
            average,
            median,
            minimum,
            maximum,
            standard_deviation,
            birthday_bound,
            expected_mean,
            percent_difference,
            execution_time
        ])

        print()
        print(
            f"{bits}-bit {algorithm_name} Birthday Attack"
        )
        print("-" * 40)
        print("Trials:", number_of_trials)
        print(
            "Average attempts:",
            round(average, 2)
        )
        print(
            "Median attempts:",
            median
        )
        print(
            "Minimum attempts:",
            minimum
        )
        print(
            "Maximum attempts:",
            maximum
        )
        print(
            "Standard deviation:",
            round(standard_deviation, 2)
        )
        print(
            "Birthday-bound scale:",
            round(birthday_bound, 2)
        )
        print(
            "Expected mean:",
            round(expected_mean, 2)
        )
        print(
            "Percent difference:",
            round(percent_difference, 2),
            "%"
        )
        print(
            "Execution time:",
            round(execution_time, 4),
            "seconds"
        )


# --------------------------------------------------
# Save all experiment results
# --------------------------------------------------

with open(
    "collision_results_all_algorithms.csv",
    "w",
    newline=""
) as file:

    writer = csv.writer(file)

    writer.writerow([
        "Algorithm",
        "Bits",
        "Trials",
        "Average Attempts",
        "Median Attempts",
        "Minimum Attempts",
        "Maximum Attempts",
        "Standard Deviation",
        "Birthday Bound",
        "Expected Mean",
        "Percent Difference",
        "Execution Time (Seconds)"
    ])

    writer.writerows(summary_results)


print()
print(
    "Results saved to "
    "collision_results_all_algorithms.csv"
)


# --------------------------------------------------
# Graph 1:
# Experimental collision attempts by algorithm
# --------------------------------------------------

plt.figure(figsize=(10, 6))

for algorithm_name in hash_functions:

    algorithm_rows = [
        row for row in summary_results
        if row[0] == algorithm_name
    ]

    bits_values = [
        row[1] for row in algorithm_rows
    ]

    experimental_averages = [
        row[3] for row in algorithm_rows
    ]

    plt.plot(
        bits_values,
        experimental_averages,
        marker="o",
        label=algorithm_name
    )


# Theoretical expected mean
expected_values = [
    math.sqrt(math.pi / 2)
    * (2 ** (bits / 2))
    for bits in digest_lengths
]

plt.plot(
    digest_lengths,
    expected_values,
    marker="s",
    linestyle="--",
    linewidth=2,
    label="Theoretical Expected Mean"
)

plt.xlabel("Truncated Hash Length (bits)")
plt.ylabel("Average Attempts Until First Collision")

plt.title(
    "Birthday Attack Collision Search "
    "Across Hash Algorithms"
)

plt.xticks(digest_lengths)
plt.grid(True)
plt.legend()

plt.tight_layout()

plt.savefig(
    "collision_comparison_all_algorithms.png",
    dpi=300
)


print(
    "Graph saved to "
    "collision_comparison_all_algorithms.png"
)

plt.show()
