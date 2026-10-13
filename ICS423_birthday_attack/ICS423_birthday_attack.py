import hashlib
import statistics
import math
import csv
import matplotlib.pyplot as plt


def truncate_hash(hash_bytes, bits):
    # Convert the entire hash to an integer
    hash_integer = int.from_bytes(hash_bytes, byteorder="big")

    # SHA-256 contains 256 bits.
    # Shift right so only the requested number of bits remain.
    return hash_integer >> (256 - bits)


def find_collision(trial_number, bits):
    seen_hashes = {}
    attempt = 0

    while True:
        message = f"{bits}bit_trial{trial_number}_message{attempt}"

        full_hash = hashlib.sha256(message.encode()).digest()

        truncated_hash = truncate_hash(full_hash, bits)

        if truncated_hash in seen_hashes:
            return attempt + 1

        seen_hashes[truncated_hash] = message
        attempt += 1


digest_lengths = [8, 12, 16, 20, 24]
number_of_trials = 100

summary_results = []

for bits in digest_lengths:
    results = []

    for trial in range(number_of_trials):
        attempts = find_collision(trial, bits)
        results.append(attempts)

    average = statistics.mean(results)
    median = statistics.median(results)
    minimum = min(results)
    maximum = max(results)
    standard_deviation = statistics.stdev(results)

    birthday_bound = 2 ** (bits / 2)

    expected_mean = math.sqrt(math.pi / 2) * birthday_bound

    summary_results.append([
        bits,
        number_of_trials,
        average,
        median,
        minimum,
        maximum,
        standard_deviation,
        birthday_bound,
        expected_mean
    ])

    print()
    print(f"{bits}-bit SHA-256 Birthday Attack")
    print("--------------------------------")
    print("Trials:", number_of_trials)
    print("Average attempts:", round(average, 2))
    print("Median attempts:", median)
    print("Minimum attempts:", minimum)
    print("Maximum attempts:", maximum)
    print("Standard deviation:", round(standard_deviation, 2))
    print("Birthday-bound scale:", round(birthday_bound, 2))
    print("Expected mean:", round(expected_mean, 2))


# Save results to CSV
with open("sha256_collision_results.csv", "w", newline="") as file:
    writer = csv.writer(file)

    writer.writerow([
        "Bits",
        "Trials",
        "Average Attempts",
        "Median Attempts",
        "Minimum Attempts",
        "Maximum Attempts",
        "Standard Deviation",
        "Birthday Bound",
        "Expected Mean"
    ])

    writer.writerows(summary_results)

print()
print("Results saved to sha256_collision_results.csv")


# ---------------------------------------
# Create graph after experiments are done
# ---------------------------------------

bits_values = [row[0] for row in summary_results]
experimental_averages = [row[2] for row in summary_results]
birthday_bounds = [row[7] for row in summary_results]
expected_means = [row[8] for row in summary_results]

plt.figure(figsize=(9, 6))

plt.plot(
    bits_values,
    experimental_averages,
    marker="o",
    label="Experimental Average"
)

plt.plot(
    bits_values,
    expected_means,
    marker="s",
    label="Theoretical Expected Mean"
)

plt.plot(
    bits_values,
    birthday_bounds,
    marker="^",
    linestyle="--",
    label="Birthday Bound $2^{m/2}$"
)

plt.xlabel("Truncated Hash Length (bits)")
plt.ylabel("Attempts Until First Collision")
plt.title("SHA-256 Birthday Attack: Experimental vs. Theoretical Results")

plt.xticks(bits_values)
plt.grid(True)
plt.legend()

plt.tight_layout()

# Save graph
plt.savefig("sha256_collision_graph.png", dpi=300)

print("Graph saved to sha256_collision_graph.png")

# Display graph
plt.show()
