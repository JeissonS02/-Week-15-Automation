import argparse
import json
import re
from collections import Counter


FAILED_PATTERN = re.compile(
    r"Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)

SUCCESS_PATTERN = re.compile(
    r"Accepted \S+ for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)


def analyze_auth_log(log_file: str):

    failed_ips = Counter()
    targeted_users = Counter()

    failed_count = 0
    success_count = 0

    with open(log_file, "r") as f:

        for line in f:

            failed_match = FAILED_PATTERN.search(line)

            if failed_match:

                user = failed_match.group(1)
                ip = failed_match.group(2)

                failed_ips[ip] += 1
                targeted_users[user] += 1

                failed_count += 1

            success_match = SUCCESS_PATTERN.search(line)

            if success_match:
                success_count += 1

    suspicious_ips = sorted(
        [
            {
                "ip": ip,
                "failed_attempts": count
            }
            for ip, count in failed_ips.items()
            if count > 10
        ],
        key=lambda x: x["failed_attempts"],
        reverse=True
    )

    if success_count == 0:
        ratio = "Infinity"
    else:
        ratio = round(failed_count / success_count, 2)

    results = {
        "suspicious_ips": suspicious_ips,
        "targeted_users": dict(targeted_users),
        "failed_logins": failed_count,
        "successful_logins": success_count,
        "failed_to_success_ratio": ratio
    }

    return results


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Analyze authentication logs"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Input auth log"
    )

    parser.add_argument(
        "--output",
        default="auth_results.json",
        help="Output JSON file"
    )

    args = parser.parse_args()

    results = analyze_auth_log(args.input)

    print(json.dumps(results, indent=4))

    with open(args.output, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\nResults saved to: {args.output}")
