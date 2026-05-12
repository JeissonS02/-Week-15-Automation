import argparse
import json
import re
import statistics

from datetime import datetime
from collections import Counter


LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>.*?)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\d+)'
)

ATTACK_PATTERNS = re.compile(
    r"(union.*select"          # SQL injection
    r"|insert.*into"
    r"|drop\s+table"
    r"|\.\./"                  # Path traversal
    r"|\.\.\\\\"
    r"|<script"                # XSS
    r"|cmd="
    r"|exec="
    r"|shell=)",
    re.IGNORECASE
)


def analyze_access_log(log_file: str):

    suspicious_requests = []

    ip_counts = Counter()
    status_counts = Counter()
    hourly_counts = Counter()

    with open(log_file, "r") as f:

        for line in f:

            match = LOG_PATTERN.search(line)

            if not match:
                continue

            ip = match.group("ip")
            path = match.group("path")
            status = match.group("status")
            timestamp = match.group("timestamp")

            ip_counts[ip] += 1
            status_counts[status] += 1

            # Hour extraction
            hour_match = re.search(
                r":(\d{2}):\d{2}:\d{2}",
                timestamp
            )

            if hour_match:
                hour = hour_match.group(1)
                hourly_counts[hour] += 1

            # Attack detection
            if ATTACK_PATTERNS.search(path):

                suspicious_requests.append({
                    "ip": ip,
                    "path": path,
                    "status": status
                })

    # Top IPs
    top_ips = ip_counts.most_common(5)

    # 3-sigma anomaly detection
    anomalies = []

    counts = list(hourly_counts.values())

    if len(counts) >= 2:

        mean = statistics.mean(counts)
        stdev = statistics.stdev(counts)

        threshold = mean + (3 * stdev)

        for hour, count in hourly_counts.items():

            if count > threshold:

                z_score = (
                    (count - mean) / stdev
                )

                anomalies.append({
                    "hour": hour,
                    "requests": count,
                    "z_score": round(z_score, 2)
                })

    results = {
        "suspicious_requests": suspicious_requests,
        "top_ips": top_ips,
        "status_distribution": dict(status_counts),
        "anomalies": anomalies
    }

    return results

def generate_report(auth_results, log_results):

    report = f"""# Security Analysis Report

Generated: {datetime.now().isoformat()}

---

# Authentication Analysis

## Suspicious IPs

"""

    for entry in auth_results["suspicious_ips"]:

        report += (
            f"- {entry['ip']} → "
            f"{entry['failed_attempts']} failed attempts\n"
        )

    report += "\n## Targeted Users\n\n"

    for user, count in auth_results["targeted_users"].items():

        report += f"- {user}: {count} attempts\n"

    report += f"""

## Login Statistics

- Failed logins: {auth_results['failed_logins']}
- Successful logins: {auth_results['successful_logins']}
- Failed/Success ratio: {auth_results['failed_to_success_ratio']}

---

# Web Log Analysis

## Top IPs

"""

    for ip, count in log_results["top_ips"]:

        report += f"- {ip}: {count} requests\n"

    report += "\n## HTTP Status Distribution\n\n"

    for status, count in log_results["status_distribution"].items():

        report += f"- {status}: {count}\n"

    report += "\n## Detected Suspicious Requests\n\n"

    for req in log_results["suspicious_requests"][:20]:

        report += (
            f"- [{req['status']}] "
            f"{req['ip']} → {req['path']}\n"
        )

    report += "\n## Traffic Anomalies\n\n"

    for anomaly in log_results["anomalies"]:

        report += (
            f"- Hour {anomaly['hour']}: "
            f"{anomaly['requests']} requests "
            f"(z-score={anomaly['z_score']})\n"
        )

    return report



if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Analyze web access logs"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Input access log"
    )

    parser.add_argument(
        "--auth",
        default="auth_results.json",
        help="Authentication analysis JSON"
    )

    parser.add_argument(
        "--output",
        default="log_results.json",
        help="Output JSON file"
    )

    parser.add_argument(
        "--report",
        default="report.md",
        help="Markdown report output"
    )

    args = parser.parse_args()

    log_results = analyze_access_log(args.input)

    print(json.dumps(log_results, indent=4))

    with open(args.output, "w") as f:
        json.dump(log_results, f, indent=4)

    # Load auth analysis
    with open(args.auth, "r") as f:
        auth_results = json.load(f)

    # Generate markdown report
    report = generate_report(
        auth_results,
        log_results
    )

    with open(args.report, "w") as f:
        f.write(report)

    print(f"\nResults saved to: {args.output}")
    print(f"Markdown report saved to: {args.report}")	
