
from collections import Counter
from pathlib import Path
import argparse
import re

FAILED_LOGIN = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*"
    r"Failed password",
    re.IGNORECASE,
)

def analyze_log(file_path):
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    failed_ips = Counter()
    total_lines = 0
    failed_attempts = 0

    with path.open("r", encoding="utf-8", errors="replace") as file:
        for line in file:
            total_lines += 1
            match = FAILED_LOGIN.search(line)

            if match:
                ip = match.group("ip")
                failed_ips[ip] += 1
                failed_attempts += 1

    return total_lines, failed_attempts, failed_ips


def main():
    parser = argparse.ArgumentParser(
        description="Analyze sample logs for repeated failed logins."
    )
    parser.add_argument(
        "file",
        nargs="?",
        default="sample.log",
        help="Path to a log file (default: sample.log)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Flag IPs with at least this many failed attempts",
    )
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    try:
        lines, failures, ips = analyze_log(args.file)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print("\n=== LOGSLEUTH SECURITY REPORT ===")
    print(f"Lines analyzed: {lines}")
    print(f"Failed login attempts: {failures}")
    print(f"Unique IPs with failed logins: {len(ips)}")

    print("\nRepeated failed-login sources:")
    flagged = {
        ip: count
        for ip, count in ips.most_common()
        if count >= args.threshold
    }

    if not flagged:
        print("No IPs met the configured threshold.")
    else:
        for ip, count in flagged.items():
            print(f"  {ip}: {count} failed attempts")

    print("\nNote: This is a basic log-analysis demo, not an IDS.")


if __name__ == "__main__":
    main()
