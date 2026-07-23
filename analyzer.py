import re
import sys
import json
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.ticker import MaxNLocator
from datetime import datetime
from pathlib import Path 

# Configuration setup
DEFAULT_CONFIG_PATH = Path(__file__).resolve().with_name("config.json")


class ConfigError(Exception):
    """Raised when analyzer configuration is unusable."""


def load_config(path):
    config_path = Path(path)

    try:
        with config_path.open(encoding="utf-8") as file:
            config = json.load(file)
    except FileNotFoundError:
        raise ConfigError(
            f"Configuration file not found: {config_path}"
        ) from None
    except json.JSONDecodeError as error:
        raise ConfigError(
            f"Invalid JSON in configuration file {config_path} "
            f"at line {error.lineno}, column {error.colno}"
        ) from None
    except OSError as error:
        raise ConfigError(
            f"Unable to read configuration file {config_path}: {error}"
        ) from None

    if not isinstance(config, dict):
        raise ConfigError("Configuration must contain a JSON object")

    limits = {}

    for key in ("bruteforce_limit", "dos_limit"):
        value = config.get(key)

        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ConfigError(f"'{key}' must be a positive integer")

        limits[key] = value

    logs_dir = config.get("logs_dir", "logs")

    if not isinstance(logs_dir, str) or not logs_dir.strip():
        raise ConfigError("'logs_dir' must be a non-empty string")

    logs_path = Path(logs_dir)

    if not logs_path.is_absolute():
        logs_path = config_path.resolve().parent / logs_path

    return {
        "logs_dir": logs_path,
        "bruteforce_limit": limits["bruteforce_limit"],
        "dos_limit": limits["dos_limit"],
    }

# ---------------- COMMAND LINE INTERFACE ----------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Log File Analyzer - Intrusion Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("files", nargs="*", help="Log files to analyze")
    parser.add_argument("--ssh", metavar="FILE", help="Force treat as SSH log")
    parser.add_argument("--apache", metavar="FILE", help="Force treat as Apache log")
    parser.add_argument("--no-graph", action="store_true", help="Skip graph generation")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to the JSON configuration file",)
    return parser.parse_args()

# ---------------- LOG DISCOVERY ----------------

def find_logs(logs_dir):
    folder = Path(logs_dir)
    if not folder.exists():
        print(f"[!] Directory not found: {logs_dir}")
        return [], []

    all_files = list(folder.glob("*.log")) + list(folder.glob("*.txt"))
    apache_files, ssh_files = [], []

    for f in all_files:
        name = f.name.lower()
        if any(k in name for k in ["apache", "access", "http"]):
            apache_files.append(f)
        elif any(k in name for k in ["ssh", "auth", "secure"]):
            ssh_files.append(f)

    return apache_files, ssh_files

def resolve_files(args, logs_dir):
    if not args.files and not args.ssh and not args.apache:
        return find_logs(logs_dir)

    apache_files, ssh_files = [], []
    if args.apache:
        p = Path(args.apache)
        if p.exists(): apache_files.append(p)
    if args.ssh:
        p = Path(args.ssh)
        if p.exists(): ssh_files.append(p)

    for fname in args.files:
        p = Path(fname)
        if not p.exists():
            p = Path(logs_dir) / fname
        if not p.exists(): continue

        name = p.name.lower()
        if any(k in name for k in ["apache", "access", "http"]):
            apache_files.append(p)
        elif any(k in name for k in ["ssh", "auth", "secure"]):
            ssh_files.append(p)
    
    return apache_files, ssh_files

# ---------------- PARSING LOGIC ----------------

def parse_ssh(files):
    pattern = (
        r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*"
        r"Failed password for .*? from (\d+\.\d+\.\d+\.\d+)"
    )
    events = []

    for file in files:
        with open(file) as f:
            for line_number, line in enumerate(f, start=1):
                match = re.search(pattern, line)

                if match:
                    timestamp_text = match.group(1)
                    ip = match.group(2)

                    try:
                        timestamp = datetime.strptime(
                            f"2000 {timestamp_text}",
                            "%Y %b %d %H:%M:%S"
                        )
                    except ValueError:
                        print(
                            f"[!] Skipping invalid SSH timestamp "
                            f"in {file} at line {line_number}: "
                            f"{timestamp_text}",
                            file=sys.stderr
                        )
                        continue

                    events.append({
                        "ip": ip,
                        "time": timestamp
                    })

    return events

def parse_apache(files):
    pattern = r'^(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+)'
    data = []

    for file in files:
        with open(file) as f:
            for line_number, line in enumerate(f, start=1):
                match = re.search(pattern, line)

                if match:
                    timestamp_text = match.group(2)

                    try:
                        timestamp = datetime.strptime(
                            timestamp_text,
                            "%d/%b/%Y:%H:%M:%S %z"
                        )
                    except ValueError:
                        print(
                            f"[!] Skipping invalid Apache timestamp "
                            f"in {file} at line {line_number}: "
                            f"{timestamp_text}",
                            file=sys.stderr
                        )
                        continue

                    data.append([
                        match.group(1),
                        timestamp,
                        match.group(3),
                        match.group(4),
                    ])

    return data

# ---------------- DETECTION ENGINES ----------------


def find_peak_window(timestamps, window_seconds):
    ordered_timestamps = sorted(timestamps)

    if not ordered_timestamps:
        return None

    window_start = 0
    peak_start = 0
    peak_end = 0
    peak_count = 0

    for window_end in range(len(ordered_timestamps)):
        while (
            ordered_timestamps[window_end]
            - ordered_timestamps[window_start]
        ).total_seconds() > window_seconds:
            window_start += 1

        count = window_end - window_start + 1

        if count > peak_count:
            peak_count = count
            peak_start = window_start
            peak_end = window_end

    return {
        "count": peak_count,
        "window_start": ordered_timestamps[peak_start],
        "window_end": ordered_timestamps[peak_end],
    }


def detect_bruteforce(events, limit, window_seconds=60):
    events_by_ip = {}

    for event in events:
        events_by_ip.setdefault(event["ip"], []).append(event["time"])

    alerts = []

    for ip, timestamps in events_by_ip.items():
        peak = find_peak_window(timestamps, window_seconds)

        if peak["count"] >= limit:
            alerts.append(
                {
                    "ip": ip,
                    "count": peak["count"],
                    "window_start": peak["window_start"],
                    "window_end": peak["window_end"],
                    "threshold": limit,
                    "window_seconds": window_seconds,
                }
            )

    return sorted(
        alerts,
        key=lambda alert: (-alert["count"], alert["ip"]),
    )


def detect_dos(data, limit, window_seconds=60):
    timestamps_by_ip = {}

    for ip, timestamp, request, status in data:
        timestamps_by_ip.setdefault(ip, []).append(timestamp)

    alerts = []

    for ip, timestamps in timestamps_by_ip.items():
        peak = find_peak_window(timestamps, window_seconds)

        if peak["count"] >= limit:
            alerts.append(
                {
                    "ip": ip,
                    "count": peak["count"],
                    "window_start": peak["window_start"],
                    "window_end": peak["window_end"],
                    "threshold": limit,
                    "window_seconds": window_seconds,
                }
            )

    return sorted(
        alerts,
        key=lambda alert: (-alert["count"], alert["ip"]),
    )

# ---------------- THREAT INTELLIGENCE ----------------

def load_blacklist(file="blacklist.txt"):
    p = Path(file)
    return set(p.read_text().splitlines()) if p.exists() else set()

def check_blacklist(ip_list, blacklist):
    return list(set(ip for ip in ip_list if ip in blacklist))

# ---------------- VISUALIZATION ----------------

def plot_ips(data, blacklist=set(), bf_ips=set(), dos_ips=set()):
    if not data: return
    Path("graphs").mkdir(exist_ok=True)

    df = pd.DataFrame(data, columns=["ip", "time", "req", "status"])
    counts = df["ip"].value_counts().head(10)
    colors = ["#c0392b" if ip in blacklist else "#e67e22" if (ip in bf_ips or ip in dos_ips) else "#2980b9" for ip in counts.index]

    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")
    ax.bar(counts.index, counts.values, color=colors)

    ax.set_title("Top IP Access Count", color="white", fontweight="bold")
    ax.tick_params(colors="white")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig("graphs/access.png", facecolor=fig.get_facecolor())
    plt.close()

# ---------------- REPORTING ----------------

def format_alert(alert, activity):
    return (
        f"  {alert['ip']} -> {alert['count']} {activity}; "
        f"window {alert['window_start'].isoformat()} "
        f"to {alert['window_end'].isoformat()} "
        f"(threshold {alert['threshold']} "
        f"in {alert['window_seconds']}s)"
    )


def save_report(bf, dos, bad):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = [
        f"{'=' * 40}\n"
        f" Intrusion Detection Report\n"
        f" {timestamp}\n"
        f"{'=' * 40}"
    ]

    output.append("\n[Brute Force - SSH]")
    output.extend(
        [format_alert(alert, "attempts") for alert in bf]
        if bf
        else ["  no alerts"]
    )

    output.append("\n[DoS Pattern - Apache]")
    output.extend(
        [format_alert(alert, "requests") for alert in dos]
        if dos
        else ["  no alerts"]
    )

    output.append("\n[Blacklisted IPs]")
    output.extend(
        [f"  {ip}" for ip in bad]
        if bad
        else ["  none found"]
    )

    report_content = "\n".join(output)

    with open("report.txt", "w") as file:
        file.write(report_content)

    print(report_content)
    
# ---------------- EXECUTION ----------------

def main():
    args = parse_args()

    try:
        config = load_config(args.config)
    except ConfigError as error:
        print(f"[!] {error}", file=sys.stderr)
        return 2

    apache_files, ssh_files = resolve_files(
        args,
        config["logs_dir"],
    )

    apache_data = parse_apache(apache_files)
    ssh_data = parse_ssh(ssh_files)

    bf_alerts = detect_bruteforce(
        ssh_data,
        config["bruteforce_limit"],
    )
    dos_alerts = detect_dos(
        apache_data,
        config["dos_limit"],
    )

    ssh_ips = [event["ip"] for event in ssh_data]
    apache_ips = [row[0] for row in apache_data]
    all_seen_ips = ssh_ips + apache_ips

    blacklist = load_blacklist()
    blacklisted_found = check_blacklist(all_seen_ips, blacklist)

    if not args.no_graph:
        bf_ips = {alert["ip"] for alert in bf_alerts}
        dos_ips = {alert["ip"] for alert in dos_alerts}

        plot_ips(
            apache_data,
            blacklist,
            bf_ips,
            dos_ips,
        )

    save_report(
        bf_alerts,
        dos_alerts,
        blacklisted_found,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
