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
with open("config.json") as f:
    config = json.load(f)

LOGS_DIR = config.get("logs_dir", "logs")
BF_LIMIT = config["bruteforce_limit"]
DOS_LIMIT = config["dos_limit"]

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

def resolve_files(args):
    if not args.files and not args.ssh and not args.apache:
        return find_logs(LOGS_DIR)

    apache_files, ssh_files = [], []
    if args.apache:
        p = Path(args.apache)
        if p.exists(): apache_files.append(p)
    if args.ssh:
        p = Path(args.ssh)
        if p.exists(): ssh_files.append(p)

    for fname in args.files:
        p = Path(fname)
        if not p.exists(): p = Path(LOGS_DIR) / fname
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
            for line in f:
                match = re.search(pattern, line)

                if match:
                    # Extract the timestamp and IP from the matched log line
                    timestamp_text = match.group(1)
                    ip = match.group(2)

                    # SSH logs have no year, so use 2000 as a placeholder
                    timestamp = datetime.strptime(
                        f"2000 {timestamp_text}",
                        "%Y %b %d %H:%M:%S"
                    )

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
            for line in f:
                match = re.search(pattern, line)

                if match:
                    timestamp = datetime.strptime(
                        match.group(2),
                        "%d/%b/%Y:%H:%M:%S %z"
                    )

                    data.append([
                        match.group(1),
                        timestamp,
                        match.group(3),
                        match.group(4),
                    ])

    return data

# ---------------- DETECTION ENGINES ----------------

def detect_bruteforce(events, window_seconds=60):
    events_by_ip = {}

    # Group timestamps by IP address
    for event in events:
        ip = event["ip"]
        timestamp = event["time"]

        if ip not in events_by_ip:
            events_by_ip[ip] = []

        events_by_ip[ip].append(timestamp)

    alerts = []

    # Examine each IP separately
    for ip, timestamps in events_by_ip.items():
        timestamps.sort()

        window_start = 0
        max_attempts = 0

        for window_end in range(len(timestamps)):
            while (
                timestamps[window_end] - timestamps[window_start]
            ).total_seconds() > window_seconds:
                window_start += 1

            attempts_in_window = window_end - window_start + 1
            max_attempts = max(max_attempts, attempts_in_window)

        if max_attempts >= BF_LIMIT:
            alerts.append((ip, max_attempts))

    return alerts

def detect_dos(data, window_seconds=60):
    if not data:
        return pd.Series(dtype=int)

    timestamps_by_ip = {}

    for ip, timestamp, request, status in data:
        if ip not in timestamps_by_ip:
            timestamps_by_ip[ip] = []

        timestamps_by_ip[ip].append(timestamp)

    alerts = {}

    for ip, timestamps in timestamps_by_ip.items():
        timestamps.sort()

        window_start = 0
        max_requests = 0

        for window_end in range(len(timestamps)):
            while (
                timestamps[window_end] - timestamps[window_start]
            ).total_seconds() > window_seconds:
                window_start += 1

            requests_in_window = window_end - window_start + 1
            max_requests = max(max_requests, requests_in_window)

        if max_requests >= DOS_LIMIT:
            alerts[ip] = max_requests

    return pd.Series(alerts, dtype=int).sort_values(ascending=False)

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

def save_report(bf, dos, bad):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = [f"{'='*40}\n Intrusion Detection Report\n {timestamp}\n{'='*40}"]

    output.append("\n[Brute Force - SSH]")
    output.extend([f"  {ip} -> {n} attempts" for ip, n in bf] if bf else ["  no alerts"])

    output.append("\n[DoS Pattern - Apache]")
    output.extend([f"  {ip} -> {n} requests" for ip, n in dos.items()] if not dos.empty else ["  no alerts"])

    output.append("\n[Blacklisted IPs]")
    output.extend([f"  {ip}" for ip in bad] if bad else ["  none found"])

    report_content = "\n".join(output)
    with open("report.txt", "w") as f:
        f.write(report_content)
    print(report_content)

# ---------------- EXECUTION ----------------

def main():
    args = parse_args()

    apache_files, ssh_files = resolve_files(args)

    apache_data = parse_apache(apache_files)
    ssh_data = parse_ssh(ssh_files)

    bf_alerts = detect_bruteforce(ssh_data)
    dos_alerts = detect_dos(apache_data)

    # Extract plain IP strings before blacklist checking
    ssh_ips = [event["ip"] for event in ssh_data]
    apache_ips = [row[0] for row in apache_data]
    all_seen_ips = ssh_ips + apache_ips

    blacklist = load_blacklist()
    blacklisted_found = check_blacklist(all_seen_ips, blacklist)

    if not args.no_graph:
        bf_ips = {ip for ip, attempts in bf_alerts}
        dos_ips = set(dos_alerts.index)

        plot_ips(
            apache_data,
            blacklist,
            bf_ips,
            dos_ips
        )

    save_report(
        bf_alerts,
        dos_alerts,
        blacklisted_found
    )


if __name__ == "__main__":
    main()
