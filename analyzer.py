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

def plot_event_overview(apache_data, ssh_data, blacklist=None, bf_ips=None, dos_ips=None):
    """Create one source-aware chart for all successfully parsed events.

    Apache rows and SSH failed-login events use different fields, so the chart
    first normalizes them to ``(source_ip, event_type)`` pairs. Future parsers
    can join this overview by supplying the same two pieces of information.
    """
    blacklist = blacklist or set()
    bf_ips = bf_ips or set()
    dos_ips = dos_ips or set()

    events = [
        (ip, "HTTP request")
        for ip, _timestamp, _request, _status in apache_data
    ]
    events.extend(
        (event["ip"], "Failed SSH login")
        for event in ssh_data
    )

    if not events:
        return False

    event_frame = pd.DataFrame(events, columns=["ip", "event_type"])
    source_counts = event_frame["ip"].value_counts().head(10)
    type_counts = event_frame["event_type"].value_counts()

    source_colors = [
        "#c0392b" if ip in blacklist
        else "#e67e22" if ip in (bf_ips | dos_ips)
        else "#2980b9"
        for ip in source_counts.index
    ]
    type_colors = {
        "HTTP request": "#2980b9",
        "Failed SSH login": "#8e44ad",
    }

    fig, (source_ax, type_ax) = plt.subplots(1, 2, figsize=(14, 6))
    fig.patch.set_facecolor("#1a1a2e")

    for axis in (source_ax, type_ax):
        axis.set_facecolor("#16213e")
        axis.tick_params(colors="white")
        for spine in axis.spines.values():
            spine.set_color("#aab2bd")

    source_ax.bar(source_counts.index, source_counts.values, color=source_colors)
    source_ax.set_title("Top Source IPs", color="white", fontweight="bold")
    source_ax.set_ylabel("Parsed events", color="white")
    source_ax.tick_params(axis="x", rotation=30)
    source_ax.yaxis.set_major_locator(MaxNLocator(integer=True))

    type_ax.bar(
        type_counts.index,
        type_counts.values,
        color=[type_colors.get(event_type, "#16a085") for event_type in type_counts.index],
    )
    type_ax.set_title("Parsed Events by Type", color="white", fontweight="bold")
    type_ax.set_ylabel("Event count", color="white")
    type_ax.tick_params(axis="x", rotation=20)
    type_ax.yaxis.set_major_locator(MaxNLocator(integer=True))

    source_ax.legend(
        handles=[
            mpatches.Patch(color="#c0392b", label="Blacklisted IP"),
            mpatches.Patch(color="#e67e22", label="Detection source"),
            mpatches.Patch(color="#2980b9", label="Observed source"),
        ],
        facecolor="#16213e",
        edgecolor="#aab2bd",
        labelcolor="white",
        loc="upper right",
    )
    fig.suptitle("Log Event Overview", color="white", fontweight="bold", fontsize=16)
    fig.tight_layout(rect=(0, 0, 1, 0.93))

    output_directory = Path("graphs")
    output_directory.mkdir(exist_ok=True)
    fig.savefig(
        output_directory / "event-overview.png",
        facecolor=fig.get_facecolor(),
    )
    plt.close(fig)
    return True


def plot_ips(data, blacklist=None, bf_ips=None, dos_ips=None):
    """Backward-compatible wrapper for callers using the old graph helper."""
    return plot_event_overview(data, [], blacklist, bf_ips, dos_ips)


def write_dashboard(apache_data, ssh_data, bf_alerts, dos_alerts, blacklisted_ips):
    """Write a self-contained, filterable local dashboard for parsed events."""
    detection_ips = {
        alert["ip"]
        for alert in bf_alerts + dos_alerts
    }
    blacklisted_ips = set(blacklisted_ips)

    events = [
        {
            "ip": ip,
            "time": timestamp.isoformat(),
            "source": "Apache",
            "event_type": "HTTP request",
            "suspicious": ip in detection_ips or ip in blacklisted_ips,
            "blacklisted": ip in blacklisted_ips,
        }
        for ip, timestamp, _request, _status in apache_data
    ]
    events.extend(
        {
            "ip": event["ip"],
            "time": event["time"].isoformat(),
            "source": "SSH",
            "event_type": "Failed SSH login",
            "suspicious": (
                event["ip"] in detection_ips
                or event["ip"] in blacklisted_ips
            ),
            "blacklisted": event["ip"] in blacklisted_ips,
        }
        for event in ssh_data
    )

    if not events:
        return False

    alerts = []
    for alert in bf_alerts:
        alerts.append(
            {
                "source": "SSH",
                "rule": "SSH brute-force candidate",
                "ip": alert["ip"],
                "count": alert["count"],
                "activity": "failed attempts",
                "window_start": alert["window_start"].isoformat(),
                "window_end": alert["window_end"].isoformat(),
                "threshold": alert["threshold"],
                "window_seconds": alert["window_seconds"],
                "blacklisted": alert["ip"] in blacklisted_ips,
            }
        )
    for alert in dos_alerts:
        alerts.append(
            {
                "source": "Apache",
                "rule": "Apache request-burst candidate",
                "ip": alert["ip"],
                "count": alert["count"],
                "activity": "requests",
                "window_start": alert["window_start"].isoformat(),
                "window_end": alert["window_end"].isoformat(),
                "threshold": alert["threshold"],
                "window_seconds": alert["window_seconds"],
                "blacklisted": alert["ip"] in blacklisted_ips,
            }
        )

    payload = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "events": events,
        "alerts": alerts,
        "summary": {
            "events": len(events),
            "ssh_alerts": len(bf_alerts),
            "apache_alerts": len(dos_alerts),
            "blacklisted_ips": len(blacklisted_ips),
        },
    }
    payload_json = json.dumps(payload).replace("</", "<\\/")

    dashboard_html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Log File Analyzer Dashboard</title>
  <style>
    :root { color-scheme: dark; --bg: #0b1120; --panel: #111b30; --line: #263653; --text: #e5edf9; --muted: #9db0cc; --blue: #4da3ff; --orange: #f59e0b; --red: #fb7185; --green: #34d399; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Inter, Segoe UI, Arial, sans-serif; background: var(--bg); color: var(--text); }
    main { max-width: 1320px; margin: 0 auto; padding: 32px 24px 48px; }
    header { display: flex; gap: 20px; justify-content: space-between; align-items: start; margin-bottom: 24px; }
    h1 { font-size: clamp(1.6rem, 4vw, 2.3rem); margin: 0 0 7px; }
    h2 { font-size: 1.05rem; margin: 0 0 16px; }
    p { margin: 0; color: var(--muted); }
    .generated { font-size: .85rem; text-align: right; white-space: nowrap; }
    .cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 22px; }
    .card, .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; }
    .card { padding: 18px; }
    .metric { display: block; font-size: 1.8rem; font-weight: 750; margin-top: 8px; }
    .label { font-size: .82rem; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }
    .filters { display: flex; flex-wrap: wrap; gap: 9px; margin: 0 0 22px; }
    button { border: 1px solid var(--line); border-radius: 999px; background: transparent; color: var(--muted); padding: 8px 13px; cursor: pointer; }
    button:hover, button.active { color: #06101f; border-color: var(--blue); background: var(--blue); font-weight: 700; }
    .grid { display: grid; grid-template-columns: 1.1fr .9fr; gap: 18px; margin-bottom: 18px; }
    .panel { padding: 20px; min-width: 0; }
    .bar-row { display: grid; grid-template-columns: minmax(105px, 170px) 1fr 46px; gap: 10px; align-items: center; margin: 11px 0; font-size: .86rem; }
    .bar-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text); }
    .track { height: 10px; background: #0a1326; border-radius: 99px; overflow: hidden; }
    .bar { height: 100%; background: var(--blue); border-radius: inherit; }
    .bar.suspicious { background: var(--orange); }
    .bar.blacklisted { background: var(--red); }
    .count { text-align: right; color: var(--muted); font-variant-numeric: tabular-nums; }
    .timeline { display: flex; gap: 7px; align-items: end; min-height: 145px; border-bottom: 1px solid var(--line); padding-top: 12px; }
    .timeline-bin { flex: 1; min-width: 12px; display: flex; flex-direction: column; justify-content: end; gap: 6px; }
    .timeline-bar { min-height: 4px; background: linear-gradient(180deg, var(--blue), #635bff); border-radius: 5px 5px 0 0; }
    .timeline-label { color: var(--muted); font-size: .65rem; transform: rotate(-35deg); transform-origin: top left; white-space: nowrap; margin-top: 3px; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: .88rem; }
    th, td { text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
    th { color: var(--muted); font-size: .76rem; text-transform: uppercase; letter-spacing: .05em; }
    .chip { display: inline-block; border-radius: 999px; padding: 3px 8px; font-size: .75rem; font-weight: 700; background: #253653; color: #c9dcf9; }
    .chip.alert { background: #523913; color: #ffd58a; }
    .chip.blacklisted { background: #5b2030; color: #ffbac6; }
    .empty { color: var(--muted); padding: 20px 0; }
    @media (max-width: 780px) { main { padding: 22px 15px; } header { display: block; } .generated { text-align: left; margin-top: 10px; white-space: normal; } .cards, .grid { grid-template-columns: 1fr; } .bar-row { grid-template-columns: 100px 1fr 38px; } }
  </style>
</head>
<body>
  <main>
    <header>
      <div><h1>Log File Analyzer Dashboard</h1><p>Parsed-event overview and detection evidence. Alerts require analyst validation.</p></div>
      <p class="generated" id="generated-at"></p>
    </header>
    <section class="cards">
      <div class="card"><span class="label">Parsed events</span><span class="metric" id="event-count"></span></div>
      <div class="card"><span class="label">SSH alerts</span><span class="metric" id="ssh-alert-count"></span></div>
      <div class="card"><span class="label">Apache alerts</span><span class="metric" id="apache-alert-count"></span></div>
      <div class="card"><span class="label">Blacklisted IPs</span><span class="metric" id="blacklist-count"></span></div>
    </section>
    <nav class="filters" aria-label="Dashboard filters">
      <button class="active" data-filter="all">All events</button><button data-filter="SSH">SSH</button><button data-filter="Apache">Apache</button><button data-filter="suspicious">Suspicious only</button>
    </nav>
    <section class="grid">
      <article class="panel"><h2>Top source IPs</h2><div id="sources"></div></article>
      <article class="panel"><h2>Parsed events by type</h2><div id="event-types"></div></article>
    </section>
    <section class="panel" style="margin-bottom:18px"><h2>Busiest event minutes</h2><div class="timeline" id="timeline"></div></section>
    <section class="panel"><h2>Detection evidence</h2><div class="table-wrap"><table><thead><tr><th>Rule</th><th>Source IP</th><th>Activity</th><th>Peak window</th><th>Threshold</th><th>Status</th></tr></thead><tbody id="alerts"></tbody></table></div></section>
  </main>
  <script>const dashboardData = __DASHBOARD_DATA__;</script>
  <script>
    const esc = value => String(value).replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
    const byCount = values => Object.entries(values).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const countBy = (items, field) => items.reduce((counts, item) => (counts[item[field]] = (counts[item[field]] || 0) + 1, counts), {});
    const matches = (item, filter) => filter === 'all' || (filter === 'suspicious' ? item.suspicious || item.blacklisted : item.source === filter);
    let activeFilter = 'all';
    function barRows(rows, type) {
      if (!rows.length) return '<p class="empty">No matching events.</p>';
      const maximum = rows[0][1];
      return rows.map(([label, value]) => {
        const matchingEvents = dashboardData.events.filter(item => (type === 'ip' ? item.ip : item.event_type) === label);
        const blacklisted = matchingEvents.some(item => item.blacklisted);
        const suspicious = matchingEvents.some(item => item.suspicious);
        const color = type === 'ip' && blacklisted ? ' blacklisted' : type === 'ip' && suspicious ? ' suspicious' : '';
        return `<div class="bar-row"><span class="bar-label" title="${esc(label)}">${esc(label)}</span><div class="track"><div class="bar${color}" style="width:${Math.max(4, value / maximum * 100)}%"></div></div><span class="count">${value}</span></div>`;
      }).join('');
    }
    function render() {
      const events = dashboardData.events.filter(item => matches(item, activeFilter));
      const alerts = dashboardData.alerts.filter(item => activeFilter === 'all' || activeFilter === 'suspicious' || item.source === activeFilter);
      document.querySelector('#event-count').textContent = events.length;
      document.querySelector('#ssh-alert-count').textContent = dashboardData.summary.ssh_alerts;
      document.querySelector('#apache-alert-count').textContent = dashboardData.summary.apache_alerts;
      document.querySelector('#blacklist-count').textContent = dashboardData.summary.blacklisted_ips;
      document.querySelector('#sources').innerHTML = barRows(byCount(countBy(events, 'ip')).slice(0, 10), 'ip');
      document.querySelector('#event-types').innerHTML = barRows(byCount(countBy(events, 'event_type')), 'type');
      const minutes = countBy(events.map(item => ({minute: item.time.slice(0, 16)})), 'minute');
      const busiest = byCount(minutes).slice(0, 12).sort((a, b) => a[0].localeCompare(b[0]));
      const maximum = busiest.length ? Math.max(...busiest.map(([, count]) => count)) : 1;
      document.querySelector('#timeline').innerHTML = busiest.length ? busiest.map(([minute, count]) => `<div class="timeline-bin" title="${esc(minute)}: ${count} events"><div class="timeline-bar" style="height:${Math.max(4, count / maximum * 105)}px"></div><span class="timeline-label">${esc(minute.slice(5).replace('T', ' '))}</span></div>`).join('') : '<p class="empty">No matching events.</p>';
      document.querySelector('#alerts').innerHTML = alerts.length ? alerts.map(alert => `<tr><td>${esc(alert.rule)}<br><span class="chip">${esc(alert.source)}</span></td><td>${esc(alert.ip)}</td><td>${alert.count} ${esc(alert.activity)}</td><td>${esc(alert.window_start)}<br>to ${esc(alert.window_end)}</td><td>${alert.threshold} in ${alert.window_seconds}s</td><td><span class="chip ${alert.blacklisted ? 'blacklisted' : 'alert'}">${alert.blacklisted ? 'Blacklisted match' : 'Requires review'}</span></td></tr>`).join('') : '<tr><td colspan="6" class="empty">No matching detection alerts.</td></tr>';
    }
    document.querySelector('#generated-at').textContent = `Generated: ${dashboardData.generated_at}`;
    document.querySelectorAll('[data-filter]').forEach(button => button.addEventListener('click', () => { activeFilter = button.dataset.filter; document.querySelectorAll('[data-filter]').forEach(item => item.classList.toggle('active', item === button)); render(); }));
    render();
  </script>
</body>
</html>
""".replace("__DASHBOARD_DATA__", payload_json)

    output_directory = Path("graphs")
    output_directory.mkdir(exist_ok=True)
    (output_directory / "dashboard.html").write_text(
        dashboard_html,
        encoding="utf-8",
    )
    return True

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

        graph_created = plot_event_overview(
            apache_data,
            ssh_data,
            blacklist,
            bf_ips,
            dos_ips,
        )
        if not graph_created:
            print(
                "[i] No parsed events found; graph was not generated.",
                file=sys.stderr,
            )
        else:
            write_dashboard(
                apache_data,
                ssh_data,
                bf_alerts,
                dos_alerts,
                blacklisted_found,
            )

    save_report(
        bf_alerts,
        dos_alerts,
        blacklisted_found,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
