# Log File Analyzer for Intrusion Detection

A Python command-line tool that analyzes Apache and SSH logs for suspicious activity, including SSH brute-force attempts, Apache request bursts, and connections from blacklisted IP addresses.

Built during my internship at Elevate Labs.

## Features

- Parses Apache access logs and OpenSSH failed-password events
- Detects SSH brute-force attempts within a rolling 60-second window
- Detects high-volume Apache request bursts within a rolling 60-second window
- Reports the actual peak activity window for each detection
- Checks IP addresses from both SSH and Apache logs against a local blacklist
- Skips malformed timestamps without discarding other valid log entries
- Generates a color-coded chart of the top Apache client IPs
- Writes a timestamped incident report
- Supports custom configuration files
- Includes automated tests through GitHub Actions

## Detection Logic

### SSH brute-force detection

An IP address is flagged when its failed SSH login count reaches the configured `bruteforce_limit` within an inclusive 60-second window.

### Apache request-burst detection

An IP address is flagged when its Apache request count reaches the configured `dos_limit` within an inclusive 60-second window.

These detections use the busiest qualifying window for each IP. Requests distributed outside that window are not combined into a single alert.

> [!NOTE]
> These are threshold-based heuristics intended for learning and small-scale log analysis. A high request count is not by itself proof of a denial-of-service attack.

## Supported Log Formats

The parser currently supports:

- OpenSSH `Failed password` entries containing an IPv4 address
- Apache access-log entries beginning with an IPv4 address and containing a standard Apache timestamp, request, and status code

Invalid timestamps are reported to standard error and skipped. Other valid entries in the same file continue to be processed.

## Project Structure

```text
.
├── .github/
│   └── workflows/          # GitHub Actions test workflow
├── analyzer.py             # Main application
├── config.json             # Default configuration
├── blacklist.txt           # Known suspicious IP addresses
├── requirements.txt        # Python dependencies
├── logs/
│   ├── apache.log          # Sample Apache log
│   └── ssh.log             # Sample SSH log
├── tests/                  # Automated test suite
├── graphs/
│   └── access.png          # Generated Apache traffic chart
└── report.txt              # Generated incident report
```

`report.txt` and `graphs/access.png` are generated at runtime and overwritten by later runs.

The graph represents Apache traffic only. SSH detections appear in the report but are not plotted unless the same IP also appears in the Apache data.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/harshhhhh10/Log-File-Analyzer-Intrusion-Detection.git
cd Log-File-Analyzer-Intrusion-Detection
```

### 2. Install dependencies

```bash
python -m pip install -r requirements.txt
```

## Usage

### Analyze all recognized logs

When no files are provided, the analyzer scans the configured log directory for `.log` and `.txt` files with recognized names.

```bash
python analyzer.py
```

Recognized Apache filename keywords:

```text
apache, access, http
```

Recognized SSH filename keywords:

```text
ssh, auth, secure
```

### Analyze individual files

```bash
python analyzer.py ssh.log
python analyzer.py apache.log
```

Bare filenames are also searched for inside the configured logs directory.

### Analyze multiple files

```bash
python analyzer.py ssh.log apache.log
```

### Force the log type

Use these options when a filename does not contain a recognized keyword:

```bash
python analyzer.py --ssh mylog.txt
python analyzer.py --apache mylog.txt
```

### Use a custom configuration file

```bash
python analyzer.py --config path/to/config.json
```

Relative `logs_dir` paths are resolved from the directory containing the selected configuration file.

### Skip graph generation

```bash
python analyzer.py --no-graph
```

Options can be combined:

```bash
python analyzer.py --config custom-config.json --no-graph
```

## Configuration

The default `config.json` contains:

```json
{
  "logs_dir": "logs",
  "bruteforce_limit": 3,
  "dos_limit": 4
}
```

- `logs_dir` — directory scanned when no files are supplied
- `bruteforce_limit` — failed SSH attempts required within 60 seconds
- `dos_limit` — Apache requests required within 60 seconds

Both detection limits must be positive integers. Missing files, invalid JSON, invalid thresholds, and invalid log-directory values produce a clear configuration error.

## Blacklist

Add one IPv4 address per line to `blacklist.txt`:

```text
45.33.21.90
10.0.0.5
```

The analyzer checks IP addresses parsed from both SSH and Apache logs. Matching addresses are listed in the report.

## Output

### Incident report

Each run writes `report.txt` and prints the same content to the terminal.

Example:

```text
========================================
 Intrusion Detection Report
 2026-04-15 10:25:00
========================================

[Brute Force - SSH]
  192.168.1.10 -> 5 attempts; window 2000-03-12T10:00:00 to 2000-03-12T10:00:40 (threshold 3 in 60s)

[DoS Pattern - Apache]
  45.33.21.90 -> 5 requests; window 2026-03-12T10:00:00+00:00 to 2026-03-12T10:00:40+00:00 (threshold 4 in 60s)

[Blacklisted IPs]
  45.33.21.90
```

The SSH parser uses the fixed year `2000` because traditional syslog timestamps do not include a year.

### Traffic chart

When Apache data is available, the analyzer writes:

```text
graphs/access.png
```

The chart displays the ten most active Apache IP addresses:

- Red — blacklisted IP
- Orange — IP that triggered a detection
- Blue — other observed IP

Use `--no-graph` when only the text report is required.

## Running the Tests

Run the complete test suite with:

```bash
python -m unittest discover -s tests -v
```

Current expected result:

```text
Ran 22 tests
OK
```

GitHub Actions runs the same test suite for pull requests targeting `main` and pushes to `main`.

## Technologies

- Python 3
- Regular expressions
- Pandas
- Matplotlib
- `unittest`
- GitHub Actions

## Current Limitations

- Supports IPv4 addresses only
- Uses fixed 60-second detection windows
- Uses filename keywords for automatic log-type detection
- SSH syslog entries are assigned the year `2000`
- Threshold alerts indicate suspicious volume, not confirmed malicious intent
- The chart visualizes Apache traffic only
- Generated reports and charts are overwritten by subsequent runs

## Legal and Ethical Use

Use this tool only with logs and systems you own or are authorized to analyze. Detection results should be reviewed in context before treating an IP address as malicious.
