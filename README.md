# Log File Analyzer for Intrusion Detection

A Python-based tool to analyze Apache and SSH log files and detect suspicious activity like brute force attempts, DoS patterns, and blacklisted IPs.

Built during my internship at Elevate Labs.

---

## What it does

- Parses Apache and SSH log files
- Detects brute force login attempts on SSH
- Flags IPs with unusually high request counts within the analyzed log file (threshold-based on total volume, not time-windowed — so a burst of requests in seconds and the same count spread over a week are both flagged the same way)
- Checks all IPs against a blacklist
- Generates a color-coded bar chart of top accessing IPs
- Saves a timestamped incident report

---

## Project Structure

```
├── analyzer.py        # main script
├── config.json        # settings (log folder, thresholds)
├── blacklist.txt      # known bad IPs
├── requirements.txt
├── logs/
│   ├── apache.log
│   └── ssh.log
├── graphs/ 
│   └── access.png     # generated after running
└── report.txt         # generated after running
```
Note: the chart plots Apache/web traffic only — SSH brute-force activity is captured in the report but not the graph.

---

## How to run

**1. Clone the repo**
```bash
git clone https://github.com/harshhhhh10/log-file-analyzer-intrusion-detection.git
cd log-analyzer
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Run**

```bash
# analyze all logs in logs/ folder (auto-detected)
python analyzer.py

# analyze only ssh log
python analyzer.py ssh.log

# analyze only apache log
python analyzer.py apache.log

# analyze multiple files at once
python analyzer.py ssh.log apache.log

# force file type using flags
python analyzer.py --ssh mylog.txt
python analyzer.py --apache mylog.txt

# skip graph generation
python analyzer.py --no-graph
```

---

## Config

Edit `config.json` to change the logs folder or detection thresholds:

```json
{
  "logs_dir": "logs",
  "bruteforce_limit": 3,
  "dos_limit": 4
}
```

- `logs_dir` — folder to scan when no files are passed as arguments
- `bruteforce_limit` — failed SSH attempts before flagging an IP
- `dos_limit` — Apache requests before flagging an IP

---

## Blacklist

Add IPs to `blacklist.txt`, one per line. Any match from the SSH log gets flagged in the report.

---

## Sample Output

```
========================================
   Intrusion Detection Report
   2025-03-12 10:25:00
========================================

[Brute Force - SSH]
  192.168.1.10  ->  5 failed attempts

[DoS Pattern - Apache]
  192.168.1.10  ->  5 requests
  45.33.21.90   ->  5 requests

[Blacklisted IPs]
  45.33.21.90
  10.0.0.5
```

---

## Tools used

- Python 3
- Regex
- Pandas
- Matplotlib

---
### 🛠️ Recent Security Updates (April 2026)
* **Detection Fix:** I identified a bug where the parser was missing "invalid user" attempts in SSH logs. I've updated the regex to be more flexible (using lazy matching), which closed this visibility gap.
* **IP Correlation:** The tool now checks both SSH and Apache logs against the blacklist. This prevents attackers from hiding their activity by switching protocols.
* **Code Documentation:** Added detailed comments to the main logic to explain the "why" behind the detection thresholds.
