import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestCLIWorkflow(unittest.TestCase):
    def test_complete_analysis_with_custom_config_and_no_graph(self):
        repository = Path(__file__).resolve().parents[1]
        analyzer = repository / "analyzer.py"

        ssh_log = (
            "Mar 12 10:00:00 server sshd[1001]: "
            "Failed password for invalid user admin "
            "from 198.51.100.10 port 50001 ssh2\n"
            "Mar 12 10:00:20 server sshd[1002]: "
            "Failed password for invalid user admin "
            "from 198.51.100.10 port 50002 ssh2\n"
            "Mar 12 10:00:40 server sshd[1003]: "
            "Failed password for invalid user admin "
            "from 198.51.100.10 port 50003 ssh2\n"
        )

        apache_log = (
            '203.0.113.20 - - [12/Mar/2026:10:05:00 +0000] '
            '"GET /login HTTP/1.1" 200 512\n'
            '203.0.113.20 - - [12/Mar/2026:10:05:10 +0000] '
            '"GET /login HTTP/1.1" 200 512\n'
            '203.0.113.20 - - [12/Mar/2026:10:05:20 +0000] '
            '"GET /login HTTP/1.1" 200 512\n'
            '203.0.113.20 - - [12/Mar/2026:10:05:30 +0000] '
            '"GET /login HTTP/1.1" 200 512\n'
        )

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            logs_directory = workspace / "sample-logs"
            logs_directory.mkdir()

            (logs_directory / "ssh.log").write_text(
                ssh_log,
                encoding="utf-8",
            )
            (logs_directory / "apache.log").write_text(
                apache_log,
                encoding="utf-8",
            )
            (workspace / "blacklist.txt").write_text(
                "203.0.113.20\n",
                encoding="utf-8",
            )

            config_path = workspace / "custom-config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "logs_dir": "sample-logs",
                        "bruteforce_limit": 3,
                        "dos_limit": 4,
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(analyzer),
                    "--config",
                    str(config_path),
                    "--no-graph",
                ],
                cwd=workspace,
                capture_output=True,
                text=True,
                check=False,
            )

            report_path = workspace / "report.txt"

            self.assertEqual(
                result.returncode,
                0,
                msg=result.stderr,
            )
            self.assertTrue(report_path.is_file())

            report = report_path.read_text(encoding="utf-8")

            self.assertEqual(result.stdout, report + "\n")
            self.assertIn(
                (
                    "198.51.100.10 -> 3 attempts; "
                    "window 2000-03-12T10:00:00 "
                    "to 2000-03-12T10:00:40 "
                    "(threshold 3 in 60s)"
                ),
                report,
            )
            self.assertIn(
                (
                    "203.0.113.20 -> 4 requests; "
                    "window 2026-03-12T10:05:00+00:00 "
                    "to 2026-03-12T10:05:30+00:00 "
                    "(threshold 4 in 60s)"
                ),
                report,
            )
            self.assertIn(
                "[Blacklisted IPs]\n  203.0.113.20",
                report,
            )
            self.assertFalse((workspace / "graphs").exists())


if __name__ == "__main__":
    unittest.main()
