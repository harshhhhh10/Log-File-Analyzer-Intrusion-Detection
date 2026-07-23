import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from analyzer import (
    check_blacklist,
    format_alert,
    load_blacklist,
    save_report,
)


class TestBlacklist(unittest.TestCase):
    def test_loads_blacklist_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "blacklist.txt"
            path.write_text(
                "198.51.100.10\n203.0.113.20\n",
                encoding="utf-8",
            )

            result = load_blacklist(path)

        self.assertEqual(
            result,
            {
                "198.51.100.10",
                "203.0.113.20",
            },
        )

    def test_missing_blacklist_returns_empty_set(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.txt"

            result = load_blacklist(path)

        self.assertEqual(result, set())

    def test_matches_seen_ips_without_duplicates(self):
        seen_ips = [
            "198.51.100.10",
            "203.0.113.20",
            "198.51.100.10",
            "192.0.2.30",
        ]
        blacklist = {
            "198.51.100.10",
            "203.0.113.20",
        }

        result = check_blacklist(seen_ips, blacklist)

        self.assertCountEqual(
            result,
            [
                "198.51.100.10",
                "203.0.113.20",
            ],
        )


class TestReporting(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.original_directory = Path.cwd()
        os.chdir(self.temporary_directory.name)

    def tearDown(self):
        os.chdir(self.original_directory)
        self.temporary_directory.cleanup()

    def alert(
        self,
        ip,
        count,
        start,
        end,
        threshold,
    ):
        return {
            "ip": ip,
            "count": count,
            "window_start": start,
            "window_end": end,
            "threshold": threshold,
            "window_seconds": 60,
        }

    def test_formats_complete_alert_evidence(self):
        start = datetime(2026, 3, 12, 10, 0, 0)
        alert = self.alert(
            "198.51.100.10",
            3,
            start,
            start + timedelta(seconds=40),
            3,
        )

        result = format_alert(alert, "attempts")

        self.assertEqual(
            result,
            (
                "  198.51.100.10 -> 3 attempts; "
                "window 2026-03-12T10:00:00 "
                "to 2026-03-12T10:00:40 "
                "(threshold 3 in 60s)"
            ),
        )

    def test_writes_and_prints_report_with_alert_evidence(self):
        ssh_start = datetime(2026, 3, 12, 10, 0, 0)
        apache_start = datetime(
            2026,
            3,
            12,
            10,
            5,
            0,
            tzinfo=timezone.utc,
        )

        brute_force_alerts = [
            self.alert(
                "198.51.100.10",
                3,
                ssh_start,
                ssh_start + timedelta(seconds=40),
                3,
            )
        ]
        dos_alerts = [
            self.alert(
                "203.0.113.20",
                4,
                apache_start,
                apache_start + timedelta(seconds=30),
                4,
            )
        ]

        stdout = io.StringIO()

        with patch("analyzer.datetime") as mocked_datetime:
            mocked_datetime.now.return_value = datetime(
                2026,
                3,
                12,
                12,
                0,
                0,
            )

            with redirect_stdout(stdout):
                save_report(
                    brute_force_alerts,
                    dos_alerts,
                    ["203.0.113.20"],
                )

        report = Path("report.txt").read_text(encoding="utf-8")

        self.assertEqual(stdout.getvalue(), report + "\n")
        self.assertIn(
            "Intrusion Detection Report\n 2026-03-12 12:00:00",
            report,
        )
        self.assertIn(
            (
                "198.51.100.10 -> 3 attempts; "
                "window 2026-03-12T10:00:00 "
                "to 2026-03-12T10:00:40 "
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

    def test_reports_empty_sections(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            save_report([], [], [])

        report = Path("report.txt").read_text(encoding="utf-8")

        self.assertEqual(stdout.getvalue(), report + "\n")
        self.assertEqual(report.count("  no alerts"), 2)
        self.assertIn("[Blacklisted IPs]\n  none found", report)


if __name__ == "__main__":
    unittest.main()
