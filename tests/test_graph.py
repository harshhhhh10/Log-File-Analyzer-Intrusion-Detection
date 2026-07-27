import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from matplotlib import pyplot as plt
from matplotlib.colors import to_hex
from analyzer import plot_event_overview, write_dashboard


class TestGraphGeneration(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.original_directory = Path.cwd()
        os.chdir(self.temporary_directory.name)

        self.timestamp = datetime(
            2026,
            3,
            12,
            10,
            0,
            0,
            tzinfo=timezone.utc,
        )

    def tearDown(self):
        os.chdir(self.original_directory)
        self.temporary_directory.cleanup()

    def apache_rows(self, ip, count):
        return [
            [
                ip,
                self.timestamp,
                "GET / HTTP/1.1",
                "200",
            ]
            for _ in range(count)
        ]

    def ssh_events(self, ip, count):
        return [
            {
                "ip": ip,
                "time": self.timestamp,
            }
            for _ in range(count)
        ]

    def test_skips_graph_when_no_parsed_events_exist(self):
        created = plot_event_overview([], [])

        self.assertFalse(created)
        self.assertFalse(Path("graphs").exists())

    def test_creates_non_empty_graph_file_for_apache_events(self):
        data = self.apache_rows("198.51.100.10", 3)

        created = plot_event_overview(data, [])

        graph = Path("graphs/event-overview.png")

        self.assertTrue(graph.is_file())
        self.assertGreater(graph.stat().st_size, 0)
        self.assertTrue(created)

    def test_creates_graph_for_ssh_only_events(self):
        created = plot_event_overview(
            [],
            self.ssh_events("198.51.100.10", 3),
        )

        self.assertTrue(created)
        self.assertTrue(Path("graphs/event-overview.png").is_file())

    def test_applies_blacklist_detection_and_default_colors(self):
        data = (
            self.apache_rows("198.51.100.10", 4)
            + self.apache_rows("203.0.113.20", 3)
            + self.apache_rows("192.0.2.30", 2)
            + self.apache_rows("192.0.2.40", 1)
        )
        captured = {}
        original_subplots = plt.subplots

        def capture_subplots(*args, **kwargs):
            figure, axes = original_subplots(*args, **kwargs)
            captured["axes"] = axes
            return figure, axes

        with patch(
            "analyzer.plt.subplots",
            side_effect=capture_subplots,
        ):
            plot_event_overview(
                data,
                [],
                blacklist={"198.51.100.10"},
                bf_ips={"203.0.113.20"},
                dos_ips={"192.0.2.30"},
            )

        colors = [
            to_hex(bar.get_facecolor())
            for bar in captured["axes"][0].patches
        ]

        self.assertEqual(
            colors,
            [
                "#c0392b",
                "#e67e22",
                "#e67e22",
                "#2980b9",
            ],
        )

    def test_includes_apache_and_ssh_event_types(self):
        captured = {}
        original_subplots = plt.subplots

        def capture_subplots(*args, **kwargs):
            figure, axes = original_subplots(*args, **kwargs)
            captured["axes"] = axes
            return figure, axes

        with patch(
            "analyzer.plt.subplots",
            side_effect=capture_subplots,
        ):
            plot_event_overview(
                self.apache_rows("203.0.113.20", 2),
                self.ssh_events("198.51.100.10", 3),
            )

        labels = [
            tick.get_text()
            for tick in captured["axes"][1].get_xticklabels()
        ]
        self.assertEqual(labels, ["Failed SSH login", "HTTP request"])

    def test_creates_filterable_dashboard_for_ssh_events(self):
        ssh_events = self.ssh_events("198.51.100.10", 3)
        alerts = [
            {
                "ip": "198.51.100.10",
                "count": 3,
                "window_start": self.timestamp,
                "window_end": self.timestamp,
                "threshold": 3,
                "window_seconds": 60,
            }
        ]

        created = write_dashboard(
            [],
            ssh_events,
            alerts,
            [],
            {"198.51.100.10"},
        )

        dashboard = Path("graphs/dashboard.html")
        self.assertTrue(created)
        self.assertTrue(dashboard.is_file())

        content = dashboard.read_text(encoding="utf-8")
        self.assertIn("Log File Analyzer Dashboard", content)
        self.assertIn("198.51.100.10", content)
        self.assertIn('data-filter="suspicious"', content)

    def test_skips_dashboard_when_no_parsed_events_exist(self):
        self.assertFalse(write_dashboard([], [], [], [], set()))
        self.assertFalse(Path("graphs/dashboard.html").exists())


if __name__ == "__main__":
    unittest.main()
