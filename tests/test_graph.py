import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from matplotlib.colors import to_hex

from analyzer import plot_ips


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

    def test_skips_graph_when_apache_data_is_empty(self):
        plot_ips([])

        self.assertFalse(Path("graphs").exists())

    def test_creates_non_empty_graph_file(self):
        data = self.apache_rows("198.51.100.10", 3)

        plot_ips(data)

        graph = Path("graphs/access.png")

        self.assertTrue(graph.is_file())
        self.assertGreater(graph.stat().st_size, 0)

    def test_applies_blacklist_detection_and_default_colors(self):
        data = (
            self.apache_rows("198.51.100.10", 4)
            + self.apache_rows("203.0.113.20", 3)
            + self.apache_rows("192.0.2.30", 2)
            + self.apache_rows("192.0.2.40", 1)
        )
        captured = {}

        def capture_subplots(*args, **kwargs):
            from matplotlib import pyplot as plt

            figure, axes = plt.subplots(*args, **kwargs)
            captured["axes"] = axes
            return figure, axes

        with patch(
            "analyzer.plt.subplots",
            side_effect=capture_subplots,
        ):
            plot_ips(
                data,
                blacklist={"198.51.100.10"},
                bf_ips={"203.0.113.20"},
                dos_ips={"192.0.2.30"},
            )

        colors = [
            to_hex(bar.get_facecolor())
            for bar in captured["axes"].patches
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


if __name__ == "__main__":
    unittest.main()
