import unittest
from datetime import datetime, timedelta, timezone

from analyzer import detect_dos


class TestApacheDosWindow(unittest.TestCase):
    def setUp(self):
        self.start = datetime(
            2026,
            3,
            12,
            10,
            0,
            0,
            tzinfo=timezone.utc,
        )

    def requests_at(self, ip, *second_offsets):
        return [
            [
                ip,
                self.start + timedelta(seconds=offset),
                "GET / HTTP/1.1",
                "200",
            ]
            for offset in second_offsets
        ]

    def expected_alert(self, ip, count, start_offset, end_offset):
        return {
            "ip": ip,
            "count": count,
            "window_start": self.start
            + timedelta(seconds=start_offset),
            "window_end": self.start
            + timedelta(seconds=end_offset),
            "threshold": 4,
            "window_seconds": 60,
        }

    def test_detects_request_burst_within_60_seconds(self):
        data = self.requests_at("198.51.100.10", 0, 10, 20, 30)

        result = detect_dos(data, limit=4)

        self.assertEqual(
            result,
            [
                self.expected_alert(
                    "198.51.100.10",
                    4,
                    0,
                    30,
                )
            ],
        )

    def test_ignores_requests_spread_beyond_window(self):
        data = self.requests_at("198.51.100.10", 0, 61, 122, 183)

        result = detect_dos(data, limit=4)

        self.assertEqual(result, [])

    def test_includes_exact_60_second_boundary(self):
        data = self.requests_at("198.51.100.10", 0, 20, 40, 60)

        result = detect_dos(data, limit=4)

        self.assertEqual(
            result,
            [
                self.expected_alert(
                    "198.51.100.10",
                    4,
                    0,
                    60,
                )
            ],
        )

    def test_keeps_ip_addresses_independent(self):
        data = (
            self.requests_at("198.51.100.10", 0, 10, 20, 30)
            + self.requests_at("203.0.113.20", 0, 61, 122, 183)
        )

        result = detect_dos(data, limit=4)

        self.assertEqual(
            result,
            [
                self.expected_alert(
                    "198.51.100.10",
                    4,
                    0,
                    30,
                )
            ],
        )

    def test_reports_actual_peak_window(self):
        data = self.requests_at(
            "198.51.100.10",
            0,
            50,
            120,
            130,
            140,
            150,
        )

        result = detect_dos(data, limit=4)

        self.assertEqual(
            result,
            [
                self.expected_alert(
                    "198.51.100.10",
                    4,
                    120,
                    150,
                )
            ],
        )


if __name__ == "__main__":
    unittest.main()
