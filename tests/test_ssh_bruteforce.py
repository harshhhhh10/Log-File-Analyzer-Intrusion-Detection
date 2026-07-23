import unittest
from datetime import datetime, timedelta

from analyzer import detect_bruteforce


class TestSSHBruteforceWindow(unittest.TestCase):
    def setUp(self):
        self.ip = "198.51.100.10"
        self.start = datetime(2026, 3, 12, 10, 0, 0)

    def events_at(self, *second_offsets):
        return [
            {
                "ip": self.ip,
                "time": self.start + timedelta(seconds=offset),
            }
            for offset in second_offsets
        ]

    def expected_alert(self, count, start_offset, end_offset):
        return {
            "ip": self.ip,
            "count": count,
            "window_start": self.start
            + timedelta(seconds=start_offset),
            "window_end": self.start
            + timedelta(seconds=end_offset),
            "threshold": 3,
            "window_seconds": 60,
        }

    def test_detects_three_attempts_within_60_seconds(self):
        events = self.events_at(0, 20, 40)

        result = detect_bruteforce(events, limit=3)

        self.assertEqual(
            result,
            [self.expected_alert(3, 0, 40)],
        )

    def test_ignores_attempts_spread_beyond_window(self):
        events = self.events_at(0, 61, 122)

        result = detect_bruteforce(events, limit=3)

        self.assertEqual(result, [])

    def test_includes_attempt_exactly_at_60_second_boundary(self):
        events = self.events_at(0, 30, 60)

        result = detect_bruteforce(events, limit=3)

        self.assertEqual(
            result,
            [self.expected_alert(3, 0, 60)],
        )

    def test_reports_actual_peak_window(self):
        events = self.events_at(0, 50, 120, 130, 140)

        result = detect_bruteforce(events, limit=3)

        self.assertEqual(
            result,
            [self.expected_alert(3, 120, 140)],
        )


if __name__ == "__main__":
    unittest.main()
