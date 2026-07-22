import io
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta
from pathlib import Path

from analyzer import parse_apache, parse_ssh


class TestLogParsers(unittest.TestCase):
    def write_log(self, directory, filename, content):
        path = Path(directory) / filename
        path.write_text(content, encoding="utf-8")
        return path

    def test_parses_valid_ssh_log_line(self):
        line = (
            "Mar 12 10:15:30 server sshd[1234]: "
            "Failed password for invalid user admin "
            "from 198.51.100.10 port 54321 ssh2\n"
        )

        with tempfile.TemporaryDirectory() as directory:
            path = self.write_log(directory, "auth.log", line)
            result = parse_ssh([path])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ip"], "198.51.100.10")
        self.assertEqual(
            result[0]["time"],
            datetime(2000, 3, 12, 10, 15, 30),
        )

    def test_ssh_parser_skips_bad_timestamp_and_keeps_valid_line(self):
        content = (
            "Mar 32 10:15:30 server sshd[1234]: "
            "Failed password for root from 198.51.100.9 port 12345 ssh2\n"
            "Mar 12 10:16:00 server sshd[1235]: "
            "Failed password for root from 198.51.100.10 port 12346 ssh2\n"
        )

        with tempfile.TemporaryDirectory() as directory:
            path = self.write_log(directory, "auth.log", content)
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                result = parse_ssh([path])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ip"], "198.51.100.10")
        self.assertIn("Skipping invalid SSH timestamp", stderr.getvalue())
        self.assertIn("line 1", stderr.getvalue())
        self.assertIn("Mar 32 10:15:30", stderr.getvalue())

    def test_parses_valid_apache_log_line(self):
        line = (
            '203.0.113.20 - - [12/Mar/2026:10:15:30 +0530] '
            '"GET /login HTTP/1.1" 200 512\n'
        )

        with tempfile.TemporaryDirectory() as directory:
            path = self.write_log(directory, "access.log", line)
            result = parse_apache([path])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "203.0.113.20")
        self.assertEqual(result[0][2], "GET /login HTTP/1.1")
        self.assertEqual(result[0][3], "200")
        self.assertEqual(
            result[0][1].isoformat(),
            "2026-03-12T10:15:30+05:30",
        )
        self.assertEqual(
            result[0][1].utcoffset(),
            timedelta(hours=5, minutes=30),
        )

    def test_apache_parser_skips_bad_timestamp_and_keeps_valid_line(self):
        content = (
            '203.0.113.9 - - [32/Mar/2026:10:15:30 +0530] '
            '"GET /bad HTTP/1.1" 200 100\n'
            '203.0.113.20 - - [12/Mar/2026:10:16:00 +0530] '
            '"GET /good HTTP/1.1" 200 200\n'
        )

        with tempfile.TemporaryDirectory() as directory:
            path = self.write_log(directory, "access.log", content)
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                result = parse_apache([path])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "203.0.113.20")
        self.assertEqual(result[0][2], "GET /good HTTP/1.1")
        self.assertIn("Skipping invalid Apache timestamp", stderr.getvalue())
        self.assertIn("line 1", stderr.getvalue())
        self.assertIn(
            "32/Mar/2026:10:15:30 +0530",
            stderr.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
