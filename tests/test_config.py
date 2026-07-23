import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from analyzer import ConfigError, load_config, main


class TestConfiguration(unittest.TestCase):
    def write_config(self, directory, content):
        path = Path(directory) / "config.json"
        path.write_text(content, encoding="utf-8")
        return path

    def test_loads_valid_configuration(self):
        content = json.dumps(
            {
                "logs_dir": "sample-logs",
                "bruteforce_limit": 3,
                "dos_limit": 100,
            }
        )

        with tempfile.TemporaryDirectory() as directory:
            path = self.write_config(directory, content)
            config = load_config(path)

            self.assertEqual(
                config["logs_dir"],
                Path(directory) / "sample-logs",
            )

        self.assertEqual(config["bruteforce_limit"], 3)
        self.assertEqual(config["dos_limit"], 100)

    def test_defaults_logs_directory_relative_to_config(self):
        content = json.dumps(
            {
                "bruteforce_limit": 3,
                "dos_limit": 100,
            }
        )

        with tempfile.TemporaryDirectory() as directory:
            path = self.write_config(directory, content)
            config = load_config(path)

            self.assertEqual(
                config["logs_dir"],
                Path(directory) / "logs",
            )

    def test_rejects_missing_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.json"

            with self.assertRaisesRegex(
                ConfigError,
                "Configuration file not found",
            ):
                load_config(path)

    def test_rejects_malformed_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_config(
                directory,
                '{"bruteforce_limit": 3,',
            )

            with self.assertRaises(ConfigError) as context:
                load_config(path)

        message = str(context.exception)
        self.assertIn("Invalid JSON", message)
        self.assertIn("line", message)
        self.assertIn("column", message)

    def test_rejects_non_object_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_config(directory, "[]")

            with self.assertRaisesRegex(
                ConfigError,
                "Configuration must contain a JSON object",
            ):
                load_config(path)

    def test_rejects_invalid_thresholds(self):
        invalid_values = [True, 0, -1, "3", None]

        for key in ("bruteforce_limit", "dos_limit"):
            for value in invalid_values:
                with self.subTest(key=key, value=value):
                    config = {
                        "logs_dir": "logs",
                        "bruteforce_limit": 3,
                        "dos_limit": 100,
                    }
                    config[key] = value

                    with tempfile.TemporaryDirectory() as directory:
                        path = self.write_config(
                            directory,
                            json.dumps(config),
                        )

                        with self.assertRaisesRegex(
                            ConfigError,
                            f"'{key}' must be a positive integer",
                        ):
                            load_config(path)

    def test_rejects_invalid_logs_directory(self):
        invalid_values = [None, "", "   ", 12, ["logs"]]

        for value in invalid_values:
            with self.subTest(value=value):
                content = json.dumps(
                    {
                        "logs_dir": value,
                        "bruteforce_limit": 3,
                        "dos_limit": 100,
                    }
                )

                with tempfile.TemporaryDirectory() as directory:
                    path = self.write_config(directory, content)

                    with self.assertRaisesRegex(
                        ConfigError,
                        "'logs_dir' must be a non-empty string",
                    ):
                        load_config(path)

    def test_main_returns_two_for_configuration_error(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_path = Path(directory) / "missing.json"
            args = SimpleNamespace(config=missing_path)
            stderr = io.StringIO()

            with patch("analyzer.parse_args", return_value=args):
                with redirect_stderr(stderr):
                    result = main()

        self.assertEqual(result, 2)
        self.assertIn(
            "Configuration file not found",
            stderr.getvalue(),
        )

    def test_analyzer_import_does_not_read_configuration(self):
        repository = Path(__file__).resolve().parents[1]
        environment = os.environ.copy()
        existing_pythonpath = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = os.pathsep.join(
            part
            for part in (str(repository), existing_pythonpath)
            if part
        )

        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-c", "import analyzer"],
                cwd=directory,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
