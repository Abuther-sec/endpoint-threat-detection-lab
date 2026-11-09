"""Unit tests for the analyze command line. They use only synthetic data."""
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, "src")

import analyze

SAMPLE = "sample-logs/synthetic_security_events.json"


def run_cli(arguments):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = analyze.main(arguments)
    return code, out.getvalue(), err.getvalue()


class AnalyzeCommandTests(unittest.TestCase):
    def test_synthetic_run_writes_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = run_cli([SAMPLE, "--origin", "synthetic", "--out", tmp])
            self.assertEqual(code, 0)
            self.assertIn("Findings: 21", out)
            for name in ("json", "csv", "md"):
                self.assertTrue((Path(tmp) / ("security_report." + name)).is_file())

    def test_thresholds_can_be_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = [SAMPLE, "--origin", "synthetic", "--out", tmp, "--repeat-threshold", "9"]
            code, out, err = run_cli(args)
            self.assertEqual(code, 0)
            self.assertIn("Findings: 20", out)

    def test_real_origin_is_refused_outside_the_output_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = run_cli([SAMPLE, "--origin", "real", "--out", tmp])
            self.assertEqual(code, 1)
            self.assertIn("output folder", err)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_missing_file_returns_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "nope.json")
            code, out, err = run_cli([missing, "--origin", "synthetic", "--out", tmp])
            self.assertEqual(code, 1)
            self.assertIn("File not found", err)

    def test_invalid_threshold_returns_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = [SAMPLE, "--origin", "synthetic", "--out", tmp, "--repeat-threshold", "1"]
            code, out, err = run_cli(args)
            self.assertEqual(code, 1)
            self.assertIn("repeated_failures_threshold", err)

    def test_origin_is_required(self):
        with self.assertRaises(SystemExit) as caught:
            run_cli([SAMPLE])
        self.assertEqual(caught.exception.code, 2)
