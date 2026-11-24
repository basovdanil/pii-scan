"""Tests for pii_scan: detection, masking, encodings, exit codes."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pii_scan  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def tmp_csv(text: str, encoding: str = "utf-8") -> Path:
    handle = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding=encoding)
    handle.write(text)
    handle.close()
    return Path(handle.name)


class DetectionTest(unittest.TestCase):
    def test_finds_email(self):
        report = pii_scan.scan(FIXTURES / "dirty.csv")
        self.assertEqual(report["totals"]["email"], 2)

    def test_finds_phone_in_several_formats(self):
        report = pii_scan.scan(FIXTURES / "dirty.csv")
        self.assertEqual(report["totals"]["phone"], 3)

    def test_finds_passport_and_snils(self):
        report = pii_scan.scan(FIXTURES / "dirty.csv")
        self.assertEqual(report["totals"]["passport"], 2)
        self.assertEqual(report["totals"]["snils"], 1)

    def test_clean_file_has_no_findings(self):
        report = pii_scan.scan(FIXTURES / "clean.csv")
        self.assertEqual(report["findings"], {})
        self.assertEqual(report["rows"], 3)

    def test_counts_rows_and_columns(self):
        report = pii_scan.scan(FIXTURES / "clean.csv")
        self.assertEqual(report["columns"], ["id", "store", "amount"])


class MaskingTest(unittest.TestCase):
    def test_email_masked(self):
        self.assertEqual(pii_scan.mask("ivan.petrov@example.com", "email"), "i***@example.com")

    def test_phone_masked(self):
        self.assertEqual(pii_scan.mask("+7 900 123-45-67", "phone"), "***52")

    def test_report_carries_no_raw_values(self):
        report = pii_scan.scan(FIXTURES / "dirty.csv")
        dumped = json.dumps(report, ensure_ascii=False)
        self.assertNotIn("ivan.petrov@example.com", dumped)
        self.assertNotIn("9001234567", dumped)


class InputTest(unittest.TestCase):
    def test_windows_1251_file(self):
        path = tmp_csv("id,comment\n1,почта ivan@example.com\n", encoding="cp1251")
        report = pii_scan.scan(path, encoding="cp1251")
        self.assertEqual(report["totals"]["email"], 1)

    def test_semicolon_delimiter(self):
        path = tmp_csv("id;mail\n1;a@b.ru\n")
        report = pii_scan.scan(path, delimiter=";")
        self.assertIn("mail", report["findings"])

    def test_empty_file_is_an_error(self):
        path = tmp_csv("")
        with self.assertRaises(ValueError):
            pii_scan.scan(path)


class ExitCodeTest(unittest.TestCase):
    def _run(self, args: list[str]):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = pii_scan.main(args)
        return code, buf.getvalue()

    def test_clean_returns_zero(self):
        code, out = self._run([str(FIXTURES / "clean.csv")])
        self.assertEqual(code, 0)
        self.assertIn("nothing found", out)

    def test_findings_return_four(self):
        code, out = self._run([str(FIXTURES / "dirty.csv")])
        self.assertEqual(code, 4)
        self.assertIn("email=2", out)

    def test_missing_file_returns_three(self):
        code, _ = self._run([str(FIXTURES / "nope.csv")])
        self.assertEqual(code, 3)

    def test_json_output_is_parseable(self):
        code, out = self._run([str(FIXTURES / "dirty.csv"), "--json"])
        self.assertEqual(code, 4)
        data = json.loads(out)
        self.assertEqual(data["rows"], 3)
        self.assertIn("phone", data["findings"])


if __name__ == "__main__":
    unittest.main()
