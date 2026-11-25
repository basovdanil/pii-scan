"""Tests for the directory mode of pii_scan: aggregation, recursion, exit codes."""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pii_scan  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
DIRTY = "id,mail,phone\n1,ivan@example.com,+7 900 123-45-67\n"
CLEAN = "id,store,amount\n1,Москва,1500\n"


def make_tree(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


class ScanDirectoryTest(unittest.TestCase):
    def tearDown(self):
        for folder in getattr(self, "_folders", []):
            shutil.rmtree(folder, ignore_errors=True)

    def _tree(self, files: dict[str, str]) -> Path:
        root = make_tree(files)
        self._folders = getattr(self, "_folders", []) + [root]
        return root

    def test_aggregates_files(self):
        root = self._tree({"a.csv": DIRTY, "b.csv": CLEAN})
        report = pii_scan.scan_directory(root)
        self.assertEqual(report["file_count"], 2)
        self.assertEqual(report["files_with_findings"], 1)
        self.assertEqual(report["totals"]["email"], 1)
        self.assertEqual(report["totals"]["phone"], 1)

    def test_ignores_non_csv_files(self):
        root = self._tree({"a.csv": DIRTY, "notes.txt": DIRTY, "data.json": "{}"})
        self.assertEqual(pii_scan.scan_directory(root)["file_count"], 1)

    def test_non_recursive_by_default(self):
        root = self._tree({"top.csv": CLEAN, "nested/deep.csv": DIRTY})
        self.assertEqual(pii_scan.scan_directory(root)["file_count"], 1)
        self.assertEqual(pii_scan.scan_directory(root, recursive=True)["file_count"], 2)

    def test_clean_directory_has_empty_totals(self):
        root = self._tree({"a.csv": CLEAN})
        report = pii_scan.scan_directory(root)
        self.assertEqual(report["totals"], {})
        self.assertEqual(report["files_with_findings"], 0)


class DirectoryExitCodeTest(unittest.TestCase):
    def _run(self, args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = pii_scan.main(args)
        return code, buf.getvalue()

    def test_directory_with_findings_returns_four(self):
        root = make_tree({"a.csv": DIRTY, "b.csv": CLEAN})
        try:
            code, out = self._run(["--from-dir", str(root)])
            self.assertEqual(code, 4)
            self.assertIn("2 CSV files, 1 with findings", out)
            self.assertIn("b.csv: nothing found", out)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_clean_directory_returns_zero(self):
        root = make_tree({"a.csv": CLEAN})
        try:
            code, _ = self._run(["--from-dir", str(root)])
            self.assertEqual(code, 0)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_missing_directory_returns_three(self):
        code, _ = self._run(["--from-dir", str(FIXTURES / "absent")])
        self.assertEqual(code, 3)

    def test_directory_without_csv_returns_three(self):
        root = make_tree({"readme.txt": "hello"})
        try:
            code, _ = self._run(["--from-dir", str(root)])
            self.assertEqual(code, 3)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_file_and_dir_together_return_two(self):
        code, _ = self._run([str(FIXTURES / "clean.csv"), "--from-dir", "somewhere"])
        self.assertEqual(code, 2)

    def test_no_arguments_return_two(self):
        code, _ = self._run([])
        self.assertEqual(code, 2)

    def test_directory_passed_as_file_returns_three(self):
        code, out = self._run([str(FIXTURES)])
        self.assertEqual(code, 3)

    def test_json_report_shape(self):
        root = make_tree({"a.csv": DIRTY})
        try:
            code, out = self._run(["--from-dir", str(root), "--json"])
            self.assertEqual(code, 4)
            data = json.loads(out)
            self.assertEqual(data["file_count"], 1)
            self.assertIn("totals", data)
            self.assertEqual(data["totals"]["email"], 1)
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
