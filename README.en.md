# pii-scan

[![tests](https://github.com/basovdanil/pii-scan/actions/workflows/tests.yml/badge.svg)](https://github.com/basovdanil/pii-scan/actions/workflows/tests.yml)

**English** · [Русский](README.md)

<p align="center">
  <img src="https://raw.githubusercontent.com/basovdanil/basovdanil/main/assets/tools.png"
       alt="Eight tools with tests and exit codes" width="100%">
</p>

Scans a CSV export for personal data before the file leaves the company and returns a non-zero exit
code, so it can gate a pipeline.

```
python pii_scan.py export.csv
```

```
export.csv: 3 rows, 4 columns with findings, 8 matches
  email: 2 (email=2); examples: i***@example.com, p***@example.com
  phone: 3 (phone=3); examples: ***52, ***67, ***67
  passport: 2 (passport=2); examples: ***56, ***56
  note: 1 (snils=1); examples: ***64
```

What it finds: e-mail addresses, Russian phone numbers in any of the usual spellings
(`+7 900 123-45-67`, `8 (495) 123-45-67`, `89001234567`), passport series and number pairs, SNILS.
The report never contains the raw values — only a mask like `i***@example.com` or `***52`, so the
report itself can be shared.

## Usage

```
python pii_scan.py <file.csv> [--json] [--delimiter ';']
python pii_scan.py --from-dir exports/ [--recursive] [--json]
```

- `--json` prints the report object: rows, columns, per-column findings, totals by type;
- `--from-dir` scans every `*.csv` in a directory and prints one line per file plus the grand total;
  `--recursive` includes subdirectories, `--json` returns `{files, totals, files_with_findings}`;
- `--delimiter` for exports from Excel and 1C that use `;`;
- UTF-8 with or without BOM; a windows-1251 file needs the encoding adjusted in code (one argument).

Exit codes: `0` nothing found, `2` bad arguments, `3` the file cannot be read (or the directory has
no CSV), `4` personal data found.

## Use in CI as a GitHub Action

```yaml
- uses: basovdanil/pii-scan@v1
  id: pii
  with:
    file: export.csv          # path in your repository
    delimiter: ","            # ";" for Excel and 1C exports
    json: "false"             # "true" for the machine-readable report

- run: echo '${{ steps.pii.outputs.result }}'
```

Exit code `4` fails the step when anything is found, so a workflow that uploads an export stops
before the file leaves the runner. `actions/setup-python` is included in the action.

## What it is not

This is a smoke detector, not a compliance tool. It finds data by shape, so it misses anything
unstructured (a name in a free-text comment), and it can flag a harmless number that looks like a
phone. Use it to catch the obvious leak in an export pipeline, not to sign off a data transfer.

## Tests

```
python -m unittest discover -s tests
```

15 tests: each type on a fixture, masking, absence of raw values in the report, cp1251 input,
`;` delimiter, empty file, every exit code, `--json` shape.

Python 3.8+, standard library only.

---

More projects: [github.com/basovdanil](https://github.com/basovdanil) · write-ups: [portfolio](https://basovdanil.github.io/portfolio/)
