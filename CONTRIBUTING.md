# Contributing

Issues and pull requests are welcome.

## Setup

```bash
python -m venv venv
venv\Scripts\activate        # Linux/macOS: source venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

## Ground rules

- Run `pytest` before you send a change. Add a test for any bug you fix; the tests in `tests/` show the style (small synthetic `.nessus` files built in code).
- Never commit real scan files or output. `.gitignore` already excludes `*.nessus`, `*.csv` and `*.xlsx`. Use synthetic data in tests.
- The 106-column list lives in one place, `nessus_common.py`. If you add a field, add it there, then update the SQL types in `nessus_to_sql.py`, the field list in the README, and the column count checks in the tests.
- Scripts take paths on the command line. The file pickers are only a fallback when no path is given, and tests must never open one.
- Plain, direct wording in docs and messages.
