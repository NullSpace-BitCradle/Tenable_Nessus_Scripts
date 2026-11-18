"""
Nessus to SQL Server Import Script

Imports .nessus (XML) vulnerability scan files into a SQL Server table, 106
columns per finding.

Usage:
    python nessus_to_sql.py [PATH ...] [--server S] [--database D] [--table T]
                            [--create-table] [--trust-server-certificate]
                            [--dry-run]

Each PATH is a .nessus file or a folder (searched recursively). Anything you do
not give on the command line is asked for at the prompt; with no PATH the script
falls back to a folder picker, which needs a desktop session.

Tables:
- Name an existing table with --table, or choose one from the menu. The script
  checks that it has every column it needs and stops if it does not.
- To make a new table, pass --create-table with --table NEW_NAME, or choose
  "Create a new table" in the menu.
- The file_path column holds the file's base name, not a full path.

Re-importing: next to the findings table the script keeps a log table named
<table>_import_log (created on first use, also for existing tables). It holds
one row per imported file: the file's base name, the SHA-256 of its bytes and the
row count. A file whose name and SHA-256 are already in the log is skipped, so
running the same folder twice adds nothing. A file with the same name but
different content is imported again in full. No findings table or index drops a
row by key: a finding is skipped only when all 106 columns equal an earlier row
in the same run.

Each file is imported in one transaction, rows and log entry together: if any
batch of a file fails, nothing from that file is kept and it is not logged. A
file that cannot be parsed is skipped and reported.

Connection: Windows authentication (Trusted_Connection) through ODBC Driver 18.
The server certificate is validated. If your server uses a self-signed
certificate, install it as trusted, or pass --trust-server-certificate to accept
any certificate (this lets someone in the network path impersonate the server).

--dry-run reads the files and prints the SQL it would run, without connecting.
"""

import argparse
import hashlib
import os
import re
import sys
import time
from datetime import date, datetime

import nessus_common as nc

BATCH_SIZE = 500_000
DEFAULT_TABLE = "nessus_findings"
EXAMPLE_SERVER = "sqlserver.example.com"

# ---- Column types ------------------------------------------------------------

_INT_COLUMNS = {"severity_reversed", "port", "pluginID"}
_BIGINT_COLUMNS = {"host_start_timestamp", "host_end_timestamp"}
_DATE_COLUMNS = {
    "plugin_publication_date", "plugin_modification_date", "patch_publication_date",
    "vuln_publication_date", "scan_date",
}
# Short fixed-vocabulary fields.
_SHORT_TEXT_COLUMNS = {
    "severity_rating", "risk_factor", "plugin_type", "exploit_available",
    "exploit_framework_canvas", "exploit_framework_core", "exploit_framework_metasploit",
    "exploited_by_malware", "exploited_by_nessus", "local_checks_proto", "Credentialed_Scan",
    "always_run", "agent", "cisa_known_exploited", "thorough_tests", "unsupported_by_vendor",
    "in_the_news",
}
# Columns with a fixed, bounded size (the file name is at most 255 characters on Windows).
_KEY_TYPES = {"host_ip": "NVARCHAR(255)", "protocol": "NVARCHAR(100)", "file_path": "NVARCHAR(255)"}
# Columns that can hold several values joined with ", ".
MULTI_VALUE_COLUMNS = [c[0] for c in nc.COLUMNS if c[2] == "multi"]


def sql_column_name(column):
    """The SQL name for an output column. The CSV's file_name is stored as file_path."""
    return "file_path" if column == "file_name" else column


def sql_type(column):
    name = sql_column_name(column)
    if name in _KEY_TYPES:
        return _KEY_TYPES[name]
    if name in _INT_COLUMNS:
        return "INT"
    if name in _BIGINT_COLUMNS:
        return "BIGINT"
    if name in _DATE_COLUMNS:
        return "DATE"
    if name in _SHORT_TEXT_COLUMNS:
        return "NVARCHAR(100)"
    return "NVARCHAR(MAX)"


SQL_COLUMNS = [(sql_column_name(c), sql_type(c)) for c in nc.COLUMN_NAMES]
SQL_COLUMN_NAMES = [c for c, _ in SQL_COLUMNS]


# ---- Names and connection strings --------------------------------------------

def sanitize_table_name(name):
    """
    Validate a NEW table name typed by the user: letters, digits, underscore and
    hyphen, starting with a letter or underscore, at most 100 characters.
    """
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,99}", name):
        raise ValueError(
            f"Invalid table name: {name!r}. Use letters, digits, underscore or hyphen, "
            "starting with a letter or underscore (100 characters at most).")
    return name


def quote_identifier(name):
    """
    Bracket-quote a SQL Server identifier, doubling any ']'. Safe for any name that
    came back from the server's own table list, including names with hyphens or spaces.
    """
    if not isinstance(name, str) or not name or len(name) > 128 or any(
            ord(ch) < 32 or ch == "\x7f" for ch in name):
        raise ValueError(f"Invalid identifier: {name!r}")
    return "[" + name.replace("]", "]]") + "]"


def _odbc_value(value):
    """Escape a connection-string value so ';' and braces in it cannot add options."""
    if not value or any(ord(ch) < 32 for ch in value):
        raise ValueError(f"Invalid connection value: {value!r}")
    if any(ch in value for ch in ";{}"):
        return "{" + value.replace("}", "}}") + "}"
    return value


def build_connection_string(server, database=None, trust_server_certificate=False):
    parts = [
        "DRIVER={ODBC Driver 18 for SQL Server}",
        f"SERVER={_odbc_value(server)}",
    ]
    if database:
        parts.append(f"DATABASE={_odbc_value(database)}")
    parts.append("Trusted_Connection=yes")
    if trust_server_certificate:
        parts.append("TrustServerCertificate=yes")
    return ";".join(parts) + ";"


# ---- SQL text ----------------------------------------------------------------

def build_create_table_sql(table):
    """CREATE TABLE statement for a new findings table. It has no unique key on purpose."""
    quoted = quote_identifier(table)
    columns = ",\n    ".join(f"{name} {typ}" for name, typ in SQL_COLUMNS)
    return f"CREATE TABLE dbo.{quoted} (\n    {columns}\n)"


def log_table_name(table):
    return f"{table}_import_log"


LOG_COLUMN_NAMES = ["file_name", "file_sha256", "row_count", "imported_at"]


def build_create_log_table_sql(table):
    """CREATE TABLE statement for the import log that sits next to a findings table."""
    log = quote_identifier(log_table_name(table))
    pk = quote_identifier(f"PK_{log_table_name(table)}")
    return (f"CREATE TABLE dbo.{log} (\n"
            "    file_name NVARCHAR(255) NOT NULL,\n"
            "    file_sha256 CHAR(64) NOT NULL,\n"
            "    row_count INT NOT NULL,\n"
            "    imported_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),\n"
            f"    CONSTRAINT {pk} PRIMARY KEY (file_sha256, file_name)\n"
            ")")


def build_log_insert_sql(table):
    return (f"INSERT INTO dbo.{quote_identifier(log_table_name(table))} "
            "(file_name, file_sha256, row_count) VALUES (?, ?, ?)")


def build_log_lookup_sql(table):
    return (f"SELECT COUNT(*) FROM dbo.{quote_identifier(log_table_name(table))} "
            "WHERE file_sha256 = ? AND file_name = ?")


def build_insert_sql(table):
    columns = ", ".join(SQL_COLUMN_NAMES)
    marks = ", ".join("?" for _ in SQL_COLUMN_NAMES)
    return f"INSERT INTO dbo.{quote_identifier(table)} ({columns}) VALUES ({marks})"


# ---- Value conversion --------------------------------------------------------

_DATE_FORMATS = ("%Y/%m/%d", "%Y-%m-%d")


def _to_date(value):
    """Parse a Nessus date to a date, or None. Done here so SQL Server's language setting
    cannot change how 2024/03/05 is read."""
    if not value:
        return None
    if isinstance(value, date):
        return value
    text = value.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text[:10], fmt).date()
        except ValueError:
            continue
    return None


def _to_int(value):
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def to_sql_row(row):
    """Convert one 106-column row to values for the INSERT: ints, dates and NULLs where typed."""
    out = []
    for (name, _typ), value in zip(SQL_COLUMNS, row):
        if name in _INT_COLUMNS or name in _BIGINT_COLUMNS:
            out.append(_to_int(value))
        elif name in _DATE_COLUMNS:
            out.append(_to_date(value))
        else:
            out.append("" if value is None else value)
    return out


# ---- Database helpers (take a connection so they can be tested without a server) ----

def connect(conn_str):
    """Open an ODBC connection. pyodbc is imported here so --dry-run and the tests do not need it."""
    try:
        import pyodbc  # type: ignore[import-not-found]
    except ImportError:
        raise SystemExit("pyodbc is not installed. Run: pip install -r requirements.txt")
    return pyodbc.connect(conn_str)


def list_databases(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sys.databases WHERE database_id > 4 ORDER BY name")
    names = [row[0] for row in cursor.fetchall()]
    cursor.close()
    return names


def list_tables(conn):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
        "WHERE TABLE_TYPE = 'BASE TABLE' AND TABLE_SCHEMA = 'dbo' ORDER BY TABLE_NAME")
    names = [row[0] for row in cursor.fetchall()]
    cursor.close()
    return names


def get_table_columns(conn, table):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
        "WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION", (table,))
    names = [row[0] for row in cursor.fetchall()]
    cursor.close()
    return names


def missing_columns(existing_columns):
    """Columns the import needs that the table does not have (names compared ignoring case)."""
    have = {c.lower() for c in existing_columns}
    return [c for c in SQL_COLUMN_NAMES if c.lower() not in have]


def narrow_multi_value_columns(conn, table):
    """
    Names of multi-value columns (cwe, bid, mskb, cve, ...) in an existing table that
    have a fixed length. Several values joined with ", " can be longer than that, and
    SQL Server then rejects the whole batch with "String or binary data would be truncated".
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COLUMN_NAME, CHARACTER_MAXIMUM_LENGTH FROM INFORMATION_SCHEMA.COLUMNS "
        "WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = ?", (table,))
    rows = cursor.fetchall()
    cursor.close()
    lengths = {name.lower(): length for name, length in rows}
    return [c for c in MULTI_VALUE_COLUMNS
            if lengths.get(c.lower()) not in (None, -1)]


def alter_multi_value_columns_sql(table, columns):
    quoted = quote_identifier(table)
    return "\n".join(f"ALTER TABLE dbo.{quoted} ALTER COLUMN {c} NVARCHAR(MAX) NULL;" for c in columns)


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ensure_log_table(conn, table):
    """Create <table>_import_log if it is missing; refuse a table of that name that has other columns."""
    log = log_table_name(table)
    existing = get_table_columns(conn, log)
    if existing:
        have = {c.lower() for c in existing}
        missing = [c for c in LOG_COLUMN_NAMES if c not in have]
        if missing:
            raise ValueError(f"Table dbo.{log} exists but is not an import log "
                             f"(missing columns: {', '.join(missing)}).")
        return
    cursor = conn.cursor()
    try:
        cursor.execute(build_create_log_table_sql(table))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()


def is_already_imported(conn, table, file_name, sha256):
    cursor = conn.cursor()
    try:
        cursor.execute(build_log_lookup_sql(table), (sha256, file_name))
        return cursor.fetchone()[0] > 0
    finally:
        cursor.close()


def create_table(conn, table):
    create_table_sql = build_create_table_sql(table)
    cursor = conn.cursor()
    try:
        cursor.execute(create_table_sql)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()


def prepare_table(conn, table, create):
    """
    Make sure `table` can take the import.

    Returns "existing" or "created". Raises ValueError if the table is missing and
    create is False, or if an existing table lacks required columns.
    """
    existing = get_table_columns(conn, table)
    if existing:
        missing = missing_columns(existing)
        if missing:
            raise ValueError(
                f"Table dbo.{table} does not look like a Nessus findings table. "
                f"Missing columns: {', '.join(missing)}")
        return "existing"
    if not create:
        raise ValueError(
            f"Table dbo.{table} does not exist. Pass --create-table to create it.")
    sanitize_table_name(table)
    create_table(conn, table)
    return "created"


def import_rows(conn, table, rows, batch_size=BATCH_SIZE, log=None):
    """
    Insert `rows` into `table` in batches inside one transaction.

    `log` is an optional (file_name, sha256) pair; its import-log row is written in the
    same transaction, so the rows and the log entry land together or not at all.
    Commits at the end; any error rolls back everything done by this call.
    Returns the number of rows inserted (no row is skipped by key, so this equals
    the rows that landed once the commit succeeded).
    """
    insert_sql = build_insert_sql(table)
    cursor = conn.cursor()
    sent = 0
    try:
        for start in range(0, len(rows), batch_size):
            batch = [to_sql_row(r) for r in rows[start:start + batch_size]]
            cursor.executemany(insert_sql, batch)
            sent += len(batch)
        if log is not None:
            cursor.execute(build_log_insert_sql(table), (log[0], log[1], sent))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
    return sent


# ---- Prompts -----------------------------------------------------------------

def select_from_list(items, item_type="item", input_fn=input, extra=None):
    """
    Numbered menu. `extra` is an optional extra choice shown last; if picked, the
    function returns the `extra` string itself. Returns None if there is nothing to pick.
    """
    options = list(items) + ([extra] if extra else [])
    if not options:
        print(f"No {item_type}s found.")
        return None

    print(f"\nAvailable {item_type}s:")
    for idx, item in enumerate(options, 1):
        print(f"{idx}. {item}")

    while True:
        try:
            choice_num = int(input_fn(f"\nEnter the number of your choice (1-{len(options)}): ").strip())
        except ValueError:
            print("Invalid input. Please enter a number.\n")
            continue
        if not 1 <= choice_num <= len(options):
            print(f"Invalid selection. Please enter a number between 1 and {len(options)}.\n")
            continue
        selected = options[choice_num - 1]
        if input_fn(f"You have selected '{selected}'. Is this correct? (Y/N): ").strip().lower() == "y":
            return selected
        print("Let's try again.\n")


NEW_TABLE_CHOICE = "[Create a new table]"


def choose_table(conn, input_fn=input):
    """Interactive table choice. Returns (table_name, create_flag) or (None, False)."""
    tables = list_tables(conn)
    picked = select_from_list(tables, "table", input_fn, extra=NEW_TABLE_CHOICE)
    if picked is None:
        return None, False
    if picked != NEW_TABLE_CHOICE:
        return picked, False
    while True:
        name = input_fn("Name for the new table: ").strip()
        try:
            return sanitize_table_name(name), True
        except ValueError as exc:
            print(f"{exc}\n")


# ---- Main --------------------------------------------------------------------

def parse_args(argv):
    parser = argparse.ArgumentParser(description="Import .nessus files into SQL Server.")
    parser.add_argument("paths", nargs="*", help=".nessus files or folders (recursive)")
    parser.add_argument("--server", help=f"SQL Server address, e.g. localhost or {EXAMPLE_SERVER}")
    parser.add_argument("--database", help="database to import into")
    parser.add_argument("--table", help="target table in the dbo schema")
    parser.add_argument("--create-table", action="store_true",
                        help="create the table if it does not exist")
    parser.add_argument("--trust-server-certificate", action="store_true",
                        help="accept any server certificate (not recommended)")
    parser.add_argument("--dry-run", action="store_true",
                        help="parse the files and print the SQL, without connecting")
    return parser.parse_args(argv)


def _dry_run(args, files):
    table = sanitize_table_name(args.table or DEFAULT_TABLE)
    print("-- Would run, if the table did not exist:")
    print(build_create_table_sql(table) + ";")
    print("\n-- Would run, if the import log did not exist:")
    print(build_create_log_table_sql(table) + ";")
    print("\n-- Would insert each row with:")
    print(build_insert_sql(table) + ";")
    print("\n-- And, per file, in the same transaction:")
    print(build_log_insert_sql(table) + ";\n")
    stats = nc.RunStats()
    total = sum(1 for _ in nc.iter_unique_rows(files, stats))
    failed = nc.report_failures(stats)
    print(f"Dry run: {stats.files_ok} of {stats.files_seen} files read, {stats.hosts} hosts, "
          f"{total} rows would be inserted ({stats.duplicates} duplicates removed). "
          "Nothing was sent to a server.")
    if stats.files_ok == 0:
        return nc.EXIT_FAILED
    return nc.EXIT_PARTIAL if failed else nc.EXIT_OK


def main(argv=None, connect_fn=None, input_fn=input):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    connect_fn = connect_fn or connect
    start_time = time.time()

    paths = args.paths
    if not paths:
        paths = nc.pick_inputs_gui(allow_files=False)
        if not paths:
            print("No folder selected. Exiting.")
            return nc.EXIT_FAILED
    try:
        files = nc.collect_nessus_files(paths)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return nc.EXIT_FAILED
    if not files:
        print("No .nessus files found. Exiting.", file=sys.stderr)
        return nc.EXIT_FAILED

    try:
        if args.dry_run:
            return _dry_run(args, files)

        server = args.server
        if not server:
            print("=" * 60)
            print("SQL Server Connection Setup")
            print("=" * 60)
            server = input_fn(f"Enter SQL Server address (e.g., localhost or {EXAMPLE_SERVER}): ").strip()
        if not server:
            print("Server address is required. Exiting.", file=sys.stderr)
            return nc.EXIT_FAILED

        trust = args.trust_server_certificate
        database = args.database
        if not database:
            print(f"\nConnecting to server '{server}' to retrieve databases...")
            conn = connect_fn(build_connection_string(server, None, trust))
            try:
                database = select_from_list(list_databases(conn), "database", input_fn)
            finally:
                conn.close()
        if not database:
            print("No database selected. Exiting.", file=sys.stderr)
            return nc.EXIT_FAILED

        print(f"\nConnecting to database '{database}'...")
        conn = connect_fn(build_connection_string(server, database, trust))
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return nc.EXIT_FAILED
    except EOFError:
        print("Input ended before all required values were given. Pass them as arguments.",
              file=sys.stderr)
        return nc.EXIT_FAILED
    except Exception as exc:  # connection errors from the ODBC driver
        print(f"Error connecting to SQL Server: {exc}", file=sys.stderr)
        if "certificate" in str(exc).lower():
            print("The server certificate was not trusted. Install it as trusted, or pass "
                  "--trust-server-certificate to accept any certificate.", file=sys.stderr)
        return nc.EXIT_FAILED

    try:
        table, create = args.table, args.create_table
        if not table:
            table, create = choose_table(conn, input_fn)
        if not table:
            print("No table selected. Exiting.", file=sys.stderr)
            return nc.EXIT_FAILED
        try:
            quote_identifier(f"PK_{log_table_name(table)}")  # name must fit; fail before any change
            state = prepare_table(conn, table, create)
            ensure_log_table(conn, table)
            narrow = narrow_multi_value_columns(conn, table) if state == "existing" else []
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return nc.EXIT_FAILED
        print(f"\nProceeding with:\n  Server: {server}\n  Database: {database}\n"
              f"  Table: dbo.{table} ({state})\n  Import log: dbo.{log_table_name(table)}\n"
              + "=" * 60)
        if narrow:
            print("WARNING: these columns can hold several joined values but have a fixed length, "
                  "so a long list (many CVEs, CWEs or MSKB numbers) can make SQL Server reject a "
                  "batch with 'String or binary data would be truncated':\n  "
                  + ", ".join(narrow) + "\nWiden them with:\n"
                  + alter_multi_value_columns_sql(table, narrow) + "\n", file=sys.stderr)

        stats = nc.RunStats()
        seen = set()
        landed = 0          # rows committed to the table by this run
        imported_files = 0
        skipped_files = []  # already in the import log
        for path in files:
            file_name = os.path.basename(path)
            try:
                sha256 = file_sha256(path)
            except OSError as exc:
                stats.files_seen += 1
                print(f"Error reading {path}: {exc}", file=sys.stderr)
                stats.failures.append((path, f"cannot read file: {exc}"))
                continue
            if is_already_imported(conn, table, file_name, sha256):
                print(f"Skipping {path}: this file (same name and SHA-256) was already imported.")
                skipped_files.append(path)
                continue
            failures_before = len(stats.failures)
            rows = list(nc.iter_unique_rows([path], stats, seen))
            if len(stats.failures) > failures_before:
                continue
            try:
                landed += import_rows(conn, table, rows, log=(file_name, sha256))
            except Exception as exc:
                print(f"Error importing {path}: {exc}\nNothing from this file was kept "
                      "(rolled back). Stopping.", file=sys.stderr)
                nc.report_failures(stats)
                return nc.EXIT_FAILED
            imported_files += 1
            print(f"Imported {len(rows)} rows from {path}")
    finally:
        conn.close()

    failed = nc.report_failures(stats)
    print(f"{imported_files} file(s) imported, {len(skipped_files)} skipped as already imported, "
          f"{len(stats.failures)} failed. {landed} rows inserted "
          f"({stats.duplicates} exact duplicate rows were removed before sending).")
    print(nc.format_run_metrics(start_time))
    if imported_files == 0 and not skipped_files:
        return nc.EXIT_FAILED
    return nc.EXIT_PARTIAL if failed else nc.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
