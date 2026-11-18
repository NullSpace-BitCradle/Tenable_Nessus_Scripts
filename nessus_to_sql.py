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
  "Create a new table" in the menu. The new table gets a unique index on
  (host_ip, pluginID, port, protocol, scan_date, file_path) that ignores
  duplicate rows, so importing the same file twice does not add rows twice.
  Existing tables made by another tool or an older version of this script do not
  have that index, and re-importing into them adds the rows again.
- The file_path column holds the file's base name, not a full path.

Each file is imported in one transaction: if any batch of a file fails, nothing
from that file is kept. A file that cannot be parsed is skipped and reported.

Connection: Windows authentication (Trusted_Connection) through ODBC Driver 18.
The server certificate is validated. If your server uses a self-signed
certificate, install it as trusted, or pass --trust-server-certificate to accept
any certificate (this lets someone in the network path impersonate the server).

--dry-run reads the files and prints the SQL it would run, without connecting.
"""

import argparse
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
# Columns that make up the unique index; they cannot be MAX.
_KEY_TYPES = {"host_ip": "NVARCHAR(64)", "protocol": "NVARCHAR(15)", "file_path": "NVARCHAR(255)"}
UNIQUE_KEY_COLUMNS = ["host_ip", "pluginID", "port", "protocol", "scan_date", "file_path"]


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
    """Return (CREATE TABLE statement, CREATE UNIQUE INDEX statement) for a new table."""
    quoted = quote_identifier(table)
    columns = ",\n    ".join(f"{name} {typ}" for name, typ in SQL_COLUMNS)
    create_table = f"CREATE TABLE dbo.{quoted} (\n    {columns}\n)"
    index_name = quote_identifier(f"UX_{table}_finding")
    key = ", ".join(UNIQUE_KEY_COLUMNS)
    create_index = (f"CREATE UNIQUE INDEX {index_name} ON dbo.{quoted} ({key}) "
                    "WITH (IGNORE_DUP_KEY = ON)")
    return create_table, create_index


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


def create_table(conn, table):
    create_table_sql, create_index_sql = build_create_table_sql(table)
    cursor = conn.cursor()
    try:
        cursor.execute(create_table_sql)
        cursor.execute(create_index_sql)
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


def import_rows(conn, table, rows, batch_size=BATCH_SIZE):
    """
    Insert `rows` into `table` in batches inside one transaction.

    Commits at the end; any error rolls back everything inserted by this call.
    Returns the number of rows sent.
    """
    insert_sql = build_insert_sql(table)
    cursor = conn.cursor()
    sent = 0
    try:
        for start in range(0, len(rows), batch_size):
            batch = [to_sql_row(r) for r in rows[start:start + batch_size]]
            cursor.executemany(insert_sql, batch)
            sent += len(batch)
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
    create_table_sql, create_index_sql = build_create_table_sql(table)
    print("-- Would run, if the table did not exist:")
    print(create_table_sql + ";")
    print(create_index_sql + ";")
    print("\n-- Would insert each row with:")
    print(build_insert_sql(table) + ";\n")
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
            state = prepare_table(conn, table, create)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return nc.EXIT_FAILED
        print(f"\nProceeding with:\n  Server: {server}\n  Database: {database}\n"
              f"  Table: dbo.{table} ({state})\n" + "=" * 60)

        stats = nc.RunStats()
        seen = set()
        imported = 0
        for path in files:
            failures_before = len(stats.failures)
            rows = list(nc.iter_unique_rows([path], stats, seen))
            if len(stats.failures) > failures_before:
                continue
            try:
                imported += import_rows(conn, table, rows)
            except Exception as exc:
                print(f"Error importing {path}: {exc}\nNothing from this file was kept "
                      "(rolled back). Stopping.", file=sys.stderr)
                nc.report_failures(stats)
                return nc.EXIT_FAILED
            print(f"Imported {len(rows)} rows from {path}")
    finally:
        conn.close()

    failed = nc.report_failures(stats)
    print(f"Processed {stats.files_ok} of {stats.files_seen} files, {stats.hosts} hosts, "
          f"{imported} rows sent ({stats.duplicates} duplicates removed before sending).")
    print(nc.format_run_metrics(start_time))
    if stats.files_ok == 0:
        return nc.EXIT_FAILED
    return nc.EXIT_PARTIAL if failed else nc.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
