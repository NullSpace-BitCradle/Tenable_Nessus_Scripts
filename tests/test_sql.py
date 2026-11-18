"""
nessus_to_sql.py without a SQL Server: the SQL text is built and checked as text, and the
database calls run against a small in-memory fake of a pyodbc connection.
"""

import re
from datetime import date

import pytest

import nessus_common as nc
import nessus_to_sql as sql
from helpers import basic_host, report_item, write_nessus


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, query, params=()):
        self.conn.executed.append((query, tuple(params)))
        if self.conn.fail_on and self.conn.fail_on in query:
            raise RuntimeError("boom")
        self._rows = []
        if "FROM sys.databases" in query:
            self._rows = [(d,) for d in self.conn.databases]
        elif "INFORMATION_SCHEMA.TABLES" in query:
            self._rows = [(t,) for t in self.conn.tables]
        elif "INFORMATION_SCHEMA.COLUMNS" in query:
            self._rows = [(c,) for c in self.conn.table_columns.get(params[0], [])]
        elif query.lstrip().startswith("CREATE TABLE"):
            name = re.match(r"CREATE TABLE dbo\.\[(.+?)\]", query.lstrip()).group(1)
            self.conn.table_columns[name] = list(sql.SQL_COLUMN_NAMES)
            self.conn.tables.append(name)

    def executemany(self, query, batch):
        if self.conn.fail_on_insert_after is not None and \
                len(self.conn.inserted) + len(self.conn.pending) + len(batch) > self.conn.fail_on_insert_after:
            raise RuntimeError("String or binary data would be truncated")
        self.conn.batches.append((query, len(batch)))
        self.conn.pending.extend(batch)

    def fetchall(self):
        return self._rows

    def close(self):
        pass


class FakeConn:
    def __init__(self, databases=("scans",), tables=(), table_columns=None):
        self.databases = list(databases)
        self.tables = list(tables)
        self.table_columns = dict(table_columns or {})
        self.executed, self.batches = [], []
        self.pending, self.inserted = [], []
        self.commits = self.rollbacks = 0
        self.closed = False
        self.fail_on = None
        self.fail_on_insert_after = None

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.commits += 1
        self.inserted.extend(self.pending)
        self.pending = []

    def rollback(self):
        self.rollbacks += 1
        self.pending = []

    def close(self):
        self.closed = True


def good_columns():
    return list(sql.SQL_COLUMN_NAMES)


# ---- SQL text ----

def test_create_table_has_106_columns_in_order_and_matches_the_insert():
    create, index = sql.build_create_table_sql("nessus_findings")
    names = re.findall(r"^\s{4}(\w+) [A-Z]+", create, re.M)
    assert len(names) == 106
    insert = sql.build_insert_sql("nessus_findings")
    cols = re.search(r"\(([^)]*)\) VALUES", insert).group(1).split(", ")
    assert names == cols
    assert insert.count("?") == 106
    # CSV column file_name is the SQL column file_path.
    assert cols[-2:] == ["file_path", "scan_date"] and "file_name" not in cols
    assert cols == [("file_path" if c == "file_name" else c) for c in nc.COLUMN_NAMES]


def test_create_table_text_is_for_a_new_table_with_a_dedupe_index():
    create, index = sql.build_create_table_sql("my_scans")
    assert create.startswith("CREATE TABLE dbo.[my_scans] (")
    assert "IF NOT EXISTS" not in create
    assert index == ("CREATE UNIQUE INDEX [UX_my_scans_finding] ON dbo.[my_scans] "
                     "(host_ip, pluginID, port, protocol, scan_date, file_path) "
                     "WITH (IGNORE_DUP_KEY = ON)")


def test_column_types_avoid_the_truncation_traps():
    types = dict(sql.SQL_COLUMNS)
    for wide in ("synopsis", "cve", "cwe", "bid", "pluginName", "plugin_output", "hostname",
                 "operating_system", "system_type", "see_also", "description"):
        assert types[wide] == "NVARCHAR(MAX)", wide
    assert not any(t.startswith("VARCHAR") for t in types.values())
    assert types["port"] == "INT" and types["host_start_timestamp"] == "BIGINT"
    assert types["scan_date"] == "DATE"
    # The index key must stay under the 900 byte clustered / 1700 byte limit.
    key_bytes = 0
    for c in sql.UNIQUE_KEY_COLUMNS:
        t = types[c]
        m = re.match(r"NVARCHAR\((\d+)\)", t)
        key_bytes += int(m.group(1)) * 2 if m else {"INT": 4, "DATE": 3}[t]
    assert key_bytes < 900


# ---- Names ----

@pytest.mark.parametrize("name", ["scans", "_x", "my-scans", "A1_b-2"])
def test_sanitize_accepts_valid_new_names(name):
    assert sql.sanitize_table_name(name) == name


@pytest.mark.parametrize("name", ["", "1abc", "a b", "a]b", "a;drop", "x\n", "a" * 101, "a.b", None])
def test_sanitize_rejects_bad_new_names(name):
    with pytest.raises(ValueError):
        sql.sanitize_table_name(name)


def test_trailing_newline_is_rejected():
    """Audit L8: re.match with $ accepted 'name\\n'."""
    with pytest.raises(ValueError):
        sql.sanitize_table_name("scans\n")


def test_quote_identifier_handles_hyphens_spaces_and_brackets():
    assert sql.quote_identifier("my-scans") == "[my-scans]"
    assert sql.quote_identifier("a b") == "[a b]"
    assert sql.quote_identifier("a]b") == "[a]]b]"
    for bad in ("", "x\n", "a\x00b", "a" * 129):
        with pytest.raises(ValueError):
            sql.quote_identifier(bad)


def test_connection_string_validates_certificate_by_default():
    cs = sql.build_connection_string("localhost", "scans")
    assert "TrustServerCertificate" not in cs
    assert "Trusted_Connection=yes" in cs and "DATABASE=scans" in cs
    assert "TrustServerCertificate=yes" in sql.build_connection_string("h", "d", True)


def test_connection_string_escapes_semicolons_and_braces():
    cs = sql.build_connection_string("host;Encrypt=no", "db}x;y")
    assert "SERVER={host;Encrypt=no};" in cs
    assert "DATABASE={db}}x;y};" in cs
    assert "Encrypt=no;" not in cs.replace("{host;Encrypt=no}", "")
    for bad in ("", "a\nb"):
        with pytest.raises(ValueError):
            sql.build_connection_string(bad)


# ---- Values ----

def test_to_sql_row_types_ints_dates_and_nulls(tmp_path):
    path = write_nessus(tmp_path / "s.nessus", [basic_host(items=[report_item(
        "1234", port="445", children=[("plugin_publication_date", "2024/03/05"),
                                      ("vuln_publication_date", "")])],
        extra_tags=[("HOST_START_TIMESTAMP", "1712226191")])])
    (row,) = nc.parse_nessus_file(path)
    out = dict(zip(sql.SQL_COLUMN_NAMES, sql.to_sql_row(row)))
    assert out["pluginID"] == 1234 and out["port"] == 445 and out["severity_reversed"] == 2
    assert out["host_start_timestamp"] == 1712226191 and out["host_end_timestamp"] is None
    assert out["plugin_publication_date"] == date(2024, 3, 5)
    assert out["vuln_publication_date"] is None  # '' would otherwise become 1900-01-01
    assert out["scan_date"] == date(2024, 4, 4)
    assert out["file_path"] == "s.nessus"
    assert out["hostname"] == ""


# ---- Database flow ----

def test_prepare_table_existing_good_table():
    conn = FakeConn(tables=["t"], table_columns={"t": good_columns()})
    assert sql.prepare_table(conn, "t", create=False) == "existing"
    assert not any(q.lstrip().startswith("CREATE") for q, _ in conn.executed)


def test_prepare_table_rejects_an_unrelated_table():
    conn = FakeConn(tables=["other"], table_columns={"other": ["id", "name"]})
    with pytest.raises(ValueError, match="Missing columns"):
        sql.prepare_table(conn, "other", create=True)


def test_prepare_table_missing_without_create_flag():
    with pytest.raises(ValueError, match="--create-table"):
        sql.prepare_table(FakeConn(), "new_table", create=False)


def test_prepare_table_creates_a_new_table_and_its_index():
    conn = FakeConn()
    assert sql.prepare_table(conn, "new_table", create=True) == "created"
    statements = [q.lstrip() for q, _ in conn.executed if q.lstrip().startswith("CREATE")]
    assert statements[0].startswith("CREATE TABLE dbo.[new_table]")
    assert statements[1].startswith("CREATE UNIQUE INDEX")
    assert conn.commits == 1


def test_prepare_table_validates_a_new_name():
    with pytest.raises(ValueError):
        sql.prepare_table(FakeConn(), "bad name", create=True)


def test_import_rows_batches_in_one_transaction(tmp_path):
    path = write_nessus(tmp_path / "s.nessus", [basic_host(items=[report_item(str(i)) for i in range(5)])])
    rows = nc.parse_nessus_file(path)
    conn = FakeConn()
    assert sql.import_rows(conn, "t", rows, batch_size=2) == 5
    assert [n for _, n in conn.batches] == [2, 2, 1]
    assert conn.commits == 1 and conn.rollbacks == 0 and len(conn.inserted) == 5


def test_import_rows_rolls_back_on_error(tmp_path):
    path = write_nessus(tmp_path / "s.nessus", [basic_host(items=[report_item(str(i)) for i in range(5)])])
    rows = nc.parse_nessus_file(path)
    conn = FakeConn()
    conn.fail_on_insert_after = 3
    with pytest.raises(RuntimeError):
        sql.import_rows(conn, "t", rows, batch_size=2)
    assert conn.rollbacks == 1 and conn.commits == 0 and conn.inserted == []


# ---- main() ----

def folder_with_scans(tmp_path):
    folder = tmp_path / "scans"
    folder.mkdir()
    write_nessus(folder / "a.nessus", [
        basic_host("10.0.0.1", items=[report_item("1"), report_item("1")]),
        basic_host("10.0.0.2", items=[report_item("2")], start="garbage date")])
    (folder / "bad.nessus").write_text("<broken", encoding="utf-8")
    return folder


@pytest.fixture(autouse=True)
def no_gui(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("file picker was called")
    monkeypatch.setattr(nc, "pick_inputs_gui", boom)


def test_main_unattended_creates_table_and_imports(tmp_path, capsys):
    folder = folder_with_scans(tmp_path)
    conn = FakeConn()
    seen = {}

    def connect_fn(conn_str):
        seen.setdefault("conn_strs", []).append(conn_str)
        return conn

    code = sql.main(["--server", "srv", "--database", "scans", "--table", "findings",
                     "--create-table", str(folder)], connect_fn=connect_fn,
                    input_fn=lambda p: pytest.fail("should not prompt"))
    assert code == nc.EXIT_PARTIAL  # bad.nessus failed, the rest imported
    assert len(conn.inserted) == 2  # duplicate collapsed; the bad-date host is kept (audit M6)
    assert {r[sql.SQL_COLUMN_NAMES.index("host_ip")] for r in conn.inserted} == {"10.0.0.1", "10.0.0.2"}
    assert "TrustServerCertificate" not in seen["conn_strs"][0]
    assert conn.closed
    assert "bad.nessus" in capsys.readouterr().err


def test_main_trust_flag_reaches_the_connection_string(tmp_path):
    folder = folder_with_scans(tmp_path)
    strs = []
    conn = FakeConn(tables=["t"], table_columns={"t": good_columns()})
    sql.main(["--server", "s", "--database", "d", "--table", "t", "--trust-server-certificate",
              str(folder / "a.nessus")], connect_fn=lambda cs: strs.append(cs) or conn)
    assert "TrustServerCertificate=yes" in strs[0]


def test_main_interactive_menu_can_create_a_new_table(tmp_path):
    folder = folder_with_scans(tmp_path)
    conn = FakeConn(tables=["old_table"], table_columns={"old_table": ["id"]})
    answers = iter([
        "1", "y",            # database 'scans'
        "2", "y",            # "[Create a new table]" (after old_table)
        "bad name", "fresh_table",
    ])
    code = sql.main(["--server", "srv", str(folder / "a.nessus")],
                    connect_fn=lambda cs: conn, input_fn=lambda prompt: next(answers))
    assert code == nc.EXIT_OK
    assert "fresh_table" in conn.table_columns and len(conn.inserted) == 2


def test_main_existing_wrong_table_is_refused_with_nothing_inserted(tmp_path):
    folder = folder_with_scans(tmp_path)
    conn = FakeConn(tables=["other"], table_columns={"other": ["id"]})
    code = sql.main(["--server", "s", "--database", "d", "--table", "other", str(folder / "a.nessus")],
                    connect_fn=lambda cs: conn)
    assert code == nc.EXIT_FAILED and conn.inserted == [] and conn.closed


def test_main_missing_table_without_flag_fails_cleanly(tmp_path):
    folder = folder_with_scans(tmp_path)
    conn = FakeConn()
    code = sql.main(["--server", "s", "--database", "d", "--table", "nope", str(folder / "a.nessus")],
                    connect_fn=lambda cs: conn)
    assert code == nc.EXIT_FAILED and not conn.executed[-1][0].lstrip().startswith("CREATE")


def test_main_database_error_rolls_back_that_file(tmp_path, capsys):
    folder = folder_with_scans(tmp_path)
    conn = FakeConn(tables=["t"], table_columns={"t": good_columns()})
    conn.fail_on_insert_after = 0
    code = sql.main(["--server", "s", "--database", "d", "--table", "t", str(folder / "a.nessus")],
                    connect_fn=lambda cs: conn)
    assert code == nc.EXIT_FAILED and conn.inserted == [] and conn.rollbacks >= 1
    assert "rolled back" in capsys.readouterr().err


def test_main_connection_error_mentions_the_certificate_flag(tmp_path, capsys):
    folder = folder_with_scans(tmp_path)

    def connect_fn(cs):
        raise RuntimeError("SSL Provider: certificate verify failed")

    code = sql.main(["--server", "s", "--database", "d", "--table", "t", str(folder / "a.nessus")],
                    connect_fn=connect_fn)
    assert code == nc.EXIT_FAILED
    assert "--trust-server-certificate" in capsys.readouterr().err


def test_main_dry_run_never_connects_and_prints_sql(tmp_path, capsys):
    folder = folder_with_scans(tmp_path)

    def connect_fn(cs):
        raise AssertionError("dry run must not connect")

    code = sql.main(["--dry-run", "--table", "dry", str(folder)], connect_fn=connect_fn)
    out = capsys.readouterr().out
    assert code == nc.EXIT_PARTIAL
    assert "CREATE TABLE dbo.[dry]" in out and "INSERT INTO dbo.[dry]" in out
    assert "2 rows would be inserted" in out


def test_main_no_server_and_no_input_is_a_clean_error(tmp_path):
    folder = folder_with_scans(tmp_path)

    def eof(prompt):
        raise EOFError

    assert sql.main([str(folder / "a.nessus")], connect_fn=lambda cs: FakeConn(), input_fn=eof) == nc.EXIT_FAILED
