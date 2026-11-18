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
        elif "CHARACTER_MAXIMUM_LENGTH" in query:
            lengths = self.conn.column_lengths.get(params[0], {})
            self._rows = [(c, lengths.get(c, -1)) for c in self.conn.table_columns.get(params[0], [])]
        elif "INFORMATION_SCHEMA.COLUMNS" in query:
            self._rows = [(c,) for c in self.conn.table_columns.get(params[0], [])]
        elif query.lstrip().startswith("CREATE TABLE"):
            name = re.match(r"CREATE TABLE dbo\.\[(.+?)\]", query.lstrip()).group(1)
            is_log = name.endswith("_import_log")
            self.conn.table_columns[name] = list(sql.LOG_COLUMN_NAMES if is_log else sql.SQL_COLUMN_NAMES)
            self.conn.tables.append(name)
        elif "_import_log]" in query and query.lstrip().startswith("SELECT COUNT"):
            sha, name = params
            self._rows = [(1 if (sha, name) in self.conn.log_keys else 0,)]
        elif "_import_log]" in query and query.lstrip().startswith("INSERT"):
            name, sha, count = params
            if (sha, name) in self.conn.log_keys or (sha, name) in self.conn.pending_log:
                raise RuntimeError("Violation of PRIMARY KEY constraint")
            self.conn.pending_log.append((sha, name))
            self.conn.log_counts[(sha, name)] = count

    def executemany(self, query, batch):
        if self.conn.fail_on_insert_after is not None and \
                len(self.conn.inserted) + len(self.conn.pending) + len(batch) > self.conn.fail_on_insert_after:
            raise RuntimeError("String or binary data would be truncated")
        self.conn.batches.append((query, len(batch)))
        self.conn.pending.extend(batch)

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0]

    def close(self):
        pass


class FakeConn:
    def __init__(self, databases=("scans",), tables=(), table_columns=None):
        self.databases = list(databases)
        self.tables = list(tables)
        self.table_columns = dict(table_columns or {})
        self.executed, self.batches = [], []
        self.pending, self.inserted = [], []
        self.pending_log, self.log_keys, self.log_counts = [], set(), {}
        self.column_lengths = {}
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
        self.log_keys.update(self.pending_log)
        self.pending_log = []

    def rollback(self):
        self.rollbacks += 1
        self.pending = []
        self.pending_log = []

    def close(self):
        self.closed = True


def good_columns():
    return list(sql.SQL_COLUMN_NAMES)


# ---- SQL text ----

def test_create_table_has_106_columns_in_order_and_matches_the_insert():
    create = sql.build_create_table_sql("nessus_findings")
    names = re.findall(r"^\s{4}(\w+) [A-Z]+", create, re.M)
    assert len(names) == 106
    insert = sql.build_insert_sql("nessus_findings")
    cols = re.search(r"\(([^)]*)\) VALUES", insert).group(1).split(", ")
    assert names == cols
    assert insert.count("?") == 106
    # CSV column file_name is the SQL column file_path.
    assert cols[-2:] == ["file_path", "scan_date"] and "file_name" not in cols
    assert cols == [("file_path" if c == "file_name" else c) for c in nc.COLUMN_NAMES]


def test_findings_table_has_no_key_that_could_drop_a_finding():
    """Audit review B1: a unique index on 6 columns merged distinct findings."""
    create = sql.build_create_table_sql("my_scans")
    assert create.startswith("CREATE TABLE dbo.[my_scans] (")
    for word in ("UNIQUE", "PRIMARY KEY", "IGNORE_DUP_KEY", "INDEX", "IF NOT EXISTS"):
        assert word not in create
    assert not hasattr(sql, "UNIQUE_KEY_COLUMNS")


def test_import_log_table_is_keyed_on_sha256_and_name():
    ddl = sql.build_create_log_table_sql("my_scans")
    assert ddl.startswith("CREATE TABLE dbo.[my_scans_import_log] (")
    assert "PRIMARY KEY (file_sha256, file_name)" in ddl
    assert "file_sha256 CHAR(64) NOT NULL" in ddl
    assert re.findall(r"^\s{4}(\w+) ", ddl, re.M)[:4] == sql.LOG_COLUMN_NAMES


def test_column_types_avoid_the_truncation_traps():
    types = dict(sql.SQL_COLUMNS)
    for wide in ("synopsis", "cve", "cwe", "bid", "pluginName", "plugin_output", "hostname",
                 "operating_system", "system_type", "see_also", "description"):
        assert types[wide] == "NVARCHAR(MAX)", wide
    assert not any(t.startswith("VARCHAR") for t in types.values())
    assert types["port"] == "INT" and types["host_start_timestamp"] == "BIGINT"
    assert types["scan_date"] == "DATE"
    # Every multi-value column must be able to hold a long joined list.
    for c in sql.MULTI_VALUE_COLUMNS:
        assert types[sql.sql_column_name(c)] == "NVARCHAR(MAX)", c
    assert "cwe" in sql.MULTI_VALUE_COLUMNS and "mskb" in sql.MULTI_VALUE_COLUMNS


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


def test_prepare_table_creates_a_new_table_without_an_index():
    conn = FakeConn()
    assert sql.prepare_table(conn, "new_table", create=True) == "created"
    statements = [q.lstrip() for q, _ in conn.executed if q.lstrip().startswith("CREATE")]
    assert len(statements) == 1 and statements[0].startswith("CREATE TABLE dbo.[new_table]")
    assert conn.commits == 1


def test_ensure_log_table_creates_once_and_rejects_a_lookalike():
    conn = FakeConn()
    sql.ensure_log_table(conn, "t")
    sql.ensure_log_table(conn, "t")
    creates = [q for q, _ in conn.executed if q.lstrip().startswith("CREATE")]
    assert len(creates) == 1 and "[t_import_log]" in creates[0]
    other = FakeConn(tables=["t_import_log"], table_columns={"t_import_log": ["id"]})
    with pytest.raises(ValueError, match="not an import log"):
        sql.ensure_log_table(other, "t")


def test_narrow_multi_value_columns_are_found_and_the_alter_text_is_built():
    cols = good_columns()
    conn = FakeConn(tables=["old"], table_columns={"old": cols})
    conn.column_lengths["old"] = {"cwe": 150, "bid": 150, "cve": 4000, "mskb": -1}
    narrow = sql.narrow_multi_value_columns(conn, "old")
    assert set(narrow) >= {"cwe", "bid", "cve"} and "mskb" not in narrow
    alter = sql.alter_multi_value_columns_sql("old", ["cwe"])
    assert alter == "ALTER TABLE dbo.[old] ALTER COLUMN cwe NVARCHAR(MAX) NULL;"


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


# ---- Findings that look alike must all land (review B1) ----

def compliance_folder(tmp_path):
    """Three compliance ReportItems under one plugin on one host, differing only in the text,
    plus a host with no host-ip tag whose two items also differ only in the text."""
    from helpers import report_host
    items = [report_item("21156", "Windows Compliance Checks", sev, port="0",
                         children=[("description", f'"1.1.{n} check" : [{res}]')])
             for n, sev, res in ((1, 3, "FAILED"), (2, 1, "PASSED"), (3, 3, "FAILED"))]
    no_ip = [report_item("21156", "Windows Compliance Checks", 3, port="0",
                         children=[("description", f"no ip check {n}")]) for n in (1, 2)]
    folder = tmp_path / "compliance"
    folder.mkdir()
    write_nessus(folder / "compliance.nessus", [
        basic_host("10.0.0.5", items=items),
        report_host("noip-host", [("HOST_START", "Thu Apr  4 10:23:11 2024")], no_ip)])
    return folder


def run_import(folder, conn, *extra):
    return sql.main(["--server", "s", "--database", "d", "--table", "findings", "--create-table",
                     *extra, str(folder)], connect_fn=lambda cs: conn,
                    input_fn=lambda p: pytest.fail("should not prompt"))


def test_all_compliance_findings_land_and_the_message_counts_rows_that_landed(tmp_path, capsys):
    conn = FakeConn()
    assert run_import(compliance_folder(tmp_path), conn) == nc.EXIT_OK
    assert len(conn.inserted) == 5
    descriptions = [r[sql.SQL_COLUMN_NAMES.index("description")] for r in conn.inserted]
    assert len(set(descriptions)) == 5
    out = capsys.readouterr().out
    assert "5 rows inserted" in out and "1 file(s) imported" in out


def test_importing_the_same_folder_twice_adds_nothing(tmp_path, capsys):
    folder = compliance_folder(tmp_path)
    conn = FakeConn()
    assert run_import(folder, conn) == nc.EXIT_OK
    capsys.readouterr()
    assert run_import(folder, conn) == nc.EXIT_OK
    assert len(conn.inserted) == 5
    out = capsys.readouterr().out
    assert "already imported" in out and "0 file(s) imported, 1 skipped" in out and "0 rows inserted" in out


def test_a_changed_file_with_the_same_name_is_imported_again(tmp_path):
    folder = compliance_folder(tmp_path)
    conn = FakeConn()
    run_import(folder, conn)
    write_nessus(folder / "compliance.nessus", [basic_host("10.0.0.9", items=[report_item("1")])])
    assert run_import(folder, conn) == nc.EXIT_OK
    assert len(conn.inserted) == 6
    assert len(conn.log_keys) == 2


def test_same_content_under_another_name_is_a_separate_import(tmp_path):
    folder = compliance_folder(tmp_path)
    (folder / "copy.nessus").write_bytes((folder / "compliance.nessus").read_bytes())
    conn = FakeConn()
    assert run_import(folder, conn) == nc.EXIT_OK
    assert len(conn.inserted) == 10  # file_path differs, so these are different rows


def test_a_failed_import_is_not_logged_so_a_rerun_retries_it(tmp_path):
    folder = compliance_folder(tmp_path)
    conn = FakeConn()
    conn.fail_on_insert_after = 0
    assert run_import(folder, conn) == nc.EXIT_FAILED
    assert conn.inserted == [] and conn.log_keys == set()
    conn.fail_on_insert_after = None
    assert run_import(folder, conn) == nc.EXIT_OK
    assert len(conn.inserted) == 5


def test_a_failing_log_write_rolls_the_rows_back_too(tmp_path):
    folder = compliance_folder(tmp_path)
    conn = FakeConn()
    # Make the log INSERT fail; the findings batch before it must not stay.
    conn.fail_on = "INSERT INTO dbo.[findings_import_log]"
    assert run_import(folder, conn) == nc.EXIT_FAILED
    assert conn.inserted == [] and conn.rollbacks >= 1


def test_main_warns_about_narrow_columns_in_an_old_table(tmp_path, capsys):
    folder = compliance_folder(tmp_path)
    conn = FakeConn(tables=["findings"], table_columns={"findings": good_columns()})
    conn.column_lengths["findings"] = {"cwe": 150, "mskb": 150}
    code = sql.main(["--server", "s", "--database", "d", "--table", "findings", str(folder)],
                    connect_fn=lambda cs: conn)
    assert code == nc.EXIT_OK
    err = capsys.readouterr().err
    assert "ALTER TABLE dbo.[findings] ALTER COLUMN cwe NVARCHAR(MAX) NULL;" in err
    assert "String or binary data would be truncated" in err


def test_dry_run_shows_the_import_log_sql(tmp_path, capsys):
    folder = compliance_folder(tmp_path)
    assert sql.main(["--dry-run", "--table", "dry", str(folder)]) == nc.EXIT_OK
    out = capsys.readouterr().out
    assert "CREATE TABLE dbo.[dry_import_log]" in out and "5 rows would be inserted" in out
