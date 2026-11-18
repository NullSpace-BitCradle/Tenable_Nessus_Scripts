"""End-to-end runs of the CSV and XLSX scripts through their command-line interface (no GUI)."""

import csv

import pytest
from openpyxl import load_workbook

import nessus_common as nc
import nessus_to_csv
import nessus_to_xlsx
from helpers import basic_host, report_item, write_nessus


@pytest.fixture(autouse=True)
def no_gui(monkeypatch):
    """If a script reaches for a picker while paths were given, fail the test."""
    def boom(*a, **k):
        raise AssertionError("file picker was called")
    monkeypatch.setattr(nc, "pick_inputs_gui", boom)
    monkeypatch.setattr(nc, "pick_output_gui", boom)


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.reader(f))


def synthetic_scan(tmp_path):
    items_a = [
        report_item("1000", "=1+1", 2, children=[
            ("plugin_output", "@SUM(1+1)"), ("cwe", "CWE-79"), ("cwe", "CWE-89"),
            ("bid", "111"), ("bid", "222"), ("cve", None)]),
        report_item("2000", "Second", 4, children=[("plugin_output", "-2+3+cmd")]),
        report_item("2000", "Second", 4, children=[("plugin_output", "-2+3+cmd")]),  # exact duplicate
        report_item("3000", "Unicode", 1, children=[("plugin_output", "café привет")]),
    ]
    hosts = [
        basic_host("10.0.0.1", items=items_a),
        basic_host("10.0.0.2", items=[report_item("4000", "Other host")], start="garbage date"),
    ]
    return write_nessus(tmp_path / "scan.nessus", hosts)


def test_csv_end_to_end(tmp_path, capsys):
    scan = synthetic_scan(tmp_path)
    out = tmp_path / "out.csv"
    assert nessus_to_csv.main(["-o", str(out), scan]) == nc.EXIT_OK

    raw = out.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf"), "CSV should carry a UTF-8 BOM so Excel reads it"
    rows = read_csv(out)
    assert rows[0] == nc.COLUMN_NAMES
    assert all(len(r) == 106 for r in rows)
    body = rows[1:]
    assert len(body) == 4  # 5 items - 1 duplicate
    idx = nc.COLUMN_NAMES.index
    first = body[0]
    assert first[idx("pluginName")] == "'=1+1"
    assert first[idx("plugin_output")] == "'@SUM(1+1)"
    assert first[idx("cwe")] == "CWE-79, CWE-89"
    assert first[idx("bid")] == "111, 222"
    assert body[1][idx("plugin_output")] == "'-2+3+cmd"
    assert body[2][idx("plugin_output")] == "café привет"
    assert body[3][idx("host_ip")] == "10.0.0.2" and body[3][idx("scan_date")] == ""
    out_text = capsys.readouterr().out
    assert "Removed 1 duplicate rows" in out_text
    assert "Peak CPU" not in out_text


def test_csv_row_order_is_stable_across_runs(tmp_path):
    scan = synthetic_scan(tmp_path)
    a, b = tmp_path / "a.csv", tmp_path / "b.csv"
    nessus_to_csv.main(["-o", str(a), scan])
    nessus_to_csv.main(["-o", str(b), scan])
    assert a.read_bytes() == b.read_bytes()


def test_csv_accepts_a_folder_and_defaults_output_name(tmp_path, monkeypatch):
    folder = tmp_path / "scans"
    (folder / "nested").mkdir(parents=True)
    write_nessus(folder / "one.nessus", [basic_host(items=[report_item("1")])])
    write_nessus(folder / "nested" / "two.nessus", [basic_host("10.0.0.9", items=[report_item("2")])])
    monkeypatch.chdir(tmp_path)
    assert nessus_to_csv.main([str(folder)]) == nc.EXIT_OK
    assert len(read_csv(tmp_path / "nessus_conversion.csv")) == 3  # header + 2


def test_csv_failed_file_gives_nonzero_exit_but_keeps_good_data(tmp_path):
    good = write_nessus(tmp_path / "good.nessus", [basic_host(items=[report_item()])])
    bad = tmp_path / "bad.nessus"
    bad.write_text("<NessusClientData_v2>", encoding="utf-8")
    out = tmp_path / "out.csv"
    assert nessus_to_csv.main(["-o", str(out), str(bad), good]) == nc.EXIT_PARTIAL
    assert len(read_csv(out)) == 2


def test_csv_all_files_failed_is_an_error_and_writes_nothing(tmp_path):
    bad = tmp_path / "bad.nessus"
    bad.write_text("not xml", encoding="utf-8")
    out = tmp_path / "out.csv"
    out.write_text("previous good output", encoding="utf-8")
    assert nessus_to_csv.main(["-o", str(out), str(bad)]) == nc.EXIT_FAILED
    assert out.read_text(encoding="utf-8") == "previous good output"
    assert not (tmp_path / "out.csv.tmp").exists()


def test_csv_missing_path_and_empty_folder_are_errors(tmp_path):
    assert nessus_to_csv.main([str(tmp_path / "nope.nessus")]) == nc.EXIT_FAILED
    empty = tmp_path / "empty"
    empty.mkdir()
    assert nessus_to_csv.main([str(empty)]) == nc.EXIT_FAILED


def test_csv_gui_fallback_cancel_is_clean(monkeypatch):
    monkeypatch.setattr(nc, "pick_inputs_gui", lambda *a, **k: [])
    assert nessus_to_csv.main([]) == nc.EXIT_FAILED


def test_csv_gui_fallback_is_used_only_without_paths(tmp_path, monkeypatch):
    scan = write_nessus(tmp_path / "s.nessus", [basic_host(items=[report_item()])])
    out = tmp_path / "picked.csv"
    monkeypatch.setattr(nc, "pick_inputs_gui", lambda *a, **k: [scan])
    monkeypatch.setattr(nc, "pick_output_gui", lambda *a, **k: str(out))
    assert nessus_to_csv.main([]) == nc.EXIT_OK
    assert len(read_csv(out)) == 2


# ---- XLSX ----

def test_xlsx_end_to_end(tmp_path):
    scan = synthetic_scan(tmp_path)
    out = tmp_path / "out.xlsx"
    assert nessus_to_xlsx.main(["-o", str(out), scan]) == nc.EXIT_OK
    ws = load_workbook(out).active
    assert [c.value for c in ws[1]] == nc.XLSX_HEADERS
    assert ws.max_row == 5 and ws.max_column == 106
    assert len(ws.tables) == 1
    idx = nc.COLUMN_NAMES.index
    first = [c for c in ws[2]]
    # A formula-looking value must be stored as a string, not a formula (audit M1).
    for name, expected in (("pluginName", "'=1+1"), ("plugin_output", "'@SUM(1+1)")):
        cell = first[idx(name)]
        assert cell.data_type == "s" and cell.value == expected
    assert first[idx("cwe")].value == "CWE-79, CWE-89"
    assert ws.cell(row=5, column=idx("scan_date") + 1).value in (None, "")


def test_xlsx_long_cell_is_cut_with_a_note_and_a_warning(tmp_path, capsys):
    long_text = "x" * 40_000
    scan = write_nessus(tmp_path / "s.nessus", [basic_host(items=[
        report_item("1", children=[("plugin_output", long_text)]),
        report_item("2", children=[("plugin_output", "y" * nc.XLSX_MAX_CELL)])])])
    out = tmp_path / "out.xlsx"
    assert nessus_to_xlsx.main(["-o", str(out), scan]) == nc.EXIT_OK
    ws = load_workbook(out).active
    col = nc.COLUMN_NAMES.index("plugin_output") + 1
    cut = ws.cell(row=2, column=col).value
    assert len(cut) == nc.XLSX_MAX_CELL
    assert cut.endswith("[truncated, original was 40000 characters]")
    # A value that exactly fits is left whole.
    assert ws.cell(row=3, column=col).value == "y" * nc.XLSX_MAX_CELL
    captured = capsys.readouterr()
    assert "1 cell(s)" in captured.err


def test_fit_cell_boundaries():
    assert nessus_to_xlsx.fit_cell("a" * nc.XLSX_MAX_CELL) == ("a" * nc.XLSX_MAX_CELL, False)
    value, cut = nessus_to_xlsx.fit_cell("a" * (nc.XLSX_MAX_CELL + 1))
    assert cut and len(value) == nc.XLSX_MAX_CELL
    assert nessus_to_xlsx.fit_cell(5) == (5, False)


def test_xlsx_counts_hosts_across_files(tmp_path, capsys):
    a = write_nessus(tmp_path / "a.nessus", [basic_host("10.0.0.1", items=[report_item("1")]),
                                             basic_host("10.0.0.2", items=[report_item("1")])])
    b = write_nessus(tmp_path / "b.nessus", [basic_host("10.0.0.3", items=[report_item("1")])])
    out = tmp_path / "out.xlsx"
    assert nessus_to_xlsx.main(["-o", str(out), a, b]) == nc.EXIT_OK
    assert "3 hosts" in capsys.readouterr().out


def test_xlsx_no_findings_still_makes_a_valid_file(tmp_path):
    scan = write_nessus(tmp_path / "s.nessus", [basic_host(items=[])])
    out = tmp_path / "out.xlsx"
    assert nessus_to_xlsx.main(["-o", str(out), scan]) == nc.EXIT_OK
    ws = load_workbook(out).active
    assert ws.max_row == 1 and len(ws.tables) == 0


def test_xlsx_failure_modes_exit_nonzero(tmp_path):
    bad = tmp_path / "bad.nessus"
    bad.write_text("nope", encoding="utf-8")
    out = tmp_path / "out.xlsx"
    assert nessus_to_xlsx.main(["-o", str(out), str(bad)]) == nc.EXIT_FAILED
    assert not out.exists()
    assert nessus_to_xlsx.main(["-o", str(out), str(tmp_path / "missing.nessus")]) == nc.EXIT_FAILED


def test_xlsx_gui_fallback_cancel_is_clean(monkeypatch):
    monkeypatch.setattr(nc, "pick_inputs_gui", lambda *a, **k: [])
    assert nessus_to_xlsx.main([]) == nc.EXIT_FAILED


def test_xlsx_cancelled_save_dialog_is_clean(tmp_path, monkeypatch):
    scan = write_nessus(tmp_path / "s.nessus", [basic_host(items=[report_item()])])
    monkeypatch.setattr(nc, "pick_inputs_gui", lambda *a, **k: [scan])
    monkeypatch.setattr(nc, "pick_output_gui", lambda *a, **k: "")
    assert nessus_to_xlsx.main([]) == nc.EXIT_FAILED
