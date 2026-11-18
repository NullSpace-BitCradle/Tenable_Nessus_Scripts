import pytest

import nessus_common as nc
from helpers import basic_host, report_host, report_item, write_nessus


def col(row, name):
    return row[nc.COLUMN_NAMES.index(name)]


def test_there_are_106_unique_columns_and_headers():
    assert len(nc.COLUMN_NAMES) == 106
    assert len(set(nc.COLUMN_NAMES)) == 106
    assert len(nc.XLSX_HEADERS) == 106
    assert nc.COLUMN_NAMES[0] == "host_ip" and nc.COLUMN_NAMES[-2:] == ["file_name", "scan_date"]


def test_every_row_is_106_wide(tmp_path):
    path = write_nessus(tmp_path / "a.nessus", [basic_host(items=[report_item()])])
    rows = nc.parse_nessus_file(path)
    assert [len(r) for r in rows] == [106]


def test_repeated_reference_elements_are_all_kept(tmp_path):
    """Audit M2: only the first CWE/BID/... used to survive."""
    item = report_item(children=[
        ("cwe", "CWE-79"), ("cwe", "CWE-89"),
        ("bid", "111"), ("bid", "222"),
        ("cve", "CVE-2024-0001"), ("cve", "CVE-2024-0002"),
        ("edb-id", "5"), ("edb-id", "6"),
        ("cert", "A"), ("cert", "B"),
        ("msft", "MS1"), ("msft", "MS2"),
        ("mskb", "KB1"), ("mskb", "KB2"),
    ])
    path = write_nessus(tmp_path / "a.nessus", [basic_host(items=[item])])
    (row,) = nc.parse_nessus_file(path)
    assert col(row, "cwe") == "CWE-79, CWE-89"
    assert col(row, "bid") == "111, 222"
    assert col(row, "cve") == "CVE-2024-0001, CVE-2024-0002"
    assert col(row, "edb_id") == "5, 6"
    assert col(row, "cert") == "A, B"
    assert col(row, "msft") == "MS1, MS2"
    assert col(row, "mskb") == "KB1, KB2"


def test_empty_cve_element_does_not_crash(tmp_path):
    """Audit M3: <cve/> raised TypeError and lost the whole run."""
    item = report_item(children=[("cve", None), ("cve", "CVE-2024-1"), ("cwe", None)])
    path = write_nessus(tmp_path / "a.nessus", [basic_host(items=[item])])
    (row,) = nc.parse_nessus_file(path)
    assert col(row, "cve") == "CVE-2024-1"
    assert col(row, "cwe") == ""


def test_bad_host_start_keeps_the_host_with_no_scan_date(tmp_path):
    """Audit M6: the SQL path used to drop the host's findings."""
    hosts = [
        basic_host("10.0.0.1", items=[report_item("1")]),
        basic_host("10.0.0.2", items=[report_item("2"), report_item("3")], start="garbage date"),
    ]
    path = write_nessus(tmp_path / "a.nessus", hosts)
    rows = nc.parse_nessus_file(path)
    assert len(rows) == 3
    assert col(rows[0], "scan_date") == "2024-04-04"
    assert col(rows[1], "scan_date") is None and col(rows[1], "host_ip") == "10.0.0.2"
    assert col(rows[1], "host_start") == "garbage date"


def test_multiple_hosts_are_counted_and_keep_their_own_tags(tmp_path):
    hosts = [
        basic_host("10.0.0.1", items=[report_item("1")], extra_tags=[("hostname", "alpha")]),
        basic_host("10.0.0.2", items=[report_item("1")], extra_tags=[("hostname", "beta")]),
        report_host("10.0.0.3", [("host-ip", "10.0.0.3")], []),  # no findings
    ]
    path = write_nessus(tmp_path / "a.nessus", hosts)
    stats = nc.RunStats()
    rows = nc.parse_nessus_file(path, stats)
    assert stats.hosts == 3 and stats.findings == 2
    assert [col(r, "hostname") for r in rows] == ["alpha", "beta"]


def test_severity_mapping_and_plugin_output_is_stripped(tmp_path):
    items = [
        report_item("1", severity=0),
        report_item("2", severity=4, children=[("plugin_output", "  out \n")]),
    ]
    path = write_nessus(tmp_path / "a.nessus", [basic_host(items=items)])
    rows = nc.parse_nessus_file(path)
    assert (col(rows[0], "severity_rating"), col(rows[0], "severity_reversed")) == ("Informational", 4)
    assert (col(rows[1], "severity_rating"), col(rows[1], "severity_reversed")) == ("Critical", 0)
    assert col(rows[1], "plugin_output") == "out"


def test_invalid_severity_is_a_parse_error(tmp_path):
    path = write_nessus(tmp_path / "a.nessus", [basic_host(items=[report_item(severity="x")])])
    with pytest.raises(nc.NessusParseError):
        nc.parse_nessus_file(path)


def test_first_host_tag_wins_and_item_cpe_is_used(tmp_path):
    host = basic_host(items=[report_item(children=[("cpe", "cpe:/a:item")])],
                      extra_tags=[("cpe", "cpe:/o:host"), ("cpe", "cpe:/o:second")])
    path = write_nessus(tmp_path / "a.nessus", [host])
    (row,) = nc.parse_nessus_file(path)
    assert col(row, "cpe") == "cpe:/a:item"


def test_malformed_xml_raises_parse_error(tmp_path):
    bad = tmp_path / "bad.nessus"
    bad.write_text("<NessusClientData_v2><Report>", encoding="utf-8")
    with pytest.raises(nc.NessusParseError):
        nc.parse_nessus_file(str(bad))


def test_external_entity_is_not_resolved(tmp_path):
    secret = tmp_path / "marker.txt"
    secret.write_text("MARKER-TEXT", encoding="utf-8")
    xml = (f'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "{secret.as_uri()}">]>'
           '<NessusClientData_v2><Report><ReportHost name="h"><HostProperties>'
           '<tag name="hostname">&e;</tag></HostProperties>'
           '<ReportItem port="0" svc_name="g" protocol="tcp" severity="0" pluginID="1" '
           'pluginName="n" pluginFamily="f"/></ReportHost></Report></NessusClientData_v2>')
    bad = tmp_path / "xxe.nessus"
    bad.write_text(xml, encoding="utf-8")
    try:
        rows = nc.parse_nessus_file(str(bad))
    except nc.NessusParseError:
        return
    assert "MARKER-TEXT" not in "".join(str(v) for r in rows for v in r)


def test_missing_file_is_a_parse_error(tmp_path):
    with pytest.raises(nc.NessusParseError):
        nc.parse_nessus_file(str(tmp_path / "nope.nessus"))


def test_dedupe_keeps_first_seen_order_and_counts(tmp_path):
    items = [report_item(str(i)) for i in (3000, 1000, 2000, 1000, 3000, 4000)]
    path = write_nessus(tmp_path / "a.nessus", [basic_host(items=items)])
    stats = nc.RunStats()
    rows = list(nc.iter_unique_rows([path], stats))
    assert [col(r, "pluginID") for r in rows] == ["3000", "1000", "2000", "4000"]
    assert stats.duplicates == 2


def test_same_finding_in_two_differently_named_files_is_kept(tmp_path):
    a = write_nessus(tmp_path / "a.nessus", [basic_host(items=[report_item("1")])])
    b = write_nessus(tmp_path / "b.nessus", [basic_host(items=[report_item("1")])])
    stats = nc.RunStats()
    assert len(list(nc.iter_unique_rows([a, b], stats))) == 2
    assert stats.duplicates == 0


def test_failed_file_is_recorded_and_others_continue(tmp_path):
    good = write_nessus(tmp_path / "good.nessus", [basic_host(items=[report_item()])])
    bad = tmp_path / "bad.nessus"
    bad.write_text("<oops", encoding="utf-8")
    stats = nc.RunStats()
    rows = list(nc.iter_unique_rows([str(bad), good], stats))
    assert len(rows) == 1
    assert stats.files_seen == 2 and stats.files_ok == 1
    assert [p for p, _ in stats.failures] == [str(bad)]


def test_collect_nessus_files_walks_folders_in_sorted_order(tmp_path):
    (tmp_path / "sub").mkdir()
    for rel in ("b.nessus", "a.NESSUS", "sub/c.nessus", "note.txt"):
        (tmp_path / rel).write_text("x")
    files = nc.collect_nessus_files([str(tmp_path)])
    assert [f.replace("\\", "/").split("/")[-1] for f in files] == ["a.NESSUS", "b.nessus", "c.nessus"]


def test_collect_nessus_files_rejects_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        nc.collect_nessus_files([str(tmp_path / "missing")])


@pytest.mark.parametrize("value", ["=1+1", "@SUM(1+1)", "-2+3+cmd", "+cmd|' /C calc'!A0", "\tx", "\rx"])
def test_formula_cells_are_neutralised(value):
    assert nc.neutralize_cell(value) == "'" + value


@pytest.mark.parametrize("value", ["plain", "", "-5", "+3.5", "2024-04-04", None, 7, "a=b"])
def test_other_cells_are_left_alone(value):
    assert nc.neutralize_cell(value) == value
