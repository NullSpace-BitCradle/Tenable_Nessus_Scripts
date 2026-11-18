"""
Nessus to Excel (XLSX) Conversion Script

Converts .nessus (XML) vulnerability scan files into a formatted Excel workbook
with one table of 106 columns per finding: host information, vulnerability
details, CVSS scores, CVE IDs, exploit information and security references.

Usage:
    python nessus_to_xlsx.py [-o OUTPUT.xlsx] PATH [PATH ...]

Each PATH is a .nessus file or a folder (searched recursively). With no PATH the
script falls back to file pickers, which need a desktop session.

Things to know:
- Repeated reference elements (CWE, BID, MSKB, ...) are all kept, joined with ", "
- Exact duplicate findings are removed and the original row order is kept
- Excel cells hold at most 32,767 characters. A longer value is cut and ends with
  a "[truncated ...]" note, and the script prints how many cells were cut. Use
  nessus_to_csv.py if you need the full text.
- A sheet holds at most 1,048,576 rows. Larger inputs stop with an error; split
  the input or use the CSV script.
- Cells that start with = + - @ are stored as text, never as formulas
- Exit code 0 on success, 1 if nothing could be converted, 2 if some files failed
"""

import argparse
import os
import sys
import time

from openpyxl import Workbook
from openpyxl.worksheet.table import Table, TableStyleInfo

import nessus_common as nc

DEFAULT_OUTPUT = "nessus_conversion.xlsx"


class TooManyRowsError(Exception):
    """The input has more findings than one Excel sheet can hold."""


def fit_cell(value):
    """
    Return (value, was_truncated) for a cell value that must fit Excel's limit.

    Text over 32,767 characters is cut so that the result, including a short
    note saying how long the original was, is exactly at the limit. openpyxl
    would otherwise cut it with no sign.
    """
    if isinstance(value, str) and len(value) > nc.XLSX_MAX_CELL:
        note = f" [truncated, original was {len(value)} characters]"
        return value[:nc.XLSX_MAX_CELL - len(note)] + note, True
    return value, False


def prepare_cell(value):
    """Neutralise formulas, then fit the Excel size limit. Returns (value, truncated)."""
    if value is None:
        return None, False
    return fit_cell(nc.neutralize_cell(value))


def build_workbook(files, stats):
    """Read `files` into a new Workbook. Returns (workbook, rows_written, cells_truncated)."""
    wb = Workbook()
    ws = wb.active
    assert ws is not None  # a new Workbook always has an active worksheet
    ws.append(nc.XLSX_HEADERS)
    rows_written = 0
    truncated_cells = 0
    for row in nc.iter_unique_rows(files, stats):
        if rows_written + 1 >= nc.XLSX_MAX_ROWS:
            raise TooManyRowsError(
                f"More than {nc.XLSX_MAX_ROWS - 1} findings do not fit on one Excel sheet. "
                "Split the input or use nessus_to_csv.py.")
        out_row = []
        for value in row:
            cell, cut = prepare_cell(value)
            truncated_cells += cut
            out_row.append(cell)
        ws.append(out_row)
        rows_written += 1
        if rows_written % 1000 == 0:
            print(f"\rRead {rows_written} rows...", end="", flush=True)

    if rows_written:
        table_range = f"A1:{ws.cell(row=ws.max_row, column=ws.max_column).coordinate}"
        table = Table(displayName="Table1", ref=table_range)
        table.tableStyleInfo = TableStyleInfo(
            name="TableStyleMedium2", showFirstColumn=False, showLastColumn=False,
            showRowStripes=True, showColumnStripes=False)
        ws.add_table(table)
    return wb, rows_written, truncated_cells


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Convert .nessus files to Excel.")
    parser.add_argument("paths", nargs="*", help=".nessus files or folders (recursive)")
    parser.add_argument("-o", "--output", help=f"output XLSX path (default: {DEFAULT_OUTPUT})")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    start_time = time.time()

    paths = args.paths
    if not paths:
        paths = nc.pick_inputs_gui()
        if not paths:
            print("No files or folder selected. Exiting.")
            return nc.EXIT_FAILED
    try:
        files = nc.collect_nessus_files(paths)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return nc.EXIT_FAILED
    if not files:
        print("No .nessus files found. Exiting.", file=sys.stderr)
        return nc.EXIT_FAILED

    output_path = args.output
    if not output_path:
        if args.paths:
            output_path = DEFAULT_OUTPUT
        else:
            output_path = nc.pick_output_gui(DEFAULT_OUTPUT, ".xlsx")
            if not output_path:
                print("No output file selected. Exiting.")
                return nc.EXIT_FAILED

    stats = nc.RunStats()
    try:
        wb, rows_written, truncated = build_workbook(files, stats)
    except TooManyRowsError as exc:
        print(f"\n{exc}", file=sys.stderr)
        return nc.EXIT_FAILED
    print()
    failed = nc.report_failures(stats)
    if stats.files_ok == 0:
        print("No file could be read. No workbook was written.", file=sys.stderr)
        return nc.EXIT_FAILED

    if stats.duplicates:
        print(f"Removed {stats.duplicates} duplicate rows from the data.")
    else:
        print("No duplicate rows found.")
    if truncated:
        print(f"WARNING: {truncated} cell(s) were longer than Excel's 32,767 character limit "
              "and were cut. Use nessus_to_csv.py for the full text.", file=sys.stderr)

    print(f"Processed {stats.files_ok} of {stats.files_seen} files, {stats.hosts} hosts, "
          f"and {rows_written} findings.\nNow writing to XLSX: {output_path}.")
    tmp_path = output_path + ".tmp"
    try:
        wb.save(tmp_path)
        os.replace(tmp_path, output_path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise
    print(nc.format_run_metrics(start_time))
    return nc.EXIT_PARTIAL if failed else nc.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
