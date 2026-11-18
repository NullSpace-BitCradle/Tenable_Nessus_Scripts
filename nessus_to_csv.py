"""
Nessus to CSV Conversion Script

Converts .nessus (XML) vulnerability scan files into CSV for analysis in
spreadsheet applications. It extracts 106 fields per finding:

- Host information (IP, hostname, FQDN, MAC address, OS details)
- Vulnerability details (plugin name, severity, CVSS scores, CVE IDs)
- Exploit information (Metasploit, Canvas, Core Impact availability)
- Scan metadata (scan dates, policy used, credentialed scan status)
- Additional security references (CISA, STIG, vendor advisories)

Usage:
    python nessus_to_csv.py [-o OUTPUT.csv] PATH [PATH ...]

Each PATH is a .nessus file or a folder (searched recursively). With no PATH the
script falls back to file pickers, which need a desktop session.

Features:
- Repeated reference elements (CWE, BID, MSKB, ...) are all kept, joined with ", "
- Exact duplicate findings are removed and the original row order is kept
- Each host is released from memory once read; one file's rows are held at a time
- Cells that start with = + - @ are prefixed with ' so Excel does not run them
- Exit code 0 on success, 1 if nothing could be converted, 2 if some files failed

The output is UTF-8 with a byte order mark so Excel opens it correctly.
"""

import argparse
import csv
import os
import sys
import time

import nessus_common as nc

DEFAULT_OUTPUT = "nessus_conversion.csv"


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Convert .nessus files to CSV.")
    parser.add_argument("paths", nargs="*", help=".nessus files or folders (recursive)")
    parser.add_argument("-o", "--output", help=f"output CSV path (default: {DEFAULT_OUTPUT})")
    return parser.parse_args(argv)


def write_csv(files, output_path, stats):
    """
    Write the unique rows of `files` to `output_path`.

    Writes to a temporary file and moves it into place only if at least one input
    file was read, so a failed run does not replace an existing good CSV.
    Returns the number of rows written.
    """
    tmp_path = output_path + ".tmp"
    written = 0
    try:
        with open(tmp_path, "w", newline="", encoding="utf-8-sig") as csvfile:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(nc.COLUMN_NAMES)
            for row in nc.iter_unique_rows(files, stats):
                writer.writerow(["" if v is None else nc.neutralize_cell(v) for v in row])
                written += 1
                if written % 1000 == 0:
                    print(f"\rWrote {written} rows...", end="", flush=True)
        if stats.files_ok == 0:
            os.remove(tmp_path)
            return 0
        os.replace(tmp_path, output_path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise
    return written


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
            output_path = nc.pick_output_gui(DEFAULT_OUTPUT, ".csv")
            if not output_path:
                print("No output file selected. Exiting.")
                return nc.EXIT_FAILED

    stats = nc.RunStats()
    written = write_csv(files, output_path, stats)
    print()
    failed = nc.report_failures(stats)
    if stats.files_ok == 0:
        print("No file could be read. No CSV was written.", file=sys.stderr)
        return nc.EXIT_FAILED

    if stats.duplicates:
        print(f"Removed {stats.duplicates} duplicate rows from the data.")
    else:
        print("No duplicate rows found.")
    print(f"Processed {stats.files_ok} of {stats.files_seen} files, {stats.hosts} hosts, "
          f"and {written} findings. Wrote {output_path}.")
    print(nc.format_run_metrics(start_time))
    return nc.EXIT_PARTIAL if failed else nc.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
