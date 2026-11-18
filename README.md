# Tenable Nessus Scripts

A collection of Python scripts for processing and converting Tenable Nessus vulnerability scan files. Extracts **106 data fields** per finding across host info, CVSS/CVSS3 scores, CVE/CWE references, exploit intelligence, and scan metadata.

## Scripts

| Script | Purpose |
|--------|---------|
| `tenable_scan_retrieval.py` | Download scan results from Tenable.io via API |
| `nessus_to_csv.py` | Convert .nessus files to CSV |
| `nessus_to_xlsx.py` | Convert .nessus files to formatted Excel (.xlsx) |
| `nessus_to_sql.py` | Import .nessus files into SQL Server |
| `nessus_common.py` | Shared parser and column list used by the three converters. Keep it next to them. |

All three converters accept files or folders on the command line, support multiple input files, remove duplicate findings, and print performance metrics. Each also has a file-picker fallback that runs only when you give no path.

## Requirements

- Python 3.9+
- A graphical display only if you run a converter with no path (tkinter file dialogs need a desktop environment or X11 forwarding)

```bash
pip install -r requirements.txt
```

| Dependency | Used By |
|------------|---------|
| `psutil` | The converters (performance metrics) |
| `requests` | `tenable_scan_retrieval.py` (Tenable.io API) |
| `openpyxl` | `nessus_to_xlsx.py` (Excel output) |
| `pyodbc` | `nessus_to_sql.py` (SQL Server via ODBC Driver 18) |

### SQL Server Prerequisites

`nessus_to_sql.py` requires:
- Windows with ODBC Driver 18 for SQL Server installed
- Windows Authentication (Trusted Connection) to the target SQL Server
- Permission to insert data and to create tables: the import log (always) and the findings table (if you ask the script to create it)

## Usage

Exit codes for the converters: `0` success, `1` nothing could be converted (bad usage, no files, or every file failed), `2` output was written but at least one file could not be read. A file that fails to parse is skipped and listed at the end.

### Download Scans from Tenable.io

```bash
python tenable_scan_retrieval.py                       # pick scans from a list
python tenable_scan_retrieval.py --all                 # every scan, no prompts
python tenable_scan_retrieval.py --scan-id 12 --scan-id 34
python tenable_scan_retrieval.py --all --output-dir D:\scans
```

1. Provide your API credentials (Tenable.io: Settings > My Account > API Keys). Set `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY`, or type them at the prompt. The secret key is not shown as you type.
2. Select scans: with no options, enter a single number, comma-separated numbers, or "all". `--all` and `--scan-id` skip the prompt.
3. Files are saved as `<scan name>-<scan id>.nessus` in `Year/MM-MonthName/Week-XX/` under `--output-dir` (default: the current folder). Year and week are both ISO values, so 2027-01-01 goes in `2026/01-January/Week-53`.

Every request has a timeout (10 s to connect, 60 s to read). A rate-limited request (HTTP 429) is retried up to 3 times. Each download goes to a `.part` file and is renamed only when complete; the size is checked against `Content-Length` unless the response is compressed, where that length does not apply. Each scan's export is polled every 5 seconds for up to 900 seconds. Use `--export-timeout SECONDS` and `--poll-interval SECONDS` to change that for very large scans. To use another Tenable cloud, set `TENABLE_URL` (https only), for example `https://fedcloud.tenable.com`. The exit code is `1` if any selected scan failed.

### Convert to CSV

```bash
python nessus_to_csv.py -o findings.csv scan1.nessus scan2.nessus
python nessus_to_csv.py -o findings.csv D:\scans        # folders are searched recursively
python nessus_to_csv.py                                  # no path: file pickers
```

Produces a CSV with 106 columns, UTF-8 with a byte order mark so Excel reads non-ASCII text correctly. Without `-o` the output is `nessus_conversion.csv` in the current folder. The CSV is written to a temporary file first, so a run where every input fails does not overwrite an existing CSV.

### Convert to Excel

```bash
python nessus_to_xlsx.py -o findings.xlsx D:\scans
python nessus_to_xlsx.py                                 # no path: file pickers
```

Produces a formatted Excel workbook with alternating row colors, table filters, and TableStyleMedium2 styling.

- An Excel cell holds at most 32,767 characters. A longer value (usually Plugin Output) is cut, ends with `[truncated, original was N characters]`, and the script prints how many cells were cut. Use the CSV script when you need the full text.
- A sheet holds at most 1,048,576 rows. A larger input stops with an error; split it or use the CSV script.

### Import to SQL Server

```bash
python nessus_to_sql.py D:\scans --server sqlserver.example.com --database Scans --table nessus_findings --create-table
python nessus_to_sql.py D:\scans                         # prompts for server, database and table
python nessus_to_sql.py D:\scans --dry-run               # print the SQL and row count, no connection
```

1. Give a folder or files (or none, to get a folder picker).
2. Give the server, database and table on the command line, or answer the prompts. The table menu lists the existing `dbo` tables and a "Create a new table" choice that asks for a name.
3. An existing table must already have all the script's columns, or the script stops before inserting. To create a table, use `--create-table` with `--table NAME`, or choose it in the menu. The findings table has no unique key, so no finding is ever dropped for looking like another one (compliance checks, for instance, share a plugin ID, host and port and differ only in their text). The script skips a row only when all 106 columns equal an earlier row in the same run.
4. Next to the findings table the script keeps `<table>_import_log` (created on first use, for existing tables too, so the login needs permission to create it). It records each imported file's base name, its SHA-256 and its row count. A file whose name and SHA-256 are already logged is skipped, so running the same folder twice adds nothing. A file with the same name but different content is imported again in full, and the same content under a different name is a separate import (the `file_path` value differs). Delete a row from the log to force a file to be imported again.
5. Each file is imported in one transaction together with its log row, in batches of 500,000 rows. If a batch fails, nothing from that file is kept, it is not logged, and the run stops. The closing message counts rows inserted by this run, files imported and files skipped.

Tables built by the old version of this script (before this change) have `VARCHAR(150)` columns for `cwe`, `bid`, `mskb` and the other reference columns, and `NVARCHAR(4000)` for `cve`. A finding with many references makes the joined text longer than that, and SQL Server then rejects the whole batch with "String or binary data would be truncated". When you point the script at such a table it prints a warning with the `ALTER TABLE ... ALTER COLUMN ... NVARCHAR(MAX)` statements for the narrow columns. Run those once, or import into a new table. The column check looks at names only, not types.

The `file_path` column holds the file's base name (for example `scan1.nessus`), not a full path. The CSV and Excel outputs call the same value File Name.

The connection uses Windows Authentication and validates the server certificate. If your server uses a self-signed certificate, install it as trusted. `--trust-server-certificate` accepts any certificate, which lets someone in the network path impersonate the server, so use it only on a network you control.

Dates are read in Python and sent as dates, empty numbers and dates are stored as NULL, and text columns are `NVARCHAR`, so non-Latin text is stored as is. This script has been tested against a fake connection only; it has not been run against a real SQL Server.

## Extracted Data Fields (106 per finding)

<details>
<summary>Click to expand full field list</summary>

### Host Information
- IP Address, MAC Address, Virtual MAC Address
- Hostname, NetBIOS Name, FQDN, RDNS
- System Type, Operating System (name, family, confidence, detection method)
- CPE (Common Platform Enumeration): the finding's own CPE from its plugin, not the host-level OS CPE

### Vulnerability Details
- Plugin ID, Plugin Family, Plugin Name
- Severity Rating (Critical, High, Medium, Low, Informational)
- Risk Factor, Synopsis, Description, Solution
- Port, Protocol, Service Name
- Plugin Output, Plugin Type
- Publication and Modification Dates

### CVSS Scores
- CVSS v2: Base Score, Vector, Rationale, Source, Temporal Score/Vector
- CVSS v3: Base Score, Vector, Source, Temporal Score/Vector, Impact Score
- VPR Score

### Security References
- CVE, CWE
- CISA Known Exploited, CISA NCAS
- STIG Severity
- Vendor Advisories: MSFT, MSKB, Cisco Bug ID, Cisco SA, VMware SA, Secunia
- Bug IDs: BID, EDB-ID, CEA-ID, CERT
- IAVA, IAVB, IAVT, ICSA, TRA

When a finding lists the same kind of reference more than once (two CWEs, several MSKB numbers), all of them are kept, joined with `, `.

### Exploit Intelligence
- Exploit Available, Exploitability Ease, Exploit Code Maturity
- Framework availability: Metasploit, Canvas, Core Impact
- Metasploit Module Name
- Exploited by Malware, Exploited by Nessus
- Threat Recency, Threat Intensity (28-day), Threat Sources (28-day)

### Scan Metadata
- Scan Date, Host Start/End Times and Timestamps
- Policy Used, Credentialed Scan Status
- Local Checks Protocol, SMB Login Used
- WMI Domain, Thorough Tests
- Source File Name

</details>

Newer Nessus fields (such as CVSS v4 and EPSS) are not extracted.

## Notes

- **Spreadsheet safety**: in CSV and Excel output, a text cell that starts with `=`, `+`, `-` or `@` (or a tab or carriage return) gets a leading `'` so Excel does not run it as a formula. Plugin output and hostnames come from scanned hosts, so they can contain anything. Plain numbers such as `-5` are left alone. The leading `'` is visible in the cell; strip it if you load the CSV into something other than Excel.
- **Duplicate removal**: the CSV, Excel and SQL scripts drop a row only when all 106 columns match another row. The file name is one of the columns, so the same finding in two differently named files is kept. Rows stay in the order they appear in the input.
- **Memory**: each host is released after it is read and only one file's rows are held at a time, but a single very large file is still held in memory as rows.
- **Windows-optimized**: the SQL script uses Windows Authentication (Trusted Connection). The memory metric uses `peak_wset` on Windows and falls back to `rss` on Linux/macOS.
- **API credentials**: read from the environment or prompted at runtime, never stored to disk.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The tests build small synthetic `.nessus` files and run the scripts through their command-line interface, so no scan data, GUI, SQL Server or Tenable account is needed.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions, issues, and feature requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

These scripts are provided as-is for security professionals to process vulnerability scan data. Ensure you have proper authorization before processing any scan results, and follow your organization's data handling policies.
