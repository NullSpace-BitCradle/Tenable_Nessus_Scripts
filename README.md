# Tenable Nessus Scripts

A collection of Python scripts for processing and converting Tenable Nessus vulnerability scan files. Extracts **106 data fields** per finding across host info, CVSS/CVSS3 scores, CVE/CWE references, exploit intelligence, and scan metadata.

## Scripts

| Script | Purpose |
|--------|---------|
| `tenable_scan_retrieval.py` | Download scan results from Tenable.io via API |
| `nessus_to_csv.py` | Convert .nessus files to CSV |
| `nessus_to_xlsx.py` | Convert .nessus files to formatted Excel (.xlsx) |
| `nessus_to_sql.py` | Import .nessus files into SQL Server |

All conversion scripts support multiple input files, automatic duplicate removal, progress tracking, and performance metrics.

## Requirements

- Python 3.9+
- A graphical display (tkinter file dialogs require a desktop environment or X11 forwarding)

```bash
pip install -r requirements.txt
```

| Dependency | Used By |
|------------|---------|
| `psutil` | All scripts (performance metrics) |
| `requests` | `tenable_scan_retrieval.py` (Tenable.io API) |
| `openpyxl` | `nessus_to_xlsx.py` (Excel output) |
| `pyodbc` | `nessus_to_sql.py` (SQL Server via ODBC Driver 18) |

### SQL Server Prerequisites

`nessus_to_sql.py` requires:
- Windows with ODBC Driver 18 for SQL Server installed
- Windows Authentication (Trusted Connection) to the target SQL Server
- Permissions to create tables and insert data

## Usage

### Download Scans from Tenable.io

```bash
python tenable_scan_retrieval.py
```

1. Enter your API credentials (find them in Tenable.io: Settings > My Account > API Keys)
2. Select scans to download (single number, comma-separated, or "all")
3. Files are saved in a date-organized directory: `Year/MM-MonthName/Week-XX/`

### Convert to CSV

```bash
python nessus_to_csv.py
```

1. Choose file selection (1) or folder selection (2)
2. Select .nessus files or folder
3. Choose output location
4. Produces a UTF-8 CSV with 106 columns

### Convert to Excel

```bash
python nessus_to_xlsx.py
```

1. Select one or more .nessus files
2. Choose output location
3. Produces a formatted Excel workbook with alternating row colors, table filters, and TableStyleMedium2 styling

### Import to SQL Server

```bash
python nessus_to_sql.py
```

1. Select folder containing .nessus files
2. Enter SQL Server address (e.g., `localhost`, `10.10.30.20`, `server.domain.com`)
3. Select database and table from interactive menus
4. Table is auto-created if it doesn't exist
5. Data is inserted in batches of 500,000 rows for memory efficiency

## Extracted Data Fields (106 per finding)

<details>
<summary>Click to expand full field list</summary>

### Host Information
- IP Address, MAC Address, Virtual MAC Address
- Hostname, NetBIOS Name, FQDN, RDNS
- System Type, Operating System (name, family, confidence, detection method)
- CPE (Common Platform Enumeration)

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

## Platform Notes

- **GUI required**: All scripts use tkinter file dialogs for file/folder selection. They will not work over SSH without X11 forwarding or on headless servers.
- **Windows-optimized**: The SQL script uses Windows Authentication (Trusted Connection). The memory metric uses `peak_wset` on Windows and falls back to `rss` on Linux/macOS.
- **API credentials**: Prompted at runtime, never stored to disk.
- **Duplicate removal**: CSV and XLSX scripts automatically deduplicate findings before writing output.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions, issues, and feature requests are welcome.

## Disclaimer

These scripts are provided as-is for security professionals to process vulnerability scan data. Ensure you have proper authorization before processing any scan results, and follow your organization's data handling policies.
