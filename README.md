# Tenable Nessus Scripts

A collection of Python scripts for processing and converting Tenable Nessus vulnerability scan files. These tools help security professionals extract, analyze, and manage vulnerability data from Nessus scan results.

## Overview

This repository contains four main scripts:

1. **`tenable_scan_retrieval.py`** - Downloads scan results from Tenable.io cloud platform
2. **`nessus_to_csv.py`** - Converts .nessus files to CSV format
3. **`nessus_to_xlsx.py`** - Converts .nessus files to Excel format (.xlsx)
4. **`nessus_to_sql.py`** - Imports .nessus files into SQL Server database

## Features

### Common Features (All Conversion Scripts)
- Processes one or more .nessus files
- Extracts comprehensive vulnerability data including:
  - Host information (IP, hostname, FQDN, MAC address, OS details)
  - Vulnerability details (plugin name, severity, CVSS scores, CVE IDs)
  - Exploit information (Metasploit, Canvas, Core Impact availability)
  - Scan metadata (scan dates, policy used, credentialed scan status)
  - Additional security references (CISA, STIG, vendor advisories)
- Automatic duplicate removal
- Progress tracking and performance metrics
- Memory-efficient processing for large files

### Script-Specific Features

#### `tenable_scan_retrieval.py`
- Authenticates with Tenable.io using API keys
- Interactive scan selection (single, multiple, or all scans)
- Automatic export initiation and status monitoring
- Downloads scans in .nessus format
- Organizes downloads in date-based directory structure (Year/Month-Name/Week-XX)
- Progress tracking with download speed metrics

#### `nessus_to_csv.py`
- Supports processing individual files or entire folders
- Interactive file/folder selection via GUI
- Outputs to CSV format for spreadsheet applications
- UTF-8 encoding support

#### `nessus_to_xlsx.py`
- Creates formatted Excel tables with professional styling
- Alternating row colors for improved readability
- Excel table formatting with filters

#### `nessus_to_sql.py`
- Interactive SQL Server connection setup
- Queries available servers, databases, and tables
- Automatic table creation with proper schema
- Batch processing (500,000 rows per batch) for memory efficiency
- Supports Windows Authentication (Trusted Connection)

## Requirements

- Python 3.6 or higher
- See `requirements.txt` for Python package dependencies

## Installation

1. Clone or download this repository
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

### Additional Setup for SQL Script

For `nessus_to_sql.py`, you'll also need:
- SQL Server with ODBC Driver 18 for SQL Server installed
- Appropriate database permissions to create tables and insert data

## Usage

### Retrieving Scans from Tenable.io

```bash
python tenable_scan_retrieval.py
```

**Steps:**
1. Enter your Tenable.io API credentials (Access Key and Secret Key)
2. View the list of available scans
3. Select scans to download (enter numbers, comma-separated numbers, or "all")
4. Scans will be exported and downloaded automatically
5. Files are saved in organized date-based directories

**API Credentials:**
- Find your API keys in Tenable.io: Settings > My Account > API Keys

### Converting to CSV

```bash
python nessus_to_csv.py
```

**Steps:**
1. Choose to select individual files (1) or a folder (2)
2. Select .nessus files or folder containing .nessus files
3. Choose output location and filename
4. Script processes files and creates CSV output

### Converting to Excel

```bash
python nessus_to_xlsx.py
```

**Steps:**
1. Select one or more .nessus files via file dialog
2. Choose output location and filename
3. Script processes files and creates formatted Excel workbook

### Importing to SQL Server

```bash
python nessus_to_sql.py
```

**Steps:**
1. Select folder containing .nessus files
2. Enter SQL Server address (e.g., localhost, 10.10.30.20, or server.domain.com)
3. Select database from available list
4. Select table from available list (or create new one)
5. Confirm selection and proceed
6. Script processes all .nessus files in the folder and imports data

**Note:** The script will automatically create the table if it doesn't exist.

## Data Fields

All scripts extract the following comprehensive data fields:

### Host Information
- IP Address, MAC Address, Virtual MAC Address
- Hostname, NetBIOS Name, FQDN, RDNS
- System Type, Operating System details
- CPE (Common Platform Enumeration)

### Vulnerability Details
- Plugin ID, Plugin Family, Plugin Name
- Severity Rating (Critical, High, Medium, Low, Informational)
- Risk Factor, Synopsis, Description, Solution
- Port, Protocol, Service Name
- Plugin Output, Plugin Type
- Publication and Modification Dates

### CVSS Scores
- CVSS Base Score, Vector, Score Rationale, Score Source
- CVSS Temporal Score and Vector
- CVSS3 Base Score, Vector, Score Source
- CVSS3 Temporal Score and Vector
- CVSS3 Impact Score
- VPR Score

### CVE and Security References
- CVE (Common Vulnerabilities and Exposures)
- CWE (Common Weakness Enumeration)
- CISA Known Exploited, CISA NCAS
- STIG Severity
- Vendor Advisories (MSFT, MSKB, Cisco, VMWare, etc.)
- Bug IDs (BID, EDB-ID, etc.)

### Exploit Information
- Exploit Available, Exploitability Ease
- Exploit Code Maturity
- Exploit Framework (Metasploit, Canvas, Core Impact)
- Metasploit Module Name
- Exploited by Malware, Exploited by Nessus

### Scan Metadata
- Scan Date, Host Start/End Times
- Policy Used, Credentialed Scan Status
- Local Checks Protocol, SMB Login Used
- WMI Domain, Thorough Tests

## Output Formats

### CSV Output
- UTF-8 encoded CSV file
- All fields included as columns
- Suitable for import into any spreadsheet application

### Excel Output
- Formatted Excel table with alternating row colors
- Professional styling (TableStyleMedium2)
- All fields included as columns
- Excel filters enabled

### SQL Server Output
- Comprehensive table schema with appropriate data types
- Batch insertion for performance
- Supports large datasets efficiently

## Performance

All scripts include performance metrics:
- Elapsed processing time
- Peak CPU usage
- Peak memory usage

The SQL script uses batch processing (500,000 rows per batch) to handle large datasets efficiently without excessive memory consumption.

## Error Handling

- XML parsing errors are caught and reported
- Database connection errors are handled gracefully
- API errors are logged with detailed messages
- Invalid file selections are validated before processing

## Notes

- All scripts use interactive GUI dialogs for file/folder selection (tkinter)
- The SQL script requires Windows Authentication (Trusted Connection)
- Tenable.io API credentials are prompted at runtime (not stored)
- Duplicate findings are automatically removed in CSV and Excel outputs
- Large files are processed efficiently with memory management

## License

See LICENSE file for details.

## Contributing

Contributions, issues, and feature requests are welcome!

## Disclaimer

These scripts are provided as-is for security professionals to process vulnerability scan data. Ensure you have proper authorization before processing any scan results, and follow your organization's data handling policies.

