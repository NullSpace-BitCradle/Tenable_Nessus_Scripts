"""
Shared code for the Nessus conversion scripts.

Holds the one definition of the 106 output columns, the .nessus parser, the
row de-duplication, the spreadsheet-safety helper and the optional file
pickers. nessus_to_csv.py, nessus_to_xlsx.py and nessus_to_sql.py all use it,
so a fix to parsing lands in all three.

Note: column names (e.g. pluginName, Credentialed_Scan) mirror the Nessus XML
element and attribute names for traceability back to the source format.
"""

import hashlib
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

# Severity constants.
SEVERITY_MAPPING = {0: 4, 1: 3, 2: 2, 3: 1, 4: 0}
SEVERITY_RATING = {0: "Critical", 1: "High", 2: "Medium", 3: "Low", 4: "Informational"}

# Exit codes shared by the converters.
EXIT_OK = 0
EXIT_FAILED = 1   # bad usage, nothing to do, or every input failed
EXIT_PARTIAL = 2  # output written, but at least one input could not be read

# Column spec: csv_name | xlsx_header | kind | key
#   host    first <tag name="key"> under HostProperties
#   attr    attribute of <ReportItem>
#   item    text of the first child element named key
#   multi   every child element named key, joined with ", "
#   output  text of <plugin_output>, stripped
#   derived computed from the item/host (key names the value)
_COLUMN_SPEC = """
host_ip|IP Address|host|host-ip
mac_address|MAC Address|host|mac-address
virtual_mac_address|Virtual MAC Address|host|virtual-mac-address
hostname|Hostname|host|hostname
netbios_name|NETBIOS|host|netbios-name
host_fqdn|FQDN|host|host-fqdn
host_rdns|RDNS|host|host-rdns
system_type|System Type|host|system-type
cpe|CPE|item|cpe
operating_system_id|OS Family|host|os
operating_system|Operating System|host|operating-system
severity_rating|Severity Rating|derived|severity_rating
risk_factor|Risk Factor|item|risk_factor
severity_reversed|Severity Number|derived|severity_reversed
pluginName|Plugin Name|attr|pluginName
synopsis|Synopsis|item|synopsis
description|Description|item|description
solution|Solution|item|solution
port|Port|attr|port
protocol|Protocol|attr|protocol
svc_name|Service Name|attr|svc_name
plugin_output|Plugin Output|output|plugin_output
plugin_type|Plugin Type|item|plugin_type
plugin_publication_date|Plugin Publication Date|item|plugin_publication_date
plugin_modification_date|Plugin Modification Date|item|plugin_modification_date
stig_severity|STIG Severity|item|stig_severity
cvss_base_score|CVSS Score|item|cvss_base_score
cvss_vector|CVSS Vector|item|cvss_vector
cvss_score_rationale|CVSS Score Rationale|item|cvss_score_rationale
cvss_score_source|CVSS Score Source|item|cvss_score_source
cvss_temporal_score|CVSS Temporal Score|item|cvss_temporal_score
cvss_temporal_vector|CVSS Temporal Vector|item|cvss_temporal_vector
cvss3_base_score|CVSS3 Score|item|cvss3_base_score
cvss3_vector|CVSS3 Vector|item|cvss3_vector
cvss3_score_source|CVSS3 Score Source|item|cvss3_score_source
cvss3_temporal_score|CVSS3 Temporal Score|item|cvss3_temporal_score
cvss3_temporal_vector|CVSS3 Temporal Vector|item|cvss3_temporal_vector
cvssV3_impactScore|CVSS3 Impact Score|item|cvssV3_impactScore
vpr_score|VPR Score|item|vpr_score
patch_publication_date|Patch Publication Date|item|patch_publication_date
patch_summary_total_cves|Patch Summary CVE Count|host|patch-summary-total-cves
vuln_publication_date|Vulnerability Publication Date|item|vuln_publication_date
age_of_vuln|Vulnerability Age|item|age_of_vuln
product_coverage|Product Coverage|item|product_coverage
exploit_available|Exploit Available|item|exploit_available
exploitability_ease|Exploitability Ease|item|exploitability_ease
exploit_code_maturity|Exploit Code Maturity|item|exploit_code_maturity
exploit_framework_canvas|Exploitable with CANVAS|item|exploit_framework_canvas
canvas_package|CANVAS Package|item|canvas_package
exploit_framework_core|Exploitable with Core Impact|item|exploit_framework_core
exploit_framework_metasploit|Exploitable with Metasploit|item|exploit_framework_metasploit
metasploit_name|Metasploit Module|item|metasploit_name
exploited_by_malware|Exploitable by Malware|item|exploited_by_malware
exploited_by_nessus|Exploitable by Nessus|item|exploited_by_nessus
edb_id|Exploit DB ID|multi|edb-id
threat_recency|Threat Recency|item|threat_recency
threat_intensity_last_28|Threat Intensity Last 28 Days|item|threat_intensity_last_28
threat_sources_last_28|Threat Sources Last 28 Days|item|threat_sources_last_28
local_checks_proto|Local Checks Protocol|host|local-checks-proto
smb_login_used|SMB Login Used|host|smb-login-used
wmi_domain|WMI Domain|host|wmi-domain
thorough_tests|Thorough Tests Used|item|thorough_tests
Credentialed_Scan|Credentialed Scan Used|host|Credentialed_Scan
LastAuthenticatedResults|Authentication Issues|host|LastAuthenticatedResults
policy_used|Policy Used|host|policy-used
host_start|Host Scan Started|host|HOST_START
host_start_timestamp|Host Scan Started Timestamp|host|HOST_START_TIMESTAMP
host_end|Host Scan Ended|host|HOST_END
host_end_timestamp|Host Scan Ended Timestamp|host|HOST_END_TIMESTAMP
os_identification|OS Identified|item|os_identification
operating_system_conf|Operating System Confidence|host|operating-system-conf
operating_system_method|OS Identification Method|host|operating-system-method
sinfp_signature|SinFP Signature|host|sinfp-signature
pluginID|Plugin ID|attr|pluginID
pluginFamily|Plugin Family|attr|pluginFamily
script_version|Script Version|item|script_version
agent|Agent Used|item|agent
always_run|Always Run|item|always_run
asset_inventory|Asset Inventory|item|asset_inventory
asset_inventory_category|Asset Inventory Category|item|asset_inventory_category
asset_categories|Asset Categories|item|asset_categories
hardware_inventory|Hardware Inventory|item|hardware_inventory
bid|BugtraqID|multi|bid
cea_id|CEA Id|multi|cea-id
cert|CERT|multi|cert
cisa_known_exploited|CISA Known Exploited|item|cisa-known-exploited
cisa_ncas|CISA NCAS|multi|cisa-ncas
cisco_bug_id|Cisco Bug ID|multi|cisco-bug-id
cisco_sa|Cisco Security Advisory|multi|cisco-sa
cve|CVE|multi|cve
cwe|CWE|multi|cwe
iava|IAVA|multi|iava
iavb|IAVB|multi|iavb
iavt|IAVT|multi|iavt
icsa|ICSA|multi|icsa
msft|MSFT|multi|msft
mskb|MSKB|multi|mskb
tra|Trust Research Advisory|multi|tra
vmsa|VMWare Security Advisory|multi|vmsa
secunia|Secunia Security Advisory|multi|secunia
unsupported_by_vendor|Unsupported by Vendor|item|unsupported_by_vendor
see_also|See Also|item|see_also
in_the_news|In The News|item|in_the_news
generated_plugin|Generated Plugin|item|generated_plugin
file_name|File Name|derived|file_name
scan_date|Scan Date|derived|scan_date
"""

COLUMNS = [tuple(line.split("|")) for line in _COLUMN_SPEC.strip().splitlines()]
COLUMN_NAMES = [c[0] for c in COLUMNS]
XLSX_HEADERS = [c[1] for c in COLUMNS]
assert len(COLUMNS) == 106 and len(set(COLUMN_NAMES)) == 106

HOST_DATE_FORMAT = "%a %b %d %H:%M:%S %Y"
XLSX_MAX_ROWS = 1_048_576
XLSX_MAX_CELL = 32_767


class NessusParseError(Exception):
    """A .nessus file could not be read or is not shaped like a Nessus report."""


class RunStats:
    """Counters for one conversion run."""

    def __init__(self):
        self.files_seen = 0
        self.files_ok = 0
        self.hosts = 0
        self.findings = 0          # rows read, before de-duplication
        self.duplicates = 0
        self.failures = []         # list of (path, message)


def _text(el):
    return el.text if el is not None and el.text is not None else ""


def parse_scan_date(host_start):
    """Turn a Nessus HOST_START string into YYYY-MM-DD, or None if it will not parse."""
    if not host_start:
        return None
    try:
        return datetime.strptime(host_start, HOST_DATE_FORMAT).strftime("%Y-%m-%d")
    except ValueError:
        return None


def _host_tags(host):
    """Map HostProperties tag name -> text. The first tag of a name wins."""
    tags = {}
    props = host.find("HostProperties")
    if props is not None:
        for tag in props.findall("tag"):
            name = tag.get("name")
            if name is not None and name not in tags:
                tags[name] = _text(tag)
    return tags


def _item_severity(item):
    try:
        severity = int(item.attrib["severity"])
        reversed_ = SEVERITY_MAPPING[severity]
    except (KeyError, ValueError) as exc:
        raise NessusParseError(
            f"ReportItem pluginID={item.attrib.get('pluginID', '?')} has a missing or "
            f"invalid severity attribute ({exc!r})"
        ) from None
    return SEVERITY_RATING[reversed_], reversed_


def build_row(host_tags, item, file_name, scan_date):
    """Build one 106-column row from a host's tags and one ReportItem."""
    rating, reversed_ = _item_severity(item)
    derived = {
        "severity_rating": rating,
        "severity_reversed": reversed_,
        "file_name": file_name,
        "scan_date": scan_date,
    }
    row = []
    for _name, _header, kind, key in COLUMNS:
        if kind == "host":
            row.append(host_tags.get(key, ""))
        elif kind == "attr":
            row.append(item.attrib.get(key, ""))
        elif kind == "item":
            row.append(_text(item.find(key)))
        elif kind == "multi":
            row.append(", ".join(t for t in (_text(el) for el in item.findall(key)) if t))
        elif kind == "output":
            row.append(_text(item.find(key)).strip())
        else:
            row.append(derived[key])
    return row


def parse_nessus_file(path, stats=None):
    """
    Parse one .nessus file and return its rows (a list of 106-column lists).

    Hosts are read one at a time and released as they are done, so the whole XML
    tree is never held in memory; the rows of this one file are. Raises
    NessusParseError if the file cannot be read, so the caller can skip it and
    report it instead of treating the run as a success.
    """
    file_name = os.path.basename(path)
    rows = []
    hosts = 0
    try:
        for _event, elem in ET.iterparse(path, events=("end",)):
            if elem.tag != "ReportHost":
                continue
            hosts += 1
            tags = _host_tags(elem)
            scan_date = parse_scan_date(tags.get("HOST_START", ""))
            for item in elem.iter("ReportItem"):
                rows.append(build_row(tags, item, file_name, scan_date))
            elem.clear()
    except ET.ParseError as exc:
        raise NessusParseError(f"XML error: {exc}") from None
    except OSError as exc:
        raise NessusParseError(f"cannot read file: {exc}") from None
    if stats is not None:
        stats.hosts += hosts
        stats.findings += len(rows)
    return rows


def _row_digest(row):
    joined = "\x1f".join("" if v is None else str(v) for v in row)
    return hashlib.blake2b(joined.encode("utf-8", "surrogatepass"), digest_size=16).digest()


def iter_unique_rows(files, stats, seen=None):
    """
    Yield the rows of every file in order, skipping exact duplicate rows.

    A row is a duplicate only if all 106 columns match, which includes the file
    name, so the same finding in two differently named files is kept. Rows come
    out in file order, then host order, then finding order. Files that fail to
    parse are recorded in stats.failures and skipped whole. Pass the same `seen`
    set to several calls to de-duplicate across them.
    """
    if seen is None:
        seen = set()
    for path in files:
        stats.files_seen += 1
        print(f"Processing {path}")
        try:
            rows = parse_nessus_file(path, stats)
        except NessusParseError as exc:
            print(f"Error processing {path}: {exc}", file=sys.stderr)
            stats.failures.append((path, str(exc)))
            continue
        stats.files_ok += 1
        for row in rows:
            digest = _row_digest(row)
            if digest in seen:
                stats.duplicates += 1
                continue
            seen.add(digest)
            yield row


def collect_nessus_files(paths):
    """Expand a mix of files and folders into a sorted list of .nessus files."""
    files = []
    for path in paths:
        if os.path.isdir(path):
            found = []
            for root_dir, dirs, names in os.walk(path):
                dirs.sort()
                for name in sorted(names):
                    if name.lower().endswith(".nessus"):
                        found.append(os.path.join(root_dir, name))
            files.extend(found)
        elif os.path.isfile(path):
            files.append(path)
        else:
            raise FileNotFoundError(f"No such file or folder: {path}")
    return files


# Cells that a spreadsheet would read as a formula.
_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")
_PLAIN_NUMBER = re.compile(r"[+-]?\d+(\.\d+)?")


def neutralize_cell(value):
    """
    Stop a spreadsheet from running a text cell as a formula.

    A text value that starts with = + - @ tab or CR gets a leading apostrophe.
    Plain numbers such as -5 are left alone. Plugin output, hostnames and banners
    come from scanned hosts, so they can hold anything.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_LEADERS):
        if _PLAIN_NUMBER.fullmatch(value):
            return value
        return "'" + value
    return value


def format_run_metrics(start_time):
    """Return the 'Elapsed time ... Peak memory ...' line."""
    import time
    import psutil
    elapsed = time.time() - start_time
    hours = int(elapsed // 3600)
    minutes = int((elapsed % 3600) // 60)
    seconds = elapsed % 60
    mem_info = psutil.Process().memory_info()
    peak_mb = getattr(mem_info, "peak_wset", mem_info.rss) / 1024 / 1024
    return (f"Elapsed time: {hours} hours {minutes} minutes {seconds:.2f} seconds. "
            f"Peak memory usage: {peak_mb:.2f} MB.")


def report_failures(stats):
    """Print a summary of files that failed. Returns True if there were any."""
    if not stats.failures:
        return False
    print(f"\n{len(stats.failures)} of {stats.files_seen} file(s) could not be processed:",
          file=sys.stderr)
    for path, message in stats.failures:
        print(f"  {path}: {message}", file=sys.stderr)
    return True


# ---- Optional file pickers: used only when no path is given on the command line ----

def pick_inputs_gui(allow_files=True):
    """
    Ask for input with tkinter dialogs. Fallback for when no path was given.

    Returns a list of file/folder paths, or [] if the user cancelled.
    """
    import tkinter as tk
    from tkinter import filedialog
    root = tk.Tk()
    root.withdraw()
    if allow_files:
        choice = input("Select (1) for files or (2) for folder: ").strip()
    else:
        choice = "2"
    if choice == "2":
        folder = filedialog.askdirectory(title="Select folder containing .nessus files")
        return [folder] if folder else []
    return list(filedialog.askopenfilenames(
        title="Select .nessus files to process", filetypes=[("Nessus files", "*.nessus")]))


def pick_output_gui(default_name, extension):
    """Ask where to save the output. Returns '' if cancelled."""
    import tkinter as tk
    from tkinter import filedialog
    root = tk.Tk()
    root.withdraw()
    return filedialog.asksaveasfilename(
        defaultextension=extension, initialfile=default_name, title="Save output file as...")
