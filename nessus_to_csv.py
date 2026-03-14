"""
Nessus to CSV Conversion Script

This script converts .nessus (XML) vulnerability scan files into CSV format for
easier analysis in spreadsheet applications. It processes one or more .nessus files
and extracts comprehensive vulnerability data including:

- Host information (IP, hostname, FQDN, MAC address, OS details)
- Vulnerability details (plugin name, severity, CVSS scores, CVE IDs)
- Exploit information (Metasploit, Canvas, Core Impact availability)
- Scan metadata (scan dates, policy used, credentialed scan status)
- Additional security references (CISA, STIG, vendor advisories)

Features:
- Supports processing individual files or entire folders
- Removes duplicate findings automatically
- Provides progress tracking and performance metrics
- Handles large files efficiently with memory management

Note: Variable names (e.g., pluginName, Credentialed_Scan) mirror the Nessus XML
element and attribute names for traceability back to the source format.
"""

import os
import xml.etree.ElementTree as ET
import csv
import time
import tkinter as tk
from tkinter import filedialog
import psutil
from datetime import datetime

# Severity constants (defined once, not per iteration)
SEVERITY_MAPPING = {0: 4, 1: 3, 2: 2, 3: 1, 4: 0}
SEVERITY_RATING = {0: "Critical", 1: "High", 2: "Medium", 3: "Low", 4: "Informational"}


def get_text(parent, xpath, default=""):
    """Extract text from an XML element by XPath, returning default if not found."""
    el = parent.find(xpath)
    return el.text if el is not None else default


# Create a file dialog window for the user to select .nessus files or folder
root = tk.Tk()
root.withdraw()

# Ask user if they want to select files or a folder
choice = input("Select (1) for files or (2) for folder: ").strip()

if choice == "2":
    folder_path = filedialog.askdirectory(title="Select folder containing .nessus files")
    if not folder_path:
        print("No folder selected. Exiting.")
        exit()
    # Collect all .nessus files from folder
    nessus_files = []
    for root_dir, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.nessus'):
                nessus_files.append(os.path.join(root_dir, file))
else:
    nessus_files = list(filedialog.askopenfilenames(title="Select .nessus files to process", filetypes=[("Nessus files", "*.nessus")]))
    if not nessus_files:
        print("No files selected. Exiting.")
        exit()

# Start run timer.
start_time = time.time()

# Create an empty list to store the data.
data = []

# Function to process a single .nessus file
def process_nessus_file(file_path):
    """
    Processes a single .nessus XML file and extracts all vulnerability data.

    Parses the XML structure to extract:
    - Host properties (IP, hostname, OS, scan metadata)
    - Report items (vulnerabilities, findings, plugins)
    - Vulnerability details (CVSS scores, CVE IDs, descriptions, solutions)
    - Exploit and threat intelligence data

    The extracted data is added to the global 'data' list for later CSV export.

    Args:
        file_path: Path to the .nessus file to process
    """
    # Extract just the file name from the file path for tracking purposes
    file_name = os.path.basename(file_path)

    # Parse the XML file.
    try:
        tree = ET.parse(file_path)
    except ET.ParseError as e:
        print(f"Error parsing {file_path}: {e}")
        return

    xml_root = tree.getroot()
    print(f"Processing {file_path}")

    # Process each host.
    for host in xml_root.iter("ReportHost"):
        host_cpe = get_text(host, "HostProperties/tag[@name='cpe']")
        Credentialed_Scan = get_text(host, "HostProperties/tag[@name='Credentialed_Scan']")
        host_end = get_text(host, "HostProperties/tag[@name='HOST_END']")
        host_end_timestamp = get_text(host, "HostProperties/tag[@name='HOST_END_TIMESTAMP']")
        host_start = get_text(host, "HostProperties/tag[@name='HOST_START']")
        host_start_timestamp = get_text(host, "HostProperties/tag[@name='HOST_START_TIMESTAMP']")
        host_fqdn = get_text(host, "HostProperties/tag[@name='host-fqdn']")
        host_ip = get_text(host, "HostProperties/tag[@name='host-ip']")
        hostname = get_text(host, "HostProperties/tag[@name='hostname']")
        host_rdns = get_text(host, "HostProperties/tag[@name='host-rdns']")
        LastAuthenticatedResults = get_text(host, "HostProperties/tag[@name='LastAuthenticatedResults']")
        local_checks_proto = get_text(host, "HostProperties/tag[@name='local-checks-proto']")
        mac_address = get_text(host, "HostProperties/tag[@name='mac-address']")
        netbios_name = get_text(host, "HostProperties/tag[@name='netbios-name']")
        operating_system = get_text(host, "HostProperties/tag[@name='operating-system']")
        operating_system_conf = get_text(host, "HostProperties/tag[@name='operating-system-conf']")
        operating_system_method = get_text(host, "HostProperties/tag[@name='operating-system-method']")
        operating_system_id = get_text(host, "HostProperties/tag[@name='os']")
        patch_summary_total_cves = get_text(host, "HostProperties/tag[@name='patch-summary-total-cves']")
        policy_used = get_text(host, "HostProperties/tag[@name='policy-used']")
        sinfp_signature = get_text(host, "HostProperties/tag[@name='sinfp-signature']")
        smb_login_used = get_text(host, "HostProperties/tag[@name='smb-login-used']")
        system_type = get_text(host, "HostProperties/tag[@name='system-type']")
        virtual_mac_address = get_text(host, "HostProperties/tag[@name='virtual-mac-address']")
        wmi_domain = get_text(host, "HostProperties/tag[@name='wmi-domain']")

        # Extract scan_date from host_start
        scan_date = None
        host_start_tag = host.find('HostProperties/tag[@name="HOST_START"]')
        if host_start_tag is not None:
            host_start = host_start_tag.text
            if host_start:
                try:
                    scan_date = datetime.strptime(host_start, "%a %b %d %H:%M:%S %Y").strftime("%Y-%m-%d")
                except ValueError:
                    pass

        # Loop through each report item.
        for item in host.iter("ReportItem"):
            pluginFamily = item.attrib["pluginFamily"]
            pluginID = item.attrib["pluginID"]
            port = item.attrib["port"]
            protocol = item.attrib["protocol"]
            severity = item.attrib["severity"]

            severity_reversed = SEVERITY_MAPPING[int(severity)]
            severity_rating = SEVERITY_RATING[severity_reversed]

            svc_name = item.attrib["svc_name"]
            age_of_vuln = get_text(item, "age_of_vuln")
            agent = get_text(item, "agent")
            always_run = get_text(item, "always_run")
            asset_categories = get_text(item, "asset_categories")
            asset_inventory = get_text(item, "asset_inventory")
            asset_inventory_category = get_text(item, "asset_inventory_category")
            bid = get_text(item, "bid")
            canvas_package = get_text(item, "canvas_package")
            cea_id = get_text(item, "cea-id")
            cert = get_text(item, "cert")
            cisa_known_exploited = get_text(item, "cisa-known-exploited")
            cisa_ncas = get_text(item, "cisa-ncas")
            cisco_bug_id = get_text(item, "cisco-bug-id")
            cisco_sa = get_text(item, "cisco-sa")
            cpe = get_text(item, "cpe")
            cve_elements = item.findall('cve')
            cve = ', '.join(c.text for c in cve_elements) if cve_elements else ''
            cvss_base_score = get_text(item, "cvss_base_score")
            cvss_score_rationale = get_text(item, "cvss_score_rationale")
            cvss_score_source = get_text(item, "cvss_score_source")
            cvss_temporal_score = get_text(item, "cvss_temporal_score")
            cvss_temporal_vector = get_text(item, "cvss_temporal_vector")
            cvss_vector = get_text(item, "cvss_vector")
            cvss3_base_score = get_text(item, "cvss3_base_score")
            cvss3_score_source = get_text(item, "cvss3_score_source")
            cvss3_temporal_score = get_text(item, "cvss3_temporal_score")
            cvss3_temporal_vector = get_text(item, "cvss3_temporal_vector")
            cvss3_vector = get_text(item, "cvss3_vector")
            cvssV3_impactScore = get_text(item, "cvssV3_impactScore")
            cwe = get_text(item, "cwe")
            description = get_text(item, "description")
            edb_id = get_text(item, "edb-id")
            exploit_available = get_text(item, "exploit_available")
            exploit_code_maturity = get_text(item, "exploit_code_maturity")
            exploit_framework_canvas = get_text(item, "exploit_framework_canvas")
            exploit_framework_core = get_text(item, "exploit_framework_core")
            exploit_framework_metasploit = get_text(item, "exploit_framework_metasploit")
            exploitability_ease = get_text(item, "exploitability_ease")
            exploited_by_malware = get_text(item, "exploited_by_malware")
            exploited_by_nessus = get_text(item, "exploited_by_nessus")
            generated_plugin = get_text(item, "generated_plugin")
            hardware_inventory = get_text(item, "hardware_inventory")
            iava = get_text(item, "iava")
            iavb = get_text(item, "iavb")
            iavt = get_text(item, "iavt")
            icsa = get_text(item, "icsa")
            in_the_news = get_text(item, "in_the_news")
            metasploit_name = get_text(item, "metasploit_name")
            msft = get_text(item, "msft")
            mskb = get_text(item, "mskb")
            os_identification = get_text(item, "os_identification")
            patch_publication_date = get_text(item, "patch_publication_date")
            plugin_modification_date = get_text(item, "plugin_modification_date")
            pluginName = item.attrib.get("pluginName")
            plugin_output_element = item.find('plugin_output')
            plugin_output = plugin_output_element.text.strip() if plugin_output_element is not None and plugin_output_element.text else ""
            plugin_publication_date = get_text(item, "plugin_publication_date")
            plugin_type = get_text(item, "plugin_type")
            product_coverage = get_text(item, "product_coverage")
            risk_factor = get_text(item, "risk_factor")
            script_version = get_text(item, "script_version")
            secunia = get_text(item, "secunia")
            see_also = get_text(item, "see_also")
            solution = get_text(item, "solution")
            stig_severity = get_text(item, "stig_severity")
            synopsis = get_text(item, "synopsis")
            thorough_tests = get_text(item, "thorough_tests")
            threat_intensity_last_28 = get_text(item, "threat_intensity_last_28")
            threat_recency = get_text(item, "threat_recency")
            threat_sources_last_28 = get_text(item, "threat_sources_last_28")
            tra = get_text(item, "tra")
            unsupported_by_vendor = get_text(item, "unsupported_by_vendor")
            vmsa = get_text(item, "vmsa")
            vpr_score = get_text(item, "vpr_score")
            vuln_publication_date = get_text(item, "vuln_publication_date")

            # Column order: 106 fields matching CSV headers
            data.append([host_ip, mac_address, virtual_mac_address, hostname, netbios_name, host_fqdn, host_rdns, system_type, cpe, operating_system_id, operating_system, severity_rating, risk_factor, severity_reversed, pluginName, synopsis, description, solution, port, protocol, svc_name, plugin_output, plugin_type, plugin_publication_date, plugin_modification_date, stig_severity, cvss_base_score, cvss_vector, cvss_score_rationale, cvss_score_source, cvss_temporal_score, cvss_temporal_vector, cvss3_base_score, cvss3_vector, cvss3_score_source, cvss3_temporal_score, cvss3_temporal_vector, cvssV3_impactScore, vpr_score, patch_publication_date, patch_summary_total_cves, vuln_publication_date, age_of_vuln, product_coverage, exploit_available, exploitability_ease, exploit_code_maturity, exploit_framework_canvas, canvas_package, exploit_framework_core, exploit_framework_metasploit, metasploit_name, exploited_by_malware, exploited_by_nessus, edb_id, threat_recency, threat_intensity_last_28, threat_sources_last_28, local_checks_proto, smb_login_used, wmi_domain, thorough_tests, Credentialed_Scan, LastAuthenticatedResults, policy_used, host_start, host_start_timestamp, host_end, host_end_timestamp, os_identification, operating_system_conf, operating_system_method, sinfp_signature, pluginID, pluginFamily, script_version, agent, always_run, asset_inventory, asset_inventory_category, asset_categories, hardware_inventory, bid, cea_id, cert, cisa_known_exploited, cisa_ncas, cisco_bug_id, cisco_sa, cve, cwe, iava, iavb, iavt, icsa, msft, mskb, tra, vmsa, secunia, unsupported_by_vendor, see_also, in_the_news, generated_plugin, file_name, scan_date])

# Process all .nessus files
total_hosts = 0
for nessus_file in nessus_files:
    # Count hosts before processing
    try:
        tree = ET.parse(nessus_file)
        xml_root = tree.getroot()
        total_hosts += len(list(xml_root.iter("ReportHost")))
    except Exception:
        pass
    process_nessus_file(nessus_file)

# Define remove duplicates function.
def remove_duplicates(data):
    """
    Removes duplicate rows from the extracted vulnerability data.

    Duplicates can occur when the same vulnerability is found on the same host
    in multiple scans or when processing overlapping scan results. This function
    uses a set to identify and remove exact duplicate rows.

    Args:
        data: List of data rows (each row is a list of values)

    Returns:
        A tuple containing:
        - List of unique rows (duplicates removed)
        - Count of duplicates that were removed
    """
    unique_rows = set()
    duplicates_removed = 0
    for row in data:
        row_tuple = tuple(row)
        if row_tuple not in unique_rows:
            unique_rows.add(row_tuple)
        else:
            duplicates_removed += 1
    return [list(row_tuple) for row_tuple in unique_rows], duplicates_removed

# Remove duplicates from the data.
data, duplicates_removed = remove_duplicates(data)

# Print a message displaying the number of removed duplicates.
if duplicates_removed > 0:
    print(f"Removed {duplicates_removed} duplicate rows from the data.")
else:
    print("No duplicate rows found.")

# Define the default filename
csv_filename = "nessus_conversion.csv"

# Open a file dialog to choose the output filename and directory
csv_filename = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=csv_filename, title="Save CSV File As...")

if not csv_filename:
    print("No output file selected. Exiting.")
    exit()

# Define CSV headers matching the column order
headers = ["host_ip", "mac_address", "virtual_mac_address", "hostname", "netbios_name", "host_fqdn", "host_rdns", "system_type", "cpe", "operating_system_id", "operating_system", "severity_rating", "risk_factor", "severity_reversed", "pluginName", "synopsis", "description", "solution", "port", "protocol", "svc_name", "plugin_output", "plugin_type", "plugin_publication_date", "plugin_modification_date", "stig_severity", "cvss_base_score", "cvss_vector", "cvss_score_rationale", "cvss_score_source", "cvss_temporal_score", "cvss_temporal_vector", "cvss3_base_score", "cvss3_vector", "cvss3_score_source", "cvss3_temporal_score", "cvss3_temporal_vector", "cvssV3_impactScore", "vpr_score", "patch_publication_date", "patch_summary_total_cves", "vuln_publication_date", "age_of_vuln", "product_coverage", "exploit_available", "exploitability_ease", "exploit_code_maturity", "exploit_framework_canvas", "canvas_package", "exploit_framework_core", "exploit_framework_metasploit", "metasploit_name", "exploited_by_malware", "exploited_by_nessus", "edb_id", "threat_recency", "threat_intensity_last_28", "threat_sources_last_28", "local_checks_proto", "smb_login_used", "wmi_domain", "thorough_tests", "Credentialed_Scan", "LastAuthenticatedResults", "policy_used", "host_start", "host_start_timestamp", "host_end", "host_end_timestamp", "os_identification", "operating_system_conf", "operating_system_method", "sinfp_signature", "pluginID", "pluginFamily", "script_version", "agent", "always_run", "asset_inventory", "asset_inventory_category", "asset_categories", "hardware_inventory", "bid", "cea_id", "cert", "cisa_known_exploited", "cisa_ncas", "cisco_bug_id", "cisco_sa", "cve", "cwe", "iava", "iavb", "iavt", "icsa", "msft", "mskb", "tra", "vmsa", "secunia", "unsupported_by_vendor", "see_also", "in_the_news", "generated_plugin", "file_name", "scan_date"]

# Write the data to a CSV file with a progress indicator.
print(f"Processed {len(nessus_files)} files, {total_hosts} hosts, and {len(data)} findings.\nNow writing to CSV: {csv_filename}.")
with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(headers)
    for progress, row in enumerate(data, start=1):
        percent_complete = (progress / len(data)) * 100
        if progress % 1000 == 0 or progress == len(data):
            print(f"\rWriting data to CSV: {percent_complete:.2f}% complete ({progress}/{len(data)} rows).", end="", flush=True)
        writer.writerow(row)
print("\rWriting data to CSV: 100.00% complete.")

# Confirm completion and provide elapsed run time, peak CPU usage and peak memory usage.
print("Processing complete.")
end_time = time.time()
elapsed_time = end_time - start_time

# Calculate hours, minutes and seconds
hours = int(elapsed_time // 3600)
minutes = int((elapsed_time % 3600) // 60)
seconds = elapsed_time % 60

peak_cpu_usage = psutil.Process().cpu_percent()
mem_info = psutil.Process().memory_info()
peak_mem_usage = getattr(mem_info, 'peak_wset', mem_info.rss) / 1024 / 1024
print(f"Elapsed time: {hours} hours {minutes} minutes {seconds:.2f} seconds. Peak CPU usage: {peak_cpu_usage}%. Peak memory usage: {peak_mem_usage:.2f} MB.")
