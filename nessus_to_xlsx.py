"""
Nessus to Excel (XLSX) Conversion Script

This script converts .nessus (XML) vulnerability scan files into Microsoft Excel
format (.xlsx) with formatted tables for easy analysis. It processes .nessus files
and extracts comprehensive vulnerability data, then creates a formatted Excel
workbook with:

- Formatted table with alternating row colors for readability
- All vulnerability data in structured columns
- Host information, vulnerability details, CVSS scores, CVE IDs
- Exploit information and security references

Features:
- Creates formatted Excel tables with professional styling
- Supports processing multiple .nessus files
- Removes duplicate findings automatically
- Provides progress tracking and performance metrics
"""

# Import required libraries.
import os
import xml.etree.ElementTree as ET
from openpyxl import Workbook
from openpyxl.worksheet.table import Table, TableStyleInfo
import time
import tkinter as tk
from tkinter import filedialog
import psutil
from datetime import datetime

# Create a file dialog window for the user to select multiple XML files.
root = tk.Tk()
root.withdraw()
xml_files = filedialog.askopenfilenames(title="Select files to process",filetypes=[("Nessus files", "*.nessus")])

# Start run timer.
start_time = time.time()

# Create an empty list to store the data.
data = []

# Loop through each XML file.
for xml_file in xml_files:
    # Extract just the file name from the file path
    file_name = os.path.basename(xml_file)

    # Parse the XML file.
    tree = ET.parse(xml_file)
    xml_root = tree.getroot()
    print(f"Processing {xml_file}")

    # Get the total number of hosts.
    total_hosts = len(list(xml_root.iter("ReportHost")))

    # Process each host.
    for i, host in enumerate(xml_root.iter("ReportHost"), 1):
        cpe =  host.find("HostProperties/tag[@name='cpe']")
        cpe = cpe.text if cpe is not None else ""
        Credentialed_Scan =  host.find("HostProperties/tag[@name='Credentialed_Scan']")
        Credentialed_Scan = Credentialed_Scan.text if Credentialed_Scan is not None else ""
        host_end =  host.find("HostProperties/tag[@name='HOST_END']")
        host_end = host_end.text if host_end is not None else ""
        host_end_timestamp =  host.find("HostProperties/tag[@name='HOST_END_TIMESTAMP']")
        host_end_timestamp = host_end_timestamp.text if host_end_timestamp is not None else ""
        host_start =  host.find("HostProperties/tag[@name='HOST_START']")
        host_start = host_start.text if host_start is not None else ""
        host_start_timestamp =  host.find("HostProperties/tag[@name='HOST_START_TIMESTAMP']")
        host_start_timestamp = host_start_timestamp.text if host_start_timestamp is not None else ""
        host_fqdn =  host.find("HostProperties/tag[@name='host-fqdn']")
        host_fqdn = host_fqdn.text if host_fqdn is not None else ""
        host_ip =  host.find("HostProperties/tag[@name='host-ip']")
        host_ip = host_ip.text if host_ip is not None else ""
        hostname =  host.find("HostProperties/tag[@name='hostname']")
        hostname = hostname.text if hostname is not None else ""
        host_rdns =  host.find("HostProperties/tag[@name='host-rdns']")
        host_rdns = host_rdns.text if host_rdns is not None else ""
        LastAuthenticatedResults =  host.find("HostProperties/tag[@name='LastAuthenticatedResults']")
        LastAuthenticatedResults = LastAuthenticatedResults.text if LastAuthenticatedResults is not None else ""
        local_checks_proto =  host.find("HostProperties/tag[@name='local-checks-proto']")
        local_checks_proto = local_checks_proto.text if local_checks_proto is not None else ""
        mac_address =  host.find("HostProperties/tag[@name='mac-address']")
        mac_address = mac_address.text if mac_address is not None else ""
        netbios_name =  host.find("HostProperties/tag[@name='netbios-name']")
        netbios_name = netbios_name.text if netbios_name is not None else ""
        operating_system =  host.find("HostProperties/tag[@name='operating-system']")
        operating_system = operating_system.text if operating_system is not None else ""   
        operating_system_conf =  host.find("HostProperties/tag[@name='operating-system-conf']")
        operating_system_conf = operating_system_conf.text if operating_system_conf is not None else ""
        operating_system_method =  host.find("HostProperties/tag[@name='operating-system-method']")
        operating_system_method = operating_system_method.text if operating_system_method is not None else ""
        operating_system_id =  host.find("HostProperties/tag[@name='os']")
        operating_system_id = operating_system_id.text if operating_system_id is not None else ""
        patch_summary_total_cves =  host.find("HostProperties/tag[@name='patch-summary-total-cves']")
        patch_summary_total_cves = patch_summary_total_cves.text if patch_summary_total_cves is not None else ""
        policy_used =  host.find("HostProperties/tag[@name='policy-used']")
        policy_used = policy_used.text if policy_used is not None else ""
        sinfp_signature =  host.find("HostProperties/tag[@name='sinfp-signature']")
        sinfp_signature = sinfp_signature.text if sinfp_signature is not None else ""
        smb_login_used =  host.find("HostProperties/tag[@name='smb-login-used']")
        smb_login_used = smb_login_used.text if smb_login_used is not None else ""
        system_type =  host.find("HostProperties/tag[@name='system-type']")
        system_type = system_type.text if system_type is not None else ""
        virtual_mac_address =  host.find("HostProperties/tag[@name='virtual-mac-address']")
        virtual_mac_address = virtual_mac_address.text if virtual_mac_address is not None else ""
        wmi_domain =  host.find("HostProperties/tag[@name='wmi-domain']")
        wmi_domain = wmi_domain.text if wmi_domain is not None else ""
        
        # Extract scan_date from host_start
        scan_date = None
        host_start_tag = host.find('HostProperties/tag[@name="HOST_START"]')
        if host_start_tag is not None:
            host_start = host_start_tag.text
            if host_start:
                try:
                    # Extract the date from the host_start timestamp
                    scan_date = datetime.strptime(host_start, "%a %b %d %H:%M:%S %Y").strftime("%Y-%m-%d")
                except ValueError:
                    # Handle case where the timestamp format is incorrect
                    pass

        # Loop through each report item
        for item in host.iter("ReportItem"):
            pluginFamily = item.attrib ["pluginFamily"]
            pluginID = item.attrib ["pluginID"]
            port = item.attrib ["port"]
            protocol = item.attrib ["protocol"]
            severity = item.attrib ["severity"]

            # Define the severity mapping dictionary
            severity_mapping = {
            0: 4,
            1: 3,
            2: 2,
            3: 1,
            4: 0
            }

            # Reverse the severity level using the severity mapping dictionary
            severity_reversed = severity_mapping[int(severity)]

            # Get the severity rating based on the reversed severity level
            severity_rating = {0: "Critical", 1: "High", 2: "Medium", 3: "Low", 4: "Informational"}[severity_reversed]

            svc_name = item.attrib ["svc_name"]
            age_of_vuln = item.find("age_of_vuln").text if item.find("age_of_vuln") is not None else ""
            agent = item.find("agent").text if item.find("agent") is not None else ""
            always_run = item.find("always_run").text if item.find("always_run") is not None else ""
            asset_categories = item.find("asset_categories").text if item.find("asset_categories") is not None else ""
            asset_inventory = item.find("asset_inventory").text if item.find("asset_inventory") is not None else ""
            asset_inventory_category = item.find("asset_inventory_category").text if item.find("asset_inventory_category") is not None else ""
            bid = item.find("bid").text if item.find("bid") is not None else ""
            canvas_package = item.find("canvas_package").text if item.find("canvas_package") is not None else ""
            cea_id = item.find("cea-id").text if item.find("cea-id") is not None else ""
            cert = item.find("cert").text if item.find("cert") is not None else ""
            cisa_known_exploited = item.find("cisa-known-exploited").text if item.find("cisa-known-exploited") is not None else ""
            cisa_ncas = item.find("cisa-ncas").text if item.find("cisa-ncas") is not None else ""
            cisco_bug_id = item.find("cisco-bug-id").text if item.find("cisco-bug-id") is not None else ""
            cisco_sa = item.find("cisco-sa").text if item.find("cisco-sa") is not None else ""
            cpe = item.find("cpe").text if item.find("cpe") is not None else ""
            cve = ', '.join(cve.text for cve in item.findall('cve')) if item.findall('cve') else ''
            cvss_base_score = item.find("cvss_base_score").text if item.find("cvss_base_score") is not None else ""
            cvss_score_rationale = item.find("cvss_score_rationale").text if item.find("cvss_score_rationale") is not None else ""
            cvss_score_source = item.find("cvss_score_source").text if item.find("cvss_score_source") is not None else ""
            cvss_temporal_score = item.find("cvss_temporal_score").text if item.find("cvss_temporal_score") is not None else ""
            cvss_temporal_vector = item.find("cvss_temporal_vector").text if item.find("cvss_temporal_vector") is not None else ""
            cvss_vector = item.find("cvss_vector").text if item.find("cvss_vector") is not None else ""
            cvss3_base_score = item.find("cvss3_base_score").text if item.find("cvss3_base_score") is not None else ""
            cvss3_score_source = item.find("cvss3_score_source").text if item.find("cvss3_score_source") is not None else ""
            cvss3_temporal_score = item.find("cvss3_temporal_score").text if item.find("cvss3_temporal_score") is not None else ""
            cvss3_temporal_vector = item.find("cvss3_temporal_vector").text if item.find("cvss3_temporal_vector") is not None else ""
            cvss3_vector = item.find("cvss3_vector").text if item.find("cvss3_vector") is not None else ""
            cvssV3_impactScore = item.find("cvssV3_impactScore").text if item.find("cvssV3_impactScore") is not None else ""
            cwe = item.find("cwe").text if item.find("cwe") is not None else ""
            description = item.find("description").text if item.find("description") is not None else ""
            edb_id = item.find("edb-id").text if item.find("edb-id") is not None else ""
            exploit_available = item.find("exploit_available").text if item.find("exploit_available") is not None else ""
            exploit_code_maturity = item.find("exploit_code_maturity").text if item.find("exploit_code_maturity") is not None else ""
            exploit_framework_canvas = item.find("exploit_framework_canvas").text if item.find("exploit_framework_canvas") is not None else ""
            exploit_framework_core = item.find("exploit_framework_core").text if item.find("exploit_framework_core") is not None else ""
            exploit_framework_metasploit = item.find("exploit_framework_metasploit").text if item.find("exploit_framework_metasploit") is not None else ""
            exploitability_ease = item.find("exploitability_ease").text if item.find("exploitability_ease") is not None else ""
            exploited_by_malware = item.find("exploited_by_malware").text if item.find("exploited_by_malware") is not None else ""
            exploited_by_nessus = item.find("exploited_by_nessus").text if item.find("exploited_by_nessus") is not None else ""
            generated_plugin = item.find("generated_plugin").text if item.find("generated_plugin") is not None else ""
            hardware_inventory = item.find("hardware_inventory").text if item.find("hardware_inventory") is not None else ""
            iava = item.find("iava").text if item.find("iava") is not None else ""
            iavb = item.find("iavb").text if item.find("iavb") is not None else ""
            iavt = item.find("iavt").text if item.find("iavt") is not None else ""
            icsa = item.find("icsa").text if item.find("icsa") is not None else ""
            in_the_news = item.find("in_the_news").text if item.find("in_the_news") is not None else ""
            metasploit_name = item.find("metasploit_name").text if item.find("metasploit_name") is not None else ""
            msft = item.find("msft").text if item.find("msft") is not None else ""
            mskb = item.find("mskb").text if item.find("mskb") is not None else ""
            os_identification = item.find("os_identification").text if item.find("os_identification") is not None else ""
            patch_publication_date = item.find("patch_publication_date").text if item.find("patch_publication_date") is not None else ""
            plugin_modification_date = item.find("plugin_modification_date").text if item.find("plugin_modification_date") is not None else ""
            pluginName = item.attrib.get("pluginName")
            plugin_output_element = item.find('plugin_output')
            plugin_output = plugin_output_element.text.strip() if plugin_output_element is not None and plugin_output_element.text else ""
            plugin_publication_date = item.find("plugin_publication_date").text if item.find("plugin_publication_date") is not None else ""
            plugin_type = item.find("plugin_type").text if item.find("plugin_type") is not None else ""
            product_coverage = item.find("product_coverage").text if item.find("product_coverage") is not None else ""
            risk_factor = item.find("risk_factor").text if item.find("risk_factor") is not None else ""
            script_version = item.find("script_version").text if item.find("script_version") is not None else ""
            secunia = item.find("secunia").text if item.find("secunia") is not None else ""
            see_also = item.find("see_also").text if item.find("see_also") is not None else ""
            if see_also is None:
                see_also = ""
            solution = item.find("solution").text if item.find("solution") is not None else ""
            stig_severity = item.find("stig_severity").text if item.find("stig_severity") is not None else ""
            synopsis = item.find("synopsis").text if item.find("synopsis") is not None else ""
            thorough_tests = item.find("thorough_tests").text if item.find("thorough_tests") is not None else ""
            threat_intensity_last_28 = item.find("threat_intensity_last_28").text if item.find("threat_intensity_last_28") is not None else ""
            threat_recency = item.find("threat_recency").text if item.find("threat_recency") is not None else ""
            threat_sources_last_28 = item.find("threat_sources_last_28").text if item.find("threat_sources_last_28") is not None else ""
            tra = item.find("tra").text if item.find("tra") is not None else ""
            unsupported_by_vendor = item.find("unsupported_by_vendor").text if item.find("unsupported_by_vendor") is not None else ""
            vmsa = item.find("vmsa").text if item.find("vmsa") is not None else ""
            vpr_score = item.find("vpr_score").text if item.find("vpr_score") is not None else ""
            vuln_publication_date = item.find("vuln_publication_date").text if item.find("vuln_publication_date") is not None else ""

            # Add the data to the list
            data.append([host_ip, mac_address, virtual_mac_address, hostname, netbios_name, host_fqdn, host_rdns, system_type, cpe, operating_system_id, operating_system, severity_rating, risk_factor, severity_reversed, pluginName, synopsis, description, solution, port, protocol, svc_name, plugin_output, plugin_type, plugin_publication_date, plugin_modification_date, stig_severity, cvss_base_score, cvss_vector, cvss_score_rationale, cvss_score_source, cvss_temporal_score, cvss_temporal_vector, cvss3_base_score, cvss3_vector, cvss3_score_source, cvss3_temporal_score, cvss3_temporal_vector, cvssV3_impactScore, vpr_score, patch_publication_date, patch_summary_total_cves, vuln_publication_date, age_of_vuln, product_coverage, exploit_available, exploitability_ease, exploit_code_maturity, exploit_framework_canvas, canvas_package, exploit_framework_core, exploit_framework_metasploit, metasploit_name, exploited_by_malware, exploited_by_nessus, edb_id, threat_recency, threat_intensity_last_28, threat_sources_last_28, local_checks_proto, smb_login_used, wmi_domain, thorough_tests, Credentialed_Scan, LastAuthenticatedResults, policy_used, host_start, host_start_timestamp, host_end, host_end_timestamp, os_identification, operating_system_conf, operating_system_method, sinfp_signature, pluginID, pluginFamily, script_version, agent, always_run, asset_inventory, asset_inventory_category, asset_categories, hardware_inventory, bid, cea_id, cert, cisa_known_exploited, cisa_ncas, cisco_bug_id, cisco_sa, cve, cwe, iava, iavb, iavt, icsa, msft, mskb, tra, vmsa, secunia, unsupported_by_vendor, see_also, in_the_news, generated_plugin, file_name, scan_date])

# Define remove duplicates function.
def remove_duplicates(data):
    """
    Removes duplicate rows from the extracted vulnerability data.
    
    Duplicates can occur when the same vulnerability is found on the same host
    in multiple scans. This function uses a set to identify and remove exact
    duplicate rows before writing to Excel.
    
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
        # Convert the row to a tuple so it can be added to the set (sets require hashable types)
        row_tuple = tuple(row)
        if row_tuple not in unique_rows:
            unique_rows.add(row_tuple)
        else:
            duplicates_removed += 1
    # Convert the set back to a list and return it along with the number of removed duplicates.
    return [list(row_tuple) for row_tuple in unique_rows], duplicates_removed

# Remove duplicates from the data.
data, duplicates_removed = remove_duplicates(data)

# Print a message displaying the number of removed duplicates.
if duplicates_removed > 0:
    print(f"Removed {duplicates_removed} duplicate rows from the data.")
else:
    print("No duplicate rows found.")

# Define the default filename
xlsx_filename = "nessus_conversion.xlsx"

# Open a file dialog to choose the output filename and directory
xlsx_filename = filedialog.asksaveasfilename(defaultextension=".xlsx", initialfile=xlsx_filename, title="Save XLSX File As...")

# Write the data to an XLSX file with a progress indicator.
print(f"Processed {len(xml_files)} files, {total_hosts} hosts, and {len(data)} findings.\nNow writing to XLSX: {xlsx_filename}.")
wb = Workbook()
ws = wb.active
ws.append(["IP Address", "MAC Address", "Virtual MAC Address", "Hostname", "NETBIOS", "FQDN", "RDNS", "System Type", "CPE", "OS Family", "Operating System", "Severity Rating", "Risk Factor", "Severity Number", "Plugin Name", "Synopsis", "Description", "Solution", "Port", "Protocol", "Service Name", "Plugin Output", "Plugin Type", "Plugin Publication Date", "Plugin Modification Date", "STIG Severity", "CVSS Score", "CVSS Vector", "CVSS Score Rationale", "CVSS Score Source", "CVSS Temporal Score", "CVSS Temporal Vector", "CVSS3 Score", "CVSS3 Vector", "CVSS3 Score Source", "CVSS3 Temporal Score", "CVSS3 Temporal Vector", "CVSS3 Impact Score", "VPR Score", "Patch Publication Date", "Patch Summary CVE Count", "Vulnerability Publication Date", "Vulnerability Age", "Product Coverage", "Exploit Available", "Exploitability Ease", "Exploit Code Maturity", "Exploitable with CANVAS", "CANVAS Package", "Exploitable with Core Impact", "Exploitable with Metasploit", "Metasploit Module", "Exploitable by Malware", "Exploitable by Nessus", "Exploit DB ID", "Threat Recency", "Threat Intensity Last 28 Days", "Threat Sources Last 28 Days", "Local Checks Protocol", "SMB Login Used", "WMI Domain", "Thorough Tests Used", "Credentialed Scan Used", "Authentication Issues", "Policy Used", "Host Scan Started", "Host Scan Started Timestamp", "Host Scan Ended", "Host Scan Ended Timestamp", "OS Identified", "Operating System Confidence", "OS Identification Method", "SinFP Signature", "Plugin ID", "Plugin Family", "Script Version", "Agent Used", "Always Run", "Asset Inventory", "Asset Inventory Category", "Asset Categories", "Hardware Inventory", "BugtraqID", "CEA Id", "CERT", "CISA Known Exploited", "CISA NCAS", "Cisco Bug ID", "Cisco Security Advisory", "CVE", "CWE", "IAVA", "IAVB", "IAVT", "ICSA", "MSFT", "MSKB", "Trust Research Advisory", "VMWare Security Advisory", "Secunia Security Advisory", "Unsupported by Vendor", "See Also", "In The News", "Generated Plugin", "File Path", "Scan Date"])
for progress, row in enumerate(data, start=1):
    percent_complete = (progress / len(data)) * 100
    print(f"\rWriting data to XLSX: {percent_complete:.2f}% complete.", end="", flush=True)
    ws.append(row)
print("\rWriting data to XLSX: 100.00% complete.")

# Define the table range and create the table
print("Converting XLSX data to table")
table_range = f"A1:{ws.cell(row=ws.max_row, column=ws.max_column).coordinate}"
table = Table(displayName="Table1", ref=table_range)

# Define the table style
style = TableStyleInfo(name="TableStyleMedium2", showFirstColumn=False, showLastColumn=False, showRowStripes=True, showColumnStripes=False)

# Apply the table style and save the file
table.tableStyleInfo = style
ws.add_table(table)
wb.save(xlsx_filename)

# Confirm completion and provide elapsed run time, peak CPU usage and peak memory usage.
print("Processing complete.")
end_time = time.time()
elapsed_time = end_time - start_time
peak_cpu_usage = psutil.Process().cpu_percent()
peak_mem_usage = psutil.Process().memory_info().peak_wset / 1024 / 1024
print(f"Elapsed time: {elapsed_time:.2f} seconds. Peak CPU usage: {peak_cpu_usage}%. Peak memory usage: {peak_mem_usage:.2f} MB.")