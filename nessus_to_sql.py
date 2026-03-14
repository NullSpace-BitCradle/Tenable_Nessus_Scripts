"""
Nessus to SQL Server Database Import Script

This script converts .nessus (XML) vulnerability scan files and imports them into
a SQL Server database. It processes .nessus files from a selected folder and:

- Extracts comprehensive vulnerability data from XML structure
- Connects to SQL Server (with interactive server/database/table selection)
- Creates the target table if it doesn't exist
- Imports data in batches for efficient processing of large datasets
- Handles all vulnerability fields including host info, CVSS scores, CVE IDs, etc.

Features:
- Interactive SQL Server connection setup (queries available servers/databases/tables)
- Automatic table creation with proper schema
- Batch processing for memory efficiency (500,000 rows per batch)
- Progress tracking and performance metrics
- Processes all .nessus files in selected folder recursively

Note: Variable names (e.g., pluginName, Credentialed_Scan) mirror the Nessus XML
element and attribute names for traceability back to the source format.
"""

import os
import re
import xml.etree.ElementTree as ET
import time
import tkinter as tk
from tkinter import filedialog
import psutil
import pyodbc  # type: ignore[import-not-found]
from datetime import datetime

# Severity constants (defined once, not per iteration)
SEVERITY_MAPPING = {0: 4, 1: 3, 2: 2, 3: 1, 4: 0}
SEVERITY_RATING = {0: "Critical", 1: "High", 2: "Medium", 3: "Low", 4: "Informational"}


def get_text(parent, xpath, default=""):
    """Extract text from an XML element by XPath, returning default if not found."""
    el = parent.find(xpath)
    return el.text if el is not None else default


def sanitize_table_name(name):
    """Validate and sanitize a SQL Server table name to prevent injection."""
    # Only allow alphanumeric, underscores, and hyphens
    if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name):
        raise ValueError(f"Invalid table name: {name}")
    return name


# Create a file dialog window for the user to select a folder.
root_window = tk.Tk()
root_window.withdraw()
folder_path = filedialog.askdirectory(title="Select folder containing .nessus files")

# Start run timer.
start_time = time.time()

def get_databases(server):
    """
    Queries SQL Server for available user databases.

    Connects to the specified SQL Server instance and retrieves a list of
    all user databases (excluding system databases like master, model, etc.).
    This allows users to select which database to import data into.

    Args:
        server: SQL Server address (hostname, IP, or FQDN)

    Returns:
        List of database names, or None if connection fails
    """
    conn_str = (
        r'DRIVER={ODBC Driver 18 for SQL Server};'
        f'SERVER={server};'
        r'Trusted_Connection=yes;'
        r'TrustServerCertificate=yes;'
    )
    try:
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sys.databases WHERE database_id > 4 ORDER BY name")
        databases = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        return databases
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return None

def get_tables(server, database):
    """
    Queries a SQL Server database for available tables in the dbo schema.

    Retrieves a list of all user tables in the specified database, allowing
    users to select an existing table or create a new one for the import.

    Args:
        server: SQL Server address
        database: Name of the database to query

    Returns:
        List of table names, or None if query fails
    """
    conn_str = (
        r'DRIVER={ODBC Driver 18 for SQL Server};'
        f'SERVER={server};'
        f'DATABASE={database};'
        r'Trusted_Connection=yes;'
        r'TrustServerCertificate=yes;'
    )
    try:
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT TABLE_NAME
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_TYPE = 'BASE TABLE'
            AND TABLE_SCHEMA = 'dbo'
            ORDER BY TABLE_NAME
        """)
        tables = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        return tables
    except Exception as e:
        print(f"Error querying tables: {e}")
        return None

def select_from_list(items, item_type="item"):
    """
    Provides an interactive selection interface from a list of items.

    Displays numbered options and prompts user to select one, with validation
    and confirmation to prevent accidental selections. Used for selecting
    databases and tables.

    Args:
        items: List of items to choose from
        item_type: Type name for display purposes (e.g., "database", "table")

    Returns:
        The selected item, or None if selection is cancelled
    """
    if not items:
        print(f"No {item_type}s found.")
        return None

    print(f"\nAvailable {item_type}s:")
    for idx, item in enumerate(items, 1):
        print(f"{idx}. {item}")

    while True:
        try:
            choice = input(f"\nEnter the number of your choice (1-{len(items)}): ").strip()
            choice_num = int(choice)
            if 1 <= choice_num <= len(items):
                selected = items[choice_num - 1]
                confirmation = input(f"You have selected '{selected}'. Is this correct? (Y/N): ").strip().lower()
                if confirmation == 'y':
                    return selected
                else:
                    print("Let's try again.\n")
            else:
                print(f"Invalid selection. Please enter a number between 1 and {len(items)}.\n")
        except ValueError:
            print("Invalid input. Please enter a number.\n")

# Get server information
print("=" * 60)
print("SQL Server Connection Setup")
print("=" * 60)
server = input("Enter SQL Server address (e.g., localhost, 10.10.30.20, or server.domain.com): ").strip()
if not server:
    print("Server address is required. Exiting.")
    exit(1)

# Query and select database
print(f"\nConnecting to server '{server}' to retrieve databases...")
databases = get_databases(server)
if databases is None:
    print("Failed to retrieve databases. Exiting.")
    exit(1)

database = select_from_list(databases, "database")
if not database:
    print("No database selected. Exiting.")
    exit(1)

# Query and select table
print(f"\nConnecting to database '{database}' to retrieve tables...")
tables = get_tables(server, database)
if tables is None:
    print("Failed to retrieve tables. Exiting.")
    exit(1)

table_name = select_from_list(tables, "table")
if not table_name:
    print("No table selected. Exiting.")
    exit(1)

# Validate table name to prevent SQL injection
table_name = sanitize_table_name(table_name)

print(f"\nProceeding with:")
print(f"  Server: {server}")
print(f"  Database: {database}")
print(f"  Table: {table_name}")
print("=" * 60)

# Establish database connection
conn_str = (
    r'DRIVER={ODBC Driver 18 for SQL Server};'
    f'SERVER={server};'
    f'DATABASE={database};'
    r'Trusted_Connection=yes;'
    r'TrustServerCertificate=yes;'
)

conn = pyodbc.connect(conn_str)
cursor = conn.cursor()

def create_table_if_not_exists():
    """
    Creates the target table in SQL Server if it doesn't already exist.

    Defines a comprehensive schema with all vulnerability data fields including:
    - Host information (IP, hostname, MAC, OS details)
    - Vulnerability details (plugin info, severity, CVSS scores)
    - CVE and security reference IDs
    - Exploit and threat intelligence data
    - Scan metadata (dates, policy, credentials)

    Uses IF NOT EXISTS to avoid errors if the table already exists.
    """
    # Table name is validated by sanitize_table_name() — safe for bracket-quoting
    create_table_query = f'''
    IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES
                   WHERE TABLE_SCHEMA = 'dbo'
                   AND  TABLE_NAME = ?)
    BEGIN
        CREATE TABLE [{table_name}] (
        host_ip VARCHAR(200),
        mac_address NVARCHAR(MAX),
        virtual_mac_address NVARCHAR(1000),
        hostname VARCHAR(100),
        netbios_name VARCHAR(100),
        host_fqdn VARCHAR(150),
        host_rdns VARCHAR(150),
        system_type VARCHAR(25),
        cpe VARCHAR(1000),
        operating_system_id VARCHAR(150),
        operating_system VARCHAR(200),
        severity_rating VARCHAR(15),
        risk_factor VARCHAR(15),
        severity_reversed INT,
        pluginName VARCHAR(MAX),
        synopsis VARCHAR(255),
        description VARCHAR(MAX),
        solution VARCHAR(MAX),
        port INT,
        protocol VARCHAR(15),
        svc_name VARCHAR(150),
        plugin_output VARCHAR(MAX),
        plugin_type VARCHAR(15),
        plugin_publication_date DATE,
        plugin_modification_date DATE,
        stig_severity VARCHAR(100),
        cvss_base_score VARCHAR(100),
        cvss_vector VARCHAR(150),
        cvss_score_rationale VARCHAR(500),
        cvss_score_source VARCHAR(100),
        cvss_temporal_score VARCHAR(100),
        cvss_temporal_vector VARCHAR(100),
        cvss3_base_score VARCHAR(100),
        cvss3_vector VARCHAR(150),
        cvss3_score_source VARCHAR(100),
        cvss3_temporal_score VARCHAR(100),
        cvss3_temporal_vector VARCHAR(100),
        cvssV3_impactScore VARCHAR(100),
        vpr_score VARCHAR(100),
        patch_publication_date DATE,
        patch_summary_total_cves VARCHAR(150),
        vuln_publication_date DATE,
        age_of_vuln VARCHAR(100),
        product_coverage VARCHAR(150),
        exploit_available VARCHAR(15),
        exploitability_ease VARCHAR(150),
        exploit_code_maturity VARCHAR(150),
        exploit_framework_canvas VARCHAR(15),
        canvas_package VARCHAR(150),
        exploit_framework_core VARCHAR(15),
        exploit_framework_metasploit VARCHAR(15),
        metasploit_name VARCHAR(150),
        exploited_by_malware VARCHAR(15),
        exploited_by_nessus VARCHAR(15),
        edb_id VARCHAR(150),
        threat_recency VARCHAR(150),
        threat_intensity_last_28 VARCHAR(150),
        threat_sources_last_28 VARCHAR(150),
        local_checks_proto VARCHAR(15),
        smb_login_used VARCHAR(150),
        wmi_domain VARCHAR(150),
        thorough_tests VARCHAR(150),
        Credentialed_Scan VARCHAR(15),
        LastAuthenticatedResults VARCHAR(50),
        policy_used VARCHAR(150),
        host_start VARCHAR(150),
        host_start_timestamp INT,
        host_end VARCHAR(150),
        host_end_timestamp INT,
        os_identification VARCHAR(150),
        operating_system_conf VARCHAR(150),
        operating_system_method VARCHAR(150),
        sinfp_signature VARCHAR(250),
        pluginID INT,
        pluginFamily VARCHAR(150),
        script_version VARCHAR(150),
        agent VARCHAR(150),
        always_run VARCHAR(150),
        asset_inventory VARCHAR(150),
        asset_inventory_category VARCHAR(150),
        asset_categories VARCHAR(150),
        hardware_inventory VARCHAR(150),
        bid VARCHAR(150),
        cea_id VARCHAR(150),
        cert VARCHAR(150),
        cisa_known_exploited VARCHAR(150),
        cisa_ncas VARCHAR(150),
        cisco_bug_id VARCHAR(150),
        cisco_sa VARCHAR(150),
        cve NVARCHAR(4000),
        cwe VARCHAR(150),
        iava VARCHAR(150),
        iavb VARCHAR(150),
        iavt VARCHAR(150),
        icsa VARCHAR(150),
        msft VARCHAR(150),
        mskb VARCHAR(150),
        tra VARCHAR(150),
        vmsa VARCHAR(150),
        secunia VARCHAR(150),
        unsupported_by_vendor VARCHAR(15),
        see_also VARCHAR(MAX),
        in_the_news VARCHAR(15),
        generated_plugin VARCHAR(150),
        file_path VARCHAR(255),
        scan_date DATE
        )
    END
    '''
    cursor.execute(create_table_query, (table_name,))
    conn.commit()

create_table_if_not_exists()

def process_nessus_file(nessus_file_path):
    """
    Processes a single .nessus XML file and prepares data for database import.

    Parses the XML structure to extract all vulnerability data, then batches
    the data for efficient database insertion. Uses batch processing to handle
    large files without consuming excessive memory.

    Args:
        nessus_file_path: Path to the .nessus file to process
    """
    # Extract just the file name from the file path for tracking in database
    file_name = os.path.basename(nessus_file_path)

    # Parse the XML file.
    try:
        tree = ET.parse(nessus_file_path)
    except ET.ParseError as e:
        print(f"Error parsing {nessus_file_path}: {e}")
        return

    root = tree.getroot()
    print(f"Processing {nessus_file_path}")

    batch = []
    batch_size = 500000  # Process 500,000 rows per batch for memory efficiency

    # Process each host.
    for host in root.iter("ReportHost"):
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

        scan_date = None
        host_start_tag = host.find('HostProperties/tag[@name="HOST_START"]')
        if host_start_tag is not None:
            host_start = host_start_tag.text
            if host_start:
                try:
                    scan_date = datetime.strptime(host_start, "%a %b %d %H:%M:%S %Y").strftime("%Y-%m-%d")
                except ValueError:
                    print(f"Invalid date format for host_start: {host_start}")
                    continue

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

            # Column order: 106 fields matching CREATE TABLE and INSERT column order
            batch.append([host_ip, mac_address, virtual_mac_address, hostname, netbios_name, host_fqdn, host_rdns, system_type, cpe, operating_system_id, operating_system, severity_rating, risk_factor, severity_reversed, pluginName, synopsis, description, solution, port, protocol, svc_name, plugin_output, plugin_type, plugin_publication_date, plugin_modification_date, stig_severity, cvss_base_score, cvss_vector, cvss_score_rationale, cvss_score_source, cvss_temporal_score, cvss_temporal_vector, cvss3_base_score, cvss3_vector, cvss3_score_source, cvss3_temporal_score, cvss3_temporal_vector, cvssV3_impactScore, vpr_score, patch_publication_date, patch_summary_total_cves, vuln_publication_date, age_of_vuln, product_coverage, exploit_available, exploitability_ease, exploit_code_maturity, exploit_framework_canvas, canvas_package, exploit_framework_core, exploit_framework_metasploit, metasploit_name, exploited_by_malware, exploited_by_nessus, edb_id, threat_recency, threat_intensity_last_28, threat_sources_last_28, local_checks_proto, smb_login_used, wmi_domain, thorough_tests, Credentialed_Scan, LastAuthenticatedResults, policy_used, host_start, host_start_timestamp, host_end, host_end_timestamp, os_identification, operating_system_conf, operating_system_method, sinfp_signature, pluginID, pluginFamily, script_version, agent, always_run, asset_inventory, asset_inventory_category, asset_categories, hardware_inventory, bid, cea_id, cert, cisa_known_exploited, cisa_ncas, cisco_bug_id, cisco_sa, cve, cwe, iava, iavb, iavt, icsa, msft, mskb, tra, vmsa, secunia, unsupported_by_vendor, see_also, in_the_news, generated_plugin, file_name, scan_date])

            # If the batch is full, insert it into the database
            if len(batch) >= batch_size:
                insert_batch(batch)
                batch = []

    # Insert any remaining items in the batch
    if batch:
        insert_batch(batch)

def insert_batch(batch):
    """
    Inserts a batch of vulnerability data rows into the SQL Server database.

    Uses parameterized queries with executemany() for efficient bulk insertion.
    This method is much faster than inserting rows one at a time.

    Args:
        batch: List of data rows to insert (each row is a list of values)
    """
    # Table name validated by sanitize_table_name() — safe for bracket-quoting
    insert_query = f'''
    INSERT INTO [{table_name}] (
        host_ip, mac_address, virtual_mac_address, hostname, netbios_name, host_fqdn, host_rdns, system_type, cpe, operating_system_id, operating_system, severity_rating, risk_factor, severity_reversed, pluginName, synopsis, description, solution, port, protocol, svc_name, plugin_output, plugin_type, plugin_publication_date, plugin_modification_date, stig_severity, cvss_base_score, cvss_vector, cvss_score_rationale, cvss_score_source, cvss_temporal_score, cvss_temporal_vector, cvss3_base_score, cvss3_vector, cvss3_score_source, cvss3_temporal_score, cvss3_temporal_vector, cvssV3_impactScore, vpr_score, patch_publication_date, patch_summary_total_cves, vuln_publication_date, age_of_vuln, product_coverage, exploit_available, exploitability_ease, exploit_code_maturity, exploit_framework_canvas, canvas_package, exploit_framework_core, exploit_framework_metasploit, metasploit_name, exploited_by_malware, exploited_by_nessus, edb_id, threat_recency, threat_intensity_last_28, threat_sources_last_28, local_checks_proto, smb_login_used, wmi_domain, thorough_tests, Credentialed_Scan, LastAuthenticatedResults, policy_used, host_start, host_start_timestamp, host_end, host_end_timestamp, os_identification, operating_system_conf, operating_system_method, sinfp_signature, pluginID, pluginFamily, script_version, agent, always_run, asset_inventory, asset_inventory_category, asset_categories, hardware_inventory, bid, cea_id, cert, cisa_known_exploited, cisa_ncas, cisco_bug_id, cisco_sa, cve, cwe, iava, iavb, iavt, icsa, msft, mskb, tra, vmsa, secunia, unsupported_by_vendor, see_also, in_the_news, generated_plugin, file_path, scan_date
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    '''
    cursor.executemany(insert_query, batch)
    conn.commit()

# Process all .nessus files in the selected folder and its subfolders
for root, dirs, files in os.walk(folder_path):
    for file in files:
        if file.endswith('.nessus'):
            file_path = os.path.join(root, file)
            process_nessus_file(file_path)

# Confirm completion and provide elapsed run time and peak memory usage.
print("Processing complete.")
end_time = time.time()
elapsed_time = end_time - start_time

# Calculate minutes and seconds
hours = int(elapsed_time // 3600)
minutes = int((elapsed_time % 3600) // 60)
seconds = elapsed_time % 60

mem_info = psutil.Process().memory_info()
peak_mem_usage = getattr(mem_info, 'peak_wset', mem_info.rss) / 1024 / 1024
print(f"Elapsed time: {hours} hours {minutes} minutes {seconds:.2f} seconds. Peak memory usage: {peak_mem_usage:.2f} MB.")

# Close the database connection
cursor.close()
conn.close()
