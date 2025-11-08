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
"""

import os
import xml.etree.ElementTree as ET
import time
import tkinter as tk
from tkinter import filedialog
import psutil
import pyodbc  # type: ignore[import-not-found]
from datetime import datetime

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
    create_table_query = f'''
    IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES 
                   WHERE TABLE_SCHEMA = 'dbo' 
                   AND  TABLE_NAME = '{table_name}')
    BEGIN
        CREATE TABLE {table_name} (
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
    cursor.execute(create_table_query)
    conn.commit()

create_table_if_not_exists()

def process_nessus_file(file_path):
    """
    Processes a single .nessus XML file and prepares data for database import.
    
    Parses the XML structure to extract all vulnerability data, then batches
    the data for efficient database insertion. Uses batch processing to handle
    large files without consuming excessive memory.
    
    Args:
        file_path: Path to the .nessus file to process
    """
    # Extract just the file name from the file path for tracking in database
    file_name = os.path.basename(file_path)

    # Parse the XML file.
    try:
        tree = ET.parse(file_path)
    except ET.ParseError as e:
        print(f"Error parsing {file_path}: {e}")
        return

    root = tree.getroot()
    print(f"Processing {file_path}")

    batch = []
    batch_size = 500000  # Process 500,000 rows per batch for memory efficiency

    # Process each host.
    for host in root.iter("ReportHost"):
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
        operating_system_method= operating_system_method.text if operating_system_method is not None else ""
        operating_system_id =  host.find("HostProperties/tag[@name='os']")
        operating_system_id = operating_system_id = operating_system_id.text if operating_system_id is not None else ""
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
        virtual_mac_address=  host.find("HostProperties/tag[@name='virtual-mac-address']")
        virtual_mac_address= virtual_mac_address.text if virtual_mac_address is not None else ""
        wmi_domain =  host.find("HostProperties/tag[@name='wmi-domain']")
        wmi_domain = wmi_domain.text if wmi_domain is not None else ""
        file_path = file_name
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
                    print(f"Invalid date format for host_start: {host_start}")
                    continue

        # Loop through each report item.
        for item in host.iter("ReportItem"):
            pluginFamily = item.attrib ["pluginFamily"]
            pluginID = item.attrib ["pluginID"]
            port = item.attrib ["port"]
            protocol = item.attrib ["protocol"]
            severity = item.attrib ["severity"]

            # Define the severity mapping dictionary.
            severity_mapping = {
            0: 4,
            1: 3,
            2: 2,
            3: 1,
            4: 0
            }

            # Reverse the severity level using the severity mapping dictionary.
            severity_reversed = severity_mapping[int(severity)]

            # Replace the original severity value with the reversed value.
            severity_reversed = severity_mapping[int(severity)]

            # Get the severity rating based on the reversed severity level.
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

            # Add the data to the batch
            batch.append([host_ip, mac_address, virtual_mac_address, hostname, netbios_name, host_fqdn, host_rdns, system_type, cpe, operating_system_id, operating_system, severity_rating, risk_factor, severity_reversed, pluginName, synopsis, description, solution, port, protocol, svc_name, plugin_output, plugin_type, plugin_publication_date, plugin_modification_date, stig_severity, cvss_base_score, cvss_vector, cvss_score_rationale, cvss_score_source, cvss_temporal_score, cvss_temporal_vector, cvss3_base_score, cvss3_vector, cvss3_score_source, cvss3_temporal_score, cvss3_temporal_vector, cvssV3_impactScore, vpr_score, patch_publication_date, patch_summary_total_cves, vuln_publication_date, age_of_vuln, product_coverage, exploit_available, exploitability_ease, exploit_code_maturity, exploit_framework_canvas, canvas_package, exploit_framework_core, exploit_framework_metasploit, metasploit_name, exploited_by_malware, exploited_by_nessus, edb_id, threat_recency, threat_intensity_last_28, threat_sources_last_28, local_checks_proto, smb_login_used, wmi_domain, thorough_tests, Credentialed_Scan, LastAuthenticatedResults, policy_used, host_start, host_start_timestamp, host_end, host_end_timestamp, os_identification, operating_system_conf, operating_system_method, sinfp_signature, pluginID, pluginFamily, script_version, agent, always_run, asset_inventory, asset_inventory_category, asset_categories, hardware_inventory, bid, cea_id, cert, cisa_known_exploited, cisa_ncas, cisco_bug_id, cisco_sa, cve, cwe, iava, iavb, iavt, icsa, msft, mskb, tra, vmsa, secunia, unsupported_by_vendor, see_also, in_the_news, generated_plugin, file_path, scan_date])

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
    insert_query = f'''
    INSERT INTO {table_name} (
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

# Confirm completion and provide elapsed run time, peak CPU usage and peak memory usage.
print("Processing complete.")
end_time = time.time()
elapsed_time = end_time - start_time

# Calculate minutes and seconds
hours = int(elapsed_time // 3600)
minutes = int((elapsed_time % 3600) // 60)
seconds = elapsed_time % 60

peak_mem_usage = psutil.Process().memory_info().peak_wset / 1024 / 1024
print(f"Elapsed time: {hours} hours {minutes} minutes {seconds:.2f} seconds. Peak memory usage: {peak_mem_usage:.2f}")


# Close the database connection
cursor.close()
conn.close()