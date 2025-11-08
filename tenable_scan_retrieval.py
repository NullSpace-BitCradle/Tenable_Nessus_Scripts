"""
Tenable.io Scan Retrieval Script

This script connects to Tenable.io (cloud vulnerability management platform) via API
to retrieve and download vulnerability scan results. It allows users to:
- Authenticate with Tenable.io using API keys
- View all available scans
- Select scans interactively (single, multiple, or all)
- Export selected scans in .nessus format
- Organize downloads in a date-based directory structure (Year/Month-Name/Week-XX)

The script handles the full export workflow:
1. Initiates scan export requests
2. Monitors export status until ready
3. Downloads completed exports with progress tracking
4. Saves files with sanitized names in organized directories
"""

import requests
import datetime
import time
import logging
import os
import re
import sys

# Setup logging to track script execution and errors
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def get_api_credentials():
    """Prompt user for Tenable.io API credentials at runtime."""
    print("=" * 60)
    print("Tenable.io API Credentials")
    print("=" * 60)
    print("Enter your Tenable.io API credentials.")
    print("You can find these in Tenable.io under Settings > My Account > API Keys")
    print()
    
    access_key = input("Enter Access Key: ").strip()
    if not access_key:
        logging.error("Access Key is required. Exiting.")
        sys.exit(1)
    
    secret_key = input("Enter Secret Key: ").strip()
    if not secret_key:
        logging.error("Secret Key is required. Exiting.")
        sys.exit(1)
    
    print()
    return access_key, secret_key

# Get API credentials at runtime
ACCESS_KEY, SECRET_KEY = get_api_credentials()

HEADERS = {
    "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY};",
    "Accept": "application/json",
    "Content-Type": "application/json"
}

# Get current date info
current_date = datetime.datetime.now()
year = current_date.strftime("%Y")  # Four-digit year (e.g., "2025")
month_num = current_date.strftime("%m")  # Two-digit month (e.g., "03")
month_name = current_date.strftime("%B")  # Full month name (e.g., "March")
week_number = current_date.isocalendar().week  # ISO week number (correct calendar week)

# Construct dynamic directory structure
OUTPUT_DIR = os.path.join(year, f"{month_num}-{month_name}", f"Week-{week_number:02d}")

# Ensure all directories exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Print output directory path for verification
print(f"Output directory set to: {OUTPUT_DIR}")

def sanitize_filename(filename):
    """
    Sanitizes filenames by removing invalid characters that could cause OS issues.
    
    Replaces characters that are not allowed in Windows/Linux filenames with underscores.
    This prevents file system errors when saving downloaded scan files.
    
    Args:
        filename: The original filename that may contain invalid characters
        
    Returns:
        A sanitized filename safe for use in file systems
    """
    return re.sub(r'[\/:*?"<>|]', '_', filename)  # Replace special characters with "_"

def get_all_scans():
    """
    Fetches all available vulnerability scans from Tenable.io.
    
    Connects to the Tenable.io API to retrieve a list of all scans accessible
    with the provided API credentials. This includes all scan types (scheduled,
    on-demand, etc.) that the authenticated user has access to.
    
    Returns:
        A list of scan dictionaries containing scan metadata (id, name, etc.)
        Returns an empty list if the API call fails
    """
    scans_url = "https://cloud.tenable.com/scans"
    try:
        response = requests.get(scans_url, headers=HEADERS)
        response.raise_for_status()  # Raise an exception for bad status codes
        scans = response.json().get("scans", [])  # Extract scans array from JSON response
        logging.info(f"Found {len(scans)} scans.")
        return scans
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching scans: {e}")
        return []

def initiate_export(scan_id):
    """
    Initiates an export request for a specific scan in .nessus format.
    
    Tenable.io exports are asynchronous - this function starts the export process
    and returns a file_id that can be used to check status and download the file
    once the export is complete.
    
    Args:
        scan_id: The unique identifier of the scan to export
        
    Returns:
        The file_id string if export was initiated successfully, None otherwise
    """
    export_url = f"https://cloud.tenable.com/scans/{scan_id}/export"
    try:
        # Request export in .nessus format (XML format used by Nessus/Tenable)
        response = requests.post(export_url, headers=HEADERS, json={"format": "nessus"})
        response.raise_for_status()
        file_id = response.json().get("file")  # Extract file_id from response
        if file_id:
            logging.info(f"Export initiated for scan {scan_id}. File ID: {file_id}")
            return file_id
        else:
            logging.error(f"Failed to retrieve file ID for scan {scan_id}.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error initiating export for scan {scan_id}: {e}")
    return None

def wait_for_export(scan_id, file_id, max_retries=30, wait_time=5):
    """
    Polls the export status until the scan export is ready for download.
    
    Since Tenable.io exports are asynchronous, this function periodically checks
    the export status until it becomes "ready". This prevents attempting to download
    a file that hasn't finished exporting yet.
    
    Args:
        scan_id: The unique identifier of the scan being exported
        file_id: The file identifier returned from initiate_export()
        max_retries: Maximum number of status check attempts (default: 30)
        wait_time: Seconds to wait between status checks (default: 5)
        
    Returns:
        True if export is ready, False if timeout is reached
    """
    status_url = f"https://cloud.tenable.com/scans/{scan_id}/export/{file_id}/status"
    for attempt in range(max_retries):
        try:
            response = requests.get(status_url, headers=HEADERS)
            response.raise_for_status()
            status = response.json().get("status")
            if status == "ready":
                logging.info(f"Export ready for scan {scan_id}. File ID: {file_id}")
                return True
            logging.info(f"Waiting for export {scan_id}... (Attempt {attempt + 1}/{max_retries})")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error checking export status for scan {scan_id}: {e}")
        time.sleep(wait_time)  # Wait before next status check
    logging.error(f"Export did not complete for scan {scan_id}. Skipping.")
    return False

def download_scan(scan_id, scan_name, file_id):
    """
    Downloads the exported .nessus scan file with progress tracking.
    
    Downloads the completed export file in chunks to handle large files efficiently.
    Displays real-time progress including percentage complete and download speed.
    Files are saved to the date-organized output directory.
    
    Args:
        scan_id: The unique identifier of the scan
        scan_name: The name of the scan (used for filename)
        file_id: The file identifier from the export process
        
    Returns:
        The path to the downloaded file if successful, None otherwise
    """
    download_url = f"https://cloud.tenable.com/scans/{scan_id}/export/{file_id}/download"
    safe_scan_name = sanitize_filename(scan_name)  # Ensure valid filename
    output_file = os.path.join(OUTPUT_DIR, f"{safe_scan_name}.nessus")

    try:
        start_time = time.time()  # Start timing
        response = requests.get(download_url, headers=HEADERS, stream=True)
        response.raise_for_status()

        total_size = int(response.headers.get("Content-Length", 0))
        downloaded_size = 0
        chunk_size = 1024 * 1024  # 1MB chunks
        last_update_time = start_time

        with open(output_file, "wb") as f:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)
                    downloaded_size += len(chunk)

                    # Calculate percentage
                    percent_done = (downloaded_size / total_size) * 100 if total_size else 0

                    # Calculate speed
                    current_time = time.time()
                    elapsed_chunk_time = current_time - last_update_time
                    last_update_time = current_time

                    if elapsed_chunk_time > 0:
                        speed_mb_s = (len(chunk) / (1024 * 1024)) / elapsed_chunk_time
                    else:
                        speed_mb_s = 0

                    # Update progress in the same line (stdout instead of logging)
                    sys.stdout.write(f"\rDownloading {output_file}: {percent_done:.2f}% - Speed: {speed_mb_s:.2f} MB/s")
                    sys.stdout.flush()

        end_time = time.time()  # End timing
        elapsed_time = end_time - start_time  # Total time taken
        file_size_mb = downloaded_size / (1024 * 1024)
        avg_speed = file_size_mb / elapsed_time if elapsed_time > 0 else 0

        logging.info(f"\nDownload complete: {output_file} | Size: {file_size_mb:.2f} MB | Avg Speed: {avg_speed:.2f} MB/s")
        return output_file
    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading scan {scan_id}: {e}")
    return None

def select_scans_interactive(scans):
    """
    Displays available scans and provides interactive selection interface.
    
    Shows all available scans in a numbered list and allows the user to:
    - Select a single scan by entering its number
    - Select multiple scans by entering comma-separated numbers (e.g., 1,3,5)
    - Select all scans by entering "all"
    
    Includes validation and confirmation prompts to prevent accidental selections.
    
    Args:
        scans: List of scan dictionaries from get_all_scans()
        
    Returns:
        List of selected scan dictionaries, or empty list if none selected
    """
    if not scans:
        logging.info("No scans available to select.")
        return []
    
    print("\n" + "=" * 60)
    print("Available Scans")
    print("=" * 60)
    
    # Display all scans with numbers
    for idx, scan in enumerate(scans, 1):
        scan_id = scan.get("id")
        scan_name = scan.get("name", "Unknown Scan")
        print(f"{idx:3d}. {scan_name} (ID: {scan_id})")
    
    print("=" * 60)
    print("\nSelection Options:")
    print("  - Enter a single number (e.g., 1) to select one scan")
    print("  - Enter multiple numbers separated by commas (e.g., 1,3,5) to select multiple scans")
    print("  - Enter 'all' to select all scans")
    print()
    
    while True:
        selection = input("Enter your selection: ").strip().lower()
        
        if not selection:
            print("Please enter a selection.\n")
            continue
        
        # Handle "all" selection
        if selection == "all":
            confirmation = input(f"Select all {len(scans)} scans? (Y/N): ").strip().lower()
            if confirmation == 'y':
                return scans
            else:
                print("Selection cancelled. Please try again.\n")
                continue
        
        # Handle numeric selections
        try:
            # Split by comma and strip whitespace
            selected_numbers = [num.strip() for num in selection.split(',')]
            selected_indices = []
            
            for num_str in selected_numbers:
                num = int(num_str)
                if 1 <= num <= len(scans):
                    selected_indices.append(num - 1)  # Convert to 0-based index
                else:
                    print(f"Invalid number: {num}. Please enter numbers between 1 and {len(scans)}.\n")
                    break
            else:
                # All numbers were valid
                if not selected_indices:
                    print("No valid selections made. Please try again.\n")
                    continue
                
                # Remove duplicates while preserving order
                selected_indices = list(dict.fromkeys(selected_indices))
                selected_scans = [scans[idx] for idx in selected_indices]
                
                # Display selected scans for confirmation
                print("\nSelected scans:")
                for idx in selected_indices:
                    scan = scans[idx]
                    scan_name = scan.get("name", "Unknown Scan")
                    print(f"  - {scan_name}")
                
                confirmation = input(f"\nProceed with {len(selected_scans)} scan(s)? (Y/N): ").strip().lower()
                if confirmation == 'y':
                    return selected_scans
                else:
                    print("Selection cancelled. Please try again.\n")
                    continue
                    
        except ValueError:
            print("Invalid input. Please enter numbers separated by commas, or 'all'.\n")
            continue

def main():
    """
    Main execution function that orchestrates the scan retrieval workflow.
    
    Workflow:
    1. Fetches all available scans from Tenable.io
    2. Displays scans and allows user to select which ones to download
    3. For each selected scan:
       - Initiates export request
       - Waits for export to complete
       - Downloads the exported .nessus file
    """
    print("\n" + "=" * 60)
    print("Fetching Scans from Tenable.io")
    print("=" * 60)
    scans = get_all_scans()
    
    if not scans:
        logging.info("No scans found. Exiting.")
        return
    
    # Interactive scan selection - user chooses which scans to download
    selected_scans = select_scans_interactive(scans)
    
    if not selected_scans:
        logging.info("No scans selected. Exiting.")
        return
    
    print(f"\nProcessing {len(selected_scans)} selected scan(s)...\n")
    
    # Process each selected scan through the export and download workflow
    for scan in selected_scans:
        scan_id = scan.get("id")
        scan_name = scan.get("name", "Unknown Scan")
        
        logging.info(f"Processing scan: {scan_name} (ID: {scan_id})")
        
        # Step 1: Initiate export request
        file_id = initiate_export(scan_id)
        if not file_id:
            continue  # Skip to next scan if export initiation failed
        
        # Step 2: Wait for export to complete
        if wait_for_export(scan_id, file_id):
            # Step 3: Download the completed export
            download_scan(scan_id, scan_name, file_id)

if __name__ == "__main__":
    main()