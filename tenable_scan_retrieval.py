"""
Tenable.io Scan Retrieval Script

Connects to Tenable.io (cloud vulnerability management platform) through its API
and downloads scan results in .nessus format. It lets you:
- Authenticate with API keys (environment variables, or a prompt that hides the secret key)
- List all available scans
- Pick scans interactively (single, multiple or all), or name them on the command line
- Save the files in a date-based directory structure (Year/MM-MonthName/Week-XX)

Usage:
    python tenable_scan_retrieval.py                      # interactive
    python tenable_scan_retrieval.py --all                # every scan, no prompts
    python tenable_scan_retrieval.py --scan-id 12 --scan-id 34
    python tenable_scan_retrieval.py --all --output-dir D:\\scans

Credentials: set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY, or you are asked for
them (the secret key is not shown as you type). They are never written to disk.

Set TENABLE_URL to use another Tenable cloud, for example https://fedcloud.tenable.com.

Each scan's export is polled every 5 seconds for up to 900 seconds. Change that with
--export-timeout SECONDS and --poll-interval SECONDS for very large scans.

Each download goes to a .part file and is renamed only when it is complete, so
an interrupted download never leaves a truncated .nessus behind. Files are named
<scan name>-<scan id>.nessus so two scans with the same name do not overwrite
each other. The exit code is 0 if every selected scan downloaded, 1 otherwise.
"""

import argparse
import datetime
import getpass
import logging
import math
import os
import re
import sys
import time

import requests

# Setup logging to track script execution and errors
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

DEFAULT_BASE_URL = "https://cloud.tenable.com"
# (connect timeout, read timeout) in seconds. Every request uses it so a stalled
# connection cannot hang the script.
TIMEOUT = (10, 60)
MAX_RATE_LIMIT_RETRIES = 3
MAX_RETRY_AFTER = 60
DEFAULT_EXPORT_TIMEOUT = 900   # seconds to wait for one scan's export to become ready
DEFAULT_POLL_INTERVAL = 5      # seconds between export status checks

_FAILED_EXPORT_STATUSES = {"error", "failed", "cancelled", "canceled"}


def get_base_url():
    """Tenable API base URL: TENABLE_URL if set (must be https), else Tenable.io."""
    url = os.environ.get("TENABLE_URL", DEFAULT_BASE_URL).strip().rstrip("/")
    if not url.lower().startswith("https://"):
        logging.error("TENABLE_URL must start with https://")
        sys.exit(1)
    return url


def get_api_credentials():
    """Get Tenable.io API keys from the environment, or prompt for them at runtime."""
    access_key = os.environ.get("TENABLE_ACCESS_KEY", "").strip()
    secret_key = os.environ.get("TENABLE_SECRET_KEY", "").strip()
    if access_key and secret_key:
        return access_key, secret_key

    print("=" * 60)
    print("Tenable.io API Credentials")
    print("=" * 60)
    print("Enter your Tenable.io API credentials.")
    print("You can find these in Tenable.io under Settings > My Account > API Keys")
    print("(Or set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY.)")
    print()

    if not access_key:
        access_key = input("Enter Access Key: ").strip()
    if not access_key:
        logging.error("Access Key is required. Exiting.")
        sys.exit(1)

    if not secret_key:
        secret_key = getpass.getpass("Enter Secret Key (hidden): ").strip()
    if not secret_key:
        logging.error("Secret Key is required. Exiting.")
        sys.exit(1)

    print()
    return access_key, secret_key


def build_output_dir(now=None, base=""):
    """
    Build the Year/MM-MonthName/Week-XX path for a date. Does not create it.

    The year and week are both ISO values, so 2027-01-01 (ISO week 53 of 2026)
    lands in 2026/01-January/Week-53 rather than a Week-53 folder under 2027.
    """
    now = now or datetime.datetime.now()
    iso = now.isocalendar()
    return os.path.join(
        base, str(iso.year), f"{now.strftime('%m')}-{now.strftime('%B')}", f"Week-{iso.week:02d}")


_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {
    f"LPT{i}" for i in range(1, 10)}


def sanitize_filename(filename):
    """
    Turn a scan name into a safe single file name component.

    Replaces path separators (both kinds), drive colons, wildcard and control
    characters with underscores, strips trailing dots and spaces, avoids
    Windows reserved device names and caps the length. The result can never
    contain a path separator or be '.' or '..'.
    """
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", str(filename))
    name = name.strip().rstrip(". ")
    if not name:
        name = "scan"
    if name.split(".")[0].upper() in _RESERVED_NAMES:
        name = "_" + name
    return name[:150].rstrip(". ") or "scan"


def request_with_retry(method, url, **kwargs):
    """
    Call requests.get/post with the module timeout, waiting and retrying on HTTP 429.

    Honours Retry-After (capped), up to MAX_RATE_LIMIT_RETRIES retries. Returns the
    final response; the caller still calls raise_for_status().
    """
    kwargs.setdefault("timeout", TIMEOUT)
    func = requests.get if method == "get" else requests.post
    response = func(url, **kwargs)
    retries = 0
    while response.status_code == 429 and retries < MAX_RATE_LIMIT_RETRIES:
        try:
            delay = float(response.headers.get("Retry-After", 5))
        except (TypeError, ValueError):
            delay = 5.0
        delay = min(max(delay, 1.0), MAX_RETRY_AFTER)
        logging.warning(f"Rate limited (HTTP 429). Waiting {delay:.0f}s before retrying.")
        time.sleep(delay)
        retries += 1
        response = func(url, **kwargs)
    return response


def get_all_scans(headers):
    """
    Fetches all available vulnerability scans from Tenable.io.

    Args:
        headers: HTTP headers dict with API authentication keys

    Returns:
        A list of scan dictionaries (id, name, ...), possibly empty, or None if the
        API call failed.
    """
    scans_url = f"{get_base_url()}/scans"
    try:
        response = request_with_retry("get", scans_url, headers=headers)
        response.raise_for_status()
        scans = response.json().get("scans") or []  # the API may send "scans": null
        logging.info(f"Found {len(scans)} scans.")
        return scans
    except (requests.exceptions.RequestException, ValueError) as e:
        logging.error(f"Error fetching scans: {e}")
        return None


def initiate_export(scan_id, headers):
    """
    Initiates an export request for a specific scan in .nessus format.

    Returns:
        The file_id string if export was initiated successfully, None otherwise
    """
    export_url = f"{get_base_url()}/scans/{scan_id}/export"
    try:
        response = request_with_retry("post", export_url, headers=headers, json={"format": "nessus"})
        response.raise_for_status()
        file_id = response.json().get("file")
        if file_id:
            logging.info(f"Export initiated for scan {scan_id}. File ID: {file_id}")
            return file_id
        logging.error(f"Failed to retrieve file ID for scan {scan_id}.")
    except (requests.exceptions.RequestException, ValueError) as e:
        logging.error(f"Error initiating export for scan {scan_id}: {e}")
    return None


def wait_for_export(scan_id, file_id, headers, timeout=DEFAULT_EXPORT_TIMEOUT, wait_time=DEFAULT_POLL_INTERVAL):
    """
    Polls the export status until the scan export is ready for download.

    Args:
        timeout: seconds to keep waiting in total (default 900; large scans can take a while)
        wait_time: seconds between status checks

    Returns:
        True if the export is ready. False if Tenable reports a failed export or
        `timeout` seconds pass without it becoming ready.
    """
    status_url = f"{get_base_url()}/scans/{scan_id}/export/{file_id}/status"
    wait_time = max(wait_time, 1)
    max_retries = max(1, math.ceil(timeout / wait_time))
    for attempt in range(max_retries):
        try:
            response = request_with_retry("get", status_url, headers=headers)
            response.raise_for_status()
            status = response.json().get("status")
            if status == "ready":
                logging.info(f"Export ready for scan {scan_id}. File ID: {file_id}")
                return True
            if status and str(status).lower() in _FAILED_EXPORT_STATUSES:
                logging.error(f"Export for scan {scan_id} failed with status '{status}'. Skipping.")
                return False
            logging.info(f"Waiting for export {scan_id}... (Attempt {attempt + 1}/{max_retries})")
        except (requests.exceptions.RequestException, ValueError) as e:
            logging.error(f"Error checking export status for scan {scan_id}: {e}")
        time.sleep(wait_time)
    logging.error(f"Export did not complete for scan {scan_id} within {timeout} seconds. "
                  "Skipping. Raise --export-timeout for very large scans.")
    return False


def scan_output_path(output_dir, scan_name, scan_id):
    """Full path for a scan's .nessus file, guaranteed to sit directly inside output_dir."""
    safe_name = sanitize_filename(scan_name)
    safe_id = sanitize_filename(scan_id)
    path = os.path.join(output_dir, f"{safe_name}-{safe_id}.nessus")
    if os.path.dirname(os.path.abspath(path)) != os.path.abspath(output_dir):
        raise ValueError(f"Refusing to write outside {output_dir}: {path}")
    return path


def download_scan(scan_id, scan_name, file_id, headers, output_dir):
    """
    Downloads the exported .nessus scan file with progress tracking.

    The data goes to '<file>.part' and is renamed to '<file>' only after the whole
    body arrived (and matched Content-Length when the server gave one), so a failed
    or interrupted download leaves no .nessus file.

    Returns:
        The path to the downloaded file if successful, None otherwise
    """
    download_url = f"{get_base_url()}/scans/{scan_id}/export/{file_id}/download"
    output_file = scan_output_path(output_dir, scan_name, scan_id)
    part_file = output_file + ".part"

    try:
        os.makedirs(output_dir, exist_ok=True)
        start_time = time.time()
        response = request_with_retry("get", download_url, headers=headers, stream=True)
        response.raise_for_status()

        # Content-Length counts the bytes on the wire. If the body is compressed, requests hands
        # us the decoded bytes, which are more, so the length cannot be used to check them.
        encoding = str(response.headers.get("Content-Encoding", "")).strip().lower()
        compressed = encoding not in ("", "identity")
        try:
            total_size = 0 if compressed else int(response.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            total_size = 0
        downloaded_size = 0
        chunk_size = 1024 * 1024  # 1MB chunks
        last_update_time = start_time

        with open(part_file, "wb") as f:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)
                    downloaded_size += len(chunk)

                    percent_done = (downloaded_size / total_size) * 100 if total_size else 0
                    current_time = time.time()
                    elapsed_chunk_time = current_time - last_update_time
                    last_update_time = current_time
                    if elapsed_chunk_time > 0:
                        speed_mb_s = (len(chunk) / (1024 * 1024)) / elapsed_chunk_time
                    else:
                        speed_mb_s = 0

                    sys.stdout.write(f"\rDownloading {output_file}: {percent_done:.2f}% - Speed: {speed_mb_s:.2f} MB/s")
                    sys.stdout.flush()

        if total_size and downloaded_size != total_size:
            raise requests.exceptions.ChunkedEncodingError(
                f"incomplete download: got {downloaded_size} of {total_size} bytes")
        os.replace(part_file, output_file)

        elapsed_time = time.time() - start_time
        file_size_mb = downloaded_size / (1024 * 1024)
        avg_speed = file_size_mb / elapsed_time if elapsed_time > 0 else 0
        logging.info(f"\nDownload complete: {output_file} | Size: {file_size_mb:.2f} MB | Avg Speed: {avg_speed:.2f} MB/s")
        return output_file
    except (requests.exceptions.RequestException, OSError) as e:
        logging.error(f"Error downloading scan {scan_id}: {e}")
        if os.path.exists(part_file):
            try:
                os.remove(part_file)
            except OSError:
                pass
    return None


def select_scans_interactive(scans):
    """
    Displays available scans and provides interactive selection interface.

    Lets the user select one scan (a number), several (comma-separated numbers)
    or all ("all"), with a confirmation prompt.

    Returns:
        List of selected scan dictionaries, or empty list if none selected
    """
    if not scans:
        logging.info("No scans available to select.")
        return []

    print("\n" + "=" * 60)
    print("Available Scans")
    print("=" * 60)

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

        if selection == "all":
            confirmation = input(f"Select all {len(scans)} scans? (Y/N): ").strip().lower()
            if confirmation == 'y':
                return scans
            else:
                print("Selection cancelled. Please try again.\n")
                continue

        try:
            selected_numbers = [num.strip() for num in selection.split(',')]
            selected_indices = []

            for num_str in selected_numbers:
                num = int(num_str)
                if 1 <= num <= len(scans):
                    selected_indices.append(num - 1)
                else:
                    print(f"Invalid number: {num}. Please enter numbers between 1 and {len(scans)}.\n")
                    break
            else:
                if not selected_indices:
                    print("No valid selections made. Please try again.\n")
                    continue

                selected_indices = list(dict.fromkeys(selected_indices))
                selected_scans = [scans[idx] for idx in selected_indices]

                print("\nSelected scans:")
                for idx in selected_indices:
                    scan = scans[idx]
                    print(f"  - {scan.get('name', 'Unknown Scan')}")

                confirmation = input(f"\nProceed with {len(selected_scans)} scan(s)? (Y/N): ").strip().lower()
                if confirmation == 'y':
                    return selected_scans
                else:
                    print("Selection cancelled. Please try again.\n")
                    continue

        except ValueError:
            print("Invalid input. Please enter numbers separated by commas, or 'all'.\n")
            continue


def select_scans_from_args(scans, args):
    """Pick scans named by --all / --scan-id. Returns the list, or None if an id is unknown."""
    if args.all:
        return scans
    by_id = {str(s.get("id")): s for s in scans}
    missing = [i for i in args.scan_id if str(i) not in by_id]
    if missing:
        logging.error(f"Scan id(s) not found: {', '.join(map(str, missing))}")
        return None
    return [by_id[str(i)] for i in dict.fromkeys(args.scan_id)]


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Download Tenable.io scans as .nessus files.")
    parser.add_argument("--all", action="store_true", help="download every scan, no prompts")
    parser.add_argument("--scan-id", action="append", default=[],
                        help="scan id to download (repeat for more), no prompts")
    parser.add_argument("--output-dir", default="",
                        help="base folder for the Year/Month/Week folders (default: current folder)")
    parser.add_argument("--export-timeout", type=int, default=DEFAULT_EXPORT_TIMEOUT, metavar="SECONDS",
                        help="how long to wait for each scan's export to become ready "
                             f"(default: {DEFAULT_EXPORT_TIMEOUT})")
    parser.add_argument("--poll-interval", type=int, default=DEFAULT_POLL_INTERVAL, metavar="SECONDS",
                        help=f"seconds between export status checks (default: {DEFAULT_POLL_INTERVAL})")
    args = parser.parse_args(argv)
    if args.export_timeout < 1 or args.poll_interval < 1:
        parser.error("--export-timeout and --poll-interval must be at least 1 second")
    return args


def main(argv=None):
    """
    Main execution function that orchestrates the scan retrieval workflow.

    1. Fetches all available scans from Tenable.io
    2. Selects scans (from --all / --scan-id, or interactively)
    3. For each selected scan: initiates the export, waits, downloads the .nessus file

    Returns the process exit code: 0 if every selected scan downloaded, else 1.
    """
    args = parse_args(sys.argv[1:] if argv is None else argv)

    # Credentials are read here, not at import time.
    access_key, secret_key = get_api_credentials()
    headers = {
        "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key};",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    print("\n" + "=" * 60)
    print("Fetching Scans from Tenable.io")
    print("=" * 60)
    scans = get_all_scans(headers)
    if scans is None:
        return 1
    if not scans:
        logging.info("No scans found. Exiting.")
        return 0

    if args.all or args.scan_id:
        selected_scans = select_scans_from_args(scans, args)
        if selected_scans is None:
            return 1
    else:
        selected_scans = select_scans_interactive(scans)

    if not selected_scans:
        logging.info("No scans selected. Exiting.")
        return 0

    output_dir = build_output_dir(base=args.output_dir)
    print(f"\nOutput directory: {output_dir}")
    print(f"Processing {len(selected_scans)} selected scan(s)...\n")

    failures = 0
    for scan in selected_scans:
        scan_id = scan.get("id")
        scan_name = scan.get("name", "Unknown Scan")

        logging.info(f"Processing scan: {scan_name} (ID: {scan_id})")

        file_id = initiate_export(scan_id, headers)
        if not file_id:
            failures += 1
            continue

        if not wait_for_export(scan_id, file_id, headers, args.export_timeout, args.poll_interval) \
                or not download_scan(scan_id, scan_name, file_id, headers, output_dir):
            failures += 1

    if failures:
        logging.error(f"{failures} of {len(selected_scans)} scan(s) were not downloaded.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
