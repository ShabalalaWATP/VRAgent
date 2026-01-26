#!/usr/bin/env python3
"""
Offline Data Sync Script for VRAgent

Downloads and prepares all security databases for air-gapped operation:
1. ExploitDB - Offensive Security's Exploit Database (~50k exploits)
2. Nuclei Templates - CVE detection templates (~7k templates)
3. ZAP Add-ons - Active scan rules and vulnerability checks
4. OpenVAS NVT Feeds - Network Vulnerability Tests (~80k NVTs)
5. CVE Database - NVD CVE entries for reference

Run this script BEFORE deploying to an air-gapped network!

Usage:
    python scripts/sync_offline_data.py --all
    python scripts/sync_offline_data.py --exploitdb
    python scripts/sync_offline_data.py --nuclei
    python scripts/sync_offline_data.py --openvas
"""

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional

# Data directories
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data" / "offline"
EXPLOITDB_DIR = DATA_DIR / "exploitdb"
NUCLEI_DIR = DATA_DIR / "nuclei-templates"
CVE_DIR = DATA_DIR / "cve"
OSV_DIR = DATA_DIR / "osv"
ZAP_DIR = DATA_DIR / "zap-addons"
OPENVAS_DIR = DATA_DIR / "openvas-feeds"


def print_status(msg: str, status: str = "INFO"):
    """Print colored status message."""
    colors = {
        "INFO": "\033[94m",
        "OK": "\033[92m",
        "WARN": "\033[93m",
        "ERROR": "\033[91m",
    }
    reset = "\033[0m"
    print(f"{colors.get(status, '')}{status}: {msg}{reset}")


def download_file(url: str, dest: Path, desc: str = "") -> bool:
    """Download a file with progress indication."""
    print_status(f"Downloading {desc or url}...")
    try:
        # Create parent directory
        dest.parent.mkdir(parents=True, exist_ok=True)
        
        # Download with progress
        def reporthook(count, block_size, total_size):
            if total_size > 0:
                percent = int(count * block_size * 100 / total_size)
                sys.stdout.write(f"\r  Progress: {percent}%")
                sys.stdout.flush()
        
        urllib.request.urlretrieve(url, dest, reporthook)
        print()  # New line after progress
        print_status(f"Downloaded to {dest}", "OK")
        return True
    except Exception as e:
        print_status(f"Failed to download: {e}", "ERROR")
        return False


def sync_exploitdb():
    """
    Download ExploitDB database.
    
    ExploitDB contains ~50,000 exploits with CVE mappings.
    Source: https://gitlab.com/exploit-database/exploitdb
    """
    print_status("=" * 60)
    print_status("Syncing ExploitDB (Offensive Security Exploit Database)")
    print_status("=" * 60)
    
    EXPLOITDB_DIR.mkdir(parents=True, exist_ok=True)
    
    # Clone or update the repo
    if (EXPLOITDB_DIR / ".git").exists():
        print_status("Updating existing ExploitDB repository...")
        result = subprocess.run(
            ["git", "-C", str(EXPLOITDB_DIR), "pull", "--depth=1"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print_status(f"Git pull failed: {result.stderr}", "WARN")
    else:
        print_status("Cloning ExploitDB repository (this may take a while)...")
        result = subprocess.run(
            ["git", "clone", "--depth=1",
             "https://gitlab.com/exploit-database/exploitdb.git",
             str(EXPLOITDB_DIR)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print_status(f"Git clone failed: {result.stderr}", "ERROR")
            return False
    
    # Verify the CSV file exists
    csv_file = EXPLOITDB_DIR / "files_exploits.csv"
    if csv_file.exists():
        # Count entries
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            count = sum(1 for _ in f) - 1  # Subtract header
        print_status(f"ExploitDB ready: {count:,} exploits available", "OK")
        
        # Copy to Docker volume location hint
        print_status(f"CSV location: {csv_file}")
        print_status("To import into backend, run:")
        print_status(f"  docker exec vragent-backend python -c \"")
        print_status(f"    from backend.services.exploit_db_service import ExploitDBService;")
        print_status(f"    import asyncio;")
        print_status(f"    asyncio.run(ExploitDBService().import_exploitdb_csv('/app/data/offline/exploitdb/files_exploits.csv'))\"")
        return True
    else:
        print_status("ExploitDB CSV not found after clone", "ERROR")
        return False


def sync_nuclei_templates():
    """
    Download Nuclei vulnerability templates.
    
    Nuclei templates are YAML-based CVE detection rules (~7,000+ templates).
    Source: https://github.com/projectdiscovery/nuclei-templates
    """
    print_status("=" * 60)
    print_status("Syncing Nuclei Templates (CVE Detection)")
    print_status("=" * 60)
    
    NUCLEI_DIR.mkdir(parents=True, exist_ok=True)
    
    # Clone or update
    if (NUCLEI_DIR / ".git").exists():
        print_status("Updating existing Nuclei templates...")
        result = subprocess.run(
            ["git", "-C", str(NUCLEI_DIR), "pull"],
            capture_output=True, text=True
        )
    else:
        print_status("Cloning Nuclei templates repository...")
        result = subprocess.run(
            ["git", "clone", "--depth=1",
             "https://github.com/projectdiscovery/nuclei-templates.git",
             str(NUCLEI_DIR)],
            capture_output=True, text=True
        )
    
    if result.returncode != 0:
        print_status(f"Failed: {result.stderr}", "ERROR")
        return False
    
    # Count templates
    count = sum(1 for _ in NUCLEI_DIR.rglob("*.yaml"))
    print_status(f"Nuclei templates ready: {count:,} detection rules", "OK")
    
    # Show CVE coverage
    cve_count = sum(1 for f in NUCLEI_DIR.rglob("*.yaml") if "cve" in str(f).lower())
    print_status(f"  - CVE-specific templates: {cve_count:,}")
    return True


def sync_zap_addons():
    """
    Download ZAP add-ons for offline scanning.
    
    Key add-ons:
    - Active Scan Rules
    - Passive Scan Rules  
    - DOM XSS Scan Rule
    - Retire.js
    """
    print_status("=" * 60)
    print_status("Syncing ZAP Add-ons (Vulnerability Scanners)")
    print_status("=" * 60)
    
    ZAP_DIR.mkdir(parents=True, exist_ok=True)
    
    # Key ZAP add-ons for security scanning
    addons = [
        ("ascanrules", "Active Scan Rules"),
        ("ascanrulesBeta", "Active Scan Rules (Beta)"),
        ("ascanrulesAlpha", "Active Scan Rules (Alpha)"),
        ("pscanrules", "Passive Scan Rules"),
        ("pscanrulesBeta", "Passive Scan Rules (Beta)"),
        ("pscanrulesAlpha", "Passive Scan Rules (Alpha)"),
        ("domxss", "DOM XSS Scanner"),
        ("retire", "Retire.js (Known Vulnerable Libraries)"),
        ("sqliplugin", "SQL Injection Scanner"),
        ("directorylistv2_3", "Directory Listing"),
    ]
    
    print_status("ZAP add-ons are bundled with the Docker image", "INFO")
    print_status("The zaproxy/zap-stable image includes all active/passive scanners", "OK")
    print_status("For air-gapped: ensure Docker images are pre-pulled", "INFO")
    
    # Create a list of addons for reference
    addon_list = ZAP_DIR / "required_addons.txt"
    with open(addon_list, 'w') as f:
        f.write("# Required ZAP Add-ons for VRAgent\n")
        f.write("# These are bundled with zaproxy/zap-stable image\n\n")
        for addon_id, desc in addons:
            f.write(f"{addon_id}: {desc}\n")
    
    print_status(f"Add-on list saved to {addon_list}", "OK")
    return True


def sync_openvas_feeds():
    """
    Instructions for OpenVAS/GVM NVT feed sync.
    
    OpenVAS has ~80,000+ Network Vulnerability Tests (NVTs).
    Feed sync happens automatically on first run but can take 1-2 hours.
    """
    print_status("=" * 60)
    print_status("OpenVAS/GVM Feed Information")
    print_status("=" * 60)
    
    OPENVAS_DIR.mkdir(parents=True, exist_ok=True)
    
    print_status("OpenVAS feeds are synced automatically by the container", "INFO")
    print_status("First-time sync downloads ~80,000 vulnerability tests", "INFO")
    print_status("")
    print_status("For air-gapped deployment:")
    print_status("  1. Run OpenVAS on internet-connected system first")
    print_status("  2. Export the Docker volume: docker volume export vragent_openvas_data > openvas_data.tar")
    print_status("  3. Transfer to air-gapped system")
    print_status("  4. Import: docker volume import vragent_openvas_data < openvas_data.tar")
    print_status("")
    
    # Create instructions file
    instructions = OPENVAS_DIR / "AIRGAP_INSTRUCTIONS.md"
    with open(instructions, 'w') as f:
        f.write("""# OpenVAS Air-Gapped Deployment

## Overview
OpenVAS/GVM contains ~80,000+ Network Vulnerability Tests (NVTs) from the
Greenbone Community Feed. These are automatically synced on first startup
but require internet access.

## For Air-Gapped Networks

### Step 1: Initial Sync (Internet-Connected System)
```bash
# Start OpenVAS and wait for full feed sync (1-2 hours)
docker compose up -d openvas

# Monitor sync progress
docker logs -f vragent-openvas

# Wait until you see "GVM services are up and running"
```

### Step 2: Export Feed Data
```bash
# Stop the container
docker compose stop openvas

# Export the data volume
docker run --rm -v vragent_openvas_data:/data -v $(pwd):/backup alpine \\
    tar cvf /backup/openvas_data.tar /data

# Also export scans volume if needed
docker run --rm -v vragent_openvas_scans:/data -v $(pwd):/backup alpine \\
    tar cvf /backup/openvas_scans.tar /data
```

### Step 3: Transfer to Air-Gapped System
Copy the .tar files to the air-gapped system.

### Step 4: Import on Air-Gapped System
```bash
# Create volumes
docker volume create vragent_openvas_data
docker volume create vragent_openvas_scans

# Import data
docker run --rm -v vragent_openvas_data:/data -v $(pwd):/backup alpine \\
    sh -c "cd /data && tar xvf /backup/openvas_data.tar --strip 1"

docker run --rm -v vragent_openvas_scans:/data -v $(pwd):/backup alpine \\
    sh -c "cd /data && tar xvf /backup/openvas_scans.tar --strip 1"
```

### Step 5: Disable Auto-Sync
Update docker-compose.yml:
```yaml
openvas:
  environment:
    - AUTO_SYNC=false  # Disable feed sync attempts
```

## Feed Contents
- ~80,000 NVTs (Network Vulnerability Tests)
- CVE mappings
- CVSS scores
- Detection logic for thousands of products
- Updated daily by Greenbone

## Storage Requirements
- Data volume: ~2-3 GB
- Scans volume: Variable (depends on scan history)
""")
    
    print_status(f"Instructions saved to {instructions}", "OK")
    return True


def sync_osv_database():
    """
    Download OSV (Open Source Vulnerabilities) database for offline package scanning.
    
    Downloads vulnerability data from OSV.dev's public exports for all major ecosystems.
    Source: https://osv-vulnerabilities.storage.googleapis.com/
    """
    import json
    import sqlite3
    import zipfile
    from datetime import datetime
    
    print_status("=" * 60)
    print_status("Syncing OSV Database - Package Vulnerability Database")
    print_status("=" * 60)
    
    OSV_DIR.mkdir(parents=True, exist_ok=True)
    
    db_path = OSV_DIR / "osv.db"
    
    # Ecosystems to download (most common for code scanning)
    ECOSYSTEMS = [
        "PyPI",      # Python packages
        "npm",       # Node.js packages
        "Go",        # Go modules
        "Maven",     # Java packages
        "NuGet",     # .NET packages
        "crates.io", # Rust packages
        "RubyGems",  # Ruby gems
        "Packagist", # PHP packages
        "Pub",       # Dart/Flutter packages
        "Hex",       # Erlang/Elixir packages
    ]
    
    # Create SQLite database
    print_status("Creating local OSV SQLite database...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            ecosystem TEXT,
            package_name TEXT,
            summary TEXT,
            details TEXT,
            severity TEXT,
            cvss_score REAL,
            cvss_vector TEXT,
            published TEXT,
            modified TEXT,
            withdrawn TEXT,
            aliases TEXT,
            related TEXT
        );
        
        CREATE TABLE IF NOT EXISTS affected_ranges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id TEXT,
            ecosystem TEXT,
            package_name TEXT,
            range_type TEXT,
            introduced TEXT,
            fixed TEXT,
            last_affected TEXT,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
        );
        
        CREATE TABLE IF NOT EXISTS references_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id TEXT,
            ref_type TEXT,
            url TEXT,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
        );
        
        CREATE TABLE IF NOT EXISTS sync_info (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        
        CREATE INDEX IF NOT EXISTS idx_vuln_ecosystem ON vulnerabilities(ecosystem);
        CREATE INDEX IF NOT EXISTS idx_vuln_package ON vulnerabilities(package_name);
        CREATE INDEX IF NOT EXISTS idx_affected_package ON affected_ranges(ecosystem, package_name);
        CREATE INDEX IF NOT EXISTS idx_affected_vuln ON affected_ranges(vuln_id);
    """)
    conn.commit()
    
    total_vulns = 0
    
    for ecosystem in ECOSYSTEMS:
        print_status(f"Downloading {ecosystem} vulnerabilities...")
        
        # OSV provides ZIP files per ecosystem
        zip_url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
        
        try:
            zip_path = OSV_DIR / f"{ecosystem}.zip"
            
            # Download ZIP
            def reporthook(count, block_size, total_size):
                if total_size > 0:
                    percent = int(count * block_size * 100 / total_size)
                    sys.stdout.write(f"\r  {ecosystem}: {percent}%")
                    sys.stdout.flush()
            
            urllib.request.urlretrieve(zip_url, zip_path, reporthook)
            print()  # Newline after progress
            
            # Extract and process
            ecosystem_count = 0
            with zipfile.ZipFile(zip_path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.json'):
                        try:
                            with zf.open(name) as f:
                                vuln = json.loads(f.read().decode('utf-8'))
                            
                            vuln_id = vuln.get("id", "")
                            if not vuln_id:
                                continue
                            
                            # Parse severity
                            severity = None
                            cvss_score = None
                            cvss_vector = None
                            
                            for sev in vuln.get("severity", []):
                                if sev.get("type") == "CVSS_V3":
                                    cvss_vector = sev.get("score")
                                    # Parse score from vector if present
                                    if cvss_vector and "CVSS:3" in cvss_vector:
                                        # Extract base score would require parsing
                                        pass
                            
                            # Get severity from database_specific if available
                            db_specific = vuln.get("database_specific", {})
                            severity = db_specific.get("severity")
                            
                            # Get aliases (CVE IDs, etc.)
                            aliases = ",".join(vuln.get("aliases", []))
                            related = ",".join(vuln.get("related", []))
                            
                            # Insert vulnerability
                            cursor.execute("""
                                INSERT OR REPLACE INTO vulnerabilities
                                (id, ecosystem, package_name, summary, details, severity,
                                 cvss_score, cvss_vector, published, modified, withdrawn, aliases, related)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                vuln_id,
                                ecosystem,
                                "",  # Will be populated from affected
                                vuln.get("summary", ""),
                                vuln.get("details", ""),
                                severity,
                                cvss_score,
                                cvss_vector,
                                vuln.get("published"),
                                vuln.get("modified"),
                                vuln.get("withdrawn"),
                                aliases,
                                related,
                            ))
                            
                            # Process affected packages
                            for affected in vuln.get("affected", []):
                                pkg = affected.get("package", {})
                                pkg_name = pkg.get("name", "")
                                pkg_ecosystem = pkg.get("ecosystem", ecosystem)
                                
                                # Update package name in main record
                                if pkg_name and not cursor.execute(
                                    "SELECT package_name FROM vulnerabilities WHERE id = ?", 
                                    (vuln_id,)
                                ).fetchone()[0]:
                                    cursor.execute(
                                        "UPDATE vulnerabilities SET package_name = ? WHERE id = ?",
                                        (pkg_name, vuln_id)
                                    )
                                
                                # Insert version ranges
                                for rng in affected.get("ranges", []):
                                    range_type = rng.get("type", "")
                                    
                                    for event in rng.get("events", []):
                                        introduced = event.get("introduced")
                                        fixed = event.get("fixed")
                                        last_affected = event.get("last_affected")
                                        
                                        if introduced or fixed or last_affected:
                                            cursor.execute("""
                                                INSERT INTO affected_ranges
                                                (vuln_id, ecosystem, package_name, range_type, 
                                                 introduced, fixed, last_affected)
                                                VALUES (?, ?, ?, ?, ?, ?, ?)
                                            """, (
                                                vuln_id, pkg_ecosystem, pkg_name, range_type,
                                                introduced, fixed, last_affected
                                            ))
                            
                            # Insert references (limit to 5 per vuln)
                            for ref in vuln.get("references", [])[:5]:
                                cursor.execute("""
                                    INSERT INTO references_table (vuln_id, ref_type, url)
                                    VALUES (?, ?, ?)
                                """, (vuln_id, ref.get("type", ""), ref.get("url", "")))
                            
                            ecosystem_count += 1
                            
                        except Exception as e:
                            # Skip malformed entries
                            continue
            
            conn.commit()
            total_vulns += ecosystem_count
            print_status(f"  {ecosystem}: {ecosystem_count:,} vulnerabilities", "OK")
            
            # Clean up ZIP file
            zip_path.unlink()
            
        except Exception as e:
            print_status(f"  {ecosystem}: Failed - {e}", "WARN")
            continue
    
    # Update sync info
    cursor.execute("""
        INSERT OR REPLACE INTO sync_info (key, value)
        VALUES ('last_sync', ?), ('total_vulns', ?), ('ecosystems', ?)
    """, (datetime.utcnow().isoformat(), str(total_vulns), ",".join(ECOSYSTEMS)))
    conn.commit()
    
    # Get final stats
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    vuln_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM affected_ranges")
    range_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT package_name) FROM affected_ranges")
    pkg_count = cursor.fetchone()[0]
    
    conn.close()
    
    db_size = db_path.stat().st_size / (1024 * 1024)
    
    print_status(f"OSV Database ready: {vuln_count:,} vulns, {pkg_count:,} packages", "OK")
    print_status(f"Database size: {db_size:.1f} MB")
    print_status(f"Database location: {db_path}")
    
    return True


def sync_cve_database():
    """
    Download NVD CVE database for offline reference.
    
    Downloads CVE data from NVD and creates a local SQLite database
    for air-gapped operation.
    """
    import json
    import sqlite3
    import gzip
    from datetime import datetime
    
    print_status("=" * 60)
    print_status("Syncing CVE Database (NVD) - Full Offline Database")
    print_status("=" * 60)
    
    CVE_DIR.mkdir(parents=True, exist_ok=True)
    
    db_path = CVE_DIR / "nvd_cve.db"
    
    # Create SQLite database
    print_status("Creating local CVE SQLite database...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            published TEXT,
            last_modified TEXT,
            cvss_v3_score REAL,
            cvss_v3_vector TEXT,
            cvss_v3_severity TEXT,
            cvss_v2_score REAL,
            cvss_v2_vector TEXT,
            source_identifier TEXT,
            vuln_status TEXT
        );
        
        CREATE TABLE IF NOT EXISTS cve_cwes (
            cve_id TEXT,
            cwe_id TEXT,
            PRIMARY KEY (cve_id, cwe_id),
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );
        
        CREATE TABLE IF NOT EXISTS cve_references (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            url TEXT,
            source TEXT,
            tags TEXT,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );
        
        CREATE TABLE IF NOT EXISTS cve_cpes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            cpe_uri TEXT,
            vulnerable INTEGER,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );
        
        CREATE TABLE IF NOT EXISTS kev_catalog (
            cve_id TEXT PRIMARY KEY,
            vendor_project TEXT,
            product TEXT,
            vulnerability_name TEXT,
            date_added TEXT,
            short_description TEXT,
            required_action TEXT,
            due_date TEXT,
            known_ransomware_use TEXT
        );
        
        CREATE TABLE IF NOT EXISTS sync_info (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        
        CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published);
        CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(cvss_v3_severity);
        CREATE INDEX IF NOT EXISTS idx_cve_cwes_cwe ON cve_cwes(cwe_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cpes_cpe ON cve_cpes(cpe_uri);
    """)
    conn.commit()
    
    # Download CISA KEV catalog first (small, fast)
    print_status("Downloading CISA Known Exploited Vulnerabilities catalog...")
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        import urllib.request
        with urllib.request.urlopen(kev_url, timeout=30) as response:
            kev_data = json.loads(response.read().decode('utf-8'))
            
        kev_count = 0
        for vuln in kev_data.get("vulnerabilities", []):
            cursor.execute("""
                INSERT OR REPLACE INTO kev_catalog 
                (cve_id, vendor_project, product, vulnerability_name, date_added,
                 short_description, required_action, due_date, known_ransomware_use)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln.get("cveID"),
                vuln.get("vendorProject"),
                vuln.get("product"),
                vuln.get("vulnerabilityName"),
                vuln.get("dateAdded"),
                vuln.get("shortDescription"),
                vuln.get("requiredAction"),
                vuln.get("dueDate"),
                vuln.get("knownRansomwareCampaignUse"),
            ))
            kev_count += 1
        
        conn.commit()
        print_status(f"Imported {kev_count} KEV entries", "OK")
    except Exception as e:
        print_status(f"Failed to download KEV catalog: {e}", "WARN")
    
    # Download NVD CVE feeds
    # NVD provides yearly JSON feeds for historical data
    print_status("Downloading NVD CVE feeds (this may take a while)...")
    
    # Use NVD API 2.0 with pagination for recent CVEs
    # For historical data, we'd normally use the yearly feeds, but API is more reliable
    nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    total_cves = 0
    start_index = 0
    results_per_page = 2000  # NVD max
    
    # Check for NVD API key in environment
    api_key = os.environ.get("NVD_API_KEY", "")
    headers = {"User-Agent": "VRAgent/1.0 (Offline Sync)"}
    if api_key:
        headers["apiKey"] = api_key
        print_status("Using NVD API key for faster downloads", "INFO")
        delay = 0.6  # 50 req/30s with key
    else:
        print_status("No NVD_API_KEY found - using rate-limited mode (slower)", "WARN")
        print_status("Get a free API key: https://nvd.nist.gov/developers/request-an-api-key", "INFO")
        delay = 6.0  # 5 req/30s without key
    
    import time
    
    while True:
        try:
            url = f"{nvd_api}?startIndex={start_index}&resultsPerPage={results_per_page}"
            req = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=120) as response:
                data = json.loads(response.read().decode('utf-8'))
            
            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                break
            
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id")
                
                if not cve_id:
                    continue
                
                # Parse description
                description = ""
                for desc in cve.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                # Parse CVSS scores
                metrics = cve.get("metrics", {})
                cvss_v3_score = None
                cvss_v3_vector = None
                cvss_v3_severity = None
                cvss_v2_score = None
                cvss_v2_vector = None
                
                # CVSS v3.1 or v3.0
                for cvss_list in [metrics.get("cvssMetricV31", []), metrics.get("cvssMetricV30", [])]:
                    if cvss_list:
                        cvss_data = cvss_list[0].get("cvssData", {})
                        cvss_v3_score = cvss_data.get("baseScore")
                        cvss_v3_vector = cvss_data.get("vectorString")
                        cvss_v3_severity = cvss_data.get("baseSeverity")
                        break
                
                # CVSS v2
                cvss_v2_list = metrics.get("cvssMetricV2", [])
                if cvss_v2_list:
                    cvss_data = cvss_v2_list[0].get("cvssData", {})
                    cvss_v2_score = cvss_data.get("baseScore")
                    cvss_v2_vector = cvss_data.get("vectorString")
                
                # Insert CVE
                cursor.execute("""
                    INSERT OR REPLACE INTO cves 
                    (cve_id, description, published, last_modified, 
                     cvss_v3_score, cvss_v3_vector, cvss_v3_severity,
                     cvss_v2_score, cvss_v2_vector, source_identifier, vuln_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cve_id, description, 
                    cve.get("published"), cve.get("lastModified"),
                    cvss_v3_score, cvss_v3_vector, cvss_v3_severity,
                    cvss_v2_score, cvss_v2_vector,
                    cve.get("sourceIdentifier"), cve.get("vulnStatus")
                ))
                
                # Insert CWEs
                for weakness in cve.get("weaknesses", []):
                    for desc in weakness.get("description", []):
                        if desc.get("lang") == "en":
                            cwe_id = desc.get("value", "")
                            if cwe_id.startswith("CWE-") or cwe_id.startswith("NVD-CWE"):
                                cursor.execute("""
                                    INSERT OR IGNORE INTO cve_cwes (cve_id, cwe_id)
                                    VALUES (?, ?)
                                """, (cve_id, cwe_id))
                
                # Insert references (limit to 5 per CVE to save space)
                for ref in cve.get("references", [])[:5]:
                    cursor.execute("""
                        INSERT INTO cve_references (cve_id, url, source, tags)
                        VALUES (?, ?, ?, ?)
                    """, (
                        cve_id, ref.get("url"), ref.get("source"),
                        ",".join(ref.get("tags", []))
                    ))
                
                total_cves += 1
            
            conn.commit()
            
            # Progress update
            progress = min(100, int((start_index + len(vulnerabilities)) * 100 / max(total_results, 1)))
            sys.stdout.write(f"\r  Progress: {progress}% ({total_cves:,} CVEs downloaded)")
            sys.stdout.flush()
            
            # Check if we've got all results
            if start_index + len(vulnerabilities) >= total_results:
                break
            
            start_index += results_per_page
            
            # Rate limiting
            time.sleep(delay)
            
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print_status(f"\nRate limited. Waiting 30s before retry...", "WARN")
                time.sleep(30)
                continue
            else:
                print_status(f"\nHTTP error: {e}", "ERROR")
                break
        except Exception as e:
            print_status(f"\nError downloading CVEs: {e}", "ERROR")
            break
    
    print()  # New line after progress
    
    # Update sync info
    cursor.execute("""
        INSERT OR REPLACE INTO sync_info (key, value)
        VALUES ('last_sync', ?), ('total_cves', ?), ('source', 'NVD API 2.0')
    """, (datetime.utcnow().isoformat(), str(total_cves)))
    conn.commit()
    
    # Get stats
    cursor.execute("SELECT COUNT(*) FROM cves")
    cve_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM kev_catalog")
    kev_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT cwe_id) FROM cve_cwes")
    cwe_count = cursor.fetchone()[0]
    
    conn.close()
    
    db_size = db_path.stat().st_size / (1024 * 1024)
    
    print_status(f"CVE Database ready: {cve_count:,} CVEs, {kev_count:,} KEV entries", "OK")
    print_status(f"Database size: {db_size:.1f} MB")
    print_status(f"Database location: {db_path}")
    
    # Create reference file
    reference = CVE_DIR / "CVE_SOURCES.md"
    with open(reference, 'w') as f:
        f.write(f"""# CVE Data Sources in VRAgent

## Local NVD CVE Database (OFFLINE READY)
- **Location**: `{db_path}`
- **CVE Count**: {cve_count:,}
- **KEV Entries**: {kev_count:,} (Known Exploited Vulnerabilities)
- **CWE Mappings**: {cwe_count:,} unique weaknesses
- **Last Sync**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

## Built-in CVE Coverage

### OpenVAS (~80,000 CVEs)
- Full NVT feed includes CVE mappings
- CVSS scores and references
- Detection logic for vulnerabilities

### Nuclei Templates (~5,000 CVEs)  
- Direct CVE detection templates
- Proof-of-concept payloads
- Network and web CVEs

### ExploitDB CVE Mappings
- Maps exploits to CVEs
- Shows weaponized vulnerabilities

## Database Schema

```sql
-- Main CVE table
cves (cve_id, description, published, cvss_v3_score, cvss_v3_severity, ...)

-- CWE weakness mappings
cve_cwes (cve_id, cwe_id)

-- Reference links
cve_references (cve_id, url, source, tags)

-- CISA Known Exploited Vulnerabilities
kev_catalog (cve_id, vendor_project, product, vulnerability_name, ...)
```

## Air-Gapped Deployment

The local SQLite database works fully offline. No internet connection required.
To update, run on internet-connected system:
```bash
python scripts/sync_offline_data.py --cve
```
Then copy `data/offline/cve/nvd_cve.db` to air-gapped system.
""")
    
    print_status(f"CVE documentation saved to {reference}", "OK")
    return True


def create_docker_volume_mount_config():
    """Create docker-compose override for offline data volumes."""
    print_status("=" * 60)
    print_status("Creating Docker Volume Mounts for Offline Data")
    print_status("=" * 60)
    
    override_content = """# Docker Compose Override for Offline Data
# Copy this to docker-compose.override.yml

version: '3.8'

services:
  backend:
    volumes:
      - ./data/offline:/app/data/offline:ro
      # Exploit database
      - ./data/offline/exploitdb/files_exploits.csv:/app/data/exploitdb.csv:ro
  
  scanner:
    volumes:
      # Nuclei templates for offline scanning
      - ./data/offline/nuclei-templates:/root/nuclei-templates:ro
    environment:
      # Use local templates instead of updating
      - NUCLEI_TEMPLATES_PATH=/root/nuclei-templates
      - NUCLEI_UPDATE_TEMPLATES=false
  
  openvas:
    environment:
      # Disable feed sync for air-gapped
      - AUTO_SYNC=false
"""
    
    override_file = BASE_DIR / "docker-compose.airgap.yml"
    with open(override_file, 'w') as f:
        f.write(override_content)
    
    print_status(f"Created {override_file}", "OK")
    print_status("To use: docker compose -f docker-compose.yml -f docker-compose.airgap.yml up -d")
    return True


def print_summary():
    """Print summary of offline data status."""
    print_status("")
    print_status("=" * 60)
    print_status("OFFLINE DATA SUMMARY")
    print_status("=" * 60)
    
    checks = [
        ("ExploitDB", EXPLOITDB_DIR / "files_exploits.csv"),
        ("Nuclei Templates", NUCLEI_DIR / "http"),
        ("ZAP Add-ons Info", ZAP_DIR / "required_addons.txt"),
        ("OpenVAS Instructions", OPENVAS_DIR / "AIRGAP_INSTRUCTIONS.md"),
        ("CVE Sources", CVE_DIR / "CVE_SOURCES.md"),
    ]
    
    for name, path in checks:
        if path.exists():
            print_status(f"✓ {name}: Ready", "OK")
        else:
            print_status(f"✗ {name}: Not synced", "WARN")
    
    print_status("")
    print_status("For air-gapped deployment:")
    print_status("1. Run this script with --all on internet-connected system")
    print_status("2. Follow OpenVAS instructions in data/offline/openvas-feeds/")
    print_status("3. Copy entire 'data/offline/' folder to air-gapped system")
    print_status("4. Use docker-compose.airgap.yml override")
    print_status("")


def main():
    parser = argparse.ArgumentParser(
        description="Sync offline security databases for VRAgent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python sync_offline_data.py --all          # Sync everything
    python sync_offline_data.py --exploitdb    # Just ExploitDB
    python sync_offline_data.py --status       # Show current status
        """
    )
    
    parser.add_argument("--all", action="store_true", help="Sync all databases")
    parser.add_argument("--exploitdb", action="store_true", help="Sync ExploitDB")
    parser.add_argument("--nuclei", action="store_true", help="Sync Nuclei templates")
    parser.add_argument("--zap", action="store_true", help="Prepare ZAP add-on info")
    parser.add_argument("--openvas", action="store_true", help="Create OpenVAS instructions")
    parser.add_argument("--cve", action="store_true", help="Download NVD CVE database")
    parser.add_argument("--osv", action="store_true", help="Download OSV package vulnerability database")
    parser.add_argument("--status", action="store_true", help="Show current status")
    
    args = parser.parse_args()
    
    # If no args, show help
    if not any([args.all, args.exploitdb, args.nuclei, args.zap, 
                args.openvas, args.cve, args.osv, args.status]):
        parser.print_help()
        return
    
    print_status("VRAgent Offline Data Sync Tool")
    print_status(f"Data directory: {DATA_DIR}")
    print_status("")
    
    if args.status:
        print_summary()
        return
    
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    if args.all or args.exploitdb:
        sync_exploitdb()
        print_status("")
    
    if args.all or args.nuclei:
        sync_nuclei_templates()
        print_status("")
    
    if args.all or args.zap:
        sync_zap_addons()
        print_status("")
    
    if args.all or args.openvas:
        sync_openvas_feeds()
        print_status("")
    
    if args.all or args.cve:
        sync_cve_database()
        print_status("")
    
    if args.all or args.osv:
        sync_osv_database()
        print_status("")
    
    if args.all:
        create_docker_volume_mount_config()
        print_status("")
    
    print_summary()


if __name__ == "__main__":
    main()
