"""
Scanner Sidecar Server
FastAPI server that exposes nmap and nuclei scanning capabilities.
Runs with network_mode: host for full LAN access.
"""

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Literal

import httpx

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from utils import (
    validate_target,
    validate_ports,
    parse_nmap_xml,
    parse_nuclei_jsonl,
    classify_service,
    get_nuclei_tags_for_service,
)

from planner import GeminiPlanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("scanner-sidecar")

app = FastAPI(
    title="VRAgent Scanner Sidecar",
    description="Host-networked scanner for nmap and nuclei",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Scan storage
SCANS_DIR = Path("/scans")
SCANS_DIR.mkdir(parents=True, exist_ok=True)
scan_processes: Dict[str, asyncio.subprocess.Process] = {}
WORDLIST_SEARCH_DIRS = [
    Path("/wordlists"),
    Path("/usr/share/wordlists/dirbuster"),
    Path("/usr/share/dirb/wordlists"),
]
WORDLIST_KEY_MAP = {
    "quick": "directories_comprehensive.txt",
    "standard": "directories_comprehensive.txt",
    "aggressive": "directories_comprehensive.txt",
    "api": "api_endpoints.txt",
    "backup": "backup_config_files.txt",
    "sensitive": "sensitive_files.txt",
    "cms": "cms_paths.txt",
    "graphql": "graphql_comprehensive.txt",
}
DEFAULT_DIR_WORDLISTS = [
    Path("/wordlists/directories_comprehensive.txt"),
    Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
    Path("/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"),
    Path("/usr/share/dirb/wordlists/common.txt"),
]
active_scans: Dict[str, Dict[str, Any]] = {}


def _ensure_scan_dir(subdir: str) -> Path:
    """Ensure the scan subdirectory exists and return its path."""
    path = SCANS_DIR / subdir
    path.mkdir(parents=True, exist_ok=True)
    return path


# ============== Models ==============

class NmapScanRequest(BaseModel):
    target: str = Field(..., description="IP, CIDR range, or hostname")
    scan_type: str = Field(default="service", description="Scan type: ping, basic, service, comprehensive, stealth, udp")
    ports: Optional[str] = Field(default=None, description="Port specification (e.g., '22,80,443' or '1-1000')")
    extra_args: Optional[List[str]] = Field(default=None, description="Additional nmap arguments")
    timeout: int = Field(default=600, ge=30, le=3600, description="Timeout in seconds")


class NucleiScanRequest(BaseModel):
    target: str = Field(..., description="Target URL or IP:port")
    tags: Optional[List[str]] = Field(default=None, description="Template tags to use (e.g., ['cve', 'ssh'])")
    severity: Optional[List[str]] = Field(default=None, description="Severity filter (critical, high, medium, low, info)")
    templates: Optional[List[str]] = Field(default=None, description="Specific template IDs to run")
    timeout: int = Field(default=300, ge=30, le=1800, description="Timeout in seconds")
    rate_limit: int = Field(default=150, ge=10, le=1000, description="Requests per second")


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str  # pending, running, completed, failed
    scan_type: str
    target: str
    started_at: Optional[str]
    completed_at: Optional[str]
    progress: Optional[str]
    error: Optional[str]
    result: Optional[Dict[str, Any]]


class AgentPlanRequest(BaseModel):
    web_targets: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    network_targets: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    execute_scans: bool = Field(
        default=False,
        description="If true, the planner will enqueue the recommended scans.",
    )
    callback_url: Optional[str] = Field(
        default=None,
        description="Optional webhook URL that receives the plan summary.",
    )


class AgentPlanResponse(BaseModel):
    plan: Dict[str, Any]
    launched_scans: List[Dict[str, Any]]


class DirectoryScanRequest(BaseModel):
    target: str = Field(..., description="Target URL (HTTP/HTTPS) to enumerate directories on")
    engine: Literal["gobuster", "dirbuster"] = Field(
        default="gobuster",
        description="Which enumeration engine to use (Gobuster preferred in CLI environments)",
    )
    wordlist: Optional[str] = Field(
        default=None,
        description="Absolute path to the wordlist. Defaults to built-in directory list if unspecified.",
    )
    extensions: Optional[List[str]] = Field(
        default=None,
        description="Optional extensions to probe (e.g., ['php','jsp']).",
    )
    threads: int = Field(default=25, ge=5, le=60, description="Number of threads for Gobuster/Dirbuster")
    timeout: int = Field(default=600, ge=60, le=3600, description="Timeout in seconds for the scan")


class SQLMapScanRequest(BaseModel):
    target: str = Field(..., description="Target URL for SQL injection testing")
    method: Literal["GET", "POST"] = Field(default="GET", description="HTTP method to use")
    data: Optional[str] = Field(default=None, description="POST data for injection testing")
    level: int = Field(default=2, ge=1, le=5, description="SQLMap level (1-5)")
    risk: int = Field(default=2, ge=0, le=3, description="SQLMap risk (0-3)")
    timeout: int = Field(default=900, ge=60, le=3600, description="Scan timeout in seconds")
    threads: int = Field(default=1, ge=1, le=10, description="Parallel threads for SQLMap")


class WapitiScanRequest(BaseModel):
    target: str = Field(..., description="Target URL for Wapiti web scan")
    level: int = Field(default=2, ge=1, le=5, description="Wapiti scan intensity level")
    timeout: int = Field(default=900, ge=60, le=3600, description="Timeout for the scan")


def _resolve_wordlist(wordlist: Optional[str]) -> Path:
    """Resolve a wordlist path, falling back to known built-in lists."""
    candidates = []
    if wordlist:
        key = str(wordlist).strip()
        mapped = WORDLIST_KEY_MAP.get(key)
        if mapped:
            for base_dir in WORDLIST_SEARCH_DIRS:
                candidates.append(base_dir / mapped)
        candidates.append(Path(key))
        if not Path(key).is_absolute():
            candidates.append(Path.cwd() / key)
            for base_dir in WORDLIST_SEARCH_DIRS:
                candidates.append(base_dir / key)
    candidates.extend(DEFAULT_DIR_WORDLISTS)
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate
    raise FileNotFoundError("No directory wordlist found. Please provide a valid path.")


# ============== Scan Type Configurations ==============

NMAP_SCAN_TYPES = {
    "ping": {
        "args": ["-sn", "-PE", "-PP", "-PM"],
        "description": "Host discovery only (no port scan)",
        "timeout": 120,
    },
    "basic": {
        "args": ["-F", "-T4"],
        "description": "Fast scan of top 100 ports",
        "timeout": 180,
    },
    "service": {
        "args": ["-sV", "-sC", "--top-ports", "1000", "-T4"],
        "description": "Service/version detection on top 1000 ports",
        "timeout": 600,
    },
    "comprehensive": {
        "args": ["-sV", "-sC", "-O", "-A", "-p-", "-T4"],
        "description": "Full port scan with OS detection",
        "timeout": 1800,
    },
    "stealth": {
        "args": ["-sS", "-sV", "-T2", "--top-ports", "1000"],
        "description": "Slower, stealthier SYN scan",
        "timeout": 900,
    },
    "udp": {
        "args": ["-sU", "-sV", "--top-ports", "100", "-T4"],
        "description": "UDP scan of top 100 ports",
        "timeout": 600,
    },
    "vuln": {
        "args": ["-sV", "--script=vuln", "--top-ports", "1000", "-T4"],
        "description": "Vulnerability scripts scan",
        "timeout": 900,
    },
}


# ============== Health & Info ==============

def _tool_info(binary: str) -> Dict[str, Any]:
    """Return install status and path for a binary."""
    path = shutil.which(binary)
    return {"installed": bool(path), "path": path or ""}


def _collect_wordlists(limit: int = 200) -> Dict[str, Any]:
    """Collect available wordlists for directory enumeration."""
    wordlists = []
    for base_dir in WORDLIST_SEARCH_DIRS:
        if not base_dir.exists():
            continue
        for path in base_dir.glob("*.txt"):
            wordlists.append(str(path))
            if len(wordlists) >= limit:
                return {"count": len(wordlists), "paths": wordlists, "truncated": True}
    return {"count": len(wordlists), "paths": wordlists, "truncated": False}

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.get("/info")
async def scanner_info():
    """Get scanner capabilities and versions."""
    # Get nmap version
    try:
        nmap_result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
        nmap_version = nmap_result.stdout.split('\n')[0] if nmap_result.returncode == 0 else "unknown"
    except Exception:
        nmap_version = "not installed"
    
    # Get nuclei version
    try:
        nuclei_result = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=5)
        nuclei_version = nuclei_result.stdout.strip() if nuclei_result.returncode == 0 else "unknown"
    except Exception:
        nuclei_version = "not installed"
    
    direnum_engines = {
        "gobuster": _tool_info("gobuster"),
        "dirbuster": _tool_info("dirbuster"),
    }
    wordlists_info = _collect_wordlists()

    return {
        "scanner": "VRAgent Scanner Sidecar",
        "version": "1.0.0",
        "capabilities": {
            "nmap": {
                "installed": "not installed" not in nmap_version,
                "version": nmap_version,
                "scan_types": list(NMAP_SCAN_TYPES.keys()),
            },
            "nuclei": {
                "installed": "not installed" not in nuclei_version,
                "version": nuclei_version,
            },
            "direnum": {
                "engines": direnum_engines,
                "wordlists": wordlists_info,
            },
            "sqlmap": _tool_info("sqlmap"),
            "wapiti": _tool_info("wapiti"),
        },
        "network_mode": "host",
    }


# ============== Nmap Scanning ==============

@app.post("/scan/nmap", response_model=ScanStatusResponse)
async def start_nmap_scan(request: NmapScanRequest, background_tasks: BackgroundTasks):
    """Start an nmap scan."""
    # Validate target
    is_valid, error = validate_target(request.target)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)
    
    # Validate ports
    if request.ports:
        is_valid, error = validate_ports(request.ports)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error)
    
    # Check scan type
    if request.scan_type not in NMAP_SCAN_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scan type: {request.scan_type}. Available: {list(NMAP_SCAN_TYPES.keys())}"
        )
    
    # Create scan ID
    scan_id = str(uuid.uuid4())[:8]
    
    # Initialize scan status
    active_scans[scan_id] = {
        "scan_id": scan_id,
        "status": "pending",
        "scan_type": f"nmap_{request.scan_type}",
        "target": request.target,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "progress": "Initializing...",
        "error": None,
        "result": None,
    }
    
    # Start scan in background
    background_tasks.add_task(
        run_nmap_scan,
        scan_id,
        request.target,
        request.scan_type,
        request.ports,
        request.extra_args,
        request.timeout,
    )
    
    return ScanStatusResponse(**active_scans[scan_id])


async def run_nmap_scan(
    scan_id: str,
    target: str,
    scan_type: str,
    ports: Optional[str],
    extra_args: Optional[List[str]],
    timeout: int,
):
    """Execute nmap scan in background."""
    try:
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["progress"] = "Starting nmap scan..."
        
        # Get scan config
        scan_config = NMAP_SCAN_TYPES[scan_type]
        
        # Build command
        cmd = ["nmap"]
        cmd.extend(scan_config["args"])
        
        # Add specific ports if provided
        if ports:
            # Remove existing port args
            cmd = [arg for arg in cmd if arg not in ["-F", "--top-ports"] and not arg.isdigit()]
            cmd.extend(["-p", ports.replace(" ", "")])
        
        # Add extra arguments
        if extra_args:
            cmd.extend(extra_args)
        
        # Output to XML
        output_dir = _ensure_scan_dir("nmap")
        output_file = output_dir / f"{scan_id}.xml"
        cmd.extend(["-oX", str(output_file)])
        
        # Add target
        cmd.append(target)
        
        command_str = " ".join(cmd)
        logger.info(f"[{scan_id}] Running: {command_str}")
        active_scans[scan_id]["progress"] = f"Executing: {command_str}"
        
        # Use effective timeout
        effective_timeout = min(timeout, scan_config["timeout"])
        
        # Run scan
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        scan_processes[scan_id] = process
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=effective_timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            raise Exception(f"Scan timed out after {effective_timeout} seconds")
        finally:
            scan_processes.pop(scan_id, None)

        if active_scans[scan_id]["status"] == "cancelled":
            logger.info(f"[{scan_id}] Nmap scan was cancelled.")
            return
        
        # Check result
        if not output_file.exists():
            error_msg = stderr.decode() if stderr else "Nmap did not produce output"
            raise Exception(f"Scan failed: {error_msg}")
        
        # Parse XML output
        xml_content = output_file.read_text()
        parsed_result = parse_nmap_xml(xml_content)
        
        # Store result
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        active_scans[scan_id]["progress"] = "Completed"
        active_scans[scan_id]["result"] = {
            "command": command_str,
            "xml_file": str(output_file),
            "parsed": parsed_result,
        }
        
        logger.info(f"[{scan_id}] Nmap scan completed: {parsed_result['stats']}")
        
    except Exception as e:
        logger.error(f"[{scan_id}] Nmap scan failed: {e}")
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        active_scans[scan_id]["error"] = str(e)
        active_scans[scan_id]["progress"] = "Failed"


# ============== Nuclei Scanning ==============

@app.post("/scan/nuclei", response_model=ScanStatusResponse)
async def start_nuclei_scan(request: NucleiScanRequest, background_tasks: BackgroundTasks):
    """Start a nuclei CVE scan."""
    # Basic target validation
    if not request.target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    
    # Create scan ID
    scan_id = str(uuid.uuid4())[:8]
    
    # Initialize scan status
    active_scans[scan_id] = {
        "scan_id": scan_id,
        "status": "pending",
        "scan_type": "nuclei",
        "target": request.target,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "progress": "Initializing...",
        "error": None,
        "result": None,
    }
    
    # Start scan in background
    background_tasks.add_task(
        run_nuclei_scan,
        scan_id,
        request.target,
        request.tags,
        request.severity,
        request.templates,
        request.timeout,
        request.rate_limit,
    )
    
    return ScanStatusResponse(**active_scans[scan_id])


async def run_nuclei_scan(
    scan_id: str,
    target: str,
    tags: Optional[List[str]],
    severity: Optional[List[str]],
    templates: Optional[List[str]],
    timeout: int,
    rate_limit: int,
):
    """Execute nuclei scan in background."""
    try:
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["progress"] = "Starting nuclei scan..."
        
        # Build command
        cmd = ["nuclei", "-target", target, "-silent", "-jsonl"]
        
        # Add tags filter
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        
        # Add severity filter
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        
        # Add specific templates
        if templates:
            for template in templates:
                cmd.extend(["-t", template])
        
        # Rate limiting
        cmd.extend(["-rate-limit", str(rate_limit)])
        
        # Output file
        output_dir = _ensure_scan_dir("nuclei")
        output_file = output_dir / f"{scan_id}.jsonl"
        cmd.extend(["-o", str(output_file)])
        
        command_str = " ".join(cmd)
        logger.info(f"[{scan_id}] Running: {command_str}")
        active_scans[scan_id]["progress"] = f"Scanning with nuclei..."
        
        # Run scan
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        scan_processes[scan_id] = process
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            raise Exception(f"Scan timed out after {timeout} seconds")
        finally:
            scan_processes.pop(scan_id, None)

        if active_scans[scan_id]["status"] == "cancelled":
            logger.info(f"[{scan_id}] Nuclei scan was cancelled.")
            return

        # Parse results
        findings = []
        if output_file.exists():
            jsonl_content = output_file.read_text()
            findings = parse_nuclei_jsonl(jsonl_content)
        
        # Categorize findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = finding.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Store result
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        active_scans[scan_id]["progress"] = "Completed"
        active_scans[scan_id]["result"] = {
            "command": command_str,
            "output_file": str(output_file),
            "findings": findings,
            "stats": {
                "total_findings": len(findings),
                "severity_breakdown": severity_counts,
            },
        }
        
        logger.info(f"[{scan_id}] Nuclei scan completed: {len(findings)} findings")
        
    except Exception as e:
        logger.error(f"[{scan_id}] Nuclei scan failed: {e}")
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        active_scans[scan_id]["error"] = str(e)
        active_scans[scan_id]["progress"] = "Failed"


@app.post("/scan/direnum", response_model=ScanStatusResponse)
async def start_directory_scan(request: DirectoryScanRequest, background_tasks: BackgroundTasks):
    """Start a Gobuster/Dirbuster directory enumeration scan."""
    if not request.target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    engine = request.engine
    if engine == "dirbuster" and not shutil.which("dirbuster"):
        if shutil.which("gobuster"):
            logger.warning("Dirbuster not installed, falling back to gobuster")
            engine = "gobuster"
        else:
            raise HTTPException(status_code=503, detail="Dirbuster not installed and gobuster unavailable")
    if engine == "gobuster" and not shutil.which("gobuster"):
        raise HTTPException(status_code=503, detail="Gobuster not installed")

    scan_id = str(uuid.uuid4())[:8]
    active_scans[scan_id] = {
        "scan_id": scan_id,
        "status": "pending",
        "scan_type": f"direnum_{engine}",
        "target": request.target,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "progress": "Initializing...",
        "error": None,
        "result": None,
    }

    background_tasks.add_task(
        run_directory_scan,
        scan_id,
        request.target,
        engine,
        request.wordlist,
        request.extensions,
        request.threads,
        request.timeout,
    )

    return ScanStatusResponse(**active_scans[scan_id])


async def run_directory_scan(
    scan_id: str,
    target: str,
    engine: str,
    wordlist: Optional[str],
    extensions: Optional[List[str]],
    threads: int,
    timeout: int,
):
    """Execute directory enumeration using Gobuster or Dirbuster."""
    try:
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["progress"] = f"Starting {engine} directory enumeration..."

        try:
            wordlist_path = _resolve_wordlist(wordlist)
        except FileNotFoundError as e:
            raise Exception(str(e))

        output_dir = _ensure_scan_dir("direnum")
        output_file = output_dir / f"{scan_id}.txt"

        if engine == "dirbuster":
            cmd = [
                "dirbuster",
                "-u",
                target,
                "-l",
                str(wordlist_path),
                "-o",
                str(output_file),
                "-S",
                "-U",
                str(threads),
            ]
        else:
            cmd = [
                "gobuster",
                "dir",
                "-u",
                target,
                "-w",
                str(wordlist_path),
                "-q",
                "-t",
                str(threads),
                "-o",
                str(output_file),
            ]
            if extensions:
                cmd.extend(["-x", ",".join(extensions)])

        command_str = " ".join(cmd)
        logger.info(f"[{scan_id}] Running directory enumeration: {command_str}")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        scan_processes[scan_id] = process

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            raise Exception(f"{engine} scan timed out after {timeout} seconds")
        finally:
            scan_processes.pop(scan_id, None)

        if active_scans[scan_id]["status"] == "cancelled":
            logger.info(f"[{scan_id}] {engine} scan was cancelled.")
            return

        if not output_file.exists():
            raise Exception(stderr.decode() or "Enumeration did not produce output")

        findings = []
        discovered_paths = []
        regex = re.compile(r"(?P<url>\S+)\s+\(Status:\s*(?P<status>\d+)\)")
        for line in output_file.read_text().splitlines():
            match = regex.search(line)
            if match:
                url = match.group("url")
                status = int(match.group("status"))
                findings.append({
                    "path": url,
                    "status": status,
                    "line": line.strip(),
                })
                discovered_paths.append(url)

        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        active_scans[scan_id]["progress"] = "Completed"
        active_scans[scan_id]["result"] = {
            "command": command_str,
            "output_file": str(output_file),
            "findings": findings,
            "stats": {
                "total_paths": len(findings),
            },
            "discovered_urls": discovered_paths,
        }

        logger.info(f"[{scan_id}] Directory enumeration finished: {len(findings)} paths")

    except Exception as e:
        logger.error(f"[{scan_id}] Directory enumeration failed: {e}")
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        active_scans[scan_id]["error"] = str(e)
        active_scans[scan_id]["progress"] = "Failed"


@app.post("/scan/sqlmap", response_model=ScanStatusResponse)
async def start_sqlmap_scan(request: SQLMapScanRequest, background_tasks: BackgroundTasks):
    """Start a SQLMap injection scan."""
    if not request.target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    if not shutil.which("sqlmap"):
        raise HTTPException(status_code=503, detail="SQLMap not installed")

    scan_id = str(uuid.uuid4())[:8]
    active_scans[scan_id] = {
        "scan_id": scan_id,
        "status": "pending",
        "scan_type": "sqlmap",
        "target": request.target,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "progress": "Initializing...",
        "error": None,
        "result": None,
    }

    background_tasks.add_task(
        run_sqlmap_scan,
        scan_id,
        request.target,
        request.method,
        request.data,
        request.level,
        request.risk,
        request.timeout,
        request.threads,
    )

    return ScanStatusResponse(**active_scans[scan_id])


async def run_sqlmap_scan(
    scan_id: str,
    target: str,
    method: str,
    data: Optional[str],
    level: int,
    risk: int,
    timeout: int,
    threads: int,
):
    """Execute SQLMap scan."""
    try:
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["progress"] = "Starting SQLMap injection scan..."

        sqlmap_root = _ensure_scan_dir("sqlmap")
        output_dir = sqlmap_root / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            "sqlmap",
            "-u",
            target,
            "--batch",
            "--level",
            str(level),
            "--risk",
            str(risk),
            "--output-dir",
            str(output_dir),
        ]
        if method == "POST":
            cmd.extend(["--method", "POST"])
        if data:
            cmd.extend(["--data", data])
        if threads > 1:
            cmd.extend(["--threads", str(threads)])

        command_str = " ".join(cmd)
        logger.info(f"[{scan_id}] Running SQLMap: {command_str}")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=None,
        )
        scan_processes[scan_id] = process

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            raise Exception(f"SQLMap scan timed out after {timeout} seconds")
        finally:
            scan_processes.pop(scan_id, None)

        if active_scans[scan_id]["status"] == "cancelled":
            logger.info(f"[{scan_id}] SQLMap scan was cancelled.")
            return

        output_text = stdout.decode() + "\n" + stderr.decode()
        findings = []
        if "is vulnerable" in output_text.lower() or "injection point" in output_text.lower():
            findings.append({
                "url": target,
                "detail": output_text.splitlines()[-5:] if output_text else "",
                "risk": "high",
                "description": "SQL injection detected by SQLMap.",
            })

        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        active_scans[scan_id]["progress"] = "Completed"
        active_scans[scan_id]["result"] = {
            "command": command_str,
            "output_dir": str(output_dir),
            "findings": findings,
            "raw_output": output_text,
        }

        logger.info(f"[{scan_id}] SQLMap completed: {len(findings)} findings")

    except Exception as e:
        logger.error(f"[{scan_id}] SQLMap scan failed: {e}")
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        active_scans[scan_id]["error"] = str(e)
        active_scans[scan_id]["progress"] = "Failed"


@app.post("/scan/wapiti", response_model=ScanStatusResponse)
async def start_wapiti_scan(request: WapitiScanRequest, background_tasks: BackgroundTasks):
    """Start a Wapiti vulnerability scan."""
    if not shutil.which("wapiti"):
        raise HTTPException(status_code=503, detail="Wapiti not installed")
    if not request.target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")

    scan_id = str(uuid.uuid4())[:8]
    active_scans[scan_id] = {
        "scan_id": scan_id,
        "status": "pending",
        "scan_type": "wapiti",
        "target": request.target,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "progress": "Initializing...",
        "error": None,
        "result": None,
    }

    background_tasks.add_task(
        run_wapiti_scan,
        scan_id,
        request.target,
        request.level,
        request.timeout,
    )

    return ScanStatusResponse(**active_scans[scan_id])


async def run_wapiti_scan(
    scan_id: str,
    target: str,
    level: int,
    timeout: int,
):
    """Execute Wapiti scan."""
    try:
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["progress"] = "Starting Wapiti scan..."

        output_dir = _ensure_scan_dir("wapiti")
        output_file = output_dir / f"{scan_id}.json"

        cmd = [
            "wapiti",
            "-u",
            target,
            "-l",
            str(level),
            "-f",
            "json",
            "-o",
            str(output_file),
        ]

        command_str = " ".join(cmd)
        logger.info(f"[{scan_id}] Running Wapiti: {command_str}")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        scan_processes[scan_id] = process

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            raise Exception(f"Wapiti scan timed out after {timeout} seconds")
        finally:
            scan_processes.pop(scan_id, None)

        if active_scans[scan_id]["status"] == "cancelled":
            logger.info(f"[{scan_id}] Wapiti scan was cancelled.")
            return

        findings = []
        if output_file.exists():
            try:
                content = json.loads(output_file.read_text())
                for vuln in content.get("vulnerabilities", []):
                    findings.append({
                        "name": vuln.get("name"),
                        "url": vuln.get("url"),
                        "level": vuln.get("level"),
                        "description": vuln.get("description"),
                    })
            except json.JSONDecodeError:
                pass

        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        active_scans[scan_id]["progress"] = "Completed"
        active_scans[scan_id]["result"] = {
            "command": command_str,
            "output_file": str(output_file),
            "findings": findings,
            "stdout": stdout.decode(),
            "stderr": stderr.decode(),
        }

        logger.info(f"[{scan_id}] Wapiti completed: {len(findings)} findings")

    except Exception as e:
        logger.error(f"[{scan_id}] Wapiti scan failed: {e}")
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        active_scans[scan_id]["error"] = str(e)
        active_scans[scan_id]["progress"] = "Failed"


# ============== Scan Status & Results ==============

@app.get("/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """Get status and results of a scan."""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    return ScanStatusResponse(**active_scans[scan_id])


@app.get("/scans")
async def list_scans():
    """List all scans."""
    return {
        "scans": [
            {
                "scan_id": s["scan_id"],
                "status": s["status"],
                "scan_type": s["scan_type"],
                "target": s["target"],
                "started_at": s["started_at"],
            }
            for s in active_scans.values()
        ]
    }


@app.delete("/scan/{scan_id}")
async def cancel_scan(scan_id: str):
    """Cancel a running scan (best effort)."""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    if active_scans[scan_id]["status"] in ["completed", "failed"]:
        return {"message": f"Scan {scan_id} already finished"}
    
    # Mark as cancelled (the background task will check this)
    active_scans[scan_id]["status"] = "cancelled"
    active_scans[scan_id]["error"] = "Cancelled by user"
    active_scans[scan_id]["progress"] = "Cancellation requested"
    active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()

    process = scan_processes.get(scan_id)
    if process and process.returncode is None:
        process.kill()
        try:
            await process.wait()
        except Exception:
            pass
        logger.info(f"[{scan_id}] Cancelled scan process.")
        scan_processes.pop(scan_id, None)
    
    return {"message": f"Scan {scan_id} cancellation requested"}


async def _dispatch_callback(url: str, payload: Dict[str, Any]):
    """Fire-and-forget webhook for agent plans."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(url, json=payload)
    except Exception as exc:  # pragma: no cover - best-effort
        logger.warning(f"Agent callback to {url} failed: {exc}")


async def _execute_agent_action(action: Dict[str, Any], background_tasks: BackgroundTasks) -> Optional[Dict[str, Any]]:
    """Translate a planner action into a scheduled scan."""
    scan_kind = action.get("scan")
    params = action.get("params") or {}
    target = action.get("target")
    if not target:
        logger.warning("Skipping agent action because target is missing")
        return None

    try:
        if scan_kind == "nmap":
            request = NmapScanRequest(
                target=target,
                scan_type=params.get("scan_type", "service"),
                ports=params.get("ports"),
                extra_args=params.get("extra_args"),
                timeout=params.get("timeout", 600),
            )
            response = await start_nmap_scan(request, background_tasks)
        elif scan_kind == "direnum":
            request = DirectoryScanRequest(
                target=target,
                engine=params.get("engine", "gobuster"),
                wordlist=params.get("wordlist"),
                extensions=params.get("extensions"),
                threads=params.get("threads", 25),
                timeout=params.get("timeout", 300),
            )
            response = await start_directory_scan(request, background_tasks)
        elif scan_kind == "nuclei":
            request = NucleiScanRequest(
                target=target,
                tags=params.get("tags"),
                severity=params.get("severity"),
                templates=params.get("templates"),
                timeout=params.get("timeout", 300),
                rate_limit=params.get("rate_limit", 150),
            )
            response = await start_nuclei_scan(request, background_tasks)
        else:
            logger.warning(f"Agent planner requested unsupported scan type '{scan_kind}'")
            return None
        logger.info(f"Agent scheduled {scan_kind} scan for {target}")
        return response.dict()
    except HTTPException as exc:
        logger.warning(f"Agent planner scan failed for {target}: {exc.detail}")
        return {"target": target, "scan": scan_kind, "error": exc.detail}


@app.post("/agent/plan", response_model=AgentPlanResponse)
async def agent_plan(request: AgentPlanRequest, background_tasks: BackgroundTasks):
    """Plan agentic multi-step scanning flows via Gemini-inspired reasoning."""
    planner = GeminiPlanner()
    plan = planner.plan(request.web_targets, request.network_targets)
    launched: List[Dict[str, Any]] = []

    if request.execute_scans:
        for action in plan["actions"]:
            result = await _execute_agent_action(action, background_tasks)
            if result:
                launched.append(result)

    if request.callback_url:
        background_tasks.add_task(
            _dispatch_callback,
            request.callback_url,
            {"plan": plan, "launched_scans": launched},
        )

    return AgentPlanResponse(plan=plan, launched_scans=launched)


# ============== Service Classification ==============

@app.post("/classify")
async def classify_services(hosts: List[Dict[str, Any]]):
    """
    Classify discovered services for AI routing.
    Takes nmap results and returns routing recommendations.
    """
    web_targets = []
    network_targets = []
    
    for host in hosts:
        ip = host.get("ip", "")
        for port_info in host.get("ports", []):
            if port_info.get("state") != "open":
                continue
            
            port = port_info.get("port", 0)
            service = port_info.get("service", "")
            
            classification = classify_service(port, service)
            
            target_info = {
                "ip": ip,
                "port": port,
                "service": service,
                "product": port_info.get("product", ""),
                "version": port_info.get("version", ""),
            }
            
            if classification == "web":
                web_targets.append({
                    **target_info,
                    "url": f"http://{ip}:{port}" if port not in [443, 8443] else f"https://{ip}:{port}",
                })
            elif classification == "network":
                target_info["nuclei_tags"] = get_nuclei_tags_for_service(port, service)
                network_targets.append(target_info)
            elif classification == "both":
                # Add to both
                web_targets.append({
                    **target_info,
                    "url": f"http://{ip}:{port}",
                })
                target_info["nuclei_tags"] = get_nuclei_tags_for_service(port, service)
                network_targets.append(target_info)
    
    return {
        "web_targets": web_targets,
        "network_targets": network_targets,
        "summary": {
            "total_web": len(web_targets),
            "total_network": len(network_targets),
        }
    }


# ============== Main ==============

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("SCANNER_PORT", "9999"))
    logger.info(f"Starting Scanner Sidecar on port {port}")
    
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
