"""
Fuzzing Router

Endpoints for web application fuzzing and security testing.
"""

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Depends, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from datetime import datetime
import logging
import json
import asyncio

from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.core.auth import get_current_active_user
from backend.models.models import FuzzingSession, User

from backend.services.fuzzing_service import (
    FuzzConfig,
    FuzzResult,
    run_fuzzing_session,
    stream_fuzzing_session,
    export_fuzz_results_json,
    export_fuzz_results_markdown,
)

from backend.services.smart_detection_service import (
    detect_vulnerabilities,
    detect_anomalies,
    differential_analysis,
    categorize_responses,
    create_session_summary,
    SmartFinding,
    AnomalyResult,
    detect_offensive_indicators,
    generate_offensive_report,
)

from backend.services.fuzzing_advanced import (
    perform_offensive_analysis,
    analyze_c2_indicators,
    analyze_malware_behaviors,
    analyze_sandbox_evasion,
    extract_iocs,
    detect_security_products,
    generate_c2_probe_payloads,
    generate_evasion_test_payloads,
    generate_malware_string_payloads,
    generate_api_hooking_payloads,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/fuzzer", tags=["Security Fuzzer"])


class FuzzRequest(BaseModel):
    """Request model for starting a fuzzing session."""
    target_url: str = Field(..., description="Target URL with position markers (§0§, §1§, etc.)")
    method: str = Field(default="GET", description="HTTP method")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    body: str = Field(default="", description="Request body (for POST/PUT/PATCH)")
    positions: List[str] = Field(default_factory=list, description="Position markers")
    payloads: List[List[str]] = Field(default_factory=list, description="Payload sets for each position")
    attack_mode: str = Field(default="sniper", description="Attack mode: sniper, batteringram, pitchfork, clusterbomb")
    threads: int = Field(default=10, ge=1, le=50, description="Number of concurrent threads")
    delay: int = Field(default=0, ge=0, description="Delay between requests in milliseconds")
    timeout: int = Field(default=10000, ge=1000, le=60000, description="Request timeout in milliseconds")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    match_codes: List[int] = Field(default_factory=lambda: [200, 301, 302, 401, 403], description="Status codes to highlight")
    filter_codes: List[int] = Field(default_factory=list, description="Status codes to filter out")
    match_regex: str = Field(default="", description="Regex pattern to match in responses")
    proxy_url: Optional[str] = Field(default=None, description="HTTP proxy URL")


class ExportRequest(BaseModel):
    """Request model for exporting fuzzing results."""
    result: Dict[str, Any] = Field(..., description="Fuzzing result data")
    format: str = Field(default="json", description="Export format: json, markdown")


@router.post("/run", response_model=Dict[str, Any])
async def run_fuzzer(request: FuzzRequest, current_user: User = Depends(get_current_active_user)):
    """
    Run a complete fuzzing session.
    
    This endpoint executes all payload combinations and returns the complete results
    when finished. For real-time progress updates, use the /stream endpoint or WebSocket.
    """
    try:
        config = FuzzConfig(
            target_url=request.target_url,
            method=request.method,
            headers=request.headers,
            body=request.body,
            positions=request.positions,
            payloads=request.payloads,
            attack_mode=request.attack_mode,
            threads=request.threads,
            delay=request.delay,
            timeout=request.timeout,
            follow_redirects=request.follow_redirects,
            match_codes=request.match_codes,
            filter_codes=request.filter_codes,
            match_regex=request.match_regex,
            proxy_url=request.proxy_url,
        )
        
        result = await run_fuzzing_session(config)
        return result.to_dict()
        
    except Exception as e:
        logger.exception(f"Fuzzing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stream")
async def stream_fuzzer(request: FuzzRequest, current_user: User = Depends(get_current_active_user)):
    """
    Stream fuzzing results as Server-Sent Events.
    
    Each result is sent as it completes, allowing real-time progress monitoring.
    """
    config = FuzzConfig(
        target_url=request.target_url,
        method=request.method,
        headers=request.headers,
        body=request.body,
        positions=request.positions,
        payloads=request.payloads,
        attack_mode=request.attack_mode,
        threads=request.threads,
        delay=request.delay,
        timeout=request.timeout,
        follow_redirects=request.follow_redirects,
        match_codes=request.match_codes,
        filter_codes=request.filter_codes,
        match_regex=request.match_regex,
        proxy_url=request.proxy_url,
    )
    
    async def event_generator():
        try:
            async for event in stream_fuzzing_session(config):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            logger.exception(f"Streaming error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


class SingleRequestModel(BaseModel):
    """Request model for sending a single HTTP request (Repeater functionality)."""
    url: str = Field(..., description="Target URL")
    method: str = Field(default="GET", description="HTTP method")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    body: str = Field(default="", description="Request body")
    timeout: int = Field(default=10000, ge=1000, le=60000, description="Request timeout in milliseconds")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    proxy_url: Optional[str] = Field(default=None, description="HTTP/SOCKS proxy URL (e.g., http://127.0.0.1:8080 for Burp)")


@router.post("/send-single", response_model=Dict[str, Any])
async def send_single_request(request: SingleRequestModel, current_user: User = Depends(get_current_active_user)):
    """
    Send a single HTTP request (Repeater functionality).
    
    This endpoint allows manually sending and modifying requests,
    similar to Burp Suite's Repeater tool.
    """
    import aiohttp
    import time
    
    try:
        start_time = time.time()
        
        # Prepare headers
        headers = dict(request.headers)
        if "User-Agent" not in headers:
            headers["User-Agent"] = "VRAgent-Repeater/1.0"
        
        timeout = aiohttp.ClientTimeout(total=request.timeout / 1000)
        
        # Configure proxy if provided
        connector = None
        if request.proxy_url:
            from aiohttp_socks import ProxyConnector
            try:
                connector = ProxyConnector.from_url(request.proxy_url)
            except Exception:
                # Fallback for HTTP proxy
                pass
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            async with session.request(
                method=request.method,
                url=request.url,
                headers=headers,
                data=request.body if request.body else None,
                allow_redirects=request.follow_redirects,
                ssl=False,  # Disable SSL verification for testing
                proxy=request.proxy_url if not connector else None,
            ) as response:
                response_time = int((time.time() - start_time) * 1000)
                body = await response.text()
                
                # Build response headers dict
                response_headers = {}
                for key, value in response.headers.items():
                    response_headers[key] = value
                
                return {
                    "status_code": response.status,
                    "headers": response_headers,
                    "body": body,
                    "response_time": response_time,
                    "content_length": len(body),
                    "content_type": response.headers.get("Content-Type", ""),
                }
                
    except asyncio.TimeoutError:
        return {
            "status_code": 0,
            "headers": {},
            "body": "Error: Request timed out",
            "response_time": request.timeout,
            "content_length": 0,
            "content_type": "",
            "error": "timeout",
        }
    except Exception as e:
        logger.exception(f"Single request failed: {e}")
        return {
            "status_code": 0,
            "headers": {},
            "body": f"Error: {str(e)}",
            "response_time": 0,
            "content_length": 0,
            "content_type": "",
            "error": str(e),
        }


@router.websocket("/ws")
async def websocket_fuzzer(websocket: WebSocket):
    """
    WebSocket endpoint for real-time fuzzing with bidirectional communication.
    
    Supports:
    - Starting fuzzing sessions
    - Receiving real-time results
    - Stopping/pausing sessions
    """
    await websocket.accept()
    
    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action")
            
            if action == "start":
                config_data = data.get("config", {})
                config = FuzzConfig(
                    target_url=config_data.get("target_url", ""),
                    method=config_data.get("method", "GET"),
                    headers=config_data.get("headers", {}),
                    body=config_data.get("body", ""),
                    positions=config_data.get("positions", []),
                    payloads=config_data.get("payloads", []),
                    attack_mode=config_data.get("attack_mode", "sniper"),
                    threads=config_data.get("threads", 10),
                    delay=config_data.get("delay", 0),
                    timeout=config_data.get("timeout", 10000),
                    follow_redirects=config_data.get("follow_redirects", True),
                    match_codes=config_data.get("match_codes", [200, 301, 302, 401, 403]),
                    filter_codes=config_data.get("filter_codes", []),
                    match_regex=config_data.get("match_regex", ""),
                    proxy_url=config_data.get("proxy_url"),
                )
                
                async for event in stream_fuzzing_session(config):
                    await websocket.send_json(event)
                    
            elif action == "ping":
                await websocket.send_json({"type": "pong"})
                
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.exception(f"WebSocket error: {e}")
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass


@router.post("/export")
async def export_results(request: ExportRequest, current_user: User = Depends(get_current_active_user)):
    """
    Export fuzzing results in various formats.
    """
    try:
        # Reconstruct FuzzResult from dict
        from backend.services.fuzzing_service import (
            FuzzConfig, FuzzResult, FuzzResponse, FuzzFinding, FuzzStats
        )
        
        result_data = request.result
        
        config = FuzzConfig(**result_data.get("config", {}))
        stats = FuzzStats(**result_data.get("stats", {}))
        
        responses = []
        for r in result_data.get("responses", []):
            responses.append(FuzzResponse(**r))
        
        findings = []
        for f in result_data.get("findings", []):
            findings.append(FuzzFinding(**f))
        
        result = FuzzResult(
            config=config,
            responses=responses,
            findings=findings,
            stats=stats,
        )
        
        if request.format == "json":
            content = export_fuzz_results_json(result)
            return {"content": content, "filename": "fuzzing-report.json", "mime_type": "application/json"}
        elif request.format == "markdown":
            content = export_fuzz_results_markdown(result)
            return {"content": content, "filename": "fuzzing-report.md", "mime_type": "text/markdown"}
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {request.format}")
            
    except Exception as e:
        logger.exception(f"Export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Built-in wordlists endpoint
BUILTIN_WORDLISTS = {
    "sqli": {
        "name": "SQL Injection",
        "description": "Common SQL injection payloads",
        "payloads": [
            "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
            "' OR 1=1#", "admin'--", "') OR ('1'='1", "1' ORDER BY 1--",
            "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
            "'; DROP TABLE users--", "' AND 1=1--", "' AND 1=2--",
            "' WAITFOR DELAY '0:0:5'--", "'; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--", "1' AND SLEEP(5)--", "' OR SLEEP(5)--",
        ],
    },
    "xss": {
        "name": "XSS Payloads",
        "description": "Cross-site scripting test payloads",
        "payloads": [
            "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>", "javascript:alert('XSS')",
            "<body onload=alert('XSS')>", "<iframe src=\"javascript:alert('XSS')\">",
            "<input onfocus=alert('XSS') autofocus>", "\"><script>alert('XSS')</script>",
            "'-alert('XSS')-'", "';alert('XSS')//",
            "</title><script>alert('XSS')</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<svg/onload=alert('XSS')>",
        ],
    },
    "lfi": {
        "name": "Path Traversal",
        "description": "Directory traversal payloads",
        "payloads": [
            "../", "..\\", "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd", "/etc/passwd", "/etc/shadow",
            "/proc/self/environ", "/var/log/apache2/access.log",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input", "file:///etc/passwd",
        ],
    },
    "cmdi": {
        "name": "Command Injection",
        "description": "OS command injection payloads",
        "payloads": [
            "; ls -la", "| ls -la", "& ls -la", "&& ls -la", "|| ls -la",
            "`ls -la`", "$(ls -la)", "; cat /etc/passwd", "| cat /etc/passwd",
            "; id", "| id", "| whoami", "; whoami", "; sleep 5", "| sleep 5",
        ],
    },
    "ssti": {
        "name": "SSTI Payloads",
        "description": "Server-side template injection payloads",
        "payloads": [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
            "{{config}}", "{{config.items()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
        ],
    },
    "directories": {
        "name": "Common Directories",
        "description": "Common web directories for enumeration",
        "payloads": [
            "admin", "api", "backup", "config", "dashboard", "db", "debug",
            "dev", "docs", "files", "images", "include", "js", "lib", "log",
            "login", "media", "old", "php", "private", "public", "scripts",
            "static", "system", "temp", "test", "tmp", "upload", "user",
            "vendor", "wp-admin", "wp-content", ".git", ".svn", ".env",
        ],
    },
    "params": {
        "name": "API Parameters",
        "description": "Common API parameter names",
        "payloads": [
            "id", "user_id", "userId", "user", "username", "name", "email",
            "password", "token", "api_key", "apiKey", "key", "secret",
            "auth", "session", "access_token", "page", "limit", "offset",
            "sort", "order", "filter", "query", "q", "search", "type",
            "category", "status", "action", "format", "callback", "url",
        ],
    },
    # =========================================================================
    # OFFENSIVE SECURITY WORDLISTS
    # For analyzing sandboxed software and malware behavior
    # =========================================================================
    "c2_domains": {
        "name": "C2 Domains",
        "description": "Command & Control domain patterns for sandbox analysis",
        "payloads": [
            # Dynamic DNS providers
            "duckdns.org", "no-ip.org", "ddns.net", "hopto.org", "myftp.org",
            "servegame.com", "zapto.org", "sytes.net", "myvnc.com", "redirectme.net",
            # Cloudflare tunnels
            "trycloudflare.com", "ngrok.io", "localhost.run", "serveo.net",
            # Suspicious TLDs
            ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
            # Cobalt Strike defaults
            "cdn.cloudflare.com", "code.jquery.com", "ajax.googleapis.com",
            # Empire defaults
            "news.google.com", "mail.yahoo.com",
            # Generic C2
            "c2.local", "beacon.local", "callback.local", "exfil.local",
            "update.microsoft.com.local", "download.windowsupdate.local",
        ],
    },
    "malware_strings": {
        "name": "Malware Strings",
        "description": "Common malware strings for detection testing",
        "payloads": [
            # Credential theft
            "mimikatz", "sekurlsa::logonpasswords", "lsass.dmp", "hashdump",
            "wdigest", "kerberos::list", "dcsync", "golden ticket",
            # Process injection
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
            "NtMapViewOfSection", "QueueUserAPC", "SetWindowsHookEx",
            "RtlCreateUserThread", "NtCreateThreadEx",
            # Persistence
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "schtasks /create", "sc create", "New-Service",
            # Evasion
            "amsi.dll", "AmsiScanBuffer", "etw bypass", "unhook ntdll",
            "sleep(600000)", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            # Exfiltration
            "dns exfil", "telegram bot", "discord webhook", "pastebin",
            # Ransomware
            "vssadmin delete shadows", "bcdedit /set recoveryenabled no",
            "wmic shadowcopy delete", ".encrypted", ".locked", "ransom note",
        ],
    },
    "api_hooking": {
        "name": "API Hooking",
        "description": "Windows API hooking functions for EDR bypass detection",
        "payloads": [
            # NTDLL functions
            "ntdll.dll", "NtCreateFile", "NtWriteFile", "NtReadFile",
            "NtCreateProcess", "NtCreateThread", "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory", "NtMapViewOfSection", "NtUnmapViewOfSection",
            "NtQueryInformationProcess", "NtSetInformationThread",
            "LdrLoadDll", "LdrGetProcedureAddress",
            # Kernel32 functions
            "kernel32.dll", "CreateProcessW", "CreateProcessA",
            "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory",
            "VirtualAllocEx", "VirtualProtectEx", "LoadLibraryA", "LoadLibraryW",
            # Syscalls
            "syscall", "sysenter", "int 2eh", "direct syscall",
            # Hook detection
            "inline hook", "iat hook", "eat hook", "trampoline",
            "jmp [address]", "push ret", "hot patch",
            # Bypass
            "unhook", "fresh copy", "heaven's gate", "wow64",
        ],
    },
    "sandbox_evasion": {
        "name": "Sandbox Evasion",
        "description": "Sandbox/VM detection strings for evasion testing",
        "payloads": [
            # VM detection
            "VMware", "VirtualBox", "VBOX", "QEMU", "Hyper-V", "Xen", "KVM",
            "Virtual Machine", "vmtoolsd", "vmwaretray", "vboxservice",
            # Sandbox detection
            "Sandbox", "Cuckoo", "ANY.RUN", "Hybrid-Analysis", "VirusTotal",
            "Joe Sandbox", "CAPE", "Hatching Triage", "Intezer",
            # Anti-debug
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "ProcessDebugPort", "ProcessDebugFlags",
            "OutputDebugString", "CloseHandle trick", "int 2d",
            # Timing
            "GetTickCount", "QueryPerformanceCounter", "rdtsc",
            "Sleep", "NtDelayExecution", "time acceleration",
            # Environment checks
            "GetSystemMetrics", "GetCursorPos", "GetLastInputInfo",
            "mouse movement", "keyboard activity", "user interaction",
            "MAC address", "CPU count", "memory size", "disk size",
            "username", "computername", "domain name",
        ],
    },
    "c2_frameworks": {
        "name": "C2 Frameworks",
        "description": "C2 framework signatures for detection",
        "payloads": [
            # Cobalt Strike
            "Cobalt Strike", "beacon", "malleable c2", "watermark",
            "spawn to", "process-inject", "jump psexec", "execute-assembly",
            "inline-execute", "shinject", "dllinject",
            # Metasploit
            "Metasploit", "meterpreter", "reverse_tcp", "reverse_http",
            "reverse_https", "bind_tcp", "staged payload", "stageless",
            "multi/handler", "post/windows", "exploit/multi",
            # Empire
            "Empire", "stager", "launcher.bat", "Invoke-Empire",
            "powershell empire", "agent", "listener",
            # Sliver
            "Sliver", "implant", "mtls listener", "wg listener", "dns canary",
            "beacon mode", "session mode",
            # Brute Ratel
            "Brute Ratel", "BRc4", "badger", "commander",
            # Covenant
            "Covenant", "Grunt", "Elite listener",
            # Havoc
            "Havoc", "demon", "teamserver",
        ],
    },
    "persistence_mechanisms": {
        "name": "Persistence Mechanisms",
        "description": "Windows persistence techniques",
        "payloads": [
            # Registry
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
            # Scheduled tasks
            "schtasks /create", "schtasks /run", "New-ScheduledTask",
            "Register-ScheduledTask", "at command",
            # Services
            "sc create", "sc config", "New-Service", "Set-Service",
            "CreateServiceW", "ChangeServiceConfig",
            # Startup folder
            "shell:startup", "shell:common startup",
            "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            # WMI
            "wmic startup", "Win32_StartupCommand", "__EventFilter",
            "__EventConsumer", "__FilterToConsumerBinding",
            # COM hijacking
            "InprocServer32", "CLSID", "TreatAs", "ScriptletURL",
            # DLL hijacking
            "DLL search order", "phantom DLL", "side loading",
        ],
    },
    "lateral_movement": {
        "name": "Lateral Movement",
        "description": "Lateral movement techniques and tools",
        "payloads": [
            # Remote execution
            "psexec", "PSEXESVC", "remcom", "paexec",
            "wmic process call create", "Win32_Process Create",
            "winrm", "Invoke-Command", "Enter-PSSession",
            "smbexec", "dcomexec", "wmiexec", "atexec",
            # Pass-the-hash
            "pass the hash", "pth", "overpass the hash",
            "sekurlsa::pth", "mimikatz pth",
            # Pass-the-ticket
            "pass the ticket", "ptt", "golden ticket", "silver ticket",
            "kerberoast", "asreproast",
            # SMB
            "admin$", "c$", "ipc$", "smbclient", "net use",
            "net view", "net share",
            # RDP
            "mstsc", "RDP", "Remote Desktop", "tsclient",
            # SSH
            "ssh", "plink", "putty",
            # WinRM
            "winrs", "WinRM", "WSMan",
        ],
    },
    "exfiltration": {
        "name": "Exfiltration Channels",
        "description": "Data exfiltration methods and channels",
        "payloads": [
            # DNS
            "dns tunnel", "dns exfil", "iodine", "dnscat", "dns2tcp",
            "subdomain encode", "txt record",
            # HTTP/HTTPS
            "http post", "https upload", "multipart upload",
            "base64 body", "chunked transfer",
            # Cloud services
            "telegram bot", "discord webhook", "slack webhook",
            "pastebin", "transfer.sh", "file.io", "0x0.st",
            "dropbox", "google drive", "onedrive",
            # Other protocols
            "icmp tunnel", "icmp exfil", "smtp exfil",
            "ftp upload", "sftp", "scp",
            # Steganography
            "steganography", "image embed", "audio embed",
            # Clipboard
            "clipboard", "GetClipboardData",
        ],
    },
    "cryptominer": {
        "name": "Cryptominer Indicators",
        "description": "Cryptocurrency mining indicators",
        "payloads": [
            # Protocols
            "stratum+tcp://", "stratum+ssl://", "stratum://",
            # Pools
            "pool.minexmr.com", "xmr-eu1.nanopool.org", "xmrpool.eu",
            "moneropool.com", "supportxmr.com", "hashvault.pro",
            "f2pool.com", "antpool.com", "ethermine.org",
            # Miners
            "xmrig", "xmr-stak", "ccminer", "cgminer", "bfgminer",
            "ethminer", "phoenixminer", "nbminer", "t-rex",
            # Browser miners
            "coinhive", "cryptoloot", "coin-hive", "webminer",
            "miner.start()", "CoinImp",
            # Wallets (patterns)
            "4[0-9AB][0-9a-zA-Z]{93}", "1[a-km-zA-HJ-NP-Z1-9]{25,34}",
            "bc1", "0x", "wallet", "address",
        ],
    },
}


@router.get("/wordlists")
async def get_wordlists():
    """Get available built-in wordlists."""
    result = {}
    for key, wordlist in BUILTIN_WORDLISTS.items():
        result[key] = {
            "name": wordlist["name"],
            "description": wordlist["description"],
            "count": len(wordlist["payloads"]),
        }
    return result


@router.get("/wordlists/{wordlist_id}")
async def get_wordlist(wordlist_id: str):
    """Get a specific wordlist's payloads."""
    if wordlist_id not in BUILTIN_WORDLISTS:
        raise HTTPException(status_code=404, detail=f"Wordlist not found: {wordlist_id}")
    
    return BUILTIN_WORDLISTS[wordlist_id]


# ============================================================================
# ADVANCED FUZZING ENDPOINTS
# ============================================================================

from backend.services.fuzzing_advanced import (
    EncodingType,
    TransformationType,
    encode_payload,
    apply_multiple_encodings,
    generate_encoded_variants,
    transform_payload,
    GeneratorConfig,
    generate_from_config,
    generate_number_range,
    generate_date_range,
    generate_pattern_payloads,
    GrepRule,
    ExtractRule,
    apply_grep_rules,
    apply_extract_rules,
    COMMON_EXTRACT_RULES,
    cluster_responses,
    find_anomalous_responses,
    detect_waf,
    detect_rate_limiting,
    discover_parameters,
    discover_endpoints,
    mutate_payload,
    generate_all_mutations,
    prioritize_payloads,
    export_advanced_analysis,
)


class EncodeRequest(BaseModel):
    """Request for encoding payloads."""
    payloads: List[str] = Field(..., description="Payloads to encode")
    encodings: List[str] = Field(default=["url"], description="Encoding types to apply")
    chain: bool = Field(default=False, description="Chain encodings sequentially")


class GenerateRequest(BaseModel):
    """Request for generating payloads."""
    generator_type: str = Field(..., description="Generator type: number_range, char_range, date_range, uuid, pattern")
    params: Dict[str, Any] = Field(default_factory=dict, description="Generator parameters")


class MutateRequest(BaseModel):
    """Request for mutating payloads."""
    payloads: List[str] = Field(..., description="Payloads to mutate")
    mutation_types: List[str] = Field(default=["case", "encoding"], description="Mutation types to apply")


class GrepRequest(BaseModel):
    """Request for grep matching."""
    content: str = Field(..., description="Content to search")
    rules: List[Dict[str, Any]] = Field(default_factory=list, description="Custom grep rules")
    use_common_rules: bool = Field(default=True, description="Include common extraction rules")


class ClusterRequest(BaseModel):
    """Request for response clustering."""
    responses: List[Dict[str, Any]] = Field(..., description="Responses to cluster")
    similarity_threshold: float = Field(default=0.85, ge=0.5, le=1.0, description="Similarity threshold")


class AnalyzeRequest(BaseModel):
    """Request for comprehensive analysis."""
    responses: List[Dict[str, Any]] = Field(..., description="Responses to analyze")
    detect_waf: bool = Field(default=True, description="Detect WAF presence")
    detect_rate_limit: bool = Field(default=True, description="Detect rate limiting")
    discover_params: bool = Field(default=True, description="Discover parameters from responses")
    cluster_responses: bool = Field(default=True, description="Cluster similar responses")
    extract_data: bool = Field(default=True, description="Extract common data patterns")


@router.post("/encode")
async def encode_payloads(request: EncodeRequest, current_user: User = Depends(get_current_active_user)):
    """
    Encode payloads using various encoding schemes.
    
    Supported encodings: none, url, double_url, base64, html_entities, 
    html_decimal, html_hex, unicode, hex, octal, binary
    """
    try:
        results = {}
        
        for payload in request.payloads:
            if request.chain:
                # Apply encodings sequentially
                encodings = [EncodingType(e) for e in request.encodings if e in [et.value for et in EncodingType]]
                results[payload] = apply_multiple_encodings(payload, encodings)
            else:
                # Generate each encoding variant
                encodings = [EncodingType(e) for e in request.encodings if e in [et.value for et in EncodingType]]
                results[payload] = generate_encoded_variants(payload, encodings)
        
        return {
            "encoded": results,
            "available_encodings": [e.value for e in EncodingType],
        }
    except Exception as e:
        logger.exception(f"Encoding failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate")
async def generate_payloads(request: GenerateRequest, current_user: User = Depends(get_current_active_user)):
    """
    Generate payloads using various generators.
    
    Generator types:
    - number_range: {start, end, step, padding}
    - char_range: {start, end}
    - date_range: {start, end, format}
    - uuid: {count}
    - pattern: {pattern, count}
    """
    try:
        config = GeneratorConfig(type=request.generator_type, params=request.params)
        payloads = generate_from_config(config)
        
        return {
            "payloads": payloads,
            "count": len(payloads),
            "generator_type": request.generator_type,
        }
    except Exception as e:
        logger.exception(f"Generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mutate")
async def mutate_payloads(request: MutateRequest, current_user: User = Depends(get_current_active_user)):
    """
    Generate mutations of payloads.
    
    Mutation types: case, encoding, whitespace, null_byte, comment, concatenation
    """
    try:
        results = {}
        
        for payload in request.payloads:
            mutations = set([payload])
            for mutation_type in request.mutation_types:
                for mutated in mutate_payload(payload, mutation_type):
                    mutations.add(mutated)
            results[payload] = list(mutations)
        
        return {
            "mutations": results,
            "total_variants": sum(len(v) for v in results.values()),
            "available_mutation_types": ["case", "encoding", "whitespace", "null_byte", "comment", "concatenation"],
        }
    except Exception as e:
        logger.exception(f"Mutation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/grep")
async def grep_responses(request: GrepRequest, current_user: User = Depends(get_current_active_user)):
    """
    Search content using grep rules and extract data.
    
    Returns matched patterns and extracted values.
    """
    try:
        rules = []
        
        # Add custom rules
        for rule_data in request.rules:
            rules.append(GrepRule(
                name=rule_data.get("name", "custom"),
                pattern=rule_data.get("pattern", ""),
                is_regex=rule_data.get("is_regex", True),
                case_sensitive=rule_data.get("case_sensitive", False),
                extract_group=rule_data.get("extract_group"),
            ))
        
        # Apply grep rules
        matches = apply_grep_rules(request.content, rules)
        
        # Apply common extract rules if requested
        extracted = {}
        if request.use_common_rules:
            extracted = apply_extract_rules(request.content, COMMON_EXTRACT_RULES)
        
        return {
            "matches": [m.to_dict() for m in matches],
            "match_count": len(matches),
            "extracted": extracted,
        }
    except Exception as e:
        logger.exception(f"Grep failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cluster")
async def cluster_fuzz_responses(request: ClusterRequest, current_user: User = Depends(get_current_active_user)):
    """
    Cluster similar responses together.
    
    Helps identify unique responses and potential anomalies.
    """
    try:
        clusters = cluster_responses(request.responses, request.similarity_threshold)
        anomalies = find_anomalous_responses(request.responses, clusters)
        
        return {
            "clusters": [c.to_dict() for c in clusters],
            "total_clusters": len(clusters),
            "anomalous_responses": anomalies,
            "similarity_threshold": request.similarity_threshold,
        }
    except Exception as e:
        logger.exception(f"Clustering failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze")
async def analyze_responses(request: AnalyzeRequest, current_user: User = Depends(get_current_active_user)):
    """
    Perform comprehensive analysis of fuzzing responses.
    
    Includes WAF detection, rate limiting, parameter discovery, 
    response clustering, and data extraction.
    """
    try:
        results = {
            "response_count": len(request.responses),
        }
        
        # WAF Detection
        if request.detect_waf and request.responses:
            # Use first 403/503 response for WAF detection
            waf_response = next(
                (r for r in request.responses if r.get('status_code') in [403, 503]),
                request.responses[0]
            )
            waf_result = detect_waf(
                waf_response.get('headers', {}),
                waf_response.get('body', ''),
                waf_response.get('status_code', 200)
            )
            results["waf_detection"] = waf_result.to_dict()
        
        # Rate Limit Detection
        if request.detect_rate_limit:
            rate_result = detect_rate_limiting(request.responses)
            results["rate_limiting"] = rate_result.to_dict()
        
        # Parameter Discovery
        if request.discover_params:
            all_params = []
            all_endpoints = set()
            
            for r in request.responses[:10]:  # Limit to first 10 for performance
                body = r.get('body', '')
                if body:
                    params = discover_parameters(body)
                    all_params.extend([p.to_dict() for p in params])
                    endpoints = discover_endpoints(body)
                    all_endpoints.update(endpoints)
            
            # Deduplicate parameters by name
            seen_params = set()
            unique_params = []
            for p in all_params:
                if p['name'] not in seen_params:
                    seen_params.add(p['name'])
                    unique_params.append(p)
            
            results["discovered_parameters"] = unique_params
            results["discovered_endpoints"] = list(all_endpoints)[:50]  # Limit output
        
        # Response Clustering
        if request.cluster_responses:
            clusters = cluster_responses(request.responses)
            anomalies = find_anomalous_responses(request.responses, clusters)
            results["clustering"] = {
                "clusters": [c.to_dict() for c in clusters],
                "total_clusters": len(clusters),
                "anomalous_responses": anomalies,
            }
        
        # Data Extraction
        if request.extract_data:
            all_extracted = {}
            for r in request.responses[:10]:
                body = r.get('body', '')
                if body:
                    extracted = apply_extract_rules(body, COMMON_EXTRACT_RULES)
                    for key, values in extracted.items():
                        if key not in all_extracted:
                            all_extracted[key] = []
                        all_extracted[key].extend(values)
            
            # Deduplicate extracted values
            for key in all_extracted:
                all_extracted[key] = list(set(all_extracted[key]))[:20]  # Limit per category
            
            results["extracted_data"] = all_extracted
        
        # Statistics
        results["statistics"] = {
            "unique_status_codes": list(set(r.get('status_code') for r in request.responses)),
            "avg_response_time": sum(r.get('response_time', 0) for r in request.responses) / len(request.responses) if request.responses else 0,
            "avg_response_length": sum(r.get('response_length', 0) for r in request.responses) / len(request.responses) if request.responses else 0,
            "error_count": sum(1 for r in request.responses if r.get('error')),
            "interesting_count": sum(1 for r in request.responses if r.get('interesting')),
        }
        
        return results
        
    except Exception as e:
        logger.exception(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/encodings")
async def get_available_encodings():
    """Get list of available encoding types."""
    return {
        "encodings": [
            {"value": e.value, "name": e.name.replace("_", " ").title()}
            for e in EncodingType
        ]
    }


@router.get("/transformations")
async def get_available_transformations():
    """Get list of available transformation types."""
    return {
        "transformations": [
            {"value": t.value, "name": t.name.replace("_", " ").title()}
            for t in TransformationType
        ]
    }


@router.get("/generators")
async def get_available_generators():
    """Get information about available payload generators."""
    return {
        "generators": [
            {
                "type": "number_range",
                "description": "Generate a range of numbers",
                "params": {"start": "int", "end": "int", "step": "int (optional)", "padding": "int (optional)"},
                "example": {"start": 1, "end": 100, "step": 1, "padding": 4}
            },
            {
                "type": "char_range",
                "description": "Generate a range of characters",
                "params": {"start": "char", "end": "char"},
                "example": {"start": "a", "end": "z"}
            },
            {
                "type": "date_range",
                "description": "Generate a range of dates",
                "params": {"start": "YYYY-MM-DD", "end": "YYYY-MM-DD", "format": "strftime format"},
                "example": {"start": "2024-01-01", "end": "2024-12-31", "format": "%Y-%m-%d"}
            },
            {
                "type": "uuid",
                "description": "Generate random UUIDs",
                "params": {"count": "int"},
                "example": {"count": 10}
            },
            {
                "type": "pattern",
                "description": "Generate payloads from a pattern",
                "params": {"pattern": "string with [a-z], [0-9], etc.", "count": "int"},
                "example": {"pattern": "user[0-9]{4}", "count": 10}
            }
        ]
    }


# =============================================================================
# Session Management Endpoints
# =============================================================================

class SessionCreateRequest(BaseModel):
    """Request to create a new fuzzing session."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    target_url: str
    method: str = "GET"
    config: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    project_id: Optional[int] = Field(default=None, description="Associate session with a project")


class SessionUpdateRequest(BaseModel):
    """Request to update a fuzzing session."""
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    results: Optional[List[Dict[str, Any]]] = None
    findings: Optional[List[Dict[str, Any]]] = None
    analysis: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    total_requests: Optional[int] = None
    success_count: Optional[int] = None
    error_count: Optional[int] = None
    interesting_count: Optional[int] = None
    avg_response_time: Optional[float] = None


class SessionListResponse(BaseModel):
    """Response for listing sessions."""
    sessions: List[Dict[str, Any]]
    total: int
    page: int
    page_size: int


@router.post("/sessions", response_model=Dict[str, Any])
async def create_session(request: SessionCreateRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    """Create a new fuzzing session."""
    try:
        session = FuzzingSession(
            name=request.name,
            description=request.description,
            target_url=request.target_url,
            method=request.method,
            config=request.config,
            tags=request.tags,
            status="created",
            project_id=request.project_id,
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        
        return {
            "id": session.id,
            "name": session.name,
            "target_url": session.target_url,
            "status": session.status,
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "message": "Session created successfully",
        }
    except Exception as e:
        db.rollback()
        logger.exception(f"Failed to create session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    page: int = 1,
    page_size: int = 20,
    status: Optional[str] = None,
    search: Optional[str] = None,
    project_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all fuzzing sessions with pagination and filtering."""
    try:
        query = db.query(FuzzingSession)
        
        # Apply filters
        if status:
            query = query.filter(FuzzingSession.status == status)
        if search:
            query = query.filter(
                FuzzingSession.name.ilike(f"%{search}%") |
                FuzzingSession.target_url.ilike(f"%{search}%")
            )
        if project_id is not None:
            query = query.filter(FuzzingSession.project_id == project_id)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        offset = (page - 1) * page_size
        sessions = query.order_by(FuzzingSession.created_at.desc()).offset(offset).limit(page_size).all()
        
        return SessionListResponse(
            sessions=[
                {
                    "id": s.id,
                    "name": s.name,
                    "description": s.description,
                    "target_url": s.target_url,
                    "method": s.method,
                    "status": s.status,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                    "updated_at": s.updated_at.isoformat() if s.updated_at else None,
                    "started_at": s.started_at.isoformat() if s.started_at else None,
                    "finished_at": s.finished_at.isoformat() if s.finished_at else None,
                    "total_requests": s.total_requests,
                    "success_count": s.success_count,
                    "error_count": s.error_count,
                    "interesting_count": s.interesting_count,
                    "avg_response_time": s.avg_response_time,
                    "tags": s.tags or [],
                    "findings_count": len(s.findings) if s.findings else 0,
                    "project_id": s.project_id,
                }
                for s in sessions
            ],
            total=total,
            page=page,
            page_size=page_size,
        )
    except Exception as e:
        logger.exception(f"Failed to list sessions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}", response_model=Dict[str, Any])
async def get_session(session_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    """Get a specific fuzzing session with all details."""
    try:
        session = db.query(FuzzingSession).filter(FuzzingSession.id == session_id).first()
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return {
            "id": session.id,
            "name": session.name,
            "description": session.description,
            "target_url": session.target_url,
            "method": session.method,
            "status": session.status,
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "updated_at": session.updated_at.isoformat() if session.updated_at else None,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "finished_at": session.finished_at.isoformat() if session.finished_at else None,
            "config": session.config,
            "total_requests": session.total_requests,
            "success_count": session.success_count,
            "error_count": session.error_count,
            "interesting_count": session.interesting_count,
            "avg_response_time": session.avg_response_time,
            "results": session.results,
            "findings": session.findings,
            "analysis": session.analysis,
            "tags": session.tags or [],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Failed to get session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/sessions/{session_id}", response_model=Dict[str, Any])
async def update_session(
    session_id: int,
    request: SessionUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Update a fuzzing session."""
    try:
        session = db.query(FuzzingSession).filter(FuzzingSession.id == session_id).first()
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Update fields if provided
        if request.name is not None:
            session.name = request.name
        if request.description is not None:
            session.description = request.description
        if request.status is not None:
            session.status = request.status
            if request.status == "running" and not session.started_at:
                session.started_at = datetime.utcnow()
            elif request.status in ["completed", "failed"]:
                session.finished_at = datetime.utcnow()
        if request.results is not None:
            session.results = request.results
        if request.findings is not None:
            session.findings = request.findings
        if request.analysis is not None:
            session.analysis = request.analysis
        if request.tags is not None:
            session.tags = request.tags
        if request.total_requests is not None:
            session.total_requests = request.total_requests
        if request.success_count is not None:
            session.success_count = request.success_count
        if request.error_count is not None:
            session.error_count = request.error_count
        if request.interesting_count is not None:
            session.interesting_count = request.interesting_count
        if request.avg_response_time is not None:
            session.avg_response_time = request.avg_response_time
        
        db.commit()
        db.refresh(session)
        
        return {
            "id": session.id,
            "name": session.name,
            "status": session.status,
            "message": "Session updated successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"Failed to update session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    """Delete a fuzzing session."""
    try:
        session = db.query(FuzzingSession).filter(FuzzingSession.id == session_id).first()
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        db.delete(session)
        db.commit()
        
        return {"message": "Session deleted successfully", "id": session_id}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"Failed to delete session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sessions/{session_id}/duplicate", response_model=Dict[str, Any])
async def duplicate_session(session_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    """Duplicate a fuzzing session (config only, not results)."""
    try:
        original = db.query(FuzzingSession).filter(FuzzingSession.id == session_id).first()
        if not original:
            raise HTTPException(status_code=404, detail="Session not found")
        
        new_session = FuzzingSession(
            name=f"{original.name} (Copy)",
            description=original.description,
            target_url=original.target_url,
            method=original.method,
            config=original.config,
            tags=original.tags,
            status="created",
        )
        db.add(new_session)
        db.commit()
        db.refresh(new_session)
        
        return {
            "id": new_session.id,
            "name": new_session.name,
            "message": "Session duplicated successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"Failed to duplicate session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Smart Detection Endpoints
# =============================================================================

class SmartDetectRequest(BaseModel):
    """Request for smart vulnerability detection."""
    responses: List[Dict[str, Any]] = Field(..., description="Fuzzing responses to analyze")
    baseline_response: Optional[Dict[str, Any]] = Field(None, description="Optional baseline for comparison")


class AnomalyDetectRequest(BaseModel):
    """Request for anomaly detection."""
    responses: List[Dict[str, Any]] = Field(..., description="Fuzzing responses to analyze")
    sensitivity: float = Field(default=2.0, ge=1.0, le=5.0, description="Anomaly sensitivity (z-score threshold)")


class DifferentialRequest(BaseModel):
    """Request for differential analysis."""
    baseline_response: Dict[str, Any] = Field(..., description="Baseline response for comparison")
    test_responses: List[Dict[str, Any]] = Field(..., description="Responses to compare against baseline")


class AutoAnalyzeRequest(BaseModel):
    """Request for automatic comprehensive analysis."""
    responses: List[Dict[str, Any]] = Field(..., description="Fuzzing responses to analyze")
    detect_vulnerabilities: bool = Field(default=True)
    detect_anomalies: bool = Field(default=True)
    categorize: bool = Field(default=True)
    differential: bool = Field(default=False)
    baseline_index: int = Field(default=0, description="Index of response to use as baseline for differential")


@router.post("/smart-detect/vulnerabilities")
async def smart_detect_vulnerabilities(request: SmartDetectRequest, current_user: User = Depends(get_current_active_user)):
    """
    Detect potential vulnerabilities in fuzzing responses using signature-based detection.
    
    Analyzes responses for:
    - SQL injection error messages
    - XSS reflection
    - Command injection output
    - Path traversal file content
    - SSTI template evaluation
    - Information disclosure
    - And more...
    """
    try:
        # Normalize response format for detection engine
        normalized_responses = []
        for resp in request.responses:
            normalized = {
                "id": resp.get("id"),
                "payload": resp.get("payload", ""),
                "body": resp.get("body") or resp.get("response_body", ""),
                "headers": resp.get("headers") or resp.get("response_headers", {}),
                "status_code": resp.get("status_code", 0),
                "response_time": resp.get("response_time", 0),
            }
            normalized_responses.append(normalized)
        
        # Normalize baseline if provided
        baseline = None
        if request.baseline_response:
            baseline = {
                "id": request.baseline_response.get("id"),
                "body": request.baseline_response.get("body") or request.baseline_response.get("response_body", ""),
                "headers": request.baseline_response.get("headers") or request.baseline_response.get("response_headers", {}),
                "status_code": request.baseline_response.get("status_code", 0),
            }
        
        findings = detect_vulnerabilities(normalized_responses, baseline)
        
        return {
            "findings": [f.to_dict() for f in findings],
            "total": len(findings),
            "by_severity": {
                "critical": sum(1 for f in findings if f.severity.value == "critical"),
                "high": sum(1 for f in findings if f.severity.value == "high"),
                "medium": sum(1 for f in findings if f.severity.value == "medium"),
                "low": sum(1 for f in findings if f.severity.value == "low"),
                "info": sum(1 for f in findings if f.severity.value == "info"),
            },
            "by_type": _count_by_field(findings, lambda f: f.vuln_type.value),
        }
    except Exception as e:
        logger.exception(f"Vulnerability detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/smart-detect/anomalies")
async def smart_detect_anomalies(request: AnomalyDetectRequest, current_user: User = Depends(get_current_active_user)):
    """
    Detect anomalous responses using statistical analysis.
    
    Detects:
    - Response time anomalies
    - Response length anomalies
    - Status code anomalies
    - Content anomalies
    """
    try:
        # Normalize response format for detection engine
        normalized_responses = []
        for resp in request.responses:
            normalized = {
                "id": resp.get("id"),
                "payload": resp.get("payload", ""),
                "body": resp.get("body") or resp.get("response_body", ""),
                "headers": resp.get("headers") or resp.get("response_headers", {}),
                "status_code": resp.get("status_code", 0),
                "response_time": resp.get("response_time", 0),
                "content_length": resp.get("content_length") or len(resp.get("body") or resp.get("response_body", "")),
            }
            normalized_responses.append(normalized)
        
        anomalies = detect_anomalies(normalized_responses)
        
        return {
            "anomalies": [a.to_dict() for a in anomalies],
            "total": len(anomalies),
            "by_type": _count_by_field(anomalies, lambda a: a.anomaly_type),
            "most_anomalous": [a.response_id for a in anomalies[:10]],
        }
    except Exception as e:
        logger.exception(f"Anomaly detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/smart-detect/differential")
async def smart_differential_analysis(request: DifferentialRequest, current_user: User = Depends(get_current_active_user)):
    """
    Perform differential analysis comparing responses to a baseline.
    
    Useful for:
    - Boolean-based SQL injection detection
    - Authentication bypass detection
    - Access control testing
    """
    try:
        # Normalize baseline
        baseline = {
            "id": request.baseline_response.get("id"),
            "body": request.baseline_response.get("body") or request.baseline_response.get("response_body", ""),
            "headers": request.baseline_response.get("headers") or request.baseline_response.get("response_headers", {}),
            "status_code": request.baseline_response.get("status_code", 0),
            "response_time": request.baseline_response.get("response_time", 0),
            "content_length": request.baseline_response.get("content_length") or len(request.baseline_response.get("body") or request.baseline_response.get("response_body", "")),
        }
        
        # Normalize test responses
        test_responses = []
        for resp in request.test_responses:
            normalized = {
                "id": resp.get("id"),
                "payload": resp.get("payload", ""),
                "body": resp.get("body") or resp.get("response_body", ""),
                "headers": resp.get("headers") or resp.get("response_headers", {}),
                "status_code": resp.get("status_code", 0),
                "response_time": resp.get("response_time", 0),
                "content_length": resp.get("content_length") or len(resp.get("body") or resp.get("response_body", "")),
            }
            test_responses.append(normalized)
        
        results = differential_analysis(baseline, test_responses)
        
        interesting = [r for r in results if r.get("potentially_interesting")]
        
        return {
            "results": results,
            "total": len(results),
            "interesting_count": len(interesting),
            "most_different": [r["response_id"] for r in interesting[:10]],
        }
    except Exception as e:
        logger.exception(f"Differential analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/smart-detect/categorize")
async def smart_categorize_responses(request: SmartDetectRequest, current_user: User = Depends(get_current_active_user)):
    """
    Automatically categorize responses into groups.
    
    Categories include:
    - success (2xx)
    - redirect (3xx)
    - client_error (4xx)
    - server_error (5xx)
    - rate_limited (429)
    - blocked (WAF)
    - interesting
    - timeout
    """
    try:
        # Normalize responses
        normalized_responses = []
        for resp in request.responses:
            normalized = {
                "id": resp.get("id"),
                "payload": resp.get("payload", ""),
                "body": resp.get("body") or resp.get("response_body", ""),
                "headers": resp.get("headers") or resp.get("response_headers", {}),
                "status_code": resp.get("status_code", 0),
                "response_time": resp.get("response_time", 0),
                "error": resp.get("error", ""),
                "flags": resp.get("flags", []),
                "interesting": resp.get("interesting", False),
            }
            normalized_responses.append(normalized)
        
        categories = categorize_responses(normalized_responses)
        
        return {
            "categories": categories,
            "summary": {
                category: len(ids) for category, ids in categories.items()
            },
        }
    except Exception as e:
        logger.exception(f"Categorization failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _normalize_responses(responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize response format for detection engine."""
    normalized = []
    for resp in responses:
        norm = {
            "id": resp.get("id"),
            "payload": resp.get("payload", ""),
            "body": resp.get("body") or resp.get("response_body", ""),
            "headers": resp.get("headers") or resp.get("response_headers", {}),
            "status_code": resp.get("status_code", 0),
            "response_time": resp.get("response_time", 0),
            "content_length": resp.get("content_length") or len(resp.get("body") or resp.get("response_body", "")),
            "error": resp.get("error", ""),
            "flags": resp.get("flags", []),
            "interesting": resp.get("interesting", False),
        }
        normalized.append(norm)
    return normalized


@router.post("/smart-detect/auto-analyze")
async def smart_auto_analyze(request: AutoAnalyzeRequest, current_user: User = Depends(get_current_active_user)):
    """
    Perform comprehensive automatic analysis on fuzzing responses.
    
    Combines vulnerability detection, anomaly detection, categorization,
    and optionally differential analysis into a single request.
    """
    try:
        # Normalize all responses once
        normalized = _normalize_responses(request.responses)
        
        result = {
            "responses_analyzed": len(normalized),
        }
        
        # Vulnerability detection
        if request.detect_vulnerabilities:
            findings = detect_vulnerabilities(normalized)
            result["vulnerabilities"] = {
                "findings": [f.to_dict() for f in findings],
                "total": len(findings),
                "by_severity": {
                    "critical": sum(1 for f in findings if f.severity.value == "critical"),
                    "high": sum(1 for f in findings if f.severity.value == "high"),
                    "medium": sum(1 for f in findings if f.severity.value == "medium"),
                    "low": sum(1 for f in findings if f.severity.value == "low"),
                    "info": sum(1 for f in findings if f.severity.value == "info"),
                },
            }
        
        # Anomaly detection
        if request.detect_anomalies:
            anomalies = detect_anomalies(normalized)
            result["anomalies"] = {
                "items": [a.to_dict() for a in anomalies],
                "total": len(anomalies),
                "by_type": _count_by_field(anomalies, lambda a: a.anomaly_type),
            }
        
        # Categorization
        if request.categorize:
            categories = categorize_responses(normalized)
            result["categories"] = {
                "groups": categories,
                "summary": {cat: len(ids) for cat, ids in categories.items()},
            }
        
        # Differential analysis
        if request.differential and len(normalized) > request.baseline_index:
            baseline = normalized[request.baseline_index]
            test_responses = [r for i, r in enumerate(normalized) if i != request.baseline_index]
            diff_results = differential_analysis(baseline, test_responses)
            interesting = [r for r in diff_results if r.get("potentially_interesting")]
            result["differential"] = {
                "results": diff_results[:50],  # Limit output
                "interesting_count": len(interesting),
            }
        
        # Create summary
        findings = result.get("vulnerabilities", {}).get("findings", [])
        anomaly_list = result.get("anomalies", {}).get("items", [])
        
        # Calculate risk score
        severity_weights = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 1}
        risk_score = sum(
            severity_weights.get(f.get("severity", "info"), 0)
            for f in findings
        )
        risk_score = min(100, risk_score)
        
        result["summary"] = {
            "risk_score": risk_score,
            "risk_level": (
                "critical" if risk_score >= 70 else
                "high" if risk_score >= 40 else
                "medium" if risk_score >= 20 else
                "low" if risk_score >= 5 else
                "info"
            ),
            "findings_count": len(findings),
            "anomalies_count": len(anomaly_list),
            "interesting_count": len(result.get("categories", {}).get("groups", {}).get("interesting", [])),
        }
        
        return result
    except Exception as e:
        logger.exception(f"Auto analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sessions/{session_id}/auto-analyze")
async def analyze_session(session_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    """
    Run automatic analysis on a saved session's results and update the session.
    """
    try:
        session = db.query(FuzzingSession).filter(FuzzingSession.id == session_id).first()
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        if not session.results:
            raise HTTPException(status_code=400, detail="Session has no results to analyze")
        
        responses = session.results
        
        # Run all detections
        findings = detect_vulnerabilities(responses)
        anomalies = detect_anomalies(responses)
        categories = categorize_responses(responses)
        
        # Create analysis results
        analysis = {
            "vulnerabilities": {
                "findings": [f.to_dict() for f in findings],
                "total": len(findings),
                "by_severity": {
                    "critical": sum(1 for f in findings if f.severity.value == "critical"),
                    "high": sum(1 for f in findings if f.severity.value == "high"),
                    "medium": sum(1 for f in findings if f.severity.value == "medium"),
                    "low": sum(1 for f in findings if f.severity.value == "low"),
                    "info": sum(1 for f in findings if f.severity.value == "info"),
                },
            },
            "anomalies": {
                "items": [a.to_dict() for a in anomalies],
                "total": len(anomalies),
            },
            "categories": {
                "groups": categories,
                "summary": {cat: len(ids) for cat, ids in categories.items()},
            },
            "analyzed_at": datetime.utcnow().isoformat(),
        }
        
        # Calculate risk
        severity_weights = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 1}
        risk_score = min(100, sum(
            severity_weights.get(f.severity.value, 0) for f in findings
        ))
        
        analysis["summary"] = {
            "risk_score": risk_score,
            "risk_level": (
                "critical" if risk_score >= 70 else
                "high" if risk_score >= 40 else
                "medium" if risk_score >= 20 else
                "low" if risk_score >= 5 else
                "info"
            ),
        }
        
        # Update session
        session.findings = [f.to_dict() for f in findings]
        session.analysis = analysis
        db.commit()
        
        return {
            "session_id": session_id,
            "analysis": analysis,
            "message": "Session analyzed successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"Session analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _count_by_field(items, field_getter):
    """Helper to count items by a field value."""
    counts = {}
    for item in items:
        value = field_getter(item)
        counts[value] = counts.get(value, 0) + 1
    return counts


# =============================================================================
# OFFENSIVE SECURITY ANALYSIS ENDPOINTS
# For analyzing sandboxed software, malware behavior, and C2 communication
# =============================================================================

class OffensiveAnalysisRequest(BaseModel):
    """Request model for offensive security analysis."""
    responses: List[Dict[str, Any]] = Field(..., description="Responses to analyze")
    include_c2: bool = Field(default=True, description="Detect C2 communication patterns")
    include_malware: bool = Field(default=True, description="Detect malware behaviors")
    include_evasion: bool = Field(default=True, description="Detect sandbox evasion techniques")
    include_iocs: bool = Field(default=True, description="Extract IOCs (IPs, domains, hashes)")


class OffensivePayloadsRequest(BaseModel):
    """Request model for generating offensive payloads."""
    payload_types: List[str] = Field(
        default=["c2", "evasion", "malware", "api_hooking"],
        description="Types of payloads to generate"
    )


@router.post("/offensive/analyze", response_model=Dict[str, Any])
async def offensive_analysis(
    request: OffensiveAnalysisRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Perform offensive security analysis on fuzzing responses.
    
    Analyzes responses for:
    - C2 (Command & Control) communication patterns
    - Malware behavior indicators (persistence, injection, credential theft)
    - Sandbox evasion techniques
    - IOC extraction (IPs, domains, hashes, file paths)
    
    This endpoint is designed for analyzing sandboxed software responses
    to detect malicious behavior and C2 infrastructure.
    """
    try:
        normalized = _normalize_responses(request.responses)
        
        # Use fuzzing_advanced offensive analysis
        result = perform_offensive_analysis(
            normalized,
            include_c2=request.include_c2,
            include_malware=request.include_malware,
            include_evasion=request.include_evasion,
            include_iocs=request.include_iocs,
        )
        
        return result.to_dict()
        
    except Exception as e:
        logger.exception(f"Offensive analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/offensive/detect-indicators", response_model=Dict[str, Any])
async def detect_offensive_indicators_endpoint(
    request: OffensiveAnalysisRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Detect offensive security indicators using smart detection signatures.
    
    Uses pattern-based detection to identify:
    - C2 framework signatures (Cobalt Strike, Metasploit, Empire, etc.)
    - Process injection techniques
    - Credential theft indicators
    - Persistence mechanisms
    - Lateral movement techniques
    - Exfiltration patterns
    - Cryptominer and ransomware indicators
    
    Returns MITRE ATT&CK mappings for detected techniques.
    """
    try:
        normalized = _normalize_responses(request.responses)
        
        indicators = detect_offensive_indicators(
            normalized,
            include_c2=request.include_c2,
            include_malware=request.include_malware,
            include_evasion=request.include_evasion,
        )
        
        # Group by type
        by_type = {}
        for ind in indicators:
            ind_type = ind.get("type", "unknown")
            if ind_type not in by_type:
                by_type[ind_type] = []
            by_type[ind_type].append(ind)
        
        return {
            "total_indicators": len(indicators),
            "indicators": indicators,
            "by_type": by_type,
            "mitre_techniques": list(set(i.get("mitre_id") for i in indicators if i.get("mitre_id"))),
        }
        
    except Exception as e:
        logger.exception(f"Offensive indicator detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/offensive/full-report", response_model=Dict[str, Any])
async def generate_offensive_report_endpoint(
    request: OffensiveAnalysisRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Generate comprehensive offensive security analysis report.
    
    Combines all offensive analysis capabilities into a single report:
    - Threat score and level assessment
    - MITRE ATT&CK technique mapping
    - Categorized indicators by threat type
    - Actionable recommendations
    
    Ideal for security analysts investigating suspicious software behavior.
    """
    try:
        normalized = _normalize_responses(request.responses)
        
        report = generate_offensive_report(normalized)
        
        return report
        
    except Exception as e:
        logger.exception(f"Offensive report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/offensive/extract-iocs", response_model=Dict[str, Any])
async def extract_iocs_endpoint(
    request: OffensiveAnalysisRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Extract Indicators of Compromise (IOCs) from responses.
    
    Extracts:
    - IP addresses
    - Domains
    - URLs
    - File hashes (MD5, SHA1, SHA256)
    - Email addresses
    - Cryptocurrency addresses (Bitcoin, Monero)
    - File paths (Windows/Unix)
    - Registry keys
    - Mutex names
    
    Useful for threat intelligence and IOC sharing.
    """
    try:
        # Combine all response content
        all_content = ""
        for resp in request.responses:
            body = resp.get("body") or resp.get("response_body", "")
            all_content += body + "\n"
        
        iocs = extract_iocs(all_content)
        
        # Count totals
        total_iocs = sum(len(v) for v in iocs.values())
        
        return {
            "total_iocs": total_iocs,
            "iocs": iocs,
            "types_found": list(iocs.keys()),
        }
        
    except Exception as e:
        logger.exception(f"IOC extraction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/offensive/detect-security-products", response_model=Dict[str, Any])
async def detect_security_products_endpoint(
    request: OffensiveAnalysisRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Detect security products mentioned in responses.
    
    Identifies EDR/AV products:
    - CrowdStrike Falcon
    - Carbon Black
    - SentinelOne
    - Microsoft Defender
    - Symantec/Norton
    - McAfee
    - Kaspersky
    - Sophos
    
    Useful for understanding the defensive posture of analyzed systems.
    """
    try:
        all_content = ""
        for resp in request.responses:
            body = resp.get("body") or resp.get("response_body", "")
            all_content += body + "\n"
        
        products = detect_security_products(all_content)
        
        return {
            "products_detected": len(products),
            "products": products,
        }
        
    except Exception as e:
        logger.exception(f"Security product detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/offensive/payloads", response_model=Dict[str, Any])
async def get_offensive_payloads(
    payload_type: str = "all",
    current_user: User = Depends(get_current_active_user)
):
    """
    Get offensive security testing payloads.
    
    Available payload types:
    - c2: C2 infrastructure probe payloads
    - evasion: Sandbox evasion test payloads
    - malware: Common malware string payloads
    - api_hooking: API hooking detection payloads
    - all: All payload types
    
    These payloads are designed for testing detection capabilities
    and analyzing sandboxed software responses.
    """
    try:
        payloads = {}
        
        if payload_type in ["all", "c2"]:
            payloads["c2_probes"] = generate_c2_probe_payloads()
        
        if payload_type in ["all", "evasion"]:
            payloads["evasion_tests"] = generate_evasion_test_payloads()
        
        if payload_type in ["all", "malware"]:
            payloads["malware_strings"] = generate_malware_string_payloads()
        
        if payload_type in ["all", "api_hooking"]:
            payloads["api_hooking"] = generate_api_hooking_payloads()
        
        total_payloads = sum(len(v) for v in payloads.values())
        
        return {
            "total_payloads": total_payloads,
            "payload_types": list(payloads.keys()),
            "payloads": payloads,
        }
        
    except Exception as e:
        logger.exception(f"Payload generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/offensive/combined-analysis", response_model=Dict[str, Any])
async def combined_offensive_analysis(
    request: OffensiveAnalysisRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Perform combined web vulnerability and offensive security analysis.
    
    This endpoint combines:
    - Traditional web vulnerability detection (SQLi, XSS, etc.)
    - Offensive security analysis (C2, malware, evasion)
    - IOC extraction
    - MITRE ATT&CK mapping
    
    Provides comprehensive analysis for both web application security
    and malware/C2 detection use cases.
    """
    try:
        normalized = _normalize_responses(request.responses)
        
        result = {
            "responses_analyzed": len(normalized),
        }
        
        # Web vulnerability detection
        web_findings = detect_vulnerabilities(normalized)
        result["web_vulnerabilities"] = {
            "findings": [f.to_dict() for f in web_findings],
            "total": len(web_findings),
            "by_severity": {
                "critical": sum(1 for f in web_findings if f.severity.value == "critical"),
                "high": sum(1 for f in web_findings if f.severity.value == "high"),
                "medium": sum(1 for f in web_findings if f.severity.value == "medium"),
                "low": sum(1 for f in web_findings if f.severity.value == "low"),
            },
        }
        
        # Offensive analysis
        offensive_result = perform_offensive_analysis(
            normalized,
            include_c2=request.include_c2,
            include_malware=request.include_malware,
            include_evasion=request.include_evasion,
            include_iocs=request.include_iocs,
        )
        result["offensive_analysis"] = offensive_result.to_dict()
        
        # Smart detection indicators
        smart_indicators = detect_offensive_indicators(
            normalized,
            include_c2=request.include_c2,
            include_malware=request.include_malware,
            include_evasion=request.include_evasion,
        )
        result["offensive_indicators"] = {
            "total": len(smart_indicators),
            "indicators": smart_indicators,
            "mitre_techniques": list(set(
                i.get("mitre_id") for i in smart_indicators if i.get("mitre_id")
            )),
        }
        
        # Combined risk assessment
        web_risk = sum(
            {"critical": 40, "high": 25, "medium": 10, "low": 3}.get(f.severity.value, 0)
            for f in web_findings
        )
        offensive_risk = offensive_result.risk_score
        
        combined_risk = min(100, (web_risk + offensive_risk) / 2 + max(web_risk, offensive_risk) / 2)
        
        if combined_risk >= 70:
            combined_level = "critical"
        elif combined_risk >= 50:
            combined_level = "high"
        elif combined_risk >= 25:
            combined_level = "medium"
        elif combined_risk > 0:
            combined_level = "low"
        else:
            combined_level = "clean"
        
        result["combined_assessment"] = {
            "web_risk_score": min(100, web_risk),
            "offensive_risk_score": offensive_risk,
            "combined_risk_score": round(combined_risk, 1),
            "threat_level": combined_level,
            "total_findings": len(web_findings) + len(smart_indicators),
        }
        
        return result
        
    except Exception as e:
        logger.exception(f"Combined analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# WEBSOCKET DEEP FUZZING ENDPOINTS
# ============================================================================

class WSFuzzRequest(BaseModel):
    """Request model for WebSocket fuzzing."""
    target_url: str  # ws:// or wss:// URL
    initial_messages: List[str] = []
    auth_token: Optional[str] = None
    auth_header: str = "Authorization"
    origin: Optional[str] = None
    subprotocols: List[str] = []
    attack_categories: List[str] = ["all"]
    custom_payloads: List[str] = []
    message_template: str = ""
    timeout: int = 10000
    delay_between_tests: int = 100
    max_messages_per_test: int = 10


@router.post("/websocket/run", tags=["WebSocket Fuzzing"])
async def run_websocket_fuzzing(
    request: WSFuzzRequest,
    current_user: User = Depends(get_current_active_user),
):
    """
    Run WebSocket deep fuzzing session.
    
    Tests for various WebSocket vulnerabilities including:
    - Authentication bypass
    - State manipulation
    - Frame injection
    - Message tampering (injection attacks)
    - Race conditions
    - Cross-Site WebSocket Hijacking (CSWSH)
    - Protocol violations
    - Denial of service
    """
    from services.fuzzing_service import WSFuzzConfig, run_websocket_fuzzing
    
    try:
        config = WSFuzzConfig(
            target_url=request.target_url,
            initial_messages=request.initial_messages,
            auth_token=request.auth_token,
            auth_header=request.auth_header,
            origin=request.origin,
            subprotocols=request.subprotocols,
            attack_categories=request.attack_categories,
            custom_payloads=request.custom_payloads,
            message_template=request.message_template,
            timeout=request.timeout,
            delay_between_tests=request.delay_between_tests,
            max_messages_per_test=request.max_messages_per_test,
        )
        
        session = await run_websocket_fuzzing(config)
        return session.to_dict()
        
    except Exception as e:
        logger.exception(f"WebSocket fuzzing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/websocket/stream", tags=["WebSocket Fuzzing"])
async def stream_websocket_fuzzing_endpoint(
    request: WSFuzzRequest,
    current_user: User = Depends(get_current_active_user),
):
    """
    Stream WebSocket fuzzing results in real-time.
    
    Returns Server-Sent Events with:
    - start: Initial info with total tests
    - progress: Individual test results
    - complete: Final stats and findings
    """
    from services.fuzzing_service import WSFuzzConfig, stream_websocket_fuzzing
    
    config = WSFuzzConfig(
        target_url=request.target_url,
        initial_messages=request.initial_messages,
        auth_token=request.auth_token,
        auth_header=request.auth_header,
        origin=request.origin,
        subprotocols=request.subprotocols,
        attack_categories=request.attack_categories,
        custom_payloads=request.custom_payloads,
        message_template=request.message_template,
        timeout=request.timeout,
        delay_between_tests=request.delay_between_tests,
        max_messages_per_test=request.max_messages_per_test,
    )
    
    async def event_generator():
        async for event in stream_websocket_fuzzing(config):
            yield f"data: {json.dumps(event)}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@router.get("/websocket/payloads", tags=["WebSocket Fuzzing"])
async def get_websocket_payloads(
    category: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
):
    """
    Get available WebSocket attack payloads.
    
    Categories:
    - auth_bypass: Authentication bypass tests
    - state_manipulation: State machine attacks
    - frame_injection: Frame-level attacks
    - message_tampering: Injection attacks
    - race_condition: Race condition tests
    - cswsh: Cross-Site WebSocket Hijacking
    - protocol_violation: Protocol compliance tests
    - dos: Denial of service
    """
    from services.fuzzing_service import WS_ATTACK_PAYLOADS, WSAttackCategory
    
    if category:
        try:
            cat = WSAttackCategory(category)
            if cat in WS_ATTACK_PAYLOADS:
                return {category: WS_ATTACK_PAYLOADS[cat]}
            raise HTTPException(status_code=404, detail=f"Category not found: {category}")
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid category: {category}")
    
    return {
        "categories": [c.value for c in WSAttackCategory],
        "payloads": {c.value: {
            "name": info["name"],
            "description": info["description"],
            "severity": info["severity"],
            "payload_count": len(info["payloads"]),
        } for c, info in WS_ATTACK_PAYLOADS.items()},
    }


@router.get("/websocket/categories", tags=["WebSocket Fuzzing"])
async def get_websocket_categories(
    current_user: User = Depends(get_current_active_user),
):
    """Get list of WebSocket attack categories with descriptions."""
    from services.fuzzing_service import WS_ATTACK_PAYLOADS, WSAttackCategory
    
    return {
        "categories": [
            {
                "id": c.value,
                "name": WS_ATTACK_PAYLOADS[c]["name"],
                "description": WS_ATTACK_PAYLOADS[c]["description"],
                "severity": WS_ATTACK_PAYLOADS[c]["severity"],
                "payload_count": len(WS_ATTACK_PAYLOADS[c]["payloads"]),
            }
            for c in WSAttackCategory
            if c in WS_ATTACK_PAYLOADS
        ]
    }


# ============================================================================
# COVERAGE TRACKING ENDPOINTS
# ============================================================================

# In-memory coverage sessions (in production, use Redis or database)
_coverage_sessions: Dict[str, Any] = {}


class CreateCoverageSessionRequest(BaseModel):
    """Request to create a coverage tracking session."""
    target_base_url: str


class UpdateCoverageRequest(BaseModel):
    """Request to update coverage from fuzzing results."""
    session_id: str
    endpoint: str
    method: str
    techniques_tested: List[str]
    fuzz_result: Dict[str, Any]


@router.post("/coverage/sessions", tags=["Coverage Tracking"])
async def create_coverage_session_endpoint(
    request: CreateCoverageSessionRequest,
    current_user: User = Depends(get_current_active_user),
):
    """Create a new coverage tracking session."""
    from services.fuzzing_service import create_coverage_session
    
    session = create_coverage_session(request.target_base_url)
    _coverage_sessions[session.session_id] = session
    
    return session.to_dict()


@router.get("/coverage/sessions/{session_id}", tags=["Coverage Tracking"])
async def get_coverage_session(
    session_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Get coverage session by ID."""
    if session_id not in _coverage_sessions:
        raise HTTPException(status_code=404, detail="Coverage session not found")
    
    return _coverage_sessions[session_id].to_dict()


@router.get("/coverage/sessions", tags=["Coverage Tracking"])
async def list_coverage_sessions(
    current_user: User = Depends(get_current_active_user),
):
    """List all coverage sessions."""
    return {
        "sessions": [
            {
                "session_id": s.session_id,
                "target_base_url": s.target_base_url,
                "coverage_percent": s.overall_stats["coverage_percent"],
                "total_findings": s.overall_stats["total_findings"],
                "started_at": s.started_at,
                "updated_at": s.updated_at,
            }
            for s in _coverage_sessions.values()
        ]
    }


@router.post("/coverage/update", tags=["Coverage Tracking"])
async def update_coverage(
    request: UpdateCoverageRequest,
    current_user: User = Depends(get_current_active_user),
):
    """Update coverage session with fuzzing results."""
    from services.fuzzing_service import update_coverage_from_fuzz_results, FuzzResult
    
    if request.session_id not in _coverage_sessions:
        raise HTTPException(status_code=404, detail="Coverage session not found")
    
    session = _coverage_sessions[request.session_id]
    
    # Convert dict to FuzzResult
    fuzz_result = FuzzResult(**request.fuzz_result)
    
    updated_session = update_coverage_from_fuzz_results(
        session,
        fuzz_result,
        request.endpoint,
        request.method,
        request.techniques_tested,
    )
    
    _coverage_sessions[request.session_id] = updated_session
    
    return updated_session.to_dict()


@router.get("/coverage/sessions/{session_id}/gaps", tags=["Coverage Tracking"])
async def get_coverage_gaps_endpoint(
    session_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """
    Get coverage gaps and recommendations.
    
    Returns untested techniques prioritized by severity,
    partially tested techniques, and OWASP category gaps.
    """
    from services.fuzzing_service import get_coverage_gaps
    
    if session_id not in _coverage_sessions:
        raise HTTPException(status_code=404, detail="Coverage session not found")
    
    session = _coverage_sessions[session_id]
    return get_coverage_gaps(session)


@router.get("/coverage/sessions/{session_id}/heatmap", tags=["Coverage Tracking"])
async def get_coverage_heatmap_endpoint(
    session_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """
    Get heatmap data for coverage visualization.
    
    Returns a matrix of endpoints x techniques with status values:
    - 0: Not tested
    - 1: Tested (no findings)
    - 2: Secure (explicitly verified)
    - 3: Inconclusive
    - 4: Vulnerable
    """
    from services.fuzzing_service import generate_coverage_heatmap_data
    
    if session_id not in _coverage_sessions:
        raise HTTPException(status_code=404, detail="Coverage session not found")
    
    session = _coverage_sessions[session_id]
    return generate_coverage_heatmap_data(session)


@router.get("/coverage/sessions/{session_id}/report", tags=["Coverage Tracking"])
async def export_coverage_report_endpoint(
    session_id: str,
    format: str = "markdown",
    current_user: User = Depends(get_current_active_user),
):
    """
    Export coverage report.
    
    Formats:
    - markdown: Detailed markdown report
    - json: Complete session data
    """
    from services.fuzzing_service import export_coverage_report
    
    if session_id not in _coverage_sessions:
        raise HTTPException(status_code=404, detail="Coverage session not found")
    
    session = _coverage_sessions[session_id]
    report = export_coverage_report(session, format)
    
    if format == "markdown":
        return Response(
            content=report,
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=coverage-{session_id}.md"},
        )
    elif format == "json":
        return Response(
            content=report,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=coverage-{session_id}.json"},
        )
    
    return {"report": report}


@router.get("/coverage/techniques", tags=["Coverage Tracking"])
async def get_technique_registry(
    category: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
):
    """
    Get security testing technique registry.
    
    Returns all available techniques with metadata including
    OWASP mapping, severity, and estimated testing time.
    """
    from services.fuzzing_service import TECHNIQUE_REGISTRY, TechniqueCategory
    
    techniques = TECHNIQUE_REGISTRY.values()
    
    if category:
        try:
            cat = TechniqueCategory(category)
            techniques = [t for t in techniques if t.category == cat.value]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid category: {category}")
    
    return {
        "categories": [c.value for c in TechniqueCategory],
        "techniques": [t.to_dict() for t in techniques],
    }


@router.get("/coverage/owasp", tags=["Coverage Tracking"])
async def get_owasp_categories(
    current_user: User = Depends(get_current_active_user),
):
    """
    Get OWASP Top 10 2021 categories with related techniques.
    """
    from services.fuzzing_service import OWASP_CATEGORIES, TECHNIQUE_REGISTRY
    
    result = {}
    for owasp_id, info in OWASP_CATEGORIES.items():
        related_techniques = [
            {"id": t_id, "name": t.name, "severity": t.severity}
            for t_id, t in TECHNIQUE_REGISTRY.items()
            if t.owasp_category == owasp_id
        ]
        result[owasp_id] = {
            **info,
            "techniques": related_techniques,
        }
    
    return result


@router.delete("/coverage/sessions/{session_id}", tags=["Coverage Tracking"])
async def delete_coverage_session(
    session_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Delete a coverage session."""
    if session_id not in _coverage_sessions:
        raise HTTPException(status_code=404, detail="Coverage session not found")
    
    del _coverage_sessions[session_id]
    return {"deleted": session_id}
