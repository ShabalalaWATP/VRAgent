"""
Dynamic Security Scanner Service

AI-agentic orchestrator that coordinates:
1. Nmap reconnaissance
2. AI-driven service routing (web vs network CVEs)
3. ZAP web vulnerability scanning
4. Nuclei CVE scanning
5. Exploit database mapping
6. AI attack narrative generation

This is the main service that ties together all scanning components
into an automated pentesting workflow.
"""

import asyncio
import base64
import hashlib
import json
import logging
import re
import tempfile
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable, Set, Iterable
from urllib.parse import urlparse, urlunparse, urljoin, parse_qs, urlencode

import httpx
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.models.models import DynamicScan, DynamicScanFinding

from backend.services.oob_callback_service import (
    create_callback_manager,
    create_payload_generator,
    VulnerabilityType,
)
from backend.services.openapi_parser_service import (
    OpenAPIParser,
    ParsedAPISpec,
    generate_fuzzing_targets_from_spec,
)

logger = logging.getLogger(__name__)


class ScanPhase(str, Enum):
    """Phases of a dynamic security scan."""
    INITIALIZING = "initializing"
    RECONNAISSANCE = "reconnaissance"          # Nmap discovery
    ROUTING = "routing"                        # AI decides which scanners
    OPENVAS_SCANNING = "openvas_scanning"      # OpenVAS network vuln scan
    DIRECTORY_ENUMERATION = "directory_enumeration"  # Gobuster/Dirbuster
    WEB_SCANNING = "web_scanning"              # ZAP active scan
    WAPITI_SCANNING = "wapiti_scanning"        # Wapiti web scan
    SQLMAP_SCANNING = "sqlmap_scanning"        # SQLMap injection testing
    CVE_SCANNING = "cve_scanning"              # Nuclei CVE detection
    EXPLOIT_MAPPING = "exploit_mapping"        # ExploitDB lookup
    AI_ANALYSIS = "ai_analysis"                # Attack narrative
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanStatus(str, Enum):
    """Status of a scan."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class DiscoveredHost:
    """A host discovered during reconnaissance."""
    ip: str
    hostname: str = ""
    os: str = ""
    state: str = "up"
    ports: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ServiceTarget:
    """A target service to scan."""
    ip: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    url: Optional[str] = None  # For web services
    nuclei_tags: List[str] = field(default_factory=list)  # For CVE scanning


@dataclass
class ScanFinding:
    """A vulnerability finding from any scanner."""
    source: str  # "nmap", "zap", "nuclei", "exploit_db"
    severity: str  # "critical", "high", "medium", "low", "info"
    title: str
    description: str
    host: str
    port: Optional[int] = None
    url: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_info: Optional[Dict[str, Any]] = None
    auth_profile: Optional[str] = None
    validated: Optional[bool] = None
    validation_notes: Optional[str] = None
    false_positive: bool = False
    raw_data: Optional[Dict[str, Any]] = None


@dataclass
class ScanProgress:
    """Progress tracking for a scan."""
    phase: ScanPhase
    phase_progress: int  # 0-100
    overall_progress: int  # 0-100
    message: str
    started_at: str
    current_phase_started: Optional[str] = None
    hosts_discovered: int = 0
    web_targets: int = 0
    network_targets: int = 0
    findings_count: int = 0
    errors: List[str] = field(default_factory=list)


@dataclass
class DynamicScanResult:
    """Complete result of a dynamic security scan."""
    scan_id: str
    target: str
    status: ScanStatus
    progress: ScanProgress
    
    # Discovery results
    hosts: List[DiscoveredHost] = field(default_factory=list)
    web_targets: List[ServiceTarget] = field(default_factory=list)
    network_targets: List[ServiceTarget] = field(default_factory=list)
    
    # Findings from all scanners
    findings: List[ScanFinding] = field(default_factory=list)

    # Discovery and coverage
    discovered_urls: List[str] = field(default_factory=list)
    discovered_params: List[Dict[str, Any]] = field(default_factory=list)
    coverage_summary: Dict[str, Any] = field(default_factory=dict)

    # Auth/OOB/validation metadata
    auth_profiles_used: List[str] = field(default_factory=list)
    oob_summary: Dict[str, Any] = field(default_factory=dict)
    validation_summary: Dict[str, Any] = field(default_factory=dict)
    
    # AI analysis
    executive_summary: str = ""  # Management-friendly summary
    attack_narrative: str = ""   # Technical attack path description
    risk_summary: str = ""       # Quick risk assessment
    exploit_chains: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    manual_guidance: List[str] = field(default_factory=list)

    # API discovery metadata
    openapi_spec_url: Optional[str] = None
    openapi_base_url: Optional[str] = None
    graphql_endpoint_url: Optional[str] = None
    browser_crawl_config: Optional[Dict[str, Any]] = None

    # Agentic loop metadata
    agent_plan: List[str] = field(default_factory=list)
    agent_log: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[int] = None
    
    # Commands for exploitation
    exploit_commands: Dict[str, List[str]] = field(default_factory=dict)


class ScanConcurrencyError(Exception):
    """Raised when the service is operating at maximum capacity."""
    pass


class DynamicScanService:
    """
    Main orchestrator for the Dynamic Security Scanner.
    Coordinates all scanning phases and integrates results.
    """
    
    def __init__(self):
        self.scanner_url = getattr(settings, "SCANNER_URL", "http://localhost:9999")
        self.zap_url = getattr(settings, "zap_url", "http://zap:8080")
        self.zap_api_key = getattr(settings, "zap_api_key", "")
        self.http_client = httpx.AsyncClient(timeout=30.0)
        
        # Active scans tracking
        self.active_scans: Dict[str, DynamicScanResult] = {}
        
        # Progress callbacks
        self.progress_callbacks: Dict[str, List[Callable]] = {}

        # Scanner capability cache
        self._scanner_info_cache: Optional[Dict[str, Any]] = None
        self._scanner_info_checked_at: float = 0.0

        # Concurrency control
        self.max_concurrent_dynamic_scans = max(1, getattr(settings, "max_concurrent_dynamic_scans", 2))
        self.scan_semaphore = asyncio.Semaphore(self.max_concurrent_dynamic_scans)
        self.scan_tasks: Dict[str, asyncio.Task] = {}
        self.tool_scan_handles: Dict[str, Dict[str, List[str]]] = {}

    def _task_completed(self, scan_id: str, task: asyncio.Task):
        """Cleanup bookkeeping after a scan task finishes."""
        self.scan_tasks.pop(scan_id, None)
        try:
            self.scan_semaphore.release()
        except ValueError:
            pass
        self.tool_scan_handles.pop(scan_id, None)
    
    async def close(self):
        """Cleanup resources."""
        await self.http_client.aclose()
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID."""
        return f"dscan-{uuid.uuid4().hex[:8]}"

    def _acquire_scan_slot(self):
        """Attempt to reserve capacity for a new scan, raising when capacity is exhausted."""
        try:
            self.scan_semaphore.acquire_nowait()
        except ValueError as exc:
            raise ScanConcurrencyError("Maximum concurrent dynamic scans reached") from exc

    def _register_tool_scan(self, scan_id: str, tool: str, job_id: str):
        """Record an external sidecar scan for cancellation tracking."""
        if not job_id:
            return
        self.tool_scan_handles.setdefault(scan_id, {}).setdefault(tool, []).append(job_id)

    def _clear_tool_scans(self, scan_id: str):
        self.tool_scan_handles.pop(scan_id, None)

    async def _cancel_sidecar_scans(self, scan_id: str):
        """Request cancellation for any sidecar scans that belong to this dynamic scan."""
        handles = self.tool_scan_handles.get(scan_id, {})
        for tool, job_ids in handles.items():
            for job_id in job_ids:
                try:
                    await self.http_client.delete(
                        f"{self.scanner_url}/scan/{job_id}",
                        timeout=10.0,
                    )
                except Exception as exc:
                    logger.warning(f"[{scan_id}] Failed to cancel {tool} job {job_id}: {exc}")
        self._clear_tool_scans(scan_id)

    def _zap_params(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Attach API key to ZAP requests when configured."""
        merged = dict(params or {})
        if self.zap_api_key:
            merged.setdefault("apikey", self.zap_api_key)
        return merged

    def _normalize_zap_urls(self, url: str) -> tuple[str, str]:
        """Normalize target URL for ZAP scanning and alert filtering."""
        parsed = urlparse(url)
        scheme = parsed.scheme or "http"
        netloc = parsed.netloc or parsed.path
        path = parsed.path or "/"
        base_url = f"{scheme}://{netloc}".rstrip("/")
        target_url = urlunparse((scheme, netloc, path, "", "", ""))
        return base_url, target_url

    def _maybe_rewrite_localhost(self, url: str) -> str:
        """Rewrite localhost targets when running in Docker to reach the host."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if not host:
                return url
            if host.startswith("127.") or host in ("localhost", "::1"):
                if Path("/.dockerenv").exists():
                    port = f":{parsed.port}" if parsed.port else ""
                    netloc = f"host.docker.internal{port}"
                    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))
        except Exception:
            return url
        return url

    def _sanitize_zap_auth(self, zap_auth: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Remove secrets from ZAP auth config before persistence/logging."""
        if not zap_auth:
            return None
        return {
            "enabled": True,
            "method": zap_auth.get("method"),
            "login_url": zap_auth.get("login_url"),
            "context_name": zap_auth.get("context_name"),
            "username_provided": bool(zap_auth.get("username")),
            "logged_in_indicator": bool(zap_auth.get("logged_in_indicator")),
            "logged_out_indicator": bool(zap_auth.get("logged_out_indicator")),
        }

    def _sanitize_openvas_credentials(self, creds: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Summarize OpenVAS credential IDs without persisting raw identifiers."""
        if not creds:
            return None
        return {
            "ssh_credential_id": bool(creds.get("ssh_credential_id")),
            "ssh_credential_port": creds.get("ssh_credential_port") if creds.get("ssh_credential_id") else None,
            "smb_credential_id": bool(creds.get("smb_credential_id")),
            "snmp_credential_id": bool(creds.get("snmp_credential_id")),
            "esxi_credential_id": bool(creds.get("esxi_credential_id")),
        }

    def _sanitize_browser_crawl(self, config: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Strip credentials/selectors from browser crawl config before persistence."""
        if not config:
            return None
        return {
            "enabled": bool(config.get("enabled", False)),
            "start_url": config.get("start_url"),
            "login_url": config.get("login_url"),
            "max_pages": config.get("max_pages"),
            "max_duration_seconds": config.get("max_duration_seconds"),
            "same_origin_only": config.get("same_origin_only"),
            "record_har": config.get("record_har"),
        }

    def _build_plan_steps(self, scan_plan: Dict[str, Any], recommendations: List[Any]) -> List[str]:
        steps: List[str] = []
        if scan_plan.get("run_nmap"):
            steps.append("Plan: run Nmap reconnaissance")
        if scan_plan.get("run_openvas"):
            steps.append("Plan: run OpenVAS network scan")
        if scan_plan.get("run_zap"):
            zap_policy = scan_plan.get("zap_scan_policy", "standard")
            steps.append(f"Plan: run ZAP web scan ({zap_policy})")
        if scan_plan.get("run_nuclei"):
            steps.append("Plan: run Nuclei CVE scan")
        if scan_plan.get("run_directory_enum"):
            steps.append("Plan: run directory enumeration")
        if scan_plan.get("run_exploit_mapping"):
            steps.append("Plan: map exploits")
        if isinstance(recommendations, list):
            for rec in recommendations:
                if isinstance(rec, str) and rec.strip():
                    steps.append(rec.strip())
        elif isinstance(recommendations, str) and recommendations.strip():
            steps.append(recommendations.strip())
        return steps

    def _summarize_findings_for_context(self, scan: DynamicScanResult, limit: int = 3) -> str:
        severity_weight = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            scan.findings,
            key=lambda f: severity_weight.get((f.severity or "").lower(), 5),
        )
        summaries = []
        for finding in sorted_findings[:limit]:
            severity = (finding.severity or "info").upper()
            host = finding.host or "unknown"
            port = finding.port or "any"
            title = finding.title or "Unnamed finding"
            summaries.append(f"{severity} {host}:{port} - {title}")
        return "; ".join(summaries)

    async def _refresh_agent_plan(
        self,
        agent: "DynamicScanAgent",
        scan: DynamicScanResult,
        scan_id: str,
        target: str,
        user_context: Optional[str],
        aggressive_scan: bool,
        action_history: List[Dict[str, Any]],
        plan_payload: Optional[Dict[str, Any]],
        reason: str,
    ) -> Optional[Dict[str, Any]]:
        """Re-run the agent planner when new data merits replanning."""
        context_summary = self._summarize_findings_for_context(scan)
        enhanced_context = " ".join(filter(None, [
            user_context,
            reason,
            context_summary and f"Latest findings: {context_summary}",
        ]))
        try:
            new_payload = await agent.plan_scan_strategy(
                target=target,
                user_context=enhanced_context or None,
                aggressive_scan=aggressive_scan,
            )
            scan_plan = new_payload.get("scan_plan", {}) if isinstance(new_payload, dict) else {}
            recommendations = new_payload.get("recommendations", []) if isinstance(new_payload, dict) else []
            plan_steps = self._build_plan_steps(scan_plan, recommendations)
            if plan_steps:
                scan.agent_plan = list(dict.fromkeys(scan.agent_plan + plan_steps))
            action_history.append({
                "action": "replan",
                "status": "completed",
                "reason": [reason],
                "plan": scan_plan,
            })
            return new_payload
        except Exception as e:
            action_history.append({
                "action": "replan",
                "status": "failed",
                "reason": [f"{reason} failed: {str(e)[:500]}"],
                "plan": plan_payload.get("scan_plan", {}) if plan_payload else {},
            })
            scan.progress.errors.append(f"Agent replanning failed: {str(e)[:500]}")
            return plan_payload

    def _extract_basic_auth(self, zap_auth: Optional[Any]) -> Optional[tuple[str, str]]:
        """Return HTTP Basic auth credentials from ZAP auth config(s) when available."""
        if not zap_auth:
            return None
        profiles = zap_auth if isinstance(zap_auth, list) else [zap_auth]
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            method = str(profile.get("method", "")).strip().lower()
            if method in {"basic", "http_basic", "httpauthentication"}:
                username = profile.get("username")
                password = profile.get("password")
                if username is not None and password is not None:
                    return (str(username), str(password))
        return None

    def _normalize_http_method(self, method: Optional[str]) -> Optional[str]:
        if not method:
            return None
        normalized = str(method).strip().upper()
        return normalized or None

    def _is_safe_http_method(self, method: Optional[str]) -> bool:
        normalized = self._normalize_http_method(method)
        return normalized in {"GET", "HEAD", "OPTIONS"}

    def _extract_finding_method(self, finding: "ScanFinding") -> Optional[str]:
        raw = finding.raw_data
        if not isinstance(raw, dict):
            return None
        for key in ("method", "request_method", "http_method", "requestMethod"):
            value = raw.get(key)
            if value:
                return self._normalize_http_method(value)
        return None

    def build_scan_profile(self, aggressive_scan: bool) -> Dict[str, Any]:
        """Compute the default scan profile guided by aggressiveness."""
        profile = {
            "scan_depth": "aggressive" if aggressive_scan else "thorough",
            "zap_policy": "maximum" if aggressive_scan else "thorough",
            "zap_advanced_features": [
                "ajax_spider",
                "openapi_import",
                "graphql_import",
                "forced_browsing",
            ] if aggressive_scan else [],
            "forced_browse_wordlist": "aggressive" if aggressive_scan else None,
            "directory_wordlist": "aggressive" if aggressive_scan else None,
            "openvas_config": "full_and_very_deep" if aggressive_scan else "full_and_deep",
            "openvas_port_list": "all_tcp_udp" if aggressive_scan else "top_tcp_1000",
            "openvas_qod_threshold": "low" if aggressive_scan else "standard",
            "openvas_max_hosts": "aggressive" if aggressive_scan else "standard",
            "nmap_timing": "T4" if aggressive_scan else "T3",
            "run_nmap_udp": aggressive_scan,
            "nuclei_templates": (
                ["cves", "vulnerabilities", "exposures", "misconfigurations"]
                if aggressive_scan
                else ["cves", "vulnerabilities"]
            ),
            "discovery_features": {
                "enable": True,
                "js": aggressive_scan,
                "params": aggressive_scan,
            },
            "oob_testing": aggressive_scan,
            "validation_pass": aggressive_scan,
        }
        return profile

    def build_manual_guidance(
        self,
        aggressive_scan: bool,
        include_openvas: bool,
        include_web_scan: bool,
        include_cve_scan: bool,
        include_directory_enum: bool,
        include_sqlmap: bool,
        include_wapiti: bool,
        profile: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Generate step-by-step guidance for manual scans."""
        profile = profile or self.build_scan_profile(aggressive_scan)
        steps: List[str] = []
        step_num = 1
        steps.append(
            f"{step_num}. Nmap reconnaissance using {profile['nmap_timing']} timing "
            f"({'UDP probes' if profile['run_nmap_udp'] else 'TCP-only'}) to map hosts/services."
        )
        step_num += 1
        if include_openvas:
            steps.append(
                f"{step_num}. OpenVAS network vulnerability scan ({profile['openvas_config']} config, "
                f"{profile['openvas_port_list']} port list, QoD {profile['openvas_qod_threshold']})."
            )
            step_num += 1
        if include_web_scan:
            steps.append(
                f"{step_num}. OWASP ZAP active scan with {profile['zap_policy']} policy and "
                f"advanced features ({', '.join(profile['zap_advanced_features']) or 'standard'}) "
                f"{'with forced browsing' if profile['forced_browse_wordlist'] else ''}."
            )
            step_num += 1
        if include_directory_enum or profile.get("run_directory_enum"):
            wordlist = profile.get("directory_wordlist") or "custom wordlist"
            steps.append(
                f"{step_num}. Run Gobuster/Dirbuster (engine: {profile.get('directory_engine', 'gobuster')}, "
                f"wordlist: {wordlist}) to uncover hidden directories and endpoints."
            )
            step_num += 1
        if include_wapiti or profile.get("run_wapiti"):
            steps.append(
                f"{step_num}. Wapiti web app scanning (level {profile.get('wapiti_level', 2)}) "
                "to capture vulnerabilities missed by ZAP."
            )
            step_num += 1
        if include_cve_scan:
            templates = ", ".join(profile.get("nuclei_templates", []))
            steps.append(
                f"{step_num}. Nuclei CVE scan ({templates}) to correlate findings with known CVEs."
            )
            step_num += 1
        if include_sqlmap or profile.get("run_sqlmap"):
            steps.append(
                f"{step_num}. SQLMap injection testing (level {profile.get('sqlmap_level', 2)}, "
                f"risk {profile.get('sqlmap_risk', 2)}) against discovered input points."
            )
            step_num += 1
        steps.append(
            f"{step_num}. Map findings to exploits, generate attack narrative, and review recommendations."
        )
        if aggressive_scan:
            steps.append("Re-run critical phases with authenticated/discovery payloads if needed.")
        return steps

    async def _wait_for_zap_passive(
        self,
        scan_id: str,
        max_wait_seconds: int = 60,
        min_remaining: int = 0,
    ) -> int:
        """Wait briefly for ZAP passive scan queue to drain."""
        remaining = 0
        start_time = time.monotonic()
        while time.monotonic() - start_time < max_wait_seconds:
            try:
                response = await self.http_client.get(
                    f"{self.zap_url}/JSON/pscan/view/recordsToScan/",
                    params=self._zap_params(),
                    timeout=10.0,
                )
                if response.status_code != 200:
                    break
                remaining = int(response.json().get("recordsToScan", 0))
                if remaining <= min_remaining:
                    break
                await self._update_progress(
                    scan_id, ScanPhase.WEB_SCANNING, 90,
                    f"Waiting for passive scan backlog ({remaining} remaining)..."
                )
            except Exception as e:
                logger.warning(f"Failed to check passive scan backlog: {e}")
                break
            await asyncio.sleep(3)
        return remaining

    async def _get_scanner_info(self, max_age_seconds: int = 60) -> Optional[Dict[str, Any]]:
        """Fetch and cache scanner sidecar capabilities."""
        now = time.monotonic()
        if self._scanner_info_cache and (now - self._scanner_info_checked_at) < max_age_seconds:
            return self._scanner_info_cache
        try:
            response = await self.http_client.get(
                f"{self.scanner_url}/info",
                timeout=5.0,
            )
            if response.status_code == 200:
                self._scanner_info_cache = response.json()
                self._scanner_info_checked_at = now
                return self._scanner_info_cache
        except Exception as e:
            logger.debug(f"Scanner info unavailable: {e}")
        return None

    def _scanner_tool_available(self, info: Optional[Dict[str, Any]], tool_key: str) -> Optional[bool]:
        """Return True/False when known, or None when info is unavailable."""
        if not info:
            return None
        capabilities = info.get("capabilities", {})
        tool_info = capabilities.get(tool_key)
        if isinstance(tool_info, dict) and "installed" in tool_info:
            return bool(tool_info.get("installed"))
        return None

    async def _poll_scanner_job(
        self,
        scan_id: str,
        timeout_seconds: int,
        poll_interval: float = 3.0,
    ) -> Dict[str, Any]:
        """Poll scanner sidecar for job completion."""
        start = time.monotonic()
        last_progress = None
        while time.monotonic() - start < timeout_seconds:
            status_response = await self.http_client.get(
                f"{self.scanner_url}/scan/{scan_id}",
                timeout=10.0,
            )
            status_data = status_response.json()
            status = status_data.get("status")
            progress_msg = status_data.get("progress")
            if progress_msg and progress_msg != last_progress:
                last_progress = progress_msg
            if status in ["completed", "failed", "cancelled"]:
                return status_data
            await asyncio.sleep(poll_interval)
        raise TimeoutError(f"Scanner job {scan_id} timed out after {timeout_seconds} seconds")

    def _resolve_wordlist_files(self, wordlist_key: Optional[str]) -> List[str]:
        """Resolve a wordlist key or filename to concrete wordlist files."""
        from backend.services.dynamic_scan_agent import WORDLISTS
        if not wordlist_key:
            return ["directories_comprehensive.txt"]
        key = str(wordlist_key).strip()
        if not key:
            return ["directories_comprehensive.txt"]
        if key in WORDLISTS:
            files = WORDLISTS[key].get("files", [])
            return files or ["directories_comprehensive.txt"]
        return [key]

    async def _seed_zap_urls(self, urls: List[str], limit: int = 200) -> None:
        """Seed ZAP's site tree with discovered URLs."""
        for url in urls[:limit]:
            try:
                await self.http_client.get(
                    f"{self.zap_url}/JSON/core/action/accessUrl/",
                    params=self._zap_params({"url": url}),
                    timeout=20.0,
                )
            except Exception as e:
                logger.debug(f"Failed to seed ZAP URL {url}: {e}")

    async def _run_forced_browse(
        self,
        scan_id: str,
        base_url: str,
        host: str,
        port: int,
        wordlist_key: Optional[str],
        scan_policy: str,
        max_results: int = 300,
    ) -> tuple[List[ScanFinding], List[str]]:
        """Run local forced browse scans using wordlists and return findings + URLs."""
        from backend.services.forced_browse_service import get_forced_browse_service

        findings: List[ScanFinding] = []
        discovered_urls: List[str] = []
        service = get_forced_browse_service()
        wordlist_files = self._resolve_wordlist_files(wordlist_key)

        threads = 15 if scan_policy == "maximum" else 10
        recursive = scan_policy == "maximum"
        use_extensions = scan_policy in ["thorough", "maximum"]
        extensions = service.common_extensions if use_extensions else None
        timeout_seconds = 300 if scan_policy == "maximum" else 180 if scan_policy == "thorough" else 120

        for wordlist in wordlist_files:
            if len(findings) >= max_results:
                break
            try:
                session_id = await service.start_scan(
                    target_url=base_url,
                    wordlist=wordlist,
                    recursive=recursive,
                    threads=threads,
                    extensions=extensions,
                )
            except ValueError as e:
                self.active_scans[scan_id].progress.errors.append(f"Forced browse: {e}")
                continue
            except Exception as e:
                self.active_scans[scan_id].progress.errors.append(f"Forced browse failed: {str(e)[:500]}")
                continue

            start_time = time.monotonic()
            while time.monotonic() - start_time < timeout_seconds:
                status = service.get_status(session_id)
                state = status.get("status")
                if state in {"completed", "error", "stopped"}:
                    break
                await asyncio.sleep(2)

            results = service.get_results(session_id)
            for result in results:
                if len(findings) >= max_results:
                    break
                url = result.get("url")
                if not url:
                    continue
                status_code = result.get("status_code")
                path = urlparse(url).path or "/"
                title = f"Discovered Path (Forced Browse): {path}"
                evidence = f"HTTP {status_code} | Type: {result.get('content_type')} | Length: {result.get('content_length')}"
                findings.append(
                    ScanFinding(
                        source="forced_browse",
                        severity="info",
                        title=title,
                        description="Wordlist-based forced browsing discovered an accessible path.",
                        host=host,
                        port=port,
                        url=url,
                        evidence=evidence,
                        remediation="Review discovered paths for sensitive or unintended exposure.",
                        references=[],
                        raw_data=result,
                    )
                )
                discovered_urls.append(url)

        return findings, discovered_urls

    def _extract_query_parameters(self, url: str, method: Optional[str] = None) -> List[Dict[str, Any]]:
        """Extract query string parameters from a URL."""
        parsed = urlparse(url)
        params_list: List[Dict[str, Any]] = []
        if not parsed.query:
            return params_list
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        for name, values in query_params.items():
            params_list.append({
                "endpoint": url,
                "name": name,
                "values": values,
                "source": "query_string",
                "method": method or "GET",
            })
        return params_list

    def _extract_js_endpoints(self, content: str, base_url: str) -> List[str]:
        """Extract potential endpoints referenced inside JavaScript content."""
        endpoints = set()
        patterns = [
            r'["\'](/[^"\']+\.(?:php|asp|aspx|jsp|json|graphql|do|action|xml|js|html))["\']',
            r'["\'](https?://[^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.\w+\(\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                candidate = match.group(1)
                if candidate.startswith("/"):
                    candidate = urljoin(base_url, candidate)
                if candidate.startswith("http"):
                    endpoints.add(candidate)
        return list(endpoints)

    async def _collect_discovery_summary(
        self,
        scan_id: str,
        targets: List[ServiceTarget],
        include_js: bool,
        include_params: bool,
        extra_urls: List[str],
    ) -> Dict[str, Any]:
        """Collect discovered URLs, parameters, and JS endpoints from ZAP."""
        collected_urls = set(extra_urls or [])
        discovered_params: List[Dict[str, Any]] = []
        js_candidates: List[str] = []

        for target in targets:
            if not target.url:
                continue
            base_url, _ = self._normalize_zap_urls(target.url)
            try:
                response = await self.http_client.get(
                    f"{self.zap_url}/JSON/core/view/urls/",
                    params=self._zap_params({"baseurl": base_url}),
                    timeout=20.0,
                )
                if response.status_code != 200:
                    continue
                urls = response.json().get("urls", [])
                for url in urls:
                    collected_urls.add(url)
                    if include_params:
                        params = self._extract_query_parameters(url)
                        discovered_params.extend(params)
                    if include_js and url.lower().endswith(".js"):
                        js_candidates.append(url)
            except Exception as e:
                self.active_scans[scan_id].progress.errors.append(f"Discovery failed for {target.url}: {e}")

        js_endpoints = []
        if include_js and js_candidates:
            for js_url in js_candidates[:20]:
                try:
                    resp = await self.http_client.get(js_url, timeout=30.0)
                    if resp.status_code == 200 and resp.text:
                        extracted = self._extract_js_endpoints(resp.text, urljoin(js_url, "/"))
                        for endpoint in extracted:
                            collected_urls.add(endpoint)
                            js_endpoints.append(endpoint)
                            if include_params:
                                discovered_params.extend(self._extract_query_parameters(endpoint))
                except Exception as e:
                    self.active_scans[scan_id].progress.errors.append(f"JS discovery failed for {js_url}: {e}")

        return {
            "urls": sorted(collected_urls),
            "params": discovered_params,
            "coverage": {
                "total_urls": len(collected_urls),
                "js_endpoints": len(js_endpoints),
                "query_params": len(discovered_params),
            },
            "js_endpoints": js_endpoints,
        }

    def _merge_discovery_entries(
        self,
        scan: DynamicScanResult,
        urls: Iterable[str],
        params: Iterable[Dict[str, Any]],
    ) -> None:
        """Merge new URLs/parameters into the scan discovery lists."""
        existing_urls = set(scan.discovered_urls)
        for url in urls:
            if url and url not in existing_urls:
                scan.discovered_urls.append(url)
                existing_urls.add(url)

        seen_params: Set[tuple] = {(p.get("endpoint"), p.get("name"), p.get("source")) for p in scan.discovered_params}
        for param in params:
            key = (param.get("endpoint"), param.get("name"), param.get("source"))
            if key not in seen_params:
                scan.discovered_params.append(param)
                seen_params.add(key)

    async def _run_browser_crawl(
        self,
        scan_id: str,
        targets: List[ServiceTarget],
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Use Playwright to crawl and generate HAR for import."""
        if not config or not config.get("enabled"):
            return {"har_path": None, "urls": [], "params": []}

        start_url = config.get("start_url")
        if not start_url:
            start_url = next((t.url for t in targets if t.url), None)
        if not start_url:
            return {"har_path": None, "urls": [], "params": []}

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self.active_scans[scan_id].progress.errors.append(
                "Browser crawl requested but Playwright is not installed."
            )
            return {"har_path": None, "urls": [], "params": []}

        crawl_urls: Set[str] = set()
        crawl_params: List[Dict[str, Any]] = []
        har_entries: List[Dict[str, Any]] = []
        request_map: Dict[int, Dict[str, Any]] = {}

        max_pages = max(1, min(int(config.get("max_pages", 15)), 200))
        max_duration = max(10, min(int(config.get("max_duration_seconds", 120)), 900))
        same_origin_only = bool(config.get("same_origin_only", True))
        record_har = bool(config.get("record_har", True))
        base_origin = urlparse(start_url).netloc.lower()

        async def _format_headers(headers: Dict[str, str]) -> List[Dict[str, str]]:
            return [{"name": name, "value": value} for name, value in headers.items()]

        async def _on_request(request):
            request_id = id(request)
            request_map[request_id] = {
                "startedDateTime": datetime.utcnow().isoformat() + "Z",
                "time": 0,
                "request": {
                    "method": request.method,
                    "url": request.url,
                    "httpVersion": "HTTP/1.1",
                    "headers": await _format_headers(dict(request.headers)),
                    "queryString": [
                        {"name": k, "value": v}
                        for k, values in parse_qs(urlparse(request.url).query, keep_blank_values=True).items()
                        for v in values
                    ],
                    "postData": {
                        "mimeType": request.headers.get("content-type", ""),
                        "text": request.post_data or "",
                    },
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "response": {
                    "status": 0,
                    "statusText": "",
                    "headers": [],
                    "content": {"mimeType": "", "text": ""},
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "timings": {"send": 0, "wait": 0, "receive": 0},
                "_start": time.monotonic(),
            }

        async def _on_response(response):
            request = response.request
            entry = request_map.get(id(request))
            if not entry:
                return

            ended = time.monotonic()
            entry["time"] = (ended - entry.get("_start", ended)) * 1000
            entry["timings"]["wait"] = entry["time"]
            entry["response"]["status"] = response.status
            entry["response"]["statusText"] = response.status_text
            headers_dict = dict(response.headers)
            entry["response"]["headers"] = await _format_headers(headers_dict)
            entry["response"]["content"]["mimeType"] = headers_dict.get("content-type", "")
            try:
                body_text = await response.text()
            except Exception:
                body_bytes = await response.body()
                body_text = base64.b64encode(body_bytes).decode("ascii")
            entry["response"]["content"]["text"] = body_text
            entry.pop("_start", None)
            har_entries.append(entry)

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()
                page.on("request", _on_request)
                page.on("response", _on_response)

                async def _maybe_perform_login():
                    login_url = config.get("login_url")
                    username = config.get("username")
                    password = config.get("password")
                    if not (login_url and username and password):
                        return
                    await page.goto(login_url, wait_until="domcontentloaded", timeout=15000)
                    username_selector = config.get("username_selector")
                    password_selector = config.get("password_selector")
                    submit_selector = config.get("submit_selector")
                    if username_selector:
                        await page.fill(username_selector, username)
                    if password_selector:
                        await page.fill(password_selector, password)
                    if submit_selector:
                        await page.click(submit_selector)
                    wait_for = config.get("wait_for_selector")
                    if wait_for:
                        await page.wait_for_selector(wait_for, timeout=15000)

                await _maybe_perform_login()

                queue = deque([start_url])
                start_time = time.monotonic()

                while queue and len(crawl_urls) < max_pages and (time.monotonic() - start_time) < max_duration:
                    url = queue.popleft()
                    if url in crawl_urls:
                        continue
                    parsed = urlparse(url)
                    if same_origin_only and parsed.netloc.lower() != base_origin:
                        continue
                    try:
                        response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    except Exception as e:
                        self.active_scans[scan_id].progress.errors.append(
                            f"Browser crawl failed to load {url}: {e}"
                        )
                        continue

                    crawl_urls.add(url)
                    content = await page.content()
                    try:
                        from bs4 import BeautifulSoup

                        soup = BeautifulSoup(content, "html.parser")
                        for form in soup.find_all("form"):
                            method = (form.get("method") or "GET").upper()
                            action = form.get("action") or url
                            action_url = urljoin(url, action)
                            for input_tag in form.find_all(["input", "textarea", "select"]):
                                name = input_tag.get("name")
                                if not name:
                                    continue
                                value = input_tag.get("value", "")
                                crawl_params.append({
                                    "endpoint": action_url,
                                    "name": name,
                                    "values": [value],
                                    "source": "form_field",
                                    "method": method,
                                })
                    except ImportError:
                        pass

                    js_endpoints = self._extract_js_endpoints(content, urljoin(url, "/"))
                    for endpoint in js_endpoints:
                        normalized = endpoint
                        if same_origin_only and urlparse(normalized).netloc.lower() != base_origin:
                            continue
                        if normalized not in crawl_urls and len(crawl_urls) < max_pages:
                            queue.append(normalized)

                    anchors = await page.eval_on_selector_all(
                        "a[href]",
                        "elements => elements.map(e => e.href).filter(h => h)"
                    )
                    for href in anchors:
                        normalized = href
                        if not normalized:
                            continue
                        if same_origin_only and urlparse(normalized).netloc.lower() != base_origin:
                            continue
                        if normalized not in crawl_urls:
                            queue.append(normalized)

                    cookies = await context.cookies()
                    for cookie in cookies:
                        name = cookie.get("name")
                        if not name:
                            continue
                        crawl_params.append({
                            "endpoint": url,
                            "name": name,
                            "values": [cookie.get("value", "")],
                            "source": "cookie",
                            "method": "GET",
                        })

                await page.close()
                await context.close()
                await browser.close()
        except Exception as e:
            self.active_scans[scan_id].progress.errors.append(f"Browser crawl failed: {e}")
            return {"har_path": None, "urls": list(crawl_urls), "params": crawl_params}

        har_path = None
        if record_har and har_entries:
            har_log = {
                "version": "1.2",
                "creator": {"name": "VRAgent Browser Crawl", "version": "1.0"},
                "entries": har_entries,
            }
            har_content = {"log": har_log}
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".har")
            json.dump(har_content, temp_file, ensure_ascii=False)
            temp_file.flush()
            temp_file.close()
            har_path = temp_file.name

        return {"har_path": har_path, "urls": list(crawl_urls), "params": crawl_params}

    async def _import_har_to_zap(self, scan_id: str, har_path: Optional[str]) -> None:
        """Upload a HAR file into ZAP for richer context coverage."""
        if not har_path:
            return
        try:
            with open(har_path, "rb") as har_file:
                files = {"file": ("crawl.har", har_file, "application/json")}
                response = await self.http_client.post(
                    f"{self.zap_url}/JSON/har/action/importHar/",
                    params=self._zap_params(),
                    files=files,
                    timeout=120.0,
                )
                if response.status_code != 200:
                    raise Exception(f"HAR import HTTP {response.status_code}")
                result = response.json()
                if result.get("Result") != "OK":
                    raise Exception(f"HAR import error: {result}")
        except Exception as e:
            self.active_scans[scan_id].progress.errors.append(f"HAR import failed: {e}")
        finally:
            try:
                Path(har_path).unlink(missing_ok=True)
            except Exception:
                pass

    async def _load_openapi_spec(
        self,
        spec_url: Optional[str],
        spec_content: Optional[str],
        base_url: Optional[str],
    ) -> Optional["ParsedAPISpec"]:
        """Load an OpenAPI specification either from URL or inline content."""
        try:
            parser = OpenAPIParser()
            if spec_content:
                return parser.parse_content(spec_content, base_url or "")
            if spec_url:
                return await parser.parse_url(spec_url)
        except Exception as e:
            logger.warning(f"[OpenAPI] Failed to parse spec: {e}")
        return None

    async def _apply_openapi_discovery(
        self,
        scan_id: str,
        spec_url: Optional[str],
        spec_content: Optional[str],
        base_url: Optional[str],
    ) -> List[Dict[str, Any]]:
        """Import/open parse OpenAPI spec and return fuzzing targets."""
        if not spec_url and not spec_content:
            return []

        spec = await self._load_openapi_spec(spec_url, spec_content, base_url)
        if not spec or not spec.endpoints:
            self.active_scans[scan_id].progress.errors.append("OpenAPI spec did not produce endpoints.")
            return []

        target_url = base_url or spec.base_url or ""
        import_success = False
        try:
            if spec_url:
                response = await self.http_client.get(
                    f"{self.zap_url}/JSON/openapi/action/importUrl/",
                    params=self._zap_params({"url": spec_url, "target": target_url}),
                    timeout=60.0,
                )
                if response.status_code == 200 and response.json().get("Result") == "OK":
                    import_success = True
            elif spec_content:
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
                tmp.write(spec_content.encode("utf-8"))
                tmp.flush()
                tmp.close()
                try:
                    with open(tmp.name, "rb") as infile:
                        files = {"file": ("openapi.json", infile, "application/json")}
                        response = await self.http_client.post(
                            f"{self.zap_url}/JSON/openapi/action/importFile/",
                            params=self._zap_params({"target": target_url}),
                            files=files,
                            timeout=120.0,
                        )
                        if response.status_code == 200 and response.json().get("Result") == "OK":
                            import_success = True
                finally:
                    Path(tmp.name).unlink(missing_ok=True)
        except Exception as e:
            logger.warning(f"[OpenAPI] Import failed: {e}")
            self.active_scans[scan_id].progress.errors.append(f"OpenAPI import failed: {e}")

        if import_success:
            self.active_scans[scan_id].progress.message = "Imported OpenAPI specification"

        return generate_fuzzing_targets_from_spec(spec)

    def _add_api_spec_discovery(self, scan: DynamicScanResult, targets: List[Dict[str, Any]]) -> None:
        """Add parsed OpenAPI spec endpoints/params to discovery structures."""
        urls = set()
        params: List[Dict[str, Any]] = []
        for target in targets:
            endpoint_url = target.get("url")
            if endpoint_url:
                urls.add(endpoint_url)
            method = (target.get("method") or "GET").upper()
            headers = target.get("headers", {})
            for header_name, header_value in headers.items():
                params.append({
                    "endpoint": endpoint_url,
                    "name": header_name,
                    "values": [header_value],
                    "source": "header",
                    "method": method,
                })
            body = target.get("body")
            if isinstance(body, dict):
                for field_name, field_value in body.items():
                    params.append({
                        "endpoint": endpoint_url,
                        "name": field_name,
                        "values": [str(field_value)],
                        "source": "body",
                        "method": method,
                    })
            for param in target.get("parameters", []):
                params.append({
                    "endpoint": endpoint_url,
                    "name": param,
                    "values": [""],
                    "source": "openapi",
                    "method": method,
                })
        self._merge_discovery_entries(scan, urls, params)

    async def _import_graphql_schema(
        self,
        scan_id: str,
        endpoint_url: Optional[str],
        schema_url: Optional[str],
    ) -> List[Dict[str, Any]]:
        """Import GraphQL schema into ZAP and add discovery metadata."""
        if not endpoint_url:
            return []

        urls_to_try = []
        if schema_url:
            urls_to_try.append(schema_url)
        urls_to_try.append(endpoint_url)

        imported = False
        for url in urls_to_try:
            try:
                response = await self.http_client.get(
                    f"{self.zap_url}/JSON/graphql/action/importUrl/",
                    params=self._zap_params({"url": url}),
                    timeout=45.0,
                )
                if response.status_code == 200 and response.json().get("Result") == "OK":
                    imported = True
                    break
            except Exception as e:
                logger.debug(f"GraphQL import attempt failed for {url}: {e}")

        if not imported:
            self.active_scans[scan_id].progress.errors.append("GraphQL schema import failed.")

        return [
            {
                "endpoint": endpoint_url,
                "name": "query",
                "values": ["{graphql_query}"],
                "source": "graphql",
                "method": "POST",
            },
            {
                "endpoint": endpoint_url,
                "name": "variables",
                "values": ["{}"],
                "source": "graphql",
                "method": "POST",
            },
        ]

    async def _cross_validate_high_findings(
        self,
        scan_id: str,
        http_auth: Optional[tuple[str, str]] = None,
    ) -> None:
        """Re-issue safe requests to confirm high/critical findings."""
        scan = self.active_scans.get(scan_id)
        if not scan:
            return

        validated = set()
        for finding in scan.findings:
            severity = (finding.severity or "").lower()
            if severity not in {"critical", "high"}:
                continue
            url = finding.url
            if not url or url in validated:
                continue
            method = self._extract_finding_method(finding) or "HEAD"
            if not self._is_safe_http_method(method):
                method = "HEAD"
            try:
                resp = await self.http_client.request(
                    method,
                    url,
                    timeout=10.0,
                    auth=http_auth,
                )
                validated.add(url)
                if resp.status_code >= 400:
                    raise ValueError(f"HTTP {resp.status_code}")
                finding.false_positive = False
            except Exception as exc:
                finding.false_positive = True
                note = f"Cross-validation failed ({exc})"
                finding.validation_notes = (
                    (finding.validation_notes or "").strip() + " " + note
                ).strip()
                self.active_scans[scan_id].progress.errors.append(f"{note} for {finding.title}")

    async def _run_oob_testing(
        self,
        scan_id: str,
        discovered_params: List[Dict[str, Any]],
        max_targets: int,
        callback_domain: str,
        callback_port: int,
        callback_protocol: str,
        wait_seconds: int,
        http_auth: Optional[tuple[str, str]] = None,
    ) -> Dict[str, Any]:
        """Detect blind vulnerabilities via OOB payloads."""
        results: List[Dict[str, Any]] = []
        tokens_seen: Set[str] = set()
        manager = create_callback_manager(
            domain=callback_domain or "localhost",
            port=callback_port or 8080,
            protocol=callback_protocol or "http",
        )
        generator = create_payload_generator(manager)
        targets = discovered_params[: max_targets]
        targets_tested = 0
        for target in targets:
            endpoint = target.get("endpoint")
            name = target.get("name")
            if not endpoint or not name:
                continue
            method = self._normalize_http_method(target.get("method"))
            if not method or not self._is_safe_http_method(method):
                continue
            payload_map = generator.get_all_payloads(scan_id, endpoint, name)
            target_attempted = False
            for payload_type, payloads in payload_map.items():
                for payload, token in payloads[:1]:
                    try:
                        params = {name: payload}
                        await self.http_client.request(
                            method, endpoint, params=params, timeout=15.0, auth=http_auth
                        )
                        target_attempted = True
                        results.append({
                            "endpoint": endpoint,
                            "parameter": name,
                            "payload_type": payload_type.value,
                            "token": token.token,
                            "callback_url": manager.get_callback_url(token),
                        })
                    except Exception:
                        continue
            if target_attempted:
                targets_tested += 1
        await asyncio.sleep(wait_seconds)
        events = manager.check_callbacks(scan_id)
        findings = []
        callbacks = []
        severity_map = {
            VulnerabilityType.SSRF: "high",
            VulnerabilityType.XXE: "critical",
            VulnerabilityType.RCE: "critical",
            VulnerabilityType.BLIND_SQLI: "high",
            VulnerabilityType.SSTI: "high",
            VulnerabilityType.LFI: "medium",
            VulnerabilityType.UNKNOWN: "medium",
        }
        for event in events:
            if not event.correlated_endpoint or not event.correlated_parameter:
                continue
            if event.token in tokens_seen:
                continue
            tokens_seen.add(event.token)
            severity = severity_map.get(event.correlated_payload_type or VulnerabilityType.UNKNOWN, "medium")
            finding = ScanFinding(
                source="oob_callback",
                severity=severity,
                title=f"OOB {event.correlated_payload_type.value if event.correlated_payload_type else 'callback'} detected",
                description=f"Out-of-band callback received from {event.source_ip}:{event.source_port}",
                host=event.source_ip or "unknown",
                url=event.correlated_endpoint,
                port=None,
                evidence=f"Callback token: {event.token} ({event.callback_type.value})",
                remediation="Investigate the parameter for blind injection paths.",
                references=[],
                validated=True,
                validation_notes=f"Callback received at {event.timestamp.isoformat()}",
                raw_data=event.to_dict(),
            )
            findings.append(finding)
            callbacks.append(event.to_dict())
        summary = {
            "targets_tested": targets_tested,
            "callbacks_received": len(callbacks),
            "details": callbacks,
        }
        return {"findings": findings, "summary": summary}

    async def _run_validation_pass(
        self,
        scan_id: str,
        findings: List[ScanFinding],
        max_findings: int,
        http_auth: Optional[tuple[str, str]] = None,
    ) -> Dict[str, Any]:
        """Validate high/critical findings by reissuing requests."""
        ordered = sorted(
            findings,
            key=lambda f: {"critical": 0, "high": 1, "medium": 2}.get(f.severity.lower(), 3)
        )
        validated = []
        count = 0
        for finding in ordered:
            if count >= max_findings:
                break
            if finding.validated:
                validated.append({
                    "title": finding.title,
                    "status": "already_validated",
                    "notes": finding.validation_notes or "Marked during scanning",
                })
                count += 1
                continue
            if not finding.url:
                continue
            method = self._extract_finding_method(finding)
            if not method:
                validated.append({
                    "title": finding.title,
                    "status": "skipped_unknown_method",
                    "notes": "Request method unknown; skipped safe replay.",
                })
                count += 1
                continue
            if not self._is_safe_http_method(method):
                validated.append({
                    "title": finding.title,
                    "status": "skipped_unsafe_method",
                    "notes": f"Unsafe method {method}; skipped safe replay.",
                })
                count += 1
                continue
            try:
                resp = await self.http_client.request(
                    method, finding.url, timeout=15.0, auth=http_auth
                )
                finding.validated = resp.status_code < 400
                finding.validation_notes = f"HTTP {resp.status_code} re-checked"
                validated.append({
                    "title": finding.title,
                    "status": "validated" if finding.validated else "not_validated",
                    "notes": finding.validation_notes,
                })
                count += 1
            except Exception as e:
                finding.validation_notes = f"Validation failed: {e}"
                validated.append({
                    "title": finding.title,
                    "status": "validation_error",
                    "notes": finding.validation_notes,
                })
                count += 1
        return {
            "validated_findings": len([v for v in validated if v["status"] == "validated"]),
            "total_attempted": len(validated),
            "details": validated,
        }

    def _action_fingerprint(self, action: str, parameters: Dict[str, Any]) -> str:
        """Create a stable fingerprint for an agent action to prevent repeats."""
        payload = json.dumps({"action": action, "parameters": parameters}, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def _build_followup_action(
        self,
        action_name: str,
        reason: str,
        expected_signal: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a follow-up action payload matching agent schema."""
        return {
            "action": action_name,
            "parameters": parameters or {},
            "reason": [reason],
            "expected_signal": expected_signal,
            "plan_update": [],
        }

    def _count_action_history(self, action_history: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count completed/failed/timeout actions for budget enforcement."""
        counts: Dict[str, int] = {}
        for entry in action_history:
            action = entry.get("action")
            status = entry.get("status")
            if not action or status not in {"completed", "failed", "timeout"}:
                continue
            counts[action] = counts.get(action, 0) + 1
        return counts

    def _action_completed(self, action_history: List[Dict[str, Any]], action_name: str) -> bool:
        """Check whether an action completed successfully."""
        for entry in action_history:
            if entry.get("action") == action_name and entry.get("status") == "completed":
                return True
        return False

    def _count_high_critical_findings(self, findings: List["ScanFinding"]) -> int:
        """Count high and critical findings."""
        return sum(
            1 for f in findings
            if (f.severity or "").lower() in {"high", "critical"}
        )

    def _has_web_findings(self, findings: List["ScanFinding"]) -> bool:
        """Return True when any finding has a URL for validation follow-ups."""
        return any(bool(f.url) for f in findings)

    def _summarize_findings(self, findings: List[ScanFinding]) -> Dict[str, Any]:
        """Summarize findings for agent context."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        source_counts: Dict[str, int] = {}
        for finding in findings:
            sev = (finding.severity or "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            source_counts[finding.source] = source_counts.get(finding.source, 0) + 1
        top_findings = [
            {
                "title": f.title,
                "severity": f.severity,
                "source": f.source,
                "url": f.url,
                "cve_id": f.cve_id,
            }
            for f in findings[:10]
        ]
        return {
            "total": len(findings),
            "severity_breakdown": severity_counts,
            "source_breakdown": source_counts,
            "top_findings": top_findings,
        }

    def _build_agent_state(
        self,
        scan: DynamicScanResult,
        target_type: str,
        aggressive_scan: bool,
        action_history: List[Dict[str, Any]],
        scanner_info: Optional[Dict[str, Any]],
        step_index: int,
        max_steps: int,
        max_seconds: int,
        elapsed_seconds: int,
    ) -> Dict[str, Any]:
        """Build a compact state object for the agent."""
        return {
            "target": scan.target,
            "target_type": target_type,
            "aggressive_scan": aggressive_scan,
            "progress": {
                "phase": scan.progress.phase.value,
                "overall_progress": scan.progress.overall_progress,
                "message": scan.progress.message,
            },
            "coverage": {
                "hosts": len(scan.hosts),
                "web_targets": len(scan.web_targets),
                "network_targets": len(scan.network_targets),
                "discovered_urls": len(scan.discovered_urls),
                "discovered_params": len(scan.discovered_params),
            },
            "findings": self._summarize_findings(scan.findings),
            "recent_errors": scan.progress.errors[-5:],
            "action_history": action_history[-8:],
            "agent_plan": scan.agent_plan[-10:],
            "scanner_capabilities": (scanner_info or {}).get("capabilities", {}),
            "budget": {
                "step": step_index,
                "max_steps": max_steps,
                "elapsed_seconds": elapsed_seconds,
                "max_seconds": max_seconds,
                "remaining_steps": max(max_steps - step_index, 0),
                "remaining_seconds": max(max_seconds - elapsed_seconds, 0),
            },
        }

    def _normalize_agent_action(self, action_payload: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        """Normalize action payload shape from agent."""
        action_name = (action_payload.get("action") or action_payload.get("name") or "").strip()
        params = action_payload.get("parameters") or action_payload.get("params") or {}
        if not isinstance(params, dict):
            params = {}
        return action_name, params

    def _sanitize_agent_parameters(
        self,
        action_name: str,
        params: Dict[str, Any],
        scan_profile: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Clamp agent parameters to safe defaults."""
        cleaned: Dict[str, Any] = {}

        if action_name == "run_nmap":
            allowed_types = {
                "ping", "quick", "basic", "service", "version", "stealth", "script",
                "vuln", "aggressive", "os_detect", "udp_quick", "udp", "comprehensive", "full_tcp",
            }
            scan_type = params.get("scan_type") or "service"
            cleaned["scan_type"] = scan_type if scan_type in allowed_types else "service"
            ports = params.get("ports")
            cleaned["ports"] = ports if ports else None
            nse_scripts = params.get("nse_scripts") or []
            cleaned["nse_scripts"] = nse_scripts if isinstance(nse_scripts, list) else []
            timing = params.get("timing_template") or scan_profile.get("nmap_timing") or "T3"
            cleaned["timing_template"] = timing if timing in ["T0", "T1", "T2", "T3", "T4", "T5"] else "T3"
            cleaned["run_udp"] = bool(params.get("run_udp", False))
            cleaned["advanced_options"] = params.get("advanced_options") if isinstance(params.get("advanced_options"), dict) else None

        elif action_name == "run_openvas":
            from backend.services.dynamic_scan_agent import OPENVAS_SCAN_CONFIGS, OPENVAS_PORT_LISTS
            scan_config = params.get("scan_config") or scan_profile.get("openvas_config")
            cleaned["scan_config"] = scan_config if scan_config in OPENVAS_SCAN_CONFIGS else scan_profile.get("openvas_config")
            port_list = params.get("port_list") or scan_profile.get("openvas_port_list")
            cleaned["port_list"] = port_list if port_list in OPENVAS_PORT_LISTS else scan_profile.get("openvas_port_list")
            cleaned["nvt_families"] = params.get("nvt_families") if isinstance(params.get("nvt_families"), list) else []
            qod = params.get("qod_threshold") or scan_profile.get("openvas_qod_threshold")
            cleaned["qod_threshold"] = qod if qod in ["low", "standard", "high", "maximum"] else scan_profile.get("openvas_qod_threshold")
            alive_test = params.get("alive_test") or "icmp_tcp_ack_ping"
            cleaned["alive_test"] = alive_test
            max_hosts = params.get("max_hosts") or scan_profile.get("openvas_max_hosts")
            cleaned["max_hosts"] = max_hosts if max_hosts in ["conservative", "standard", "aggressive"] else scan_profile.get("openvas_max_hosts")
            cleaned["authenticated_scan"] = bool(params.get("authenticated_scan", False))
            cleaned["credential_type"] = params.get("credential_type")
            cleaned["schedule"] = params.get("schedule") or "immediate"
            cleaned["alert"] = params.get("alert")

        elif action_name == "run_zap":
            from backend.services.dynamic_scan_agent import ZAP_SCAN_POLICIES, ZAP_SPIDER_OPTIONS
            scan_policy = params.get("scan_policy") or scan_profile.get("zap_policy")
            cleaned["scan_policy"] = scan_policy if scan_policy in ZAP_SCAN_POLICIES else scan_profile.get("zap_policy")
            spider_mode = params.get("spider_mode") or "deep"
            cleaned["spider_mode"] = spider_mode if spider_mode in ZAP_SPIDER_OPTIONS else "deep"
            attack_vectors = params.get("attack_vectors") or []
            cleaned["attack_vectors"] = attack_vectors if isinstance(attack_vectors, list) else []
            advanced = params.get("advanced_features") or []
            cleaned["advanced_features"] = advanced if isinstance(advanced, list) else []
            cleaned["forced_browse"] = bool(params.get("forced_browse", False))
            cleaned["wordlist"] = params.get("wordlist")

        elif action_name == "run_nuclei":
            from backend.services.dynamic_scan_agent import NUCLEI_TEMPLATES
            templates = params.get("templates") or scan_profile.get("nuclei_templates") or ["cves", "vulnerabilities"]
            cleaned["templates"] = [t for t in templates if t in NUCLEI_TEMPLATES] or ["cves", "vulnerabilities"]
            severity = params.get("severity")
            cleaned["severity"] = severity if isinstance(severity, list) else None

        elif action_name == "run_directory_enum":
            cleaned["engine"] = params.get("engine") or "gobuster"
            cleaned["wordlist"] = params.get("wordlist")
            cleaned["extensions"] = params.get("extensions") if isinstance(params.get("extensions"), list) else None
            threads = params.get("threads")
            cleaned["threads"] = max(5, min(int(threads), 60)) if isinstance(threads, int) else 25

        elif action_name == "run_forced_browse":
            cleaned["wordlist"] = params.get("wordlist")
            cleaned["scan_policy"] = params.get("scan_policy") or scan_profile.get("zap_policy")

        elif action_name == "run_wapiti":
            level = params.get("level")
            cleaned["level"] = max(1, min(int(level), 5)) if isinstance(level, int) else 2

        elif action_name == "run_sqlmap":
            level = params.get("level")
            risk = params.get("risk")
            cleaned["level"] = max(1, min(int(level), 5)) if isinstance(level, int) else 2
            cleaned["risk"] = max(0, min(int(risk), 3)) if isinstance(risk, int) else 2
            method = params.get("method") or "GET"
            cleaned["method"] = method if method in ["GET", "POST"] else "GET"
            cleaned["data"] = params.get("data")
            threads = params.get("threads")
            cleaned["threads"] = max(1, min(int(threads), 10)) if isinstance(threads, int) else 1
            cleaned["targets"] = params.get("targets") if isinstance(params.get("targets"), list) else None

        elif action_name == "run_oob":
            cleaned["callback_domain"] = params.get("callback_domain")
            cleaned["callback_port"] = params.get("callback_port")
            cleaned["callback_protocol"] = params.get("callback_protocol")
            cleaned["wait_seconds"] = params.get("wait_seconds")
            cleaned["max_targets"] = params.get("max_targets")

        elif action_name == "run_validation":
            max_findings = params.get("max_findings")
            cleaned["max_findings"] = max(1, min(int(max_findings), 100)) if isinstance(max_findings, int) else 25

        return cleaned

    async def _execute_agent_action(
        self,
        scan_id: str,
        scan: DynamicScanResult,
        action_name: str,
        params: Dict[str, Any],
        scan_profile: Dict[str, Any],
        zap_auth: Optional[Dict[str, Any]],
        aggressive_scan: bool,
        zap_auth_profiles: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Execute a single agentic action and return outcome details."""
        start_time = time.monotonic()
        prev_counts = {
            "findings": len(scan.findings),
            "hosts": len(scan.hosts),
            "web_targets": len(scan.web_targets),
            "network_targets": len(scan.network_targets),
            "urls": len(scan.discovered_urls),
            "params": len(scan.discovered_params),
        }
        status = "completed"
        error = None

        try:
            if action_name == "run_nmap":
                await self._update_progress(scan_id, ScanPhase.RECONNAISSANCE, 0, "Agentic: running Nmap reconnaissance...")
                hosts = await self._run_nmap_recon(
                    scan_id=scan_id,
                    target=scan.target,
                    scan_type=params.get("scan_type", "service"),
                    ports=params.get("ports"),
                    nse_scripts=params.get("nse_scripts"),
                    timing_template=params.get("timing_template", "T3"),
                    run_udp=params.get("run_udp", False),
                    advanced_options=params.get("advanced_options"),
                )
                scan.hosts = hosts
                scan.progress.hosts_discovered = len(hosts)

                from backend.services.dynamic_scan_agent import DynamicScanAgent
                agent = DynamicScanAgent()
                routing_result = await agent.analyze_recon_results(
                    hosts=[asdict(h) for h in hosts],
                    target=scan.target,
                )
                web_targets = [
                    ServiceTarget(
                        ip=t["ip"],
                        port=p["port"],
                        url=p["url"],
                        service=p.get("service", "http"),
                        product=p.get("product", ""),
                        version=p.get("version", ""),
                    )
                    for t in routing_result["web_targets"]
                    for p in t["ports"]
                ]
                network_targets = [
                    ServiceTarget(
                        ip=t["ip"],
                        port=s["port"],
                        service=s["service"],
                        product=s.get("product", ""),
                        version=s.get("version", ""),
                    )
                    for t in routing_result["openvas_targets"]
                    for s in t["services"]
                ]
                scan.web_targets = web_targets
                scan.network_targets = network_targets
                scan.progress.web_targets = len(web_targets)
                scan.progress.network_targets = len(network_targets)
                await self._update_progress(
                    scan_id,
                    ScanPhase.RECONNAISSANCE,
                    100,
                    f"Nmap complete: {len(hosts)} hosts, {len(web_targets)} web targets",
                )

            elif action_name == "classify_services":
                from backend.services.dynamic_scan_agent import DynamicScanAgent
                agent = DynamicScanAgent()
                routing_result = await agent.analyze_recon_results(
                    hosts=[asdict(h) for h in scan.hosts],
                    target=scan.target,
                )
                scan.web_targets = [
                    ServiceTarget(
                        ip=t["ip"],
                        port=p["port"],
                        url=p["url"],
                        service=p.get("service", "http"),
                        product=p.get("product", ""),
                        version=p.get("version", ""),
                    )
                    for t in routing_result["web_targets"]
                    for p in t["ports"]
                ]
                scan.network_targets = [
                    ServiceTarget(
                        ip=t["ip"],
                        port=s["port"],
                        service=s["service"],
                        product=s.get("product", ""),
                        version=s.get("version", ""),
                    )
                    for t in routing_result["openvas_targets"]
                    for s in t["services"]
                ]
                scan.progress.web_targets = len(scan.web_targets)
                scan.progress.network_targets = len(scan.network_targets)

            elif action_name == "run_openvas":
                if not scan.network_targets:
                    raise ValueError("No network targets available for OpenVAS")
                await self._update_progress(
                    scan_id, ScanPhase.OPENVAS_SCANNING, 0,
                    f"Agentic: running OpenVAS ({params.get('scan_config')})..."
                )
                openvas_target_data = [
                    {"ip": t.ip, "services": [{"port": t.port, "service": t.service}]}
                    for t in scan.network_targets
                ]
                openvas_findings = await self._run_openvas_scan(
                    scan_id=scan_id,
                    openvas_targets=openvas_target_data,
                    scan_config=params.get("scan_config"),
                    port_list=params.get("port_list"),
                    nvt_families=params.get("nvt_families"),
                    qod_threshold=params.get("qod_threshold"),
                    alive_test=params.get("alive_test"),
                    max_hosts=params.get("max_hosts"),
                    authenticated_scan=params.get("authenticated_scan", False),
                    credential_type=params.get("credential_type"),
                    schedule=params.get("schedule", "immediate"),
                    alert=params.get("alert"),
                )
                scan.findings.extend(openvas_findings)
                await self._update_progress(scan_id, ScanPhase.OPENVAS_SCANNING, 100, "OpenVAS complete")

            elif action_name == "run_zap":
                if not scan.web_targets:
                    raise ValueError("No web targets available for ZAP")
                await self._update_progress(
                    scan_id, ScanPhase.WEB_SCANNING, 0,
                    f"Agentic: running ZAP ({params.get('scan_policy')})..."
                )
                web_findings = await self._run_zap_with_profiles(
                    scan_id=scan_id,
                    targets=scan.web_targets,
                    scan_policy=params.get("scan_policy"),
                    spider_mode=params.get("spider_mode"),
                    attack_vectors=params.get("attack_vectors"),
                    advanced_features=params.get("advanced_features"),
                    zap_auth=zap_auth,
                    zap_auth_profiles=zap_auth_profiles,
                    forced_browse=bool(params.get("forced_browse")),
                    forced_browse_wordlist=params.get("wordlist"),
                    browser_crawl=browser_crawl,
                    openapi_spec_url=openapi_spec_url,
                    openapi_spec_content=openapi_spec_content,
                    openapi_base_url=openapi_base_url,
                    graphql_endpoint_url=graphql_endpoint_url,
                    graphql_schema_url=graphql_schema_url,
                )
                scan.findings.extend(web_findings)

                try:
                    discovery = await self._collect_discovery_summary(
                        scan_id,
                        scan.web_targets,
                        include_js=True,
                        include_params=True,
                        extra_urls=scan.discovered_urls,
                    )
                    merged_urls = list(dict.fromkeys((scan.discovered_urls or []) + discovery.get("urls", [])))
                    scan.discovered_urls = merged_urls
                    params_seen = set()
                    unique_params: List[Dict[str, Any]] = []
                    for param_entry in discovery.get("params", []):
                        key = (param_entry.get("endpoint"), param_entry.get("name"))
                        if key not in params_seen:
                            params_seen.add(key)
                            unique_params.append(param_entry)
                    scan.discovered_params = unique_params
                    scan.coverage_summary = discovery.get("coverage", {})
                except Exception as e:
                    scan.progress.errors.append(f"Discovery summary: {str(e)[:500]}")
                await self._update_progress(scan_id, ScanPhase.WEB_SCANNING, 100, "ZAP complete")

            elif action_name == "run_nuclei":
                targets = scan.network_targets if scan.network_targets else scan.web_targets
                if not targets:
                    raise ValueError("No targets available for Nuclei")
                await self._update_progress(
                    scan_id, ScanPhase.CVE_SCANNING, 0,
                    "Agentic: running Nuclei CVE scan..."
                )
                findings = await self._run_nuclei_scan(
                    scan_id=scan_id,
                    targets=targets,
                    templates=params.get("templates"),
                )
                scan.findings.extend(findings)
                await self._update_progress(scan_id, ScanPhase.CVE_SCANNING, 100, "Nuclei complete")

            elif action_name == "run_directory_enum":
                if not scan.web_targets:
                    raise ValueError("No web targets available for directory enumeration")
                await self._update_progress(
                    scan_id, ScanPhase.DIRECTORY_ENUMERATION, 0,
                    "Agentic: running directory enumeration..."
                )
                dir_findings, dir_urls = await self._run_directory_scan(
                    scan_id=scan_id,
                    targets=scan.web_targets,
                    engine=params.get("engine", "gobuster"),
                    wordlist=params.get("wordlist"),
                    extensions=params.get("extensions"),
                    threads=params.get("threads", 25),
                )
                if dir_findings:
                    scan.findings.extend(dir_findings)
                if dir_urls:
                    new_urls = [u for u in dir_urls if u not in scan.discovered_urls]
                    if new_urls:
                        scan.discovered_urls = list(dict.fromkeys(scan.discovered_urls + new_urls))
                        await self._seed_zap_urls(new_urls[:250])
                await self._update_progress(scan_id, ScanPhase.DIRECTORY_ENUMERATION, 100, "Directory enumeration complete")

            elif action_name == "run_forced_browse":
                if not scan.web_targets:
                    raise ValueError("No web targets available for forced browse")
                await self._update_progress(
                    scan_id, ScanPhase.WEB_SCANNING, 10,
                    "Agentic: running forced browsing..."
                )
                for target in scan.web_targets:
                    if not target.url:
                        continue
                    base_url, _ = self._normalize_zap_urls(self._maybe_rewrite_localhost(target.url))
                    fb_findings, fb_urls = await self._run_forced_browse(
                        scan_id=scan_id,
                        base_url=base_url,
                        host=target.ip,
                        port=target.port,
                        wordlist_key=params.get("wordlist"),
                        scan_policy=params.get("scan_policy", scan_profile.get("zap_policy")),
                    )
                    if fb_findings:
                        scan.findings.extend(fb_findings)
                    if fb_urls:
                        await self._seed_zap_urls(fb_urls, limit=200)
                await self._update_progress(scan_id, ScanPhase.WEB_SCANNING, 40, "Forced browsing complete")

            elif action_name == "run_wapiti":
                if not scan.web_targets:
                    raise ValueError("No web targets available for Wapiti")
                await self._update_progress(
                    scan_id, ScanPhase.WAPITI_SCANNING, 0,
                    "Agentic: running Wapiti scan..."
                )
                wapiti_findings = await self._run_wapiti_scan(
                    scan_id=scan_id,
                    targets=scan.web_targets,
                    level=params.get("level", 2),
                )
                if wapiti_findings:
                    scan.findings.extend(wapiti_findings)
                await self._update_progress(scan_id, ScanPhase.WAPITI_SCANNING, 100, "Wapiti complete")

            elif action_name == "run_sqlmap":
                await self._update_progress(
                    scan_id, ScanPhase.SQLMAP_SCANNING, 0,
                    "Agentic: running SQLMap..."
                )
                targets = params.get("targets")
                if not targets:
                    targets = list(dict.fromkeys(
                        (scan.discovered_urls or []) +
                        [p.get("endpoint") for p in (scan.discovered_params or []) if p.get("endpoint")]
                    ))
                if not targets:
                    targets = [t.url for t in scan.web_targets if t.url]
                if not targets:
                    raise ValueError("No targets available for SQLMap")
                sqlmap_findings = await self._run_sqlmap_scan(
                    scan_id=scan_id,
                    urls=targets,
                    level=params.get("level", 2),
                    risk=params.get("risk", 2),
                    method=params.get("method", "GET"),
                    data=params.get("data"),
                    threads=params.get("threads", 1),
                )
                if sqlmap_findings:
                    scan.findings.extend(sqlmap_findings)
                await self._update_progress(scan_id, ScanPhase.SQLMAP_SCANNING, 100, "SQLMap complete")

            elif action_name == "run_oob":
                if not scan.discovered_params:
                    raise ValueError("No discovered parameters for OOB testing")
                await self._update_progress(
                    scan_id, ScanPhase.WEB_SCANNING, 95,
                    "Agentic: running OOB payload checks..."
                )
                http_auth = self._extract_basic_auth(zap_auth_profiles or zap_auth)
                oob_result = await self._run_oob_testing(
                    scan_id=scan_id,
                    discovered_params=scan.discovered_params,
                    max_targets=params.get("max_targets") or 30,
                    callback_domain=params.get("callback_domain") or "localhost",
                    callback_port=params.get("callback_port") or 8080,
                    callback_protocol=params.get("callback_protocol") or "http",
                    wait_seconds=params.get("wait_seconds") or 20,
                    http_auth=http_auth,
                )
                scan.findings.extend(oob_result.get("findings", []))
                scan.oob_summary = oob_result.get("summary", {})

            elif action_name == "run_validation":
                if not scan.findings:
                    raise ValueError("No findings available to validate")
                await self._update_progress(
                    scan_id, ScanPhase.EXPLOIT_MAPPING, 5,
                    "Agentic: validating findings..."
                )
                http_auth = self._extract_basic_auth(zap_auth_profiles or zap_auth)
                scan.validation_summary = await self._run_validation_pass(
                    scan_id=scan_id,
                    findings=scan.findings,
                    max_findings=params.get("max_findings", 25),
                    http_auth=http_auth,
                )

            elif action_name == "map_exploits":
                if not scan.findings:
                    raise ValueError("No findings available for exploit mapping")
                await self._update_progress(scan_id, ScanPhase.EXPLOIT_MAPPING, 0, "Agentic: mapping exploits...")
                await self._map_exploits(scan_id)
                await self._update_progress(scan_id, ScanPhase.EXPLOIT_MAPPING, 100, "Exploit mapping complete")

            elif action_name == "ai_analysis":
                await self._update_progress(scan_id, ScanPhase.AI_ANALYSIS, 0, "Agentic: generating AI analysis...")
                await self._run_ai_analysis(scan_id)
                await self._update_progress(scan_id, ScanPhase.AI_ANALYSIS, 100, "AI analysis complete")

            else:
                raise ValueError(f"Unknown action '{action_name}'")

        except Exception as e:
            status = "failed"
            error = str(e)
            scan.progress.errors.append(f"Agentic {action_name}: {str(e)[:500]}")

        duration = int(time.monotonic() - start_time)
        new_counts = {
            "findings": len(scan.findings),
            "hosts": len(scan.hosts),
            "web_targets": len(scan.web_targets),
            "network_targets": len(scan.network_targets),
            "urls": len(scan.discovered_urls),
            "params": len(scan.discovered_params),
        }
        deltas = {k: max(new_counts[k] - prev_counts[k], 0) for k in new_counts}
        return {
            "action": action_name,
            "parameters": params,
            "status": status,
            "error": error,
            "duration_seconds": duration,
            "deltas": deltas,
        }

    async def _run_agentic_scan(
        self,
        scan_id: str,
        target: str,
        include_web_scan: bool,
        include_cve_scan: bool,
        include_exploit_mapping: bool,
        include_openvas: bool,
        include_directory_enum: bool,
        include_sqlmap: bool,
        include_wapiti: bool,
        aggressive_scan: bool,
        zap_auth: Optional[Dict[str, Any]],
        zap_auth_profiles: Optional[List[Dict[str, Any]]] = None,
        openvas_credentials: Optional[Dict[str, Any]] = None,
        openapi_spec_url: Optional[str] = None,
        openapi_spec_content: Optional[str] = None,
        openapi_base_url: Optional[str] = None,
        graphql_endpoint_url: Optional[str] = None,
        graphql_schema_url: Optional[str] = None,
        browser_crawl: Optional[Dict[str, Any]] = None,
        user_context: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> None:
        """Agentic scan loop using iterative AI decisions."""
        scan = self.active_scans[scan_id]
        scan_profile = self.build_scan_profile(aggressive_scan)

        max_steps = int(getattr(settings, "dynamic_scan_agent_max_steps", 12))
        max_seconds = int(getattr(settings, "dynamic_scan_agent_max_minutes", 45)) * 60
        max_no_progress = int(getattr(settings, "dynamic_scan_agent_max_no_progress", 3))
        scanner_info = await self._get_scanner_info()

        target_type = "url" if self._is_url_target(target) else ("cidr" if "/" in target else "host")
        is_url_mode = self._is_url_target(target)

        if is_url_mode:
            include_openvas = False
            include_cve_scan = False
            host, port, url = self._parse_url_target(target)
            resolved_ips = await self._resolve_host_ips(host)
            scan.hosts = [
                DiscoveredHost(
                    ip=host,
                    hostname=host,
                    state="up",
                    ports=[{
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "https" if port == 443 else "http",
                        "product": "Web Application",
                        "version": "",
                    }]
                )
            ]
            scan.web_targets = [
                ServiceTarget(
                    ip=host,
                    port=port,
                    url=url,
                    service="https" if port == 443 else "http",
                    product="Web Application",
                    version="",
                )
            ]
            scan.network_targets = [
                ServiceTarget(
                    ip=ip,
                    port=port,
                    service="https" if port == 443 else "http",
                    product="Web Application",
                    version="",
                    nuclei_tags=["cve", "web"],
                )
                for ip in (resolved_ips or [host])
            ]
            scan.progress.hosts_discovered = 1
            scan.progress.web_targets = 1
            scan.progress.network_targets = len(scan.network_targets)

        await self._update_progress(
            scan_id,
            ScanPhase.INITIALIZING,
            10,
            "🤖 Agentic scan loop initializing...",
        )

        from backend.services.dynamic_scan_agent import DynamicScanAgent, AGENT_ACTIONS
        agent = DynamicScanAgent()
        allowed_actions = set(AGENT_ACTIONS.keys())

        action_history: List[Dict[str, Any]] = []
        action_fingerprints: Set[str] = set()
        pending_followups: List[Dict[str, Any]] = []
        queued_followups: Set[str] = set()
        high_critical_count = self._count_high_critical_findings(scan.findings)
        no_progress_steps = 0
        start_time = time.monotonic()
        action_timeout = int(getattr(settings, "dynamic_scan_agent_action_timeout", 1200))

        action_budgets = {
            "run_nmap": 0 if is_url_mode else 2,
            "classify_services": 3,
            "run_openvas": 1 if include_openvas else 0,
            "run_zap": 2 if include_web_scan else 0,
            "run_nuclei": 2 if include_cve_scan else 0,
            "run_directory_enum": 2 if include_directory_enum else 0,
            "run_forced_browse": 2 if include_directory_enum else 0,
            "run_wapiti": 1 if include_wapiti else 0,
            "run_sqlmap": 2 if include_sqlmap else 0,
            "run_oob": 1 if include_web_scan else 0,
            "run_validation": 2,
            "map_exploits": 1 if include_exploit_mapping else 0,
            "ai_analysis": 1,
        }
        requires_recon = {
            "run_openvas",
            "run_zap",
            "run_nuclei",
            "run_directory_enum",
            "run_forced_browse",
            "run_wapiti",
            "run_sqlmap",
            "run_oob",
        }
        requires_routing = set(requires_recon)

        plan_payload = None
        try:
            plan_payload = await agent.plan_scan_strategy(
                target=target,
                user_context=user_context,
                aggressive_scan=aggressive_scan,
            )
            scan_plan = plan_payload.get("scan_plan", {}) if isinstance(plan_payload, dict) else {}
            recommendations = plan_payload.get("recommendations", []) if isinstance(plan_payload, dict) else []
            plan_steps = self._build_plan_steps(scan_plan, recommendations)
            if plan_steps:
                scan.agent_plan = list(dict.fromkeys(scan.agent_plan + plan_steps))
            action_history.append({
                "step": 0,
                "action": "plan",
                "status": "completed",
                "reason": ["Initial scan plan created"],
                "plan": scan_plan,
            })
        except Exception as e:
            action_history.append({
                "step": 0,
                "action": "plan",
                "status": "failed",
                "reason": [f"Plan step failed: {str(e)[:500]}"],
            })
        scan.agent_log = action_history
        if db:
            try:
                await self._save_scan_snapshot(scan_id, db)
            except Exception as e:
                logger.warning(f"[{scan_id}] Failed to persist agent snapshot: {e}")

        for step in range(1, max_steps + 1):
            elapsed = int(time.monotonic() - start_time)
            if elapsed >= max_seconds:
                action_history.append({
                    "action": "stop",
                    "status": "budget_exhausted",
                    "reason": f"Max duration exceeded ({elapsed}s)",
                    "reason_code": "budget_exhausted",
                })
                break

            action_counts = self._count_action_history(action_history)
            recon_complete = bool(scan.hosts) or is_url_mode
            routing_complete = bool(scan.web_targets or scan.network_targets) or is_url_mode

            state = self._build_agent_state(
                scan=scan,
                target_type=target_type,
                aggressive_scan=aggressive_scan,
                action_history=action_history,
                scanner_info=scanner_info,
                step_index=step,
                max_steps=max_steps,
                max_seconds=max_seconds,
                elapsed_seconds=elapsed,
            )
            if user_context:
                state["user_context"] = user_context
            if isinstance(plan_payload, dict):
                state["plan"] = {
                    "scan_plan": plan_payload.get("scan_plan", {}),
                    "recommendations": plan_payload.get("recommendations", []),
                }
            state["constraints"] = {
                "allow_web_scan": include_web_scan,
                "allow_cve_scan": include_cve_scan,
                "allow_exploit_mapping": include_exploit_mapping,
                "allow_openvas": include_openvas and not is_url_mode,
                "allow_directory_enum": include_directory_enum,
                "allow_sqlmap": include_sqlmap,
                "allow_wapiti": include_wapiti,
                "is_url_mode": is_url_mode,
                "recon_complete": recon_complete,
                "routing_complete": routing_complete,
                "action_budgets": action_budgets,
                "action_counts": action_counts,
                "action_timeout_seconds": action_timeout,
            }

            if pending_followups:
                action_payload = pending_followups.pop(0)
            else:
                action_payload = await agent.next_action(state)
            action_name, raw_params = self._normalize_agent_action(action_payload)

            plan_update = action_payload.get("plan_update")
            if isinstance(plan_update, list) and plan_update:
                scan.agent_plan = list(dict.fromkeys(scan.agent_plan + plan_update))

            if action_name == "stop":
                action_history.append({
                    "action": "stop",
                    "status": "completed",
                    "reason": action_payload.get("stop_reason") or "Agent requested stop",
                    "reason_code": "agent_stop",
                })
                break

            if not action_name:
                action_history.append({
                    "action": "unknown",
                    "status": "failed",
                    "reason": "Agent returned empty action",
                    "reason_code": "invalid_action_empty",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue
            if action_name not in allowed_actions:
                action_history.append({
                    "action": action_name,
                    "status": "failed",
                    "reason": f"Agent returned unsupported action '{action_name}'",
                    "reason_code": "invalid_action_name",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            params = self._sanitize_agent_parameters(action_name, raw_params, scan_profile)
            fingerprint = self._action_fingerprint(action_name, params)
            if fingerprint in action_fingerprints:
                action_history.append({
                    "action": action_name,
                    "parameters": params,
                    "status": "skipped_duplicate",
                    "reason_code": "duplicate_action",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            budget = action_budgets.get(action_name)
            if budget is not None and action_counts.get(action_name, 0) >= budget:
                action_history.append({
                    "action": action_name,
                    "parameters": params,
                    "status": "skipped",
                    "reason": f"Action budget exceeded ({budget})",
                    "reason_code": "action_budget_exceeded",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            if not recon_complete and action_name in requires_recon:
                action_history.append({
                    "action": action_name,
                    "parameters": params,
                    "status": "skipped",
                    "reason": "Reconnaissance required before this action",
                    "reason_code": "prereq_missing_recon",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            if not routing_complete and action_name in requires_routing:
                action_history.append({
                    "action": action_name,
                    "parameters": params,
                    "status": "skipped",
                    "reason": "Service classification required before this action",
                    "reason_code": "prereq_missing_routing",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            # Enforce constraints
            if is_url_mode and action_name in {"run_nmap", "run_openvas"}:
                action_history.append({
                    "action": action_name,
                    "parameters": params,
                    "status": "skipped",
                    "reason": "URL mode prohibits network recon/openvas",
                    "reason_code": "url_mode_restriction",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            if not include_web_scan and action_name in {"run_zap", "run_directory_enum", "run_forced_browse", "run_wapiti", "run_sqlmap", "run_oob"}:
                action_history.append({
                    "action": action_name,
                    "parameters": params,
                    "status": "skipped",
                    "reason": "Web scanning disabled by user",
                    "reason_code": "web_scan_disabled",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            if not include_cve_scan and action_name == "run_nuclei":
                action_history.append({
                    "action": action_name,
                    "parameters": params,
                    "status": "skipped",
                    "reason": "CVE scanning disabled by user",
                    "reason_code": "cve_scan_disabled",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            if not include_exploit_mapping and action_name == "map_exploits":
                action_history.append({
                    "action": action_name,
                    "parameters": params,
                    "status": "skipped",
                    "reason": "Exploit mapping disabled by user",
                    "reason_code": "exploit_mapping_disabled",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            if not include_openvas and action_name == "run_openvas":
                action_history.append({
                    "action": action_name,
                    "parameters": params,
                    "status": "skipped",
                    "reason": "OpenVAS disabled by user",
                    "reason_code": "openvas_disabled",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            if not include_directory_enum and action_name == "run_directory_enum":
                action_history.append({
                    "action": action_name,
                    "parameters": params,
                    "status": "skipped",
                    "reason": "Directory enumeration disabled by user",
                    "reason_code": "direnum_disabled",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            if not include_sqlmap and action_name == "run_sqlmap":
                action_history.append({
                    "action": action_name,
                    "parameters": params,
                    "status": "skipped",
                    "reason": "SQLMap disabled by user",
                    "reason_code": "sqlmap_disabled",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            if not include_wapiti and action_name == "run_wapiti":
                action_history.append({
                    "action": action_name,
                    "parameters": params,
                    "status": "skipped",
                    "reason": "Wapiti disabled by user",
                    "reason_code": "wapiti_disabled",
                })
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            if scanner_info:
                capabilities = scanner_info.get("capabilities", {})
                if action_name == "run_sqlmap":
                    if not capabilities.get("sqlmap", {}).get("installed", True):
                        action_history.append({
                            "action": action_name,
                            "parameters": params,
                            "status": "skipped",
                            "reason": "SQLMap not available in scanner",
                            "reason_code": "tool_unavailable_sqlmap",
                        })
                        no_progress_steps += 1
                        if no_progress_steps >= max_no_progress:
                            break
                        continue
                if action_name == "run_wapiti":
                    if not capabilities.get("wapiti", {}).get("installed", True):
                        action_history.append({
                            "action": action_name,
                            "parameters": params,
                            "status": "skipped",
                            "reason": "Wapiti not available in scanner",
                            "reason_code": "tool_unavailable_wapiti",
                        })
                        no_progress_steps += 1
                        if no_progress_steps >= max_no_progress:
                            break
                        continue
                if action_name == "run_directory_enum":
                    engines = capabilities.get("direnum", {}).get("engines", {})
                    if not engines.get(params.get("engine", "gobuster"), {}).get("installed", True):
                        action_history.append({
                            "action": action_name,
                            "parameters": params,
                            "status": "skipped",
                            "reason": "Directory enumeration engine not available in scanner",
                            "reason_code": "tool_unavailable_direnum",
                        })
                        no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    break
                continue

            action_fingerprints.add(fingerprint)
            try:
                outcome = await asyncio.wait_for(
                    self._execute_agent_action(
                        scan_id=scan_id,
                        scan=scan,
                        action_name=action_name,
                        params=params,
                        scan_profile=scan_profile,
                        zap_auth=zap_auth,
                        zap_auth_profiles=zap_auth_profiles,
                        aggressive_scan=aggressive_scan,
                    ),
                    timeout=action_timeout,
                )
            except asyncio.TimeoutError:
                timeout_msg = f"Agent action '{action_name}' timed out after {action_timeout}s"
                scan.progress.errors.append(timeout_msg)
                outcome = {
                    "action": action_name,
                    "parameters": params,
                    "status": "timeout",
                    "error": timeout_msg,
                    "duration_seconds": action_timeout,
                    "deltas": {},
                }

            entry = {
                "step": step,
                "action": action_name,
                "parameters": params,
                "status": outcome.get("status"),
                "duration_seconds": outcome.get("duration_seconds"),
                "deltas": outcome.get("deltas"),
                "reason": action_payload.get("reason"),
                "expected_signal": action_payload.get("expected_signal"),
                "error": outcome.get("error"),
            }
            if outcome.get("status") == "timeout":
                entry["reason_code"] = "action_timeout"
            action_history.append(entry)
            scan.agent_log = action_history

            new_high_critical_count = self._count_high_critical_findings(scan.findings)
            if new_high_critical_count > high_critical_count:
                if include_exploit_mapping and "map_exploits" not in queued_followups:
                    if not self._action_completed(action_history, "map_exploits"):
                        pending_followups.append(
                            self._build_followup_action(
                                "map_exploits",
                                "High-severity findings discovered; map exploits next.",
                                "Exploit mapping results",
                            )
                        )
                        queued_followups.add("map_exploits")
                if include_web_scan and "run_validation" not in queued_followups:
                    if self._has_web_findings(scan.findings) and not self._action_completed(action_history, "run_validation"):
                        pending_followups.append(
                            self._build_followup_action(
                                "run_validation",
                                "High-severity web findings discovered; validate before proceeding.",
                                "Validation pass results",
                            )
                        )
                        queued_followups.add("run_validation")
                reason = "High-severity findings detected"
                plan_payload = await self._refresh_agent_plan(
                    agent,
                    scan,
                    scan_id,
                    target,
                    user_context,
                    aggressive_scan,
                    action_history,
                    plan_payload,
                    reason,
                )
            high_critical_count = new_high_critical_count

            if db:
                try:
                    await self._save_scan_snapshot(scan_id, db)
                except Exception as e:
                    logger.warning(f"[{scan_id}] Failed to persist agent snapshot: {e}")

            if outcome.get("status") == "completed" and sum(outcome.get("deltas", {}).values()) > 0:
                no_progress_steps = 0
            else:
                no_progress_steps += 1
                if no_progress_steps >= max_no_progress:
                    action_history.append({
                        "action": "stop",
                        "status": "no_progress",
                        "reason": "No progress across multiple steps",
                        "reason_code": "no_progress",
                    })
                    break

        if db:
            try:
                await self._save_scan_snapshot(scan_id, db)
            except Exception as e:
                logger.warning(f"[{scan_id}] Failed to persist agent snapshot: {e}")

        # Ensure AI analysis if not already done
        if not scan.attack_narrative and scan.findings:
            await self._run_ai_analysis(scan_id)

        scan.agent_log = action_history
    
    async def _update_progress(
        self,
        scan_id: str,
        phase: ScanPhase,
        phase_progress: int,
        message: str,
        **kwargs
    ):
        """Update scan progress and notify callbacks."""
        if scan_id not in self.active_scans:
            return
        
        scan = self.active_scans[scan_id]
        
        # Calculate overall progress based on phase
        phase_weights = {
            ScanPhase.INITIALIZING: (0, 5),
            ScanPhase.RECONNAISSANCE: (5, 15),
            ScanPhase.ROUTING: (15, 20),
            ScanPhase.DIRECTORY_ENUMERATION: (20, 30),
            ScanPhase.OPENVAS_SCANNING: (30, 40),
            ScanPhase.WEB_SCANNING: (40, 50),
            ScanPhase.WAPITI_SCANNING: (50, 60),
            ScanPhase.SQLMAP_SCANNING: (60, 70),
            ScanPhase.CVE_SCANNING: (70, 80),
            ScanPhase.EXPLOIT_MAPPING: (80, 90),
            ScanPhase.AI_ANALYSIS: (90, 100),
            ScanPhase.COMPLETED: (100, 100),
            ScanPhase.FAILED: (0, 0),
        }
        
        start, end = phase_weights.get(phase, (0, 100))
        overall = start + int((end - start) * phase_progress / 100)
        
        scan.progress.phase = phase
        scan.progress.phase_progress = phase_progress
        scan.progress.overall_progress = overall
        scan.progress.message = message
        
        # Update additional fields
        for key, value in kwargs.items():
            if hasattr(scan.progress, key):
                setattr(scan.progress, key, value)
        
        # Notify callbacks
        for callback in self.progress_callbacks.get(scan_id, []):
            try:
                await callback(scan.progress)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")
        
        # Broadcast progress via WebSocket for real-time UI updates
        try:
            from backend.core.websocket_manager import scan_progress_manager
            await scan_progress_manager.broadcast_scan_progress(scan_id, {
                "scan_id": scan_id,
                "phase": phase.value if hasattr(phase, 'value') else str(phase),
                "phase_progress": phase_progress,
                "overall_progress": overall,
                "message": message,
                "status": scan.status.value if hasattr(scan.status, 'value') else str(scan.status),
                "findings_count": len(scan.findings),
            })
        except Exception as e:
            # WebSocket broadcast is optional - don't fail the scan if it fails
            logger.debug(f"WebSocket broadcast skipped: {e}")
    
    async def start_scan(
        self,
        target: str,
        scan_type: str = "service",
        ports: Optional[str] = None,
        include_web_scan: bool = True,
        include_cve_scan: bool = True,
        include_exploit_mapping: bool = True,
        include_openvas: bool = True,
        aggressive_scan: bool = True,
        zap_auth: Optional[Dict[str, Any]] = None,
        zap_auth_profiles: Optional[List[Dict[str, Any]]] = None,
        zap_forced_browse: bool = False,
        zap_wordlist: Optional[str] = None,
        openvas_credentials: Optional[Dict[str, Any]] = None,
        openapi_spec_url: Optional[str] = None,
        openapi_spec_content: Optional[str] = None,
        openapi_base_url: Optional[str] = None,
        graphql_endpoint_url: Optional[str] = None,
        graphql_schema_url: Optional[str] = None,
        browser_crawl: Optional[Dict[str, Any]] = None,
        enable_discovery: bool = True,
        discover_js_endpoints: bool = True,
        discover_parameters: bool = True,
        oob_testing: bool = False,
        oob_callback_domain: Optional[str] = None,
        oob_callback_port: Optional[int] = None,
        oob_callback_protocol: Optional[str] = None,
        oob_wait_seconds: int = 20,
        oob_max_targets: int = 30,
        validation_pass: bool = False,
        validation_max_findings: int = 25,
        include_directory_enum: bool = True,
        directory_enum_engine: str = "gobuster",
        directory_enum_wordlist: Optional[str] = None,
        directory_enum_extensions: Optional[List[str]] = None,
        directory_enum_threads: int = 25,
        include_sqlmap: bool = True,
        sqlmap_level: int = 2,
        sqlmap_risk: int = 2,
        sqlmap_method: str = "GET",
        sqlmap_data: Optional[str] = None,
        sqlmap_threads: int = 1,
        include_wapiti: bool = True,
        wapiti_level: int = 2,
        ai_led: bool = False,
        user_context: Optional[str] = None,
        db: Optional[Session] = None,
        user_id: Optional[int] = None,
        project_id: Optional[int] = None,
        scan_name: Optional[str] = None,
    ) -> DynamicScanResult:
        """
        Start a new dynamic security scan.
        
        Args:
            target: IP, CIDR range, hostname, or URL to scan
            scan_type: Nmap scan type (ping, basic, service, comprehensive) - ignored if ai_led=True
            ports: Optional port specification - ignored if ai_led=True
            include_web_scan: Run ZAP on web services - may be overridden if ai_led=True
            include_cve_scan: Run Nuclei on network services - may be overridden if ai_led=True
            include_exploit_mapping: Look up exploits in database
            include_openvas: Run OpenVAS network vulnerability scan - may be overridden if ai_led=True
            aggressive_scan: Use aggressive/maximum scan intensity by default
            zap_auth: Optional ZAP authentication configuration for authenticated scans
            zap_auth_profiles: Optional list of auth profiles for role-based scanning
            zap_forced_browse: Enable forced browsing for hidden paths
            zap_wordlist: Optional wordlist key or filename for forced browsing
            openvas_credentials: OpenVAS credential IDs for authenticated scanning
            openapi_spec_url: OpenAPI spec URL for API seeding
            openapi_spec_content: OpenAPI spec content for API seeding
            openapi_base_url: Optional override base URL for OpenAPI spec
            graphql_endpoint_url: GraphQL endpoint URL for schema import
            graphql_schema_url: GraphQL schema URL if separate from endpoint
            browser_crawl: Optional browser crawl config for HAR seeding
            enable_discovery: Enable endpoint/parameter discovery enhancements
            discover_js_endpoints: Extract endpoints from JavaScript during discovery
            discover_parameters: Extract query/form parameters during discovery
            oob_testing: Enable out-of-band (OOB) testing for blind vulnerabilities
            oob_callback_domain: Callback domain for OOB payloads
            oob_callback_port: Callback port for OOB payloads
            oob_callback_protocol: Callback protocol for OOB payloads
            oob_wait_seconds: Seconds to wait for OOB callbacks
            oob_max_targets: Max parameters/endpoints to test with OOB payloads
            validation_pass: Enable validation pass for high/critical findings
            validation_max_findings: Max findings to validate
            ai_led: If True, AI decides scan strategy automatically
            user_context: Optional context for AI (e.g., "production server", "web app pentest")
            db: Database session for persistence
            user_id: User running the scan
            project_id: Project to associate with scan
            scan_name: Optional user-provided name for easy identification
        
        Returns:
            DynamicScanResult with initial state
        """
        scan_id = self._generate_scan_id()
        now = datetime.utcnow().isoformat()
        slot_acquired = False
        self._acquire_scan_slot()
        slot_acquired = True
        try:
            # Initialize scan result
            result = DynamicScanResult(
                scan_id=scan_id,
                target=target,
                status=ScanStatus.PENDING,
                progress=ScanProgress(
                    phase=ScanPhase.INITIALIZING,
                    phase_progress=0,
                    overall_progress=0,
                    message="Initializing scan..." if not ai_led else "AI analyzing target...",
                    started_at=now,
                ),
                started_at=now,
            )
            result.openapi_spec_url = openapi_spec_url
            result.openapi_base_url = openapi_base_url
            result.graphql_endpoint_url = graphql_endpoint_url
            result.browser_crawl_config = browser_crawl
            self.active_scans[scan_id] = result
            
            # Store in database if session provided
            if db:
                db_scan = DynamicScan(
                    scan_id=scan_id,
                    target=target,
                    scan_type=scan_type,
                    status=ScanStatus.PENDING.value,
                    user_id=user_id,
                    project_id=project_id,
                    scan_name=scan_name,
                    config=json.dumps({
                        "scan_type": scan_type,
                        "ports": ports,
                        "include_web_scan": include_web_scan,
                        "include_cve_scan": include_cve_scan,
                        "include_exploit_mapping": include_exploit_mapping,
                        "include_openvas": include_openvas,
                        "aggressive_scan": aggressive_scan,
                        "zap_auth": self._sanitize_zap_auth(zap_auth),
                        "zap_auth_profiles": [self._sanitize_zap_auth(p) for p in (zap_auth_profiles or [])],
                        "zap_forced_browse": zap_forced_browse,
                        "zap_wordlist": zap_wordlist,
                        "openvas_credentials": self._sanitize_openvas_credentials(openvas_credentials),
                        "openapi_spec_url": openapi_spec_url,
                        "openapi_spec_provided": bool(openapi_spec_url or openapi_spec_content),
                        "openapi_base_url": openapi_base_url,
                        "graphql_endpoint_url": graphql_endpoint_url,
                        "graphql_schema_url": graphql_schema_url,
                        "browser_crawl": self._sanitize_browser_crawl(browser_crawl),
                        "enable_discovery": enable_discovery,
                        "discover_js_endpoints": discover_js_endpoints,
                        "discover_parameters": discover_parameters,
                        "oob_testing": oob_testing,
                        "oob_callback_domain": oob_callback_domain,
                        "oob_callback_port": oob_callback_port,
                        "oob_callback_protocol": oob_callback_protocol,
                        "oob_wait_seconds": oob_wait_seconds,
                        "oob_max_targets": oob_max_targets,
                        "validation_pass": validation_pass,
                        "validation_max_findings": validation_max_findings,
                        "include_directory_enum": include_directory_enum,
                        "directory_enum_engine": directory_enum_engine,
                        "directory_enum_wordlist": directory_enum_wordlist,
                        "directory_enum_extensions": directory_enum_extensions,
                        "directory_enum_threads": directory_enum_threads,
                        "include_sqlmap": include_sqlmap,
                        "sqlmap_level": sqlmap_level,
                        "sqlmap_risk": sqlmap_risk,
                        "sqlmap_method": sqlmap_method,
                        "sqlmap_data": sqlmap_data,
                        "sqlmap_threads": sqlmap_threads,
                        "include_wapiti": include_wapiti,
                        "wapiti_level": wapiti_level,
                        "ai_led": ai_led,
                        "user_context": user_context,
                    }),
                )
                db.add(db_scan)
                db.commit()
            
            task = asyncio.create_task(
                self._run_scan(
                    scan_id=scan_id,
                    target=target,
                    scan_type=scan_type,
                    ports=ports,
                    include_web_scan=include_web_scan,
                    include_cve_scan=include_cve_scan,
                    include_exploit_mapping=include_exploit_mapping,
                    include_openvas=include_openvas,
                    aggressive_scan=aggressive_scan,
                    zap_auth=zap_auth,
                    zap_auth_profiles=zap_auth_profiles,
                    zap_forced_browse=zap_forced_browse,
                    zap_wordlist=zap_wordlist,
                    openvas_credentials=openvas_credentials,
                    openapi_spec_url=openapi_spec_url,
                    openapi_spec_content=openapi_spec_content,
                    openapi_base_url=openapi_base_url,
                    graphql_endpoint_url=graphql_endpoint_url,
                    graphql_schema_url=graphql_schema_url,
                    browser_crawl=browser_crawl,
                    enable_discovery=enable_discovery,
                    discover_js_endpoints=discover_js_endpoints,
                    discover_parameters=discover_parameters,
                    oob_testing=oob_testing,
                    oob_callback_domain=oob_callback_domain,
                    oob_callback_port=oob_callback_port,
                    oob_callback_protocol=oob_callback_protocol,
                    oob_wait_seconds=oob_wait_seconds,
                    oob_max_targets=oob_max_targets,
                    validation_pass=validation_pass,
                    validation_max_findings=validation_max_findings,
                    include_directory_enum=include_directory_enum,
                    directory_enum_engine=directory_enum_engine,
                    directory_enum_wordlist=directory_enum_wordlist,
                    directory_enum_extensions=directory_enum_extensions,
                    directory_enum_threads=directory_enum_threads,
                    include_sqlmap=include_sqlmap,
                    sqlmap_level=sqlmap_level,
                    sqlmap_risk=sqlmap_risk,
                    sqlmap_method=sqlmap_method,
                    sqlmap_data=sqlmap_data,
                    sqlmap_threads=sqlmap_threads,
                    include_wapiti=include_wapiti,
                    wapiti_level=wapiti_level,
                    ai_led=ai_led,
                    user_context=user_context,
                    db=db,
                )
            )
            self.scan_tasks[scan_id] = task
            task.add_done_callback(lambda t, sid=scan_id: self._task_completed(sid, t))
            slot_acquired = False
            return result
        except Exception:
            if slot_acquired:
                self.scan_semaphore.release()
            self.active_scans.pop(scan_id, None)
            raise
    
    def _is_url_target(self, target: str) -> bool:
        """Check if the target is a direct URL (web app scan mode)."""
        return target.startswith('http://') or target.startswith('https://')
    
    def _parse_url_target(self, url: str) -> tuple:
        """Parse a URL target into host, port, and full URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or 'localhost'
        
        # Determine port
        if parsed.port:
            port = parsed.port
        elif parsed.scheme == 'https':
            port = 443
        else:
            port = 80
        
        return host, port, url

    async def _resolve_host_ips(self, host: str) -> list[str]:
        """Resolve a hostname into IP addresses for OpenVAS targets."""
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None)
            ips = sorted({info[4][0] for info in infos if info and info[4]})
            return ips
        except Exception as e:
            logger.warning(f"[resolve_host_ips] Failed to resolve {host}: {e}")
            return []
    
    async def _run_scan(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        ports: Optional[str],
        include_web_scan: bool,
        include_cve_scan: bool,
        include_exploit_mapping: bool,
        include_openvas: bool = True,
        aggressive_scan: bool = True,
        zap_auth: Optional[Dict[str, Any]] = None,
        zap_auth_profiles: Optional[List[Dict[str, Any]]] = None,
        zap_forced_browse: bool = False,
        zap_wordlist: Optional[str] = None,
        openvas_credentials: Optional[Dict[str, Any]] = None,
        openapi_spec_url: Optional[str] = None,
        openapi_spec_content: Optional[str] = None,
        openapi_base_url: Optional[str] = None,
        graphql_endpoint_url: Optional[str] = None,
        graphql_schema_url: Optional[str] = None,
        browser_crawl: Optional[Dict[str, Any]] = None,
        enable_discovery: bool = True,
        discover_js_endpoints: bool = True,
        discover_parameters: bool = True,
        oob_testing: bool = False,
        oob_callback_domain: Optional[str] = None,
        oob_callback_port: Optional[int] = None,
        oob_callback_protocol: Optional[str] = None,
        oob_wait_seconds: int = 20,
        oob_max_targets: int = 30,
        validation_pass: bool = False,
        validation_max_findings: int = 25,
        include_directory_enum: bool = True,
        directory_enum_engine: str = "gobuster",
        directory_enum_wordlist: Optional[str] = None,
        directory_enum_extensions: Optional[List[str]] = None,
        directory_enum_threads: int = 25,
        include_sqlmap: bool = True,
        sqlmap_level: int = 2,
        sqlmap_risk: int = 2,
        sqlmap_method: str = "GET",
        sqlmap_data: Optional[str] = None,
        sqlmap_threads: int = 1,
        include_wapiti: bool = True,
        wapiti_level: int = 2,
        ai_led: bool = False,
        user_context: Optional[str] = None,
        db: Optional[Session] = None,
    ):
        """
        Execute the full agentic scan workflow.
        
        Supports three modes:
        1. AI-led mode - AI decides everything based on target analysis
        2. IP/CIDR/Hostname mode - Full reconnaissance + multi-scanner workflow
        3. URL mode - Direct web app scanning with ZAP (no Nmap recon needed)
        
        The workflow is:
        1. AI Planning (if ai_led) - Analyze target and decide strategy
        2. Nmap reconnaissance - discover hosts and services (skipped for URL mode)
        3. AI routing - classify services for appropriate scanners
        4. Optional follow-up Nmap scans (if ai_led and AI recommends)
        5. OpenVAS scan - comprehensive network vulnerability scanning
        6. ZAP scan - web application vulnerability scanning
        7. Nuclei scan - CVE-specific checks
        8. Exploit mapping - search for available exploits
        9. AI analysis - generate attack narrative
        """
        try:
            scan = self.active_scans[scan_id]
            scan.status = ScanStatus.RUNNING

            if ai_led:
                await self._run_agentic_scan(
                    scan_id=scan_id,
                    target=target,
                    include_web_scan=include_web_scan,
                    include_cve_scan=include_cve_scan,
                    include_exploit_mapping=include_exploit_mapping,
                    include_openvas=include_openvas,
                    include_directory_enum=include_directory_enum,
                    include_sqlmap=include_sqlmap,
                    include_wapiti=include_wapiti,
                    aggressive_scan=aggressive_scan,
                    zap_auth=zap_auth,
                    zap_auth_profiles=zap_auth_profiles,
                    openvas_credentials=openvas_credentials,
                    openapi_spec_url=openapi_spec_url,
                    openapi_spec_content=openapi_spec_content,
                    openapi_base_url=openapi_base_url,
                    graphql_endpoint_url=graphql_endpoint_url,
                    graphql_schema_url=graphql_schema_url,
                    browser_crawl=browser_crawl,
                    user_context=user_context,
                    db=db,
                )

                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow().isoformat()
                if scan.started_at:
                    start = datetime.fromisoformat(scan.started_at)
                    end = datetime.fromisoformat(scan.completed_at)
                    scan.duration_seconds = int((end - start).total_seconds())

                await self._update_progress(
                    scan_id, ScanPhase.COMPLETED, 100,
                    f"Agentic scan complete: {len(scan.findings)} findings discovered",
                    findings_count=len(scan.findings)
                )

                if db:
                    await self._save_results_to_db(scan_id, db)
                return
            
            # ========================================
            # AI-LED MODE: Let AI decide scan strategy
            # ========================================
            # Initialize AI config variables with defaults
            scan_profile = self.build_scan_profile(aggressive_scan)
            default_zap_policy = scan_profile["zap_policy"]
            default_openvas_config = scan_profile["openvas_config"]
            default_openvas_port_list = scan_profile["openvas_port_list"]
            default_openvas_qod_threshold = scan_profile["openvas_qod_threshold"]
            default_openvas_max_hosts = scan_profile["openvas_max_hosts"]
            default_nmap_timing = scan_profile["nmap_timing"]
            default_run_nmap_udp = scan_profile["run_nmap_udp"]
            ai_nse_scripts = []
            ai_nmap_timing = default_nmap_timing
            ai_nmap_advanced = {}  # Advanced Nmap options (firewall evasion, rate limits, etc.)
            ai_run_nmap_udp = default_run_nmap_udp
            ai_openvas_config = default_openvas_config
            ai_openvas_port_list = default_openvas_port_list
            ai_openvas_nvt_families = []  # AI can select specific NVT families
            ai_openvas_qod_threshold = default_openvas_qod_threshold  # Quality of Detection threshold
            ai_openvas_alive_test = "icmp_tcp_ack_ping"  # Alive test method
            ai_openvas_max_hosts = default_openvas_max_hosts  # Max hosts to scan simultaneously
            ai_openvas_authenticated_scan = False  # Enable authenticated scanning
            ai_openvas_credential_type = None  # Credential type for authenticated scans
            ai_openvas_schedule = "immediate"  # Scan scheduling (immediate, daily, weekly, monthly)
            ai_openvas_alert = None  # Alert type for scan completion notification
            ai_zap_policy = default_zap_policy
            ai_zap_spider_mode = "deep"
            ai_zap_attack_vectors = []  # Empty = all scanners enabled
            ai_zap_advanced_features = list(scan_profile["zap_advanced_features"])
            ai_zap_forced_browse = bool(zap_forced_browse or scan_profile["forced_browse_wordlist"])
            ai_zap_wordlist = zap_wordlist or scan_profile["forced_browse_wordlist"]
            ai_nuclei_templates = list(scan_profile["nuclei_templates"])
            ai_run_directory_enum = False
            ai_directory_wordlist = scan_profile["directory_wordlist"]
            ai_authenticated_scan_recommendation = None  # AI recommendation for authenticated scanning
            ai_enable_discovery = enable_discovery
            ai_discover_js_endpoints = discover_js_endpoints
            ai_discover_parameters = discover_parameters
            ai_oob_testing = oob_testing or scan_profile["oob_testing"]
            ai_oob_config = {
                "callback_domain": oob_callback_domain,
                "callback_port": oob_callback_port,
                "callback_protocol": oob_callback_protocol,
                "wait_seconds": oob_wait_seconds,
                "max_targets": oob_max_targets,
            }
            ai_validation_pass = validation_pass or scan_profile["validation_pass"]
            ai_validation_max_findings = validation_max_findings
            
            if ai_led:
                await self._update_progress(
                    scan_id, ScanPhase.INITIALIZING, 10,
                    "🤖 AI analyzing target to determine optimal scan strategy..."
                )
                
                from backend.services.dynamic_scan_agent import DynamicScanAgent
                agent = DynamicScanAgent()
                
                try:
                    # AI plans the scan strategy
                    strategy = await agent.plan_scan_strategy(target, user_context, aggressive_scan=aggressive_scan)
                    
                    # Extract AI decisions
                    scan_plan = strategy.get("scan_plan", {})
                    ai_reasoning = strategy.get("ai_reasoning", "")
                    
                    # Core scan parameters
                    scan_type = scan_plan.get("nmap_scan_type", scan_type)
                    ports = scan_plan.get("nmap_ports", ports)
                    run_nmap = scan_plan.get("run_nmap", True)
                    include_openvas = scan_plan.get("run_openvas", include_openvas)
                    include_web_scan = scan_plan.get("run_zap", include_web_scan)
                    include_cve_scan = scan_plan.get("run_nuclei", include_cve_scan)
                    include_exploit_mapping = scan_plan.get("run_exploit_mapping", include_exploit_mapping)
                    
                    # Extract advanced AI-selected configurations
                    ai_nse_scripts = scan_plan.get("nmap_nse_scripts", [])
                    ai_nmap_timing = scan_plan.get("nmap_timing", default_nmap_timing)
                    ai_nmap_advanced = scan_plan.get("nmap_advanced", {})
                    ai_run_nmap_udp = scan_plan.get("run_nmap_udp", default_run_nmap_udp)
                    ai_openvas_config = scan_plan.get("openvas_config", default_openvas_config)
                    ai_openvas_port_list = scan_plan.get("openvas_port_list", default_openvas_port_list)
                    ai_openvas_nvt_families = scan_plan.get("openvas_nvt_families", [])
                    ai_openvas_qod_threshold = scan_plan.get("openvas_qod_threshold", default_openvas_qod_threshold)
                    ai_openvas_alive_test = scan_plan.get("openvas_alive_test", "icmp_tcp_ack_ping")
                    ai_openvas_max_hosts = scan_plan.get("openvas_max_hosts", default_openvas_max_hosts)
                    ai_openvas_authenticated_scan = scan_plan.get("openvas_authenticated_scan", False)
                    ai_openvas_credential_type = scan_plan.get("openvas_credential_type")
                    ai_openvas_schedule = scan_plan.get("openvas_schedule", "immediate")
                    ai_openvas_alert = scan_plan.get("openvas_alert")
                    ai_zap_policy = scan_plan.get("zap_scan_policy", default_zap_policy)
                    ai_zap_spider_mode = scan_plan.get("zap_spider_mode", "deep")
                    ai_zap_attack_vectors = scan_plan.get("zap_attack_vectors", [])
                    ai_zap_advanced_features = scan_plan.get("zap_advanced_features", [])
                    ai_zap_forced_browse = scan_plan.get("zap_forced_browse", ai_zap_forced_browse)
                    ai_zap_wordlist = scan_plan.get("zap_wordlist", ai_zap_wordlist)
                    ai_nuclei_templates = scan_plan.get("nuclei_templates", ai_nuclei_templates)
                    ai_run_directory_enum = scan_plan.get("run_directory_enum", False)
                    ai_directory_wordlist = scan_plan.get("directory_wordlist")
                    ai_enable_discovery = scan_plan.get("enable_discovery", ai_enable_discovery)
                    ai_discover_js_endpoints = scan_plan.get("discover_js_endpoints", ai_discover_js_endpoints)
                    ai_discover_parameters = scan_plan.get("discover_parameters", ai_discover_parameters)
                    ai_oob_testing = scan_plan.get("oob_testing", ai_oob_testing)
                    ai_oob_config = scan_plan.get("oob_config", ai_oob_config)
                    ai_validation_pass = scan_plan.get("validation_pass", ai_validation_pass)
                    ai_validation_max_findings = scan_plan.get("validation_max_findings", ai_validation_max_findings)
                    ai_authenticated_scan_recommendation = strategy.get("authenticated_scan_recommendation")

                    if aggressive_scan:
                        ai_zap_policy = "maximum"
                        ai_openvas_config = "full_and_very_deep"
                        ai_openvas_port_list = "all_tcp_udp"
                        ai_openvas_qod_threshold = "low"
                        ai_openvas_max_hosts = "aggressive"
                        ai_nmap_timing = "T4"
                        ai_run_nmap_udp = True
                        for feature in ["ajax_spider", "openapi_import", "graphql_import", "forced_browsing"]:
                            if feature not in ai_zap_advanced_features:
                                ai_zap_advanced_features.append(feature)
                        ai_zap_forced_browse = True
                        if not ai_zap_wordlist:
                            ai_zap_wordlist = "aggressive"
                        if not ai_directory_wordlist:
                            ai_directory_wordlist = "aggressive"
                        ai_enable_discovery = True
                        ai_discover_js_endpoints = True
                        ai_discover_parameters = True
                        ai_oob_testing = True
                        ai_validation_pass = True
                    else:
                        if ai_zap_policy == "maximum":
                            ai_zap_policy = "thorough"
                        if ai_openvas_config == "full_and_very_deep":
                            ai_openvas_config = "full_and_deep"
                        if ai_openvas_port_list == "all_tcp_udp":
                            ai_openvas_port_list = "top_tcp_1000"
                        if ai_openvas_qod_threshold == "low":
                            ai_openvas_qod_threshold = "standard"
                        if ai_openvas_max_hosts == "aggressive":
                            ai_openvas_max_hosts = "standard"
                        if ai_nmap_timing in ("T4", "T5"):
                            ai_nmap_timing = "T3"
                        if ai_run_nmap_udp:
                            ai_run_nmap_udp = False

                    if zap_auth and "authenticated_scanning" not in ai_zap_advanced_features:
                        ai_zap_advanced_features.append("authenticated_scanning")
                    if (ai_zap_forced_browse or ai_run_directory_enum) and "forced_browsing" not in ai_zap_advanced_features:
                        ai_zap_advanced_features.append("forced_browsing")
                    
                    # Build detailed strategy message
                    tools_selected = []
                    if run_nmap:
                        tools_selected.append(f"Nmap ({scan_type})")
                        if ai_nse_scripts:
                            tools_selected.append(f"NSE Scripts: {', '.join(ai_nse_scripts)}")
                    if include_openvas:
                        tools_selected.append(f"OpenVAS ({ai_openvas_config})")
                    if include_web_scan:
                        tools_selected.append(f"ZAP ({ai_zap_policy})")
                    if include_cve_scan:
                        tools_selected.append(f"Nuclei ({', '.join(ai_nuclei_templates[:2])}...)")
                    
                    await self._update_progress(
                        scan_id, ScanPhase.INITIALIZING, 30,
                        f"🧠 AI Strategy: {ai_reasoning[:150]}..."
                    )
                    
                    # Store comprehensive AI strategy in scan result
                    zap_attacks_str = ', '.join(ai_zap_attack_vectors) if ai_zap_attack_vectors else 'all'
                    zap_features_str = ', '.join(ai_zap_advanced_features) if ai_zap_advanced_features else 'none'
                    forced_browse_wordlist = ai_zap_wordlist or ai_directory_wordlist
                    forced_browse_status = forced_browse_wordlist if (ai_zap_forced_browse or ai_run_directory_enum or "forced_browsing" in ai_zap_advanced_features) else 'disabled'
                    zap_auth_label = "disabled"
                    if zap_auth:
                        zap_auth_label = (zap_auth or {}).get("method") or "configured"
                    openvas_nvt_str = ', '.join(ai_openvas_nvt_families) if ai_openvas_nvt_families else 'all'
                    
                    # Build authenticated scanning recommendation text
                    auth_scan_text = ""
                    if ai_authenticated_scan_recommendation:
                        rec = ai_authenticated_scan_recommendation
                        if rec.get("recommended", False):
                            auth_scan_text = f"""
**🔐 Authenticated Scanning Recommendation:**
- Recommended credential types: {', '.join(rec.get('credential_types_needed', []))}
- Reason: {rec.get('reason', 'N/A')}
- Expected benefit: {rec.get('expected_benefit', 'N/A')}
- Current status: {'ENABLED' if ai_openvas_authenticated_scan else 'Not configured (provide credentials for deeper analysis)'}
"""
                    
                    # Build scheduling text
                    schedule_text = f"  - Schedule: {ai_openvas_schedule}" if ai_openvas_schedule != "immediate" else ""
                    alert_text = f"  - Alert: {ai_openvas_alert}" if ai_openvas_alert else ""
                    
                    scan.attack_narrative = f"""**🤖 AI Scan Strategy:**
{ai_reasoning}

**Tools Selected:** {', '.join(tools_selected)}

**Scan Configuration:**
- Intensity: {"aggressive (maximum)" if aggressive_scan else "thorough"}
- Nmap: {scan_type} scan{f' with NSE scripts: {", ".join(ai_nse_scripts)}' if ai_nse_scripts else ''}
- OpenVAS: {ai_openvas_config if include_openvas else 'disabled'}
  - Port list: {ai_openvas_port_list}
  - NVT families: {openvas_nvt_str}
  - QoD threshold: {ai_openvas_qod_threshold}
  - Alive test: {ai_openvas_alive_test}
  - Authenticated: {'Yes (' + str(ai_openvas_credential_type) + ')' if ai_openvas_authenticated_scan else 'No'}
{schedule_text}{alert_text}
- ZAP: {ai_zap_policy} policy with {ai_zap_spider_mode} spider{' (disabled)' if not include_web_scan else ''}
  - Attack vectors: {zap_attacks_str}
  - Advanced features: {zap_features_str}
  - Authenticated: {zap_auth_label}
  - Forced browse wordlist: {forced_browse_status}
- Nuclei templates: {', '.join(ai_nuclei_templates) if include_cve_scan else 'disabled'}
- Directory enumeration: {ai_directory_wordlist if ai_run_directory_enum else 'disabled'}
- Discovery: {'enabled' if ai_enable_discovery else 'disabled'} (JS: {'on' if ai_discover_js_endpoints else 'off'}, Params: {'on' if ai_discover_parameters else 'off'})
- OOB testing: {'enabled' if ai_oob_testing else 'disabled'}
- Validation pass: {'enabled' if ai_validation_pass else 'disabled'}
{auth_scan_text}
---

"""
                    
                except Exception as e:
                    logger.warning(f"AI planning failed, using defaults: {e}")
                    scan.progress.errors.append(f"AI planning failed: {str(e)[:500]}")
                    await self._update_progress(
                        scan_id, ScanPhase.INITIALIZING, 30,
                        f"⚠️ AI planning failed, using intelligent defaults..."
                    )
                    # Continue with default parameters
                    run_nmap = not self._is_url_target(target)
                
                # If AI says skip Nmap, check if it's effectively URL mode
                if not run_nmap:
                    is_url_mode = True
                else:
                    is_url_mode = self._is_url_target(target)
            else:
                # Standard mode - check if it's a URL
                is_url_mode = self._is_url_target(target)
            if is_url_mode:
                include_openvas = False
                include_cve_scan = False

            auth_profiles: List[Dict[str, Any]] = []
            if zap_auth_profiles:
                auth_profiles = list(zap_auth_profiles)
            elif zap_auth:
                auth_profiles = [zap_auth]

            if auth_profiles and "authenticated_scanning" not in ai_zap_advanced_features:
                ai_zap_advanced_features.append("authenticated_scanning")
            if (ai_zap_forced_browse or ai_run_directory_enum) and "forced_browsing" not in ai_zap_advanced_features:
                ai_zap_advanced_features.append("forced_browsing")
            
            # Check if this is a direct URL scan (web app mode)
            
            if is_url_mode:
                # URL Mode: Direct web app scanning
                await self._update_progress(scan_id, ScanPhase.RECONNAISSANCE, 0, "Direct URL mode - parsing target...")
                
                host, port, url = self._parse_url_target(target)
                
                # Create a synthetic host for the web app
                hosts = [
                    DiscoveredHost(
                        ip=host,
                        hostname=host,
                        state="up",
                        ports=[{
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "https" if port == 443 else "http",
                            "product": "Web Application",
                            "version": "",
                        }]
                    )
                ]
                
                # Create direct web target
                web_targets = [
                    ServiceTarget(
                        ip=host,
                        port=port,
                        url=url,
                        service="https" if port == 443 else "http",
                        product="Web Application",
                        version="",
                    )
                ]
                
                resolved_ips = await self._resolve_host_ips(host)
                network_targets = [
                    ServiceTarget(
                        ip=ip,
                        port=port,
                        service="https" if port == 443 else "http",
                        product="Web Application",
                        version="",
                        nuclei_tags=["cve", "web"],
                    )
                    for ip in (resolved_ips or [host])
                ]

                scan.hosts = hosts
                scan.web_targets = web_targets
                scan.network_targets = network_targets
                scan.progress.hosts_discovered = 1
                scan.progress.web_targets = 1
                scan.progress.network_targets = len(network_targets)
                
                await self._update_progress(
                    scan_id, ScanPhase.RECONNAISSANCE, 100,
                    f"Direct web app scan: {url}"
                )
                
                # Continue with the remaining scanners (OpenVAS will hit the resolved host if enabled)
                # Allow Nuclei on URL targets if enabled (HTTP templates can still apply)
                
            else:
                # IP/Hostname Mode: Full reconnaissance workflow
                # Phase 1: Reconnaissance (Nmap)
                await self._update_progress(scan_id, ScanPhase.RECONNAISSANCE, 0, "Starting Nmap reconnaissance...")
                hosts = await self._run_nmap_recon(
                    scan_id, 
                    target, 
                    scan_type, 
                    ports,
                    nse_scripts=ai_nse_scripts if ai_nse_scripts else None,
                    timing_template=ai_nmap_timing,
                    run_udp=ai_run_nmap_udp,
                    advanced_options=ai_nmap_advanced if ai_nmap_advanced else None,
                )
                scan.hosts = hosts
                scan.progress.hosts_discovered = len(hosts)
                
                if not hosts:
                    await self._update_progress(scan_id, ScanPhase.COMPLETED, 100, "No hosts discovered")
                    scan.status = ScanStatus.COMPLETED
                    return
                
                # AI-Driven Follow-up Scan Decision
                # The AI analyzes initial results and decides if targeted follow-up scans are needed
                from backend.services.dynamic_scan_agent import DynamicScanAgent
                agent = DynamicScanAgent()
                
                followup_decision = await agent.decide_followup_nmap(
                    initial_results=[asdict(h) for h in hosts],
                    initial_scan_type=scan_type,
                    target=target,
                )
                
                if followup_decision.get("run_additional_scan"):
                    followup_type = followup_decision.get("scan_type", "service")
                    followup_ports = followup_decision.get("ports")
                    followup_nse = followup_decision.get("nse_scripts", [])
                    followup_reason = followup_decision.get("reasoning", "")
                    
                    logger.info(f"[{scan_id}] AI Follow-up Decision: {followup_type} scan - {followup_reason}")
                    await self._update_progress(
                        scan_id, ScanPhase.RECONNAISSANCE, 75,
                        f"AI recommends follow-up scan: {followup_reason[:500]}..."
                    )
                    
                    # Run the follow-up Nmap scan
                    followup_hosts = await self._run_nmap_recon(
                        scan_id,
                        target,
                        followup_type,
                        followup_ports,
                        nse_scripts=followup_nse if followup_nse else None,
                        timing_template=ai_nmap_timing,
                        run_udp=followup_type in ["udp", "udp_quick"],
                        advanced_options=None,
                    )
                    
                    # Merge follow-up results with initial results
                    # Update existing hosts with new port/service info
                    host_map = {h.ip: h for h in hosts}
                    for fh in followup_hosts:
                        if fh.ip in host_map:
                            # Merge ports - add new ones, update existing with more detail
                            existing_ports = {p["port"]: p for p in host_map[fh.ip].ports}
                            for fp in fh.ports:
                                port_num = fp["port"]
                                if port_num in existing_ports:
                                    # Update with more detailed info if available
                                    if fp.get("product") and not existing_ports[port_num].get("product"):
                                        existing_ports[port_num]["product"] = fp["product"]
                                    if fp.get("version") and not existing_ports[port_num].get("version"):
                                        existing_ports[port_num]["version"] = fp["version"]
                                    if fp.get("scripts") and not existing_ports[port_num].get("scripts"):
                                        existing_ports[port_num]["scripts"] = fp["scripts"]
                                else:
                                    host_map[fh.ip].ports.append(fp)
                        else:
                            hosts.append(fh)
                    
                    scan.hosts = hosts
                    scan.progress.hosts_discovered = len(hosts)
                    logger.info(f"[{scan_id}] Follow-up scan merged. Total hosts: {len(hosts)}")
                else:
                    logger.info(f"[{scan_id}] AI decided no follow-up needed: {followup_decision.get('reasoning', 'Initial scan sufficient')}")
                
                # Phase 2: AI Routing - Intelligent service classification (only for IP/hostname mode)
                await self._update_progress(scan_id, ScanPhase.ROUTING, 0, "AI analyzing discovered services...")
                
                # Reuse the agent from follow-up decision phase
                routing_result = await agent.analyze_recon_results(
                    hosts=[asdict(h) for h in hosts],
                    target=target,
                )
                
                # Extract classified targets
                web_targets = [
                    ServiceTarget(
                        ip=t["ip"],
                        port=p["port"],
                        url=p["url"],
                        service=p.get("service", "http"),
                        product=p.get("product", ""),
                        version=p.get("version", ""),
                    )
                    for t in routing_result["web_targets"]
                    for p in t["ports"]
                ]
                
                network_targets = [
                    ServiceTarget(
                        ip=t["ip"],
                        port=s["port"],
                        service=s["service"],
                        product=s.get("product", ""),
                        version=s.get("version", ""),
                    )
                    for t in routing_result["openvas_targets"]
                    for s in t["services"]
                ]
                
                scan.web_targets = web_targets
                scan.network_targets = network_targets
                scan.progress.web_targets = len(web_targets)
                scan.progress.network_targets = len(network_targets)
                
                # Log AI recommendations
                for rec in routing_result.get("recommendations", []):
                    logger.info(f"[{scan_id}] AI Recommendation: {rec}")
                
                await self._update_progress(
                    scan_id, ScanPhase.ROUTING, 100,
                    f"Classified {len(web_targets)} web targets, {len(network_targets)} network targets"
                )
            
            # Get web_targets and network_targets from scan object (set in either mode)
            web_targets = scan.web_targets
            network_targets = scan.network_targets
            
            if not ai_led:
                scan.manual_guidance = self.build_manual_guidance(
                    aggressive_scan=aggressive_scan,
                    include_openvas=include_openvas,
                    include_web_scan=include_web_scan,
                    include_cve_scan=include_cve_scan,
                    include_directory_enum=include_directory_enum,
                    include_sqlmap=include_sqlmap,
                    include_wapiti=include_wapiti,
                    profile=scan_profile,
                )

            if include_directory_enum and web_targets:
                await self._update_progress(
                    scan_id, ScanPhase.DIRECTORY_ENUMERATION, 0,
                    "Running Gobuster/Dirbuster directory enumeration..."
                )
                try:
                    dir_findings, dir_urls = await self._run_directory_scan(
                        scan_id=scan_id,
                        targets=web_targets,
                        engine=directory_enum_engine,
                        wordlist=directory_enum_wordlist,
                        extensions=directory_enum_extensions,
                        threads=directory_enum_threads,
                    )
                    if dir_findings:
                        scan.findings.extend(dir_findings)
                    if dir_urls:
                        new_urls = [u for u in dir_urls if u not in scan.discovered_urls]
                        if new_urls:
                            scan.discovered_urls = list(dict.fromkeys(scan.discovered_urls + new_urls))
                            await self._seed_zap_urls(new_urls[:250])
                    await self._update_progress(
                        scan_id, ScanPhase.DIRECTORY_ENUMERATION, 100,
                        f"Directory enumeration finished ({len(dir_findings)} findings)"
                    )
                except Exception as e:
                    logger.warning(f"Directory enumeration failed: {e}")
                    scan.progress.errors.append(f"Directory enumeration: {str(e)[:500]}")
                    await self._update_progress(
                        scan_id, ScanPhase.DIRECTORY_ENUMERATION, 100,
                        "Directory enumeration skipped due to error"
                    )
            else:
                await self._update_progress(
                    scan_id, ScanPhase.DIRECTORY_ENUMERATION, 100,
                    "Directory enumeration disabled or no web targets"
                )

            # Phase 3: OpenVAS Network Vulnerability Scanning (skip in URL mode)
            if include_openvas and network_targets:
                await self._update_progress(
                    scan_id, ScanPhase.OPENVAS_SCANNING, 0,
                    f"Running OpenVAS ({ai_openvas_config}) on {len(network_targets)} network targets..."
                )
                # Convert network_targets to format expected by OpenVAS
                openvas_target_data = [
                    {"ip": t.ip, "services": [{"port": t.port, "service": t.service}]}
                    for t in network_targets
                ]
                try:
                    openvas_findings = await self._run_openvas_scan(
                        scan_id, 
                        openvas_target_data,
                        scan_config=ai_openvas_config,
                        port_list=ai_openvas_port_list,
                        nvt_families=ai_openvas_nvt_families,
                        qod_threshold=ai_openvas_qod_threshold,
                        alive_test=ai_openvas_alive_test,
                        max_hosts=ai_openvas_max_hosts,
                        authenticated_scan=ai_openvas_authenticated_scan,
                        credential_type=ai_openvas_credential_type,
                        schedule=ai_openvas_schedule,
                        alert=ai_openvas_alert,
                        ssh_credential_id=(openvas_credentials or {}).get("ssh_credential_id"),
                        ssh_credential_port=(openvas_credentials or {}).get("ssh_credential_port", 22),
                        smb_credential_id=(openvas_credentials or {}).get("smb_credential_id"),
                        snmp_credential_id=(openvas_credentials or {}).get("snmp_credential_id"),
                        esxi_credential_id=(openvas_credentials or {}).get("esxi_credential_id"),
                    )
                    scan.findings.extend(openvas_findings)
                except Exception as e:
                    logger.error(f"OpenVAS scan failed: {e}")
                    scan.progress.errors.append(f"OpenVAS scan failed: {str(e)[:500]}")
                    await self._update_progress(
                        scan_id, ScanPhase.OPENVAS_SCANNING, 100,
                        f"⚠️ OpenVAS failed, continuing with other scanners..."
                    )
            elif not is_url_mode:
                await self._update_progress(scan_id, ScanPhase.OPENVAS_SCANNING, 100, "No network targets for OpenVAS")
            
            # Phase 4: Web Scanning (ZAP)
            if include_web_scan and web_targets:
                await self._update_progress(
                    scan_id, ScanPhase.WEB_SCANNING, 0,
                    f"Running ZAP ({ai_zap_policy} policy) on {len(web_targets)} web targets..."
                )
                try:
                    web_findings = await self._run_zap_with_profiles(
                        scan_id=scan_id,
                        targets=web_targets,
                        scan_policy=ai_zap_policy,
                        spider_mode=ai_zap_spider_mode,
                        attack_vectors=ai_zap_attack_vectors,
                        advanced_features=ai_zap_advanced_features,
                        zap_auth=zap_auth,
                        zap_auth_profiles=zap_auth_profiles,
                        forced_browse=ai_zap_forced_browse or ai_run_directory_enum or ("forced_browsing" in ai_zap_advanced_features),
                        forced_browse_wordlist=ai_zap_wordlist or ai_directory_wordlist,
                        browser_crawl=browser_crawl,
                        openapi_spec_url=openapi_spec_url,
                        openapi_spec_content=openapi_spec_content,
                        openapi_base_url=openapi_base_url,
                        graphql_endpoint_url=graphql_endpoint_url,
                        graphql_schema_url=graphql_schema_url,
                    )
                    scan.findings.extend(web_findings)
                except Exception as e:
                    logger.error(f"ZAP scan failed: {e}")
                    scan.progress.errors.append(f"ZAP scan failed: {str(e)[:500]}")
                    await self._update_progress(
                        scan_id, ScanPhase.WEB_SCANNING, 100,
                        f"⚠️ ZAP failed, continuing with other scanners..."
                    )
            else:
                await self._update_progress(scan_id, ScanPhase.WEB_SCANNING, 100, "No web targets to scan")

            discovery_summary = {
                "urls": scan.discovered_urls or [],
                "params": scan.discovered_params or [],
                "coverage": scan.coverage_summary or {},
            }
            if web_targets and include_web_scan:
                try:
                    collected = await self._collect_discovery_summary(
                        scan_id,
                        web_targets,
                        include_js=discover_js_endpoints,
                        include_params=discover_parameters,
                        extra_urls=scan.discovered_urls,
                    )
                    merged_urls = list(dict.fromkeys((scan.discovered_urls or []) + collected.get("urls", [])))
                    scan.discovered_urls = merged_urls
                    params_seen = set()
                    unique_params: List[Dict[str, Any]] = []
                    for param_entry in collected.get("params", []):
                        key = (param_entry.get("endpoint"), param_entry.get("name"))
                        if key not in params_seen:
                            params_seen.add(key)
                            unique_params.append(param_entry)
                    scan.discovered_params = unique_params
                    scan.coverage_summary = collected.get("coverage", {})
                    discovery_summary = collected
                except Exception as e:
                    logger.warning(f"[{scan_id}] Discovery summary failed: {e}")
                    scan.progress.errors.append(f"Discovery summary: {str(e)[:500]}")

            if ai_oob_testing:
                if scan.discovered_params:
                    await self._update_progress(
                        scan_id, ScanPhase.WEB_SCANNING, 95,
                        "Running OOB payload checks for blind vulnerabilities..."
                    )
                    try:
                        http_auth = self._extract_basic_auth(zap_auth_profiles or zap_auth)
                        oob_result = await self._run_oob_testing(
                            scan_id=scan_id,
                            discovered_params=scan.discovered_params,
                            max_targets=ai_oob_config.get("max_targets", 30),
                            callback_domain=ai_oob_config.get("callback_domain") or "localhost",
                            callback_port=ai_oob_config.get("callback_port") or 8080,
                            callback_protocol=ai_oob_config.get("callback_protocol") or "http",
                            wait_seconds=ai_oob_config.get("wait_seconds", 20),
                            http_auth=http_auth,
                        )
                        scan.findings.extend(oob_result.get("findings", []))
                        scan.oob_summary = oob_result.get("summary", {})
                    except Exception as e:
                        logger.warning(f"[{scan_id}] OOB testing failed: {e}")
                        scan.progress.errors.append(f"OOB testing: {str(e)[:500]}")
                else:
                    scan.oob_summary = {"targets_tested": 0, "callbacks_received": 0, "details": []}

            if include_wapiti and web_targets:
                await self._update_progress(
                    scan_id, ScanPhase.WAPITI_SCANNING, 0,
                    "Running Wapiti web scans..."
                )
                try:
                    wapiti_findings = await self._run_wapiti_scan(scan_id, web_targets, level=wapiti_level)
                    if wapiti_findings:
                        scan.findings.extend(wapiti_findings)
                    await self._update_progress(
                        scan_id, ScanPhase.WAPITI_SCANNING, 100,
                        f"Wapiti complete ({len(wapiti_findings)} findings)"
                    )
                except Exception as e:
                    logger.warning(f"Wapiti scan failed: {e}")
                    scan.progress.errors.append(f"Wapiti: {str(e)[:500]}")
                    await self._update_progress(
                        scan_id, ScanPhase.WAPITI_SCANNING, 100,
                        "Wapiti scan skipped due to error"
                    )

            if include_sqlmap:
                sqlmap_targets = list(dict.fromkeys(
                    (scan.discovered_urls or []) +
                    [p.get("endpoint") for p in (scan.discovered_params or []) if p.get("endpoint")]
                ))
                if not sqlmap_targets:
                    sqlmap_targets = [t.url for t in web_targets if t.url]
                if sqlmap_targets:
                    await self._update_progress(
                        scan_id, ScanPhase.SQLMAP_SCANNING, 0,
                        "Running SQLMap against discovered inputs..."
                    )
                    try:
                        sqlmap_findings = await self._run_sqlmap_scan(
                            scan_id,
                            sqlmap_targets,
                            level=sqlmap_level,
                            risk=sqlmap_risk,
                            method=sqlmap_method,
                            data=sqlmap_data,
                            threads=sqlmap_threads,
                        )
                        if sqlmap_findings:
                            scan.findings.extend(sqlmap_findings)
                        await self._update_progress(
                            scan_id, ScanPhase.SQLMAP_SCANNING, 100,
                            f"SQLMap complete ({len(sqlmap_findings)} findings)"
                        )
                    except Exception as e:
                        logger.warning(f"SQLMap failed: {e}")
                        scan.progress.errors.append(f"SQLMap: {str(e)[:500]}")
                        await self._update_progress(
                            scan_id, ScanPhase.SQLMAP_SCANNING, 100,
                            "SQLMap skipped due to error"
                        )
                else:
                    await self._update_progress(
                        scan_id, ScanPhase.SQLMAP_SCANNING, 100,
                        "SQLMap skipped (no endpoints discovered)"
                    )

            # Phase 5: Nuclei CVE Scanning (network + optional web targets)
            cve_targets = network_targets if network_targets else web_targets
            if include_cve_scan and cve_targets:
                target_label = "network targets" if network_targets else "web targets"
                await self._update_progress(
                    scan_id, ScanPhase.CVE_SCANNING, 50,
                    f"Running Nuclei ({', '.join(ai_nuclei_templates[:2])}) on {target_label}..."
                )
                try:
                    cve_findings = await self._run_nuclei_scan(
                        scan_id,
                        cve_targets,
                        templates=ai_nuclei_templates,
                    )
                    scan.findings.extend(cve_findings)
                except Exception as e:
                    logger.error(f"Nuclei scan failed: {e}")
                    scan.progress.errors.append(f"Nuclei scan failed: {str(e)[:500]}")
                    await self._update_progress(
                        scan_id, ScanPhase.CVE_SCANNING, 100,
                        f"⚠️ Nuclei failed, continuing..."
                    )
            else:
                await self._update_progress(scan_id, ScanPhase.CVE_SCANNING, 100, "No CVE targets for Nuclei")
            
            # Optional: Validation pass for high/critical findings
            validation_ran = False
            http_auth = self._extract_basic_auth(zap_auth_profiles or zap_auth)
            if ai_validation_pass and scan.findings:
                await self._update_progress(
                    scan_id, ScanPhase.EXPLOIT_MAPPING, 5,
                    "Validating high/critical findings..."
                )
                try:
                    http_auth = self._extract_basic_auth(zap_auth_profiles or zap_auth)
                    scan.validation_summary = await self._run_validation_pass(
                        scan_id=scan_id,
                        findings=scan.findings,
                        max_findings=ai_validation_max_findings,
                        http_auth=http_auth,
                    )
                    validation_ran = True
                except Exception as e:
                    logger.warning(f"[{scan_id}] Validation pass failed: {e}")
                    scan.progress.errors.append(f"Validation pass: {str(e)[:500]}")

            # Phase 6: Exploit Mapping
            if include_exploit_mapping and scan.findings:
                await self._update_progress(
                    scan_id,
                    ScanPhase.EXPLOIT_MAPPING,
                    10 if validation_ran else 0,
                    "Looking up available exploits..."
                )
                try:
                    await self._map_exploits(scan_id)
                except Exception as e:
                    logger.error(f"Exploit mapping failed: {e}")
                    scan.progress.errors.append(f"Exploit mapping failed: {str(e)[:500]}")
            else:
                await self._update_progress(scan_id, ScanPhase.EXPLOIT_MAPPING, 100, "No findings to map exploits")

            await self._cross_validate_high_findings(scan_id, http_auth=http_auth)
            
            # Phase 7: AI Analysis
            await self._update_progress(scan_id, ScanPhase.AI_ANALYSIS, 0, "AI generating attack narrative...")
            try:
                await self._run_ai_analysis(scan_id)
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
                scan.progress.errors.append(f"AI analysis failed: {str(e)[:500]}")
            
            # Complete
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow().isoformat()
            if scan.started_at:
                start = datetime.fromisoformat(scan.started_at)
                end = datetime.fromisoformat(scan.completed_at)
                scan.duration_seconds = int((end - start).total_seconds())
            
            await self._update_progress(
                scan_id, ScanPhase.COMPLETED, 100,
                f"Scan complete: {len(scan.findings)} findings discovered",
                findings_count=len(scan.findings)
            )
            
            # Save to database
            if db:
                await self._save_results_to_db(scan_id, db)
            
        except asyncio.CancelledError:
            logger.info(f"Scan {scan_id} cancelled")
            if scan_id in self.active_scans:
                self.active_scans[scan_id].status = ScanStatus.CANCELLED
                self.active_scans[scan_id].progress.phase = ScanPhase.CANCELLED
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            if scan_id in self.active_scans:
                self.active_scans[scan_id].status = ScanStatus.FAILED
                self.active_scans[scan_id].progress.phase = ScanPhase.FAILED
                self.active_scans[scan_id].progress.errors.append(str(e))
    
    async def _run_openvas_scan(
        self,
        scan_id: str,
        openvas_targets: List[Dict[str, Any]],
        scan_config: str = "full_and_fast",
        port_list: str = "top_tcp_1000",
        nvt_families: Optional[List[str]] = None,
        qod_threshold: str = "standard",
        alive_test: str = "icmp_tcp_ack_ping",
        max_hosts: str = "standard",
        authenticated_scan: bool = False,
        credential_type: Optional[str] = None,
        schedule: str = "immediate",
        alert: Optional[str] = None,
    ) -> List[ScanFinding]:
        """
        Run OpenVAS vulnerability scan on network targets.
        
        OpenVAS provides comprehensive vulnerability detection with
        its extensive NVT database (50,000+ vulnerability tests).
        
        Args:
            scan_id: Unique scan identifier
            openvas_targets: List of targets with IP and services
            scan_config: OpenVAS scan configuration (full_and_fast, full_and_deep, etc.)
            port_list: Port list to use (top_tcp_1000, all_tcp, etc.)
            nvt_families: Specific NVT families to enable (e.g., ["web_servers", "databases"])
            qod_threshold: Quality of Detection threshold (low=30, standard=70, high=90, maximum=98)
            alive_test: Host alive detection method
            max_hosts: Max simultaneous hosts (conservative=5, standard=20, aggressive=50)
            authenticated_scan: Whether to use authenticated scanning
            credential_type: Type of credential to use for authenticated scanning
            schedule: Scan schedule (immediate, daily, weekly, monthly)
            alert: Alert type for scan completion (email, syslog, webhook)
        """
        findings = []
        
        # Map QoD threshold names to values
        qod_values = {
            "low": 30,
            "standard": 70,
            "high": 90,
            "maximum": 98,
        }
        min_qod = qod_values.get(qod_threshold, 70)
        
        # Map max_hosts names to values
        max_hosts_values = {
            "conservative": 5,
            "standard": 20,
            "aggressive": 50,
        }
        max_hosts_num = max_hosts_values.get(max_hosts, 20)
        
        # Track created resources for cleanup
        credential_id = None
        schedule_id = None
        alert_id = None
        
        try:
            from backend.services.openvas_service import get_openvas_service
            openvas = get_openvas_service()
            
            # Check if OpenVAS is available
            status = await openvas.check_connection()
            if not status.get("connected"):
                logger.warning(f"OpenVAS not available: {status.get('message')}")
                await self._update_progress(
                    scan_id, ScanPhase.OPENVAS_SCANNING, 10,
                    "⚠️ OpenVAS unavailable, falling back to Nuclei only"
                )
                return findings
            
            # Build target list (IPs only for OpenVAS)
            target_ips = list(set(t["ip"] for t in openvas_targets))
            target_str = ",".join(target_ips)
            
            # Log AI-selected configuration
            nvt_families_str = ', '.join(nvt_families) if nvt_families else 'all'
            auth_str = f", authenticated={credential_type}" if authenticated_scan else ""
            schedule_str = f", schedule={schedule}" if schedule != "immediate" else ""
            alert_str = f", alert={alert}" if alert else ""
            logger.info(f"OpenVAS scan config: {scan_config}, port_list: {port_list}, "
                       f"nvt_families: {nvt_families_str}, qod: {qod_threshold}({min_qod})"
                       f"{auth_str}{schedule_str}{alert_str}")
            
            # Create schedule if requested
            if schedule != "immediate":
                await self._update_progress(
                    scan_id, ScanPhase.OPENVAS_SCANNING, 2,
                    f"Creating {schedule} schedule for recurring scans..."
                )
                try:
                    # Map schedule types to period
                    schedule_periods = {
                        "daily": (1, "day"),
                        "weekly": (7, "day"),
                        "monthly": (1, "month"),
                    }
                    period_val, period_unit = schedule_periods.get(schedule, (1, "day"))
                    schedule_id = await openvas.create_schedule(
                        name=f"VRAgent_{scan_id}_{schedule}",
                        period=period_val,
                        period_unit=period_unit,
                        comment=f"AI-scheduled {schedule} scan for {target_str}",
                    )
                    logger.info(f"Created OpenVAS schedule: {schedule_id}")
                except Exception as e:
                    logger.warning(f"Failed to create schedule, continuing without: {e}")
                    schedule_id = None
            
            # Create alert if requested
            if alert:
                await self._update_progress(
                    scan_id, ScanPhase.OPENVAS_SCANNING, 3,
                    f"Configuring {alert} alert for scan completion..."
                )
                try:
                    alert_method_data = {}
                    if alert == "email":
                        # Email requires to_address - use placeholder
                        alert_method_data = {"to_address": "scan-alerts@vragent.local"}
                    elif alert == "syslog":
                        alert_method_data = {"submethod": "CEF"}
                    
                    alert_id = await openvas.create_alert(
                        name=f"VRAgent_{scan_id}_alert",
                        condition="always",
                        event="task_run_status_changed",
                        method=alert,
                        method_data=alert_method_data,
                        event_data={"status": "Done"},
                        comment=f"AI-configured {alert} alert for scan {scan_id}",
                    )
                    logger.info(f"Created OpenVAS alert: {alert_id}")
                except Exception as e:
                    logger.warning(f"Failed to create alert, continuing without: {e}")
                    alert_id = None
            
            # Note: Authenticated scanning requires credentials to be configured
            # This is typically done through the UI or API before running scans
            # The AI recommends authenticated scanning, but credentials must be provided by user
            if authenticated_scan and credential_type:
                await self._update_progress(
                    scan_id, ScanPhase.OPENVAS_SCANNING, 4,
                    f"⚠️ Authenticated scanning requested ({credential_type}) - credentials must be pre-configured"
                )
                logger.info(f"Authenticated scan requested with {credential_type} - "
                           "credentials must be pre-configured in OpenVAS")
            
            await self._update_progress(
                scan_id, ScanPhase.OPENVAS_SCANNING, 5,
                f"Starting OpenVAS ({scan_config}, QoD>{min_qod}) on {len(target_ips)} hosts..."
            )
            
            # Create custom config if AI selected specific NVT families
            custom_config_id = None
            if nvt_families and len(nvt_families) > 0:
                await self._update_progress(
                    scan_id, ScanPhase.OPENVAS_SCANNING, 6,
                    f"Creating custom scan config with {len(nvt_families)} NVT families..."
                )
                try:
                    # Map our family names to OpenVAS family names
                    family_mapping = {
                        "general": "General",
                        "web_servers": "Web Servers",
                        "databases": "Databases",
                        "windows": "Windows",
                        "linux": "Linux",
                        "credentials": "Credentials",
                        "denial_of_service": "Denial of Service",
                        "brute_force": "Brute force attacks",
                        "malware": "Malware",
                        "port_scanners": "Port scanners",
                        "service_detection": "Service detection",
                        "firewalls": "Firewalls",
                        "smtp": "SMTP problems",
                        "snmp": "SNMP",
                        "ftp": "FTP",
                        "ssl_tls": "SSL and TLS",
                        "scada": "SCADA",
                        "compliance": "Compliance",
                    }
                    openvas_families = [family_mapping.get(f, f) for f in nvt_families]
                    
                    custom_config_id = await openvas.create_custom_config_for_families(
                        name=f"VRAgent_Custom_{scan_id}",
                        families=openvas_families,
                        base_config=scan_config,
                    )
                    logger.info(f"Created custom OpenVAS config {custom_config_id} with families: {openvas_families}")
                except Exception as e:
                    logger.warning(f"Failed to create custom config, using default: {e}")
                    custom_config_id = None
            
            # Map alive test names
            alive_test_mapping = {
                "scan_config_default": None,  # Use config default
                "icmp_ping": "ICMP Ping",
                "tcp_ack_service_ping": "TCP-ACK Service Ping",
                "tcp_syn_service_ping": "TCP-SYN Service Ping",
                "arp_ping": "ARP Ping",
                "icmp_tcp_ack_ping": "ICMP & TCP-ACK Service Ping",
                "icmp_and_arp_ping": "ICMP & ARP Ping",
                "tcp_ack_service_and_arp_ping": "TCP-ACK Service & ARP Ping",
                "icmp_tcp_ack_and_arp_ping": "ICMP, TCP-ACK Service & ARP Ping",
                "consider_alive": "Consider Alive",
            }
            mapped_alive_test = alive_test_mapping.get(alive_test) if alive_test else None
            
            # Start OpenVAS scan with AI-selected config and all advanced options
            scan_result = await openvas.run_scan(
                target=target_str,
                scan_name=f"VRAgent_{scan_id}",
                scan_type=scan_config,
                port_list=port_list,
                scan_config_id=custom_config_id,
                wait_for_completion=True,
                poll_interval=30,
                timeout=7200,  # 2 hours max for deep scans
                alive_test=mapped_alive_test,
                max_hosts=max_hosts_num,
                max_checks=4,  # Default checks per host
                schedule_id=schedule_id,
                alert_ids=[alert_id] if alert_id else None,
            )
            
            # Convert OpenVAS findings to our format (filter by QoD threshold)
            for vuln in scan_result.vulnerabilities:
                # Skip findings below QoD threshold
                if vuln.qod < min_qod:
                    continue
                    
                severity = vuln.severity_level.value
                
                finding = ScanFinding(
                    source="openvas",
                    severity=severity,
                    title=vuln.name,
                    description=vuln.description,
                    host=vuln.host,
                    port=int(vuln.port) if vuln.port and vuln.port.isdigit() else None,
                    cve_id=vuln.cve_ids[0] if vuln.cve_ids else None,
                    cvss_score=vuln.cvss_score,
                    remediation=vuln.solution,
                    references=vuln.references + vuln.xref,
                    raw_data={
                        "nvt_oid": vuln.nvt_oid,
                        "cvss_vector": vuln.cvss_vector,
                        "qod": vuln.qod,
                        "impact": vuln.impact,
                        "insight": vuln.insight,
                        "affected": vuln.affected,
                        "all_cves": vuln.cve_ids,
                    },
                )
                findings.append(finding)
            
            await self._update_progress(
                scan_id, ScanPhase.CVE_SCANNING, 40,
                f"OpenVAS found {len(findings)} vulnerabilities"
            )
            
            # Cleanup OpenVAS resources
            try:
                await openvas.delete_task(scan_result.task_id)
                await openvas.delete_target(scan_result.target_id)
                # Cleanup custom config if created
                if custom_config_id:
                    try:
                        await openvas.delete_config(custom_config_id)
                    except Exception as e:
                        logger.warning(f"Failed to cleanup OpenVAS custom config: {e}")
                # Cleanup schedule and alert if created
                if schedule_id:
                    try:
                        await openvas.delete_schedule(schedule_id)
                    except Exception as e:
                        logger.warning(f"Failed to cleanup OpenVAS schedule: {e}")
                if alert_id:
                    try:
                        await openvas.delete_alert(alert_id)
                    except Exception as e:
                        logger.warning(f"Failed to cleanup OpenVAS alert: {e}")
            except Exception as e:
                logger.warning(f"Failed to cleanup OpenVAS resources: {e}")
            
            return findings
            
        except Exception as e:
            logger.error(f"OpenVAS scan failed: {e}")
            self.active_scans[scan_id].progress.errors.append(f"OpenVAS: {e}")
            return findings
    
    async def _run_nmap_recon(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        ports: Optional[str],
        nse_scripts: Optional[List[str]] = None,
        timing_template: str = "T3",
        run_udp: bool = False,
        advanced_options: Optional[Dict[str, Any]] = None,
    ) -> List[DiscoveredHost]:
        """Run Nmap reconnaissance via scanner sidecar.
        
        Args:
            scan_id: Unique scan identifier
            target: IP, CIDR range, or hostname
            scan_type: Nmap scan type (ping, basic, service, comprehensive, etc.)
            ports: Optional port specification
            nse_scripts: NSE script categories to run (e.g., ['vuln', 'smb', 'http'])
            timing_template: Nmap timing template (T0-T5), default T3
            run_udp: Also run UDP scan
            advanced_options: Dict with advanced Nmap options (version_intensity, max_retries, etc.)
        """
        try:
            # Build extra args from AI-selected options
            extra_args = []
            
            # Add NSE scripts if specified
            if nse_scripts:
                # Map script category names to actual nmap script syntax
                script_mapping = {
                    "vuln": "vuln",
                    "auth": "auth",
                    "brute": "brute",
                    "discovery": "discovery",
                    "exploit": "exploit",
                    "smb": "smb-*",
                    "http": "http-*",
                    "ssl": "ssl-*",
                    "dns": "dns-*",
                    "ftp": "ftp-*",
                    "ssh": "ssh-*",
                    "database": "mysql-*,pgsql-*,oracle-*,ms-sql-*,mongodb-*,redis-*",
                    "safe": "safe",
                    "default": "default",
                }
                scripts_to_run = []
                for script_cat in nse_scripts:
                    if script_cat in script_mapping:
                        scripts_to_run.append(script_mapping[script_cat])
                    else:
                        # Allow direct script names
                        scripts_to_run.append(script_cat)
                if scripts_to_run:
                    extra_args.extend(["--script", ",".join(scripts_to_run)])
            
            # Add timing template (override default)
            if timing_template and timing_template in ["T0", "T1", "T2", "T3", "T4", "T5"]:
                extra_args.append(f"-{timing_template}")
            
            # Apply advanced options if provided
            if advanced_options:
                # Version detection intensity
                if advanced_options.get("version_intensity"):
                    extra_args.extend(["--version-intensity", str(advanced_options["version_intensity"])])
                
                # Max retries
                if advanced_options.get("max_retries"):
                    extra_args.extend(["--max-retries", str(advanced_options["max_retries"])])
                
                # Host timeout
                if advanced_options.get("host_timeout"):
                    extra_args.extend(["--host-timeout", str(advanced_options["host_timeout"])])
                
                # Scan delay
                if advanced_options.get("scan_delay"):
                    extra_args.extend(["--scan-delay", str(advanced_options["scan_delay"])])
                
                # Min rate
                if advanced_options.get("min_rate"):
                    extra_args.extend(["--min-rate", str(advanced_options["min_rate"])])
                
                # Max rate
                if advanced_options.get("max_rate"):
                    extra_args.extend(["--max-rate", str(advanced_options["max_rate"])])
                
                # Fragmentation for firewall evasion
                if advanced_options.get("fragmentation"):
                    frag_opt = advanced_options["fragmentation"]
                    if frag_opt == "-f":
                        extra_args.append("-f")
                    elif frag_opt == "-ff":
                        extra_args.append("-ff")
                    elif frag_opt.startswith("--mtu"):
                        extra_args.extend(frag_opt.split())
                
                # Source port spoofing
                if advanced_options.get("source_port"):
                    extra_args.extend(["--source-port", str(advanced_options["source_port"])])
                
                # Decoy scanning
                if advanced_options.get("decoy"):
                    extra_args.extend(["-D", str(advanced_options["decoy"])])
                
                # Boolean flags
                if advanced_options.get("reason"):
                    extra_args.append("--reason")
                if advanced_options.get("traceroute"):
                    extra_args.append("--traceroute")
                if advanced_options.get("osscan_guess"):
                    extra_args.append("--osscan-guess")
            
            # Start main TCP scan
            response = await self.http_client.post(
                f"{self.scanner_url}/scan/nmap",
                json={
                    "target": target,
                    "scan_type": scan_type,
                    "ports": ports,
                    "extra_args": extra_args if extra_args else None,
                    "timeout": 900,
                },
                timeout=30.0,
            )
            
            if response.status_code != 200:
                raise Exception(f"Scanner returned {response.status_code}: {response.text}")
            
                nmap_scan = response.json()
                nmap_scan_id = nmap_scan["scan_id"]
                self._register_tool_scan(scan_id, "nmap", nmap_scan_id)
            
            # Poll for completion
            await self._update_progress(scan_id, ScanPhase.RECONNAISSANCE, 10, "Nmap scan in progress...")
            
            while True:
                await asyncio.sleep(3)
                
                status_response = await self.http_client.get(
                    f"{self.scanner_url}/scan/{nmap_scan_id}",
                    timeout=10.0,
                )
                status = status_response.json()
                
                if status["status"] == "completed":
                    await self._update_progress(scan_id, ScanPhase.RECONNAISSANCE, 90, "Parsing Nmap results...")
                    break
                elif status["status"] == "failed":
                    raise Exception(f"Nmap scan failed: {status.get('error', 'Unknown error')}")
                
                # Update progress message
                await self._update_progress(
                    scan_id, ScanPhase.RECONNAISSANCE, 50,
                    status.get("progress", "Scanning...")
                )
            
            # Parse results
            result = status.get("result", {})
            parsed = result.get("parsed", {})
            
            hosts = []
            for host_data in parsed.get("hosts", []):
                if host_data.get("state") != "up":
                    continue
                
                host = DiscoveredHost(
                    ip=host_data.get("ip", ""),
                    hostname=host_data.get("hostname", ""),
                    os=host_data.get("os", ""),
                    state=host_data.get("state", "up"),
                    ports=host_data.get("ports", []),
                )
                hosts.append(host)
            
            # If UDP scan is requested, run a separate UDP scan
            if run_udp:
                try:
                    await self._update_progress(scan_id, ScanPhase.RECONNAISSANCE, 92, "Running UDP scan...")
                    udp_response = await self.http_client.post(
                        f"{self.scanner_url}/scan/nmap",
                        json={
                            "target": target,
                            "scan_type": "udp",
                            "ports": None,  # Use default UDP ports
                            "timeout": 600,
                        },
                        timeout=30.0,
                    )
                    if udp_response.status_code == 200:
                        udp_scan = udp_response.json()
                        udp_scan_id = udp_scan["scan_id"]
                        self._register_tool_scan(scan_id, "nmap_udp", udp_scan_id)
                        
                        # Poll for UDP completion
                        while True:
                            await asyncio.sleep(3)
                            udp_status_response = await self.http_client.get(
                                f"{self.scanner_url}/scan/{udp_scan_id}",
                                timeout=10.0,
                            )
                            udp_status = udp_status_response.json()
                            if udp_status["status"] in ["completed", "failed"]:
                                break
                        
                        # Merge UDP results into hosts
                        if udp_status["status"] == "completed":
                            udp_result = udp_status.get("result", {})
                            udp_parsed = udp_result.get("parsed", {})
                            for udp_host_data in udp_parsed.get("hosts", []):
                                if udp_host_data.get("state") != "up":
                                    continue
                                udp_ip = udp_host_data.get("ip", "")
                                udp_ports = udp_host_data.get("ports", [])
                                # Find matching host and merge ports
                                for host in hosts:
                                    if host.ip == udp_ip:
                                        host.ports.extend(udp_ports)
                                        break
                                else:
                                    # New host from UDP
                                    hosts.append(DiscoveredHost(
                                        ip=udp_ip,
                                        hostname=udp_host_data.get("hostname", ""),
                                        os=udp_host_data.get("os", ""),
                                        state="up",
                                        ports=udp_ports,
                                    ))
                except Exception as udp_error:
                    logger.warning(f"UDP scan failed, continuing: {udp_error}")
            
            await self._update_progress(
                scan_id, ScanPhase.RECONNAISSANCE, 100,
                f"Discovered {len(hosts)} hosts"
            )
            
            return hosts
            
        except httpx.ConnectError:
            # Scanner not available - fall back to local nmap if available
            logger.warning("Scanner sidecar not available, attempting local nmap")
            return await self._run_local_nmap(scan_id, target, scan_type, ports)
        except Exception as e:
            logger.error(f"Nmap recon failed: {e}")
            self.active_scans[scan_id].progress.errors.append(f"Nmap: {e}")
            return []
    
    async def _run_local_nmap(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        ports: Optional[str],
    ) -> List[DiscoveredHost]:
        """Fallback: Run nmap locally (if available in container)."""
        import subprocess
        import tempfile
        from pathlib import Path
        
        try:
            # Import existing nmap service
            from backend.services.nmap_service import run_nmap_scan, parse_nmap_xml
            
            await self._update_progress(scan_id, ScanPhase.RECONNAISSANCE, 10, "Running local Nmap scan...")
            
            # Run scan
            output_file, command, error = run_nmap_scan(target, scan_type, ports)
            
            if error:
                raise Exception(error)
            
            if not output_file:
                raise Exception("Nmap produced no output")
            
            # Parse results
            result = parse_nmap_xml(output_file)
            
            hosts = []
            for host in result.hosts:
                hosts.append(DiscoveredHost(
                    ip=host.ip,
                    hostname=host.hostname,
                    os=host.os,
                    state=host.state,
                    ports=[
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "state": p.state,
                            "service": p.service,
                            "product": p.product,
                            "version": p.version,
                        }
                        for p in host.ports
                    ],
                ))
            
            return hosts
            
        except ImportError:
            logger.error("Local nmap service not available")
            return []
        except Exception as e:
            logger.error(f"Local nmap failed: {e}")
            return []
    
    async def _classify_services(
        self,
        scan_id: str,
        hosts: List[DiscoveredHost],
    ) -> tuple[List[ServiceTarget], List[ServiceTarget]]:
        """Classify discovered services into web and network targets."""
        try:
            # Try using scanner sidecar classification
            hosts_data = [
                {
                    "ip": h.ip,
                    "ports": h.ports,
                }
                for h in hosts
            ]
            
            response = await self.http_client.post(
                f"{self.scanner_url}/classify",
                json=hosts_data,
                timeout=10.0,
            )
            
            if response.status_code == 200:
                result = response.json()
                
                web_targets = [
                    ServiceTarget(
                        ip=t["ip"],
                        port=t["port"],
                        service=t.get("service", ""),
                        product=t.get("product", ""),
                        version=t.get("version", ""),
                        url=t.get("url"),
                    )
                    for t in result.get("web_targets", [])
                ]
                
                network_targets = [
                    ServiceTarget(
                        ip=t["ip"],
                        port=t["port"],
                        service=t.get("service", ""),
                        product=t.get("product", ""),
                        version=t.get("version", ""),
                        nuclei_tags=t.get("nuclei_tags", []),
                    )
                    for t in result.get("network_targets", [])
                ]
                
                return web_targets, network_targets
                
        except Exception as e:
            logger.warning(f"Scanner classification failed, using local: {e}")
        
        # Fall back to local classification
        return self._local_classify_services(hosts)
    
    def _local_classify_services(
        self,
        hosts: List[DiscoveredHost],
    ) -> tuple[List[ServiceTarget], List[ServiceTarget]]:
        """Local service classification without scanner sidecar."""
        WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443}
        NETWORK_PORTS = {22, 21, 23, 25, 139, 445, 3389, 3306, 5432, 1433, 27017, 6379}
        
        web_targets = []
        network_targets = []
        
        for host in hosts:
            for port_info in host.ports:
                if port_info.get("state") != "open":
                    continue
                
                port = port_info.get("port", 0)
                service = port_info.get("service", "").lower()
                
                target = ServiceTarget(
                    ip=host.ip,
                    port=port,
                    service=port_info.get("service", ""),
                    product=port_info.get("product", ""),
                    version=port_info.get("version", ""),
                )
                
                # Classify
                if port in WEB_PORTS or "http" in service:
                    scheme = "https" if port in [443, 8443] or "ssl" in service else "http"
                    target.url = f"{scheme}://{host.ip}:{port}"
                    web_targets.append(target)
                elif port in NETWORK_PORTS:
                    # Add nuclei tags based on service
                    if port == 22 or "ssh" in service:
                        target.nuclei_tags = ["ssh", "cve", "network"]
                    elif port in [139, 445]:
                        target.nuclei_tags = ["smb", "cve", "eternalblue", "ms17-010"]
                    elif port == 3389:
                        target.nuclei_tags = ["rdp", "cve", "bluekeep"]
                    else:
                        target.nuclei_tags = ["cve", "network"]
                    network_targets.append(target)
        
        return web_targets, network_targets

    async def _run_zap_with_profiles(
        self,
        scan_id: str,
        targets: List[ServiceTarget],
        scan_policy: str,
        spider_mode: str,
        attack_vectors: List[str],
        advanced_features: List[str],
        zap_auth: Optional[Dict[str, Any]],
        zap_auth_profiles: Optional[List[Dict[str, Any]]],
        forced_browse: bool,
        forced_browse_wordlist: Optional[str],
        browser_crawl: Optional[Dict[str, Any]] = None,
        openapi_spec_url: Optional[str] = None,
        openapi_spec_content: Optional[str] = None,
        openapi_base_url: Optional[str] = None,
        graphql_endpoint_url: Optional[str] = None,
        graphql_schema_url: Optional[str] = None,
    ) -> List[ScanFinding]:
        """Run ZAP scan once per auth profile (or unauthenticated if none)."""
        profiles: List[Optional[Dict[str, Any]]] = []
        if zap_auth_profiles:
            profiles = [p for p in zap_auth_profiles if isinstance(p, dict)]
        elif zap_auth:
            profiles = [zap_auth]
        if not profiles:
            profiles = [None]
        findings: List[ScanFinding] = []
        for profile in profiles:
            results = await self._run_zap_scan(
                scan_id=scan_id,
                targets=targets,
                scan_policy=scan_policy,
                spider_mode=spider_mode,
                attack_vectors=attack_vectors,
                advanced_features=advanced_features,
                zap_auth=profile,
                forced_browse=forced_browse,
                forced_browse_wordlist=forced_browse_wordlist,
                browser_crawl=browser_crawl,
                openapi_spec_url=openapi_spec_url,
                openapi_spec_content=openapi_spec_content,
                openapi_base_url=openapi_base_url,
                graphql_endpoint_url=graphql_endpoint_url,
                graphql_schema_url=graphql_schema_url,
            )
            if results:
                findings.extend(results)
        return findings
    
    async def _run_zap_scan(
        self,
        scan_id: str,
        targets: List[ServiceTarget],
        scan_policy: str = "standard",
        spider_mode: str = "standard",
        attack_vectors: List[str] = None,
        advanced_features: List[str] = None,
        zap_auth: Optional[Dict[str, Any]] = None,
        forced_browse: bool = False,
        forced_browse_wordlist: Optional[str] = None,
        browser_crawl: Optional[Dict[str, Any]] = None,
        openapi_spec_url: Optional[str] = None,
        openapi_spec_content: Optional[str] = None,
        openapi_base_url: Optional[str] = None,
        graphql_endpoint_url: Optional[str] = None,
        graphql_schema_url: Optional[str] = None,
    ) -> List[ScanFinding]:
        """
        Run ZAP scans on web targets with AI-selected attack vectors and features.
        
        Args:
            scan_id: Unique scan identifier
            targets: List of web targets to scan
            scan_policy: ZAP scan policy (light, standard, thorough, maximum, etc.)
            spider_mode: Spider configuration (quick, standard, deep, spa_focused)
            attack_vectors: AI-selected attack categories (injection, xss, ssrf, etc.)
            advanced_features: AI-requested features (ajax_spider, forced_browsing, etc.)
            zap_auth: Optional authentication configuration for authenticated scans
            forced_browse: Enable wordlist-based forced browsing
            forced_browse_wordlist: Optional wordlist key or filename for forced browsing
        """
        findings = []
        scan = self.active_scans.get(scan_id)
        attack_vectors = attack_vectors or []
        advanced_features = advanced_features or []
        if "all" in attack_vectors:
            attack_vectors = []
        auth_requested = bool(zap_auth and zap_auth.get("method"))
        forced_browse = bool(forced_browse)
        
        # Import configurations
        from backend.services.dynamic_scan_agent import (
            ZAP_SPIDER_OPTIONS, ZAP_SCAN_POLICIES, 
            ZAP_ATTACK_VECTORS, ZAP_ADVANCED_FEATURES
        )
        
        # Get spider config
        spider_config = ZAP_SPIDER_OPTIONS.get(spider_mode, ZAP_SPIDER_OPTIONS["standard"])
        policy_config = ZAP_SCAN_POLICIES.get(scan_policy, ZAP_SCAN_POLICIES["standard"])
        
        max_depth = spider_config.get("max_depth", 5)
        max_children = spider_config.get("max_children", 0)
        use_ajax_spider = spider_config.get("ajax_spider", False) or "ajax_spider" in advanced_features
        ajax_duration = spider_config.get("ajax_duration", 30)
        if scan_policy == "maximum":
            ajax_duration = max(ajax_duration, 120)
        elif scan_policy == "thorough":
            ajax_duration = max(ajax_duration, 60)
        
        # Determine which scanner IDs to enable based on attack vectors
        enabled_scanner_ids = set()
        if attack_vectors:
            for vector in attack_vectors:
                if vector in ZAP_ATTACK_VECTORS:
                    enabled_scanner_ids.update(ZAP_ATTACK_VECTORS[vector].get("scanner_ids", []))
            logger.info(f"[{scan_id}] AI selected attack vectors: {attack_vectors}, scanner IDs: {enabled_scanner_ids}")
        
        # Log advanced features requested
        if advanced_features:
            logger.info(f"[{scan_id}] AI requested advanced features: {advanced_features}")

        # Pre-crawl API discovery
        if browser_crawl and targets:
            crawl_result = await self._run_browser_crawl(scan_id, targets, browser_crawl)
            if scan:
                self._merge_discovery_entries(scan, crawl_result.get("urls", []), crawl_result.get("params", []))
                if crawl_result.get("har_path"):
                    await self._import_har_to_zap(scan_id, crawl_result["har_path"])

        if openapi_spec_url or openapi_spec_content:
            openapi_targets = await self._apply_openapi_discovery(
                scan_id, openapi_spec_url, openapi_spec_content, openapi_base_url
            )
            if scan:
                scan.openapi_spec_url = openapi_spec_url
                scan.openapi_base_url = openapi_base_url
                self._add_api_spec_discovery(scan, openapi_targets)

        graphql_params = []
        if graphql_endpoint_url:
            graphql_params = await self._import_graphql_schema(
                scan_id, graphql_endpoint_url, graphql_schema_url
            )
            if scan:
                scan.graphql_endpoint_url = graphql_endpoint_url
                self._merge_discovery_entries(scan, [graphql_endpoint_url], graphql_params)

        # Sanity check ZAP API availability early
        try:
            version_response = await self.http_client.get(
                f"{self.zap_url}/JSON/core/view/version/",
                params=self._zap_params(),
                timeout=10.0,
            )
            if version_response.status_code != 200:
                raise Exception(f"HTTP {version_response.status_code}: {version_response.text[:200]}")
        except Exception as e:
            error_msg = f"ZAP API unavailable: {e}"
            logger.error(error_msg)
            self.active_scans[scan_id].progress.errors.append(error_msg)
            await self._update_progress(
                scan_id, ScanPhase.WEB_SCANNING, 100,
                "ZAP unavailable - skipping web scan"
            )
            return findings

        scanners_customized = False
        session_name = f"vragent_{scan_id}"

        try:
            session_response = await self.http_client.get(
                f"{self.zap_url}/JSON/core/action/newSession/",
                params=self._zap_params({"name": session_name, "overwrite": "true"}),
                timeout=30.0,
            )
            if session_response.status_code != 200:
                raise Exception(f"newSession HTTP {session_response.status_code}")
        except Exception as e:
            logger.warning(f"[{scan_id}] Failed to create new ZAP session: {e}")

        try:
            backlog_response = await self.http_client.get(
                f"{self.zap_url}/JSON/pscan/view/recordsToScan/",
                params=self._zap_params(),
                timeout=10.0,
            )
            if backlog_response.status_code == 200:
                backlog = int(backlog_response.json().get("recordsToScan", 0))
                if backlog > 50000:
                    warning = f"ZAP passive queue is very large ({backlog}). Consider restarting ZAP."
                    logger.warning(f"[{scan_id}] {warning}")
                    self.active_scans[scan_id].progress.errors.append(warning)
        except Exception as e:
            logger.warning(f"[{scan_id}] Failed to read passive scan backlog: {e}")

        spider_max_children = max_children if max_children > 0 else 100
        try:
            await self.http_client.get(
                f"{self.zap_url}/JSON/spider/action/setOptionMaxDepth/",
                params=self._zap_params({"Integer": str(max_depth)}),
                timeout=10.0,
            )
            await self.http_client.get(
                f"{self.zap_url}/JSON/spider/action/setOptionMaxChildren/",
                params=self._zap_params({"Integer": str(spider_max_children)}),
                timeout=10.0,
            )
        except Exception as e:
            logger.warning(f"[{scan_id}] Failed to set spider options: {e}")
        
        # =====================================================================
        # IMPLEMENT ADVANCED FEATURES BEFORE SCANNING
        # =====================================================================
        
        # 1. OpenAPI/Swagger Import - Automatically discover API endpoints
        if "openapi_import" in advanced_features:
            for target in targets:
                try:
                    # Common OpenAPI/Swagger paths to try
                    swagger_paths = [
                        "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
                        "/v2/api-docs", "/v3/api-docs", "/api/swagger.json", "/api/openapi.json",
                        "/swagger/v1/swagger.json", "/api-docs"
                    ]
                    if not target.url:
                        continue
                    normalized_url = self._maybe_rewrite_localhost(target.url)
                    base_url, _ = self._normalize_zap_urls(normalized_url)
                    
                    for swagger_path in swagger_paths:
                        try:
                            spec_url = f"{base_url}{swagger_path}"
                            import_response = await self.http_client.get(
                                f"{self.zap_url}/JSON/openapi/action/importUrl/",
                                params=self._zap_params({"url": spec_url}),
                                timeout=30.0,
                            )
                            if import_response.status_code == 200:
                                result = import_response.json()
                                if result.get("Result") != "error":
                                    logger.info(f"[{scan_id}] Imported OpenAPI spec from {spec_url}")
                                    break
                        except Exception:
                            continue
                except Exception as e:
                    logger.warning(f"OpenAPI import failed for {target.url}: {e}")
        
        # 2. GraphQL Import - Introspect GraphQL schema for testing
        if "graphql_import" in advanced_features:
            for target in targets:
                try:
                    # Common GraphQL endpoints to try
                    graphql_paths = ["/graphql", "/api/graphql", "/gql", "/query"]
                    if not target.url:
                        continue
                    normalized_url = self._maybe_rewrite_localhost(target.url)
                    base_url, _ = self._normalize_zap_urls(normalized_url)
                    
                    for gql_path in graphql_paths:
                        try:
                            gql_url = f"{base_url}{gql_path}"
                            import_response = await self.http_client.get(
                                f"{self.zap_url}/JSON/graphql/action/importUrl/",
                                params=self._zap_params({"url": gql_url}),
                                timeout=30.0,
                            )
                            if import_response.status_code == 200:
                                result = import_response.json()
                                if result.get("Result") != "error":
                                    logger.info(f"[{scan_id}] Imported GraphQL schema from {gql_url}")
                                    break
                        except Exception:
                            continue
                except Exception as e:
                    logger.warning(f"GraphQL import failed for {target.url}: {e}")
        
        # 3. Enable/Disable Scanners based on AI-selected attack vectors
        if enabled_scanner_ids:
            try:
                # First disable all scanners
                disable_response = await self.http_client.get(
                    f"{self.zap_url}/JSON/ascan/action/disableAllScanners/",
                    params=self._zap_params(),
                    timeout=10.0,
                )
                if disable_response.status_code != 200:
                    raise Exception(f"disableAllScanners HTTP {disable_response.status_code}")
                # Then enable only selected ones
                scanner_ids_str = ",".join(str(sid) for sid in enabled_scanner_ids)
                enable_response = await self.http_client.get(
                    f"{self.zap_url}/JSON/ascan/action/enableScanners/",
                    params=self._zap_params({"ids": scanner_ids_str}),
                    timeout=10.0,
                )
                if enable_response.status_code != 200:
                    raise Exception(f"enableScanners HTTP {enable_response.status_code}")
                scanners_customized = True
                logger.info(f"[{scan_id}] Enabled {len(enabled_scanner_ids)} scanners based on attack vectors")
            except Exception as e:
                logger.warning(f"Failed to configure scanners: {e}")
                try:
                    await self.http_client.get(
                        f"{self.zap_url}/JSON/ascan/action/enableAllScanners/",
                        params=self._zap_params(),
                        timeout=10.0,
                    )
                except Exception:
                    pass
        
        # 4. WebSocket Testing - Capture and analyze WebSocket traffic
        if "websocket_testing" in advanced_features:
            try:
                # Enable WebSocket passive scanning
                await self.http_client.get(
                    f"{self.zap_url}/JSON/pscan/action/enableAllScanners/",
                    params=self._zap_params(),
                    timeout=10.0,
                )
                logger.info(f"[{scan_id}] WebSocket testing enabled - traffic will be captured during spider")
            except Exception as e:
                logger.warning(f"WebSocket testing setup failed: {e}")
        
        # 5. Authentication setup (optional)
        auth_config = None
        auth_context = None
        auth_scope_netloc = None
        if auth_requested:
            try:
                from backend.services.zap_service import ZAPAuthConfig, ZAPAuthMethod, ZAPScanner

                method_raw = str((zap_auth or {}).get("method", "")).strip()
                method_map = {
                    "form": ZAPAuthMethod.FORM_BASED,
                    "formbasedauthentication": ZAPAuthMethod.FORM_BASED,
                    "json": ZAPAuthMethod.JSON_BASED,
                    "jsonbasedauthentication": ZAPAuthMethod.JSON_BASED,
                    "basic": ZAPAuthMethod.HTTP_BASIC,
                    "httpauthentication": ZAPAuthMethod.HTTP_BASIC,
                    "script": ZAPAuthMethod.SCRIPT_BASED,
                    "scriptbasedauthentication": ZAPAuthMethod.SCRIPT_BASED,
                }
                auth_method = method_map.get(method_raw.lower())
                if not auth_method:
                    raise ValueError(f"Unsupported auth method: {method_raw}")

                login_url = (zap_auth or {}).get("login_url")
                username = (zap_auth or {}).get("username")
                password = (zap_auth or {}).get("password")

                if auth_method in (ZAPAuthMethod.FORM_BASED, ZAPAuthMethod.JSON_BASED) and not login_url:
                    raise ValueError("login_url is required for form/json authentication")
                if auth_method in (ZAPAuthMethod.FORM_BASED, ZAPAuthMethod.JSON_BASED, ZAPAuthMethod.HTTP_BASIC):
                    if not username or password is None:
                        raise ValueError("username/password required for authenticated scanning")

                login_request_data = (zap_auth or {}).get("login_request_data")
                json_template = (zap_auth or {}).get("json_template")
                if auth_method == ZAPAuthMethod.JSON_BASED and not json_template:
                    json_template = login_request_data

                auth_config = ZAPAuthConfig(
                    method=auth_method,
                    login_url=login_url,
                    login_request_data=login_request_data,
                    json_template=json_template,
                    hostname=(zap_auth or {}).get("hostname"),
                    realm=(zap_auth or {}).get("realm"),
                    port=(zap_auth or {}).get("port"),
                    script_name=(zap_auth or {}).get("script_name"),
                    script_params=(zap_auth or {}).get("script_params"),
                    username=username,
                    password=password,
                    logged_in_indicator=(zap_auth or {}).get("logged_in_indicator"),
                    logged_out_indicator=(zap_auth or {}).get("logged_out_indicator"),
                )

                if login_url:
                    auth_scope_netloc = urlparse(login_url).netloc.lower()
            except Exception as e:
                warn_msg = f"ZAP auth config invalid: {str(e)[:500]}"
                logger.warning(f"[{scan_id}] {warn_msg}")
                self.active_scans[scan_id].progress.errors.append(warn_msg)
                auth_requested = False

        # 6. Context Creation for AJAX/Scoped Scanning (non-auth)
        context_id_shared = None
        context_name_shared = None
        contexts_to_cleanup = []
        create_context = use_ajax_spider or "context_separation" in advanced_features
        if create_context and not auth_requested:
            try:
                context_name_shared = f"scan_{scan_id}"
                context_response = await self.http_client.get(
                    f"{self.zap_url}/JSON/context/action/newContext/",
                    params=self._zap_params({"contextName": context_name_shared}),
                    timeout=10.0,
                )
                if context_response.status_code == 200:
                    context_result = context_response.json()
                    context_id_shared = context_result.get("contextId")
                    if context_id_shared:
                        # Include all targets in the context (base URL scope)
                        for target in targets:
                            if not target.url:
                                continue
                            normalized_url = self._maybe_rewrite_localhost(target.url)
                            base_url, _ = self._normalize_zap_urls(normalized_url)
                            include_regex = f"{re.escape(base_url)}/.*"
                            await self.http_client.get(
                                f"{self.zap_url}/JSON/context/action/includeInContext/",
                                params=self._zap_params({
                                    "contextName": context_name_shared,
                                    "regex": include_regex,
                                }),
                                timeout=10.0,
                            )
                        await self.http_client.get(
                            f"{self.zap_url}/JSON/context/action/setContextInScope/",
                            params=self._zap_params({
                                "contextName": context_name_shared,
                                "booleanInScope": "true",
                            }),
                            timeout=10.0,
                        )
                        static_excludes = [
                            r".*\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$"
                        ]
                        for pattern in static_excludes:
                            await self.http_client.get(
                                f"{self.zap_url}/JSON/context/action/excludeFromContext/",
                                params=self._zap_params({
                                    "contextName": context_name_shared,
                                    "regex": pattern,
                                }),
                                timeout=10.0,
                            )
                        contexts_to_cleanup.append(context_name_shared)
                        logger.info(f"[{scan_id}] Created scan context {context_name_shared} for scoped scanning")
            except Exception as e:
                logger.warning(f"Context creation failed: {e}")
        
        for i, target in enumerate(targets):
            try:
                if not target.url:
                    continue
                original_url = target.url
                rewritten_url = self._maybe_rewrite_localhost(original_url)
                base_url, scan_url = self._normalize_zap_urls(rewritten_url)
                if scan_url != original_url:
                    info_msg = f"Adjusted target URL for scanning: {original_url} -> {scan_url}"
                    logger.info(f"[{scan_id}] {info_msg}")
                    self.active_scans[scan_id].progress.errors.append(info_msg)

                context_id = context_id_shared
                context_name = context_name_shared
                user_id = None

                if auth_requested and auth_config:
                    base_netloc = urlparse(base_url).netloc.lower()
                    if not auth_scope_netloc:
                        auth_scope_netloc = base_netloc
                    if base_netloc == auth_scope_netloc:
                        if not auth_context:
                            try:
                                from backend.services.zap_service import ZAPScanner

                                scanner = ZAPScanner(base_url=self.zap_url, api_key=self.zap_api_key)
                                auth_target = (zap_auth or {}).get("login_url") or scan_url
                                if auth_target and not auth_target.startswith("http"):
                                    auth_target = f"{base_url.rstrip('/')}/{auth_target.lstrip('/')}"
                                if auth_config.login_url and not auth_config.login_url.startswith("http"):
                                    auth_config.login_url = f"{base_url.rstrip('/')}/{auth_config.login_url.lstrip('/')}"
                                auth_result = await scanner.setup_authentication(
                                    auth_config,
                                    target_url=auth_target,
                                    context_name=(zap_auth or {}).get("context_name"),
                                )
                                auth_context = auth_result
                                context_id = auth_result.get("context_id")
                                context_name = auth_result.get("context_name")
                                user_id = auth_result.get("user_id")
                                if context_name:
                                    contexts_to_cleanup.append(context_name)

                                try:
                                    await self.http_client.get(
                                        f"{self.zap_url}/JSON/context/action/setContextInScope/",
                                        params=self._zap_params({
                                            "contextName": context_name,
                                            "booleanInScope": "true",
                                        }),
                                        timeout=10.0,
                                    )
                                    static_excludes = [
                                        r".*\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$"
                                    ]
                                    for pattern in static_excludes:
                                        await self.http_client.get(
                                            f"{self.zap_url}/JSON/context/action/excludeFromContext/",
                                            params=self._zap_params({
                                                "contextName": context_name,
                                                "regex": pattern,
                                            }),
                                            timeout=10.0,
                                        )
                                except Exception as e:
                                    logger.warning(f"Context scope setup failed: {e}")
                            except Exception as e:
                                warn_msg = f"ZAP auth setup failed: {str(e)[:500]}"
                                logger.warning(f"[{scan_id}] {warn_msg}")
                                self.active_scans[scan_id].progress.errors.append(warn_msg)
                                auth_requested = False
                        else:
                            context_id = auth_context.get("context_id")
                            context_name = auth_context.get("context_name")
                            user_id = auth_context.get("user_id")

                progress = int((i / len(targets)) * 100)
                await self._update_progress(
                    scan_id, ScanPhase.WEB_SCANNING, progress,
                    f"Scanning {scan_url} ({i+1}/{len(targets)}) with {scan_policy} policy"
                )
                
                # Start ZAP spider with configured options
                spider_params = {
                    "url": scan_url,
                    "maxChildren": spider_max_children,
                    "recurse": True,
                    "subtreeOnly": True,
                }

                spider_endpoint = "scan"
                if user_id and context_id:
                    spider_endpoint = "scanAsUser"
                    spider_params.update({
                        "contextId": context_id,
                        "userId": user_id,
                    })

                spider_response = await self.http_client.get(
                    f"{self.zap_url}/JSON/spider/action/{spider_endpoint}/",
                    params=self._zap_params(spider_params),
                    timeout=30.0,
                )
                
                if spider_response.status_code == 200:
                    spider_result = spider_response.json()
                    spider_id = spider_result.get("scan")
                    
                    # Wait for spider with configurable timeout
                    spider_timeout = 120 if spider_mode in ["deep", "spa_focused"] else 60
                    if scan_policy == "maximum" and spider_mode in ["deep", "spa_focused"]:
                        spider_timeout = max(spider_timeout, 180)
                    if spider_id:
                        for _ in range(spider_timeout // 3):
                            await asyncio.sleep(3)
                            status = await self.http_client.get(
                                f"{self.zap_url}/JSON/spider/view/status/",
                                params=self._zap_params({"scanId": spider_id}),
                                timeout=10.0,
                            )
                            if status.status_code == 200:
                                status_data = status.json()
                                if int(status_data.get("status", 0)) >= 100:
                                    break
                else:
                    self.active_scans[scan_id].progress.errors.append(
                        f"ZAP spider failed for {scan_url}: HTTP {spider_response.status_code}"
                    )
                
                # Run AJAX spider for SPA/JavaScript-heavy sites
                if use_ajax_spider:
                    try:
                        await self._update_progress(
                            scan_id, ScanPhase.WEB_SCANNING, progress + 5,
                            f"Running AJAX spider on {scan_url}..."
                        )
                        ajax_response = await self.http_client.get(
                            f"{self.zap_url}/JSON/ajaxSpider/action/scan/",
                            params=self._zap_params({
                                "url": base_url,
                                "inScope": str(bool(context_id)).lower(),
                            }),
                            timeout=30.0,
                        )
                        if ajax_response.status_code == 200:
                            # Wait for AJAX spider with configured duration
                            ajax_cap = 180 if scan_policy == "maximum" else 120
                            await asyncio.sleep(min(ajax_duration, ajax_cap))
                            # Stop AJAX spider
                            await self.http_client.get(
                                f"{self.zap_url}/JSON/ajaxSpider/action/stop/",
                                params=self._zap_params(),
                                timeout=10.0,
                            )
                        else:
                            self.active_scans[scan_id].progress.errors.append(
                                f"ZAP AJAX spider failed for {scan_url}: HTTP {ajax_response.status_code}"
                            )
                    except Exception as e:
                        logger.warning(f"AJAX spider failed for {scan_url}: {e}")
                
                # 4. Forced Browsing (Directory Enumeration)
                forced_browse_max_results = 1000 if scan_policy == "maximum" else 500 if scan_policy == "thorough" else 300
                seed_limit = 1000 if scan_policy == "maximum" else 500 if scan_policy == "thorough" else 200
                if forced_browse:
                    try:
                        await self._update_progress(
                            scan_id, ScanPhase.WEB_SCANNING, progress + 8,
                            f"Running forced browsing on {base_url}..."
                        )
                        fb_findings, fb_urls = await self._run_forced_browse(
                            scan_id=scan_id,
                            base_url=base_url,
                            host=target.ip,
                            port=target.port,
                            wordlist_key=forced_browse_wordlist,
                            scan_policy=scan_policy,
                            max_results=forced_browse_max_results,
                        )
                        if fb_findings:
                            findings.extend(fb_findings)
                        if fb_urls:
                            await self._seed_zap_urls(fb_urls, limit=seed_limit)
                        logger.info(f"[{scan_id}] Forced browsing completed for {scan_url}")
                    except Exception as e:
                        logger.warning(f"Forced browsing failed for {scan_url}: {e}")
                
                # Start ZAP active scan with policy-based configuration
                ascan_params = {
                    "url": scan_url,
                    "recurse": True,
                }
                
                ascan_endpoint = "scan"
                if user_id and context_id:
                    ascan_endpoint = "scanAsUser"
                    ascan_params["contextId"] = context_id
                    ascan_params["userId"] = user_id
                elif context_id:
                    ascan_params["contextId"] = context_id
                
                # Set scan policy strength if available
                if policy_config.get("attack_strength"):
                    try:
                        await self.http_client.get(
                            f"{self.zap_url}/JSON/ascan/action/setOptionAttackStrength/",
                            params=self._zap_params({"String": policy_config["attack_strength"]}),
                            timeout=10.0,
                        )
                    except Exception:
                        pass
                
                # Set alert threshold if available
                if policy_config.get("alert_threshold"):
                    try:
                        await self.http_client.get(
                            f"{self.zap_url}/JSON/ascan/action/setOptionAlertThreshold/",
                            params=self._zap_params({"String": policy_config["alert_threshold"]}),
                            timeout=10.0,
                        )
                    except Exception:
                        pass
                
                ascan_response = await self.http_client.get(
                    f"{self.zap_url}/JSON/ascan/action/{ascan_endpoint}/",
                    params=self._zap_params(ascan_params),
                    timeout=30.0,
                )
                
                if ascan_response.status_code == 200:
                    ascan_result = ascan_response.json()
                    ascan_id = ascan_result.get("scan")
                    
                    # Wait for active scan with policy-based timeout
                    if scan_policy == "maximum":
                        scan_timeout = 900
                    elif scan_policy == "thorough":
                        scan_timeout = 600
                    else:
                        scan_timeout = 180
                    if ascan_id:
                        for _ in range(scan_timeout // 3):
                            await asyncio.sleep(3)
                            status = await self.http_client.get(
                                f"{self.zap_url}/JSON/ascan/view/status/",
                                params=self._zap_params({"scanId": ascan_id}),
                                timeout=10.0,
                            )
                            if status.status_code == 200:
                                status_data = status.json()
                                if int(status_data.get("status", 0)) >= 100:
                                    break
                else:
                    self.active_scans[scan_id].progress.errors.append(
                        f"ZAP active scan failed for {scan_url}: HTTP {ascan_response.status_code}"
                    )

                await self._wait_for_zap_passive(
                    scan_id,
                    max_wait_seconds=240 if scan_policy == "maximum" else 120 if scan_policy == "thorough" else 60,
                    min_remaining=0,
                )
                
                # Get alerts for this target
                alerts = []
                page_size = 100
                max_alerts = 5000
                start = 0
                truncated = False
                while len(alerts) < max_alerts:
                    alerts_response = await self.http_client.get(
                        f"{self.zap_url}/JSON/core/view/alerts/",
                        params=self._zap_params({
                            "baseurl": base_url,
                            "start": start,
                            "count": page_size,
                        }),
                        timeout=60.0,
                    )
                    if alerts_response.status_code != 200:
                        self.active_scans[scan_id].progress.errors.append(
                            f"ZAP alerts fetch failed for {scan_url}: HTTP {alerts_response.status_code}"
                        )
                        break
                    page_alerts = alerts_response.json().get("alerts", [])
                    alerts.extend(page_alerts)
                    if len(page_alerts) < page_size:
                        break
                    start += page_size
                if len(alerts) >= max_alerts:
                    truncated = True
                
                if not alerts:
                    try:
                        all_alerts = []
                        start = 0
                        while len(all_alerts) < max_alerts:
                            all_alerts_response = await self.http_client.get(
                                f"{self.zap_url}/JSON/core/view/alerts/",
                                params=self._zap_params({
                                    "start": start,
                                    "count": page_size,
                                }),
                                timeout=60.0,
                            )
                            if all_alerts_response.status_code != 200:
                                break
                            page_alerts = all_alerts_response.json().get("alerts", [])
                            all_alerts.extend(page_alerts)
                            if len(page_alerts) < page_size:
                                break
                            start += page_size
                        if all_alerts:
                            alerts = [a for a in all_alerts if a.get("url", "").startswith(base_url)]
                    except Exception:
                        pass
                
                if truncated:
                    self.active_scans[scan_id].progress.errors.append(
                        f"ZAP alerts truncated at {max_alerts} for {scan_url}"
                    )

                for alert in alerts:
                    # Map ZAP risk to severity
                    risk_map = {
                        "High": "high",
                        "Medium": "medium",
                        "Low": "low",
                        "Informational": "info",
                    }
                    
                    finding = ScanFinding(
                        source="zap",
                        severity=risk_map.get(alert.get("risk", ""), "info"),
                        title=alert.get("alert", ""),
                        description=alert.get("description", ""),
                        host=target.ip,
                        port=target.port,
                        url=alert.get("url", scan_url),
                        evidence=alert.get("evidence", ""),
                        remediation=alert.get("solution", ""),
                        references=[ref for ref in alert.get("reference", "").split("\n") if ref],
                        raw_data=alert,
                    )
                    findings.append(finding)
                
            except Exception as e:
                err_text = str(e).strip()
                if not err_text:
                    err_text = type(e).__name__
                logger.error(f"ZAP scan failed for {target.url}: {err_text}")
                self.active_scans[scan_id].progress.errors.append(f"ZAP ({target.url}): {err_text[:80]}")

        if scanners_customized:
            try:
                await self.http_client.get(
                    f"{self.zap_url}/JSON/ascan/action/enableAllScanners/",
                    params=self._zap_params(),
                    timeout=10.0,
                )
            except Exception as e:
                logger.warning(f"Failed to restore ZAP scanners: {e}")

        if auth_context:
            try:
                await self.http_client.get(
                    f"{self.zap_url}/JSON/forcedUser/action/setForcedUserModeEnabled/",
                    params=self._zap_params({"boolean": "false"}),
                    timeout=10.0,
                )
            except Exception as e:
                logger.warning(f"Failed to disable forced user mode: {e}")

        if contexts_to_cleanup:
            for context_to_remove in sorted(set(contexts_to_cleanup)):
                try:
                    await self.http_client.get(
                        f"{self.zap_url}/JSON/context/action/removeContext/",
                        params=self._zap_params({"contextName": context_to_remove}),
                        timeout=10.0,
                    )
                except Exception as e:
                    logger.warning(f"Failed to cleanup ZAP context {context_to_remove}: {e}")

        await self._update_progress(
            scan_id, ScanPhase.WEB_SCANNING, 100,
            f"Web scanning complete: {len(findings)} findings"
        )
        
        return findings
    
    async def _run_nuclei_scan(
        self,
        scan_id: str,
        targets: List[ServiceTarget],
        templates: List[str] = None,
    ) -> List[ScanFinding]:
        """
        Run Nuclei CVE scans on network targets.
        
        Args:
            scan_id: Unique scan identifier
            targets: List of network targets to scan
            templates: List of Nuclei template categories to use
        """
        findings = []
        
        # Default templates if none specified
        if not templates:
            templates = ["cves", "vulnerabilities"]
        
        # Import template definitions
        from backend.services.dynamic_scan_agent import NUCLEI_TEMPLATES
        
        # Build severity filter based on templates
        severities = ["critical", "high", "medium"]
        if "all_critical" in templates:
            severities = ["critical"]
        elif "all_high" in templates:
            severities = ["critical", "high"]
        
        for i, target in enumerate(targets):
            try:
                progress = int((i / len(targets)) * 100)
                scan_target = f"{target.ip}:{target.port}"
                if target.url:
                    normalized_url = self._maybe_rewrite_localhost(target.url)
                    _, scan_target = self._normalize_zap_urls(normalized_url)

                await self._update_progress(
                    scan_id, ScanPhase.CVE_SCANNING, progress,
                    f"CVE scanning {scan_target} ({i+1}/{len(targets)}) with {len(templates)} template categories"
                )
                
                # Build tags from selected templates
                nuclei_tags = []
                for t in templates:
                    if t in NUCLEI_TEMPLATES:
                        # Extract relevant tags from template category
                        if t == "cves":
                            nuclei_tags.extend(["cve"])
                        elif t == "exposures":
                            nuclei_tags.extend(["exposure", "config"])
                        elif t == "misconfigurations":
                            nuclei_tags.extend(["misconfig", "default-login"])
                        elif t == "vulnerabilities":
                            nuclei_tags.extend(["vuln", "rce", "sqli", "xss"])
                        elif t == "network":
                            nuclei_tags.extend(["network", "tcp"])
                        elif t == "default_logins":
                            nuclei_tags.extend(["default-login"])
                        elif t == "technologies":
                            nuclei_tags.extend(["tech", "detect"])
                
                # Also include service-specific tags
                if target.nuclei_tags:
                    nuclei_tags.extend(target.nuclei_tags)
                if target.url:
                    nuclei_tags.extend(["http", "web"])
                
                # Deduplicate
                nuclei_tags = list(set(nuclei_tags)) if nuclei_tags else ["cve", "network"]
                
                # Start nuclei scan via sidecar
                payload = {
                    "target": scan_target,
                    "tags": nuclei_tags,
                    "severity": severities,
                    "timeout": 300,  # 5 min per target
                }
                response = await self.http_client.post(
                    f"{self.scanner_url}/scan/nuclei",
                    json=payload,
                    timeout=30.0,
                )
                
                if response.status_code != 200:
                    continue
                
                nuclei_scan = response.json()
                nuclei_scan_id = nuclei_scan["scan_id"]
                self._register_tool_scan(scan_id, "nuclei", nuclei_scan_id)
                status_data = await self._poll_scanner_job(
                    nuclei_scan_id,
                    timeout_seconds=payload["timeout"] + 60,
                )
                if status_data.get("status") != "completed":
                    continue
                result = status_data.get("result", {})
                
                for f in result.get("findings", []):
                    finding = ScanFinding(
                        source="nuclei",
                        severity=f.get("severity", "info"),
                        title=f.get("template_name", f.get("template_id", "")),
                        description=f.get("description", ""),
                        host=target.ip,
                        port=target.port,
                        cve_id=f.get("cve_id", [None])[0] if f.get("cve_id") else None,
                        cvss_score=f.get("cvss_score"),
                        evidence=f.get("matched_at", ""),
                        references=f.get("reference", []),
                        raw_data=f,
                    )
                    findings.append(finding)
                
            except Exception as e:
                target_label = target.url or f"{target.ip}:{target.port}"
                logger.error(f"Nuclei scan failed for {target_label}: {e}")
        
        await self._update_progress(
            scan_id, ScanPhase.CVE_SCANNING, 100,
            f"CVE scanning complete: {len(findings)} findings"
        )
        
        return findings

    async def _run_directory_scan(
        self,
        scan_id: str,
        targets: List[ServiceTarget],
        engine: str = "gobuster",
        wordlist: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        threads: int = 25,
    ) -> tuple[List[ScanFinding], List[str]]:
        """Run directory enumeration (Gobuster/Dirbuster) and return findings + discovered URLs."""
        findings: List[ScanFinding] = []
        discovered_urls: List[str] = []
        scanner_info = await self._get_scanner_info()
        if scanner_info:
            direnum_caps = scanner_info.get("capabilities", {}).get("direnum", {})
            engines = direnum_caps.get("engines", {})
            if engine == "dirbuster" and not engines.get("dirbuster", {}).get("installed", False):
                if engines.get("gobuster", {}).get("installed", False):
                    logger.warning(f"[{scan_id}] Dirbuster unavailable; falling back to gobuster.")
                    engine = "gobuster"
                else:
                    warning = "Directory enumeration unavailable: dirbuster/gobuster not installed in scanner."
                    logger.warning(f"[{scan_id}] {warning}")
                    self.active_scans[scan_id].progress.errors.append(warning)
                    return findings, discovered_urls
            if engine == "gobuster" and not engines.get("gobuster", {}).get("installed", False):
                warning = "Directory enumeration unavailable: gobuster not installed in scanner."
                logger.warning(f"[{scan_id}] {warning}")
                self.active_scans[scan_id].progress.errors.append(warning)
                return findings, discovered_urls

        for i, target in enumerate(targets):
            if not target.url:
                continue
            payload = {
                "target": target.url,
                "engine": engine,
                "wordlist": wordlist,
                "extensions": extensions,
                "threads": threads,
                "timeout": 300,
            }

            await self._update_progress(
                scan_id, ScanPhase.DIRECTORY_ENUMERATION,
                int((i / len(targets)) * 100),
                f"Running {engine} directory enumeration on {target.url}..."
            )

            try:
                response = await self.http_client.post(
                    f"{self.scanner_url}/scan/direnum",
                    json=payload,
                    timeout=60.0,
                )
                if response.status_code != 200:
                    raise Exception(f"Scanner returned HTTP {response.status_code}")

                data = response.json()
                scan_job_id = data.get("scan_id")
                if not scan_job_id:
                    raise Exception("Scanner did not return scan_id for direnum")
                self._register_tool_scan(scan_id, f"direnum_{engine}", scan_job_id)

                status_data = await self._poll_scanner_job(
                    scan_job_id,
                    timeout_seconds=payload["timeout"] + 60,
                )
                if status_data.get("status") != "completed":
                    raise Exception(status_data.get("error") or "Directory enumeration failed")

                result = status_data.get("result", {})
                for entry in result.get("findings", []):
                    path = entry.get("path") or entry.get("url")
                    if not path:
                        continue
                    findings.append(
                        ScanFinding(
                            source="direnum",
                            severity="info",
                            title=f"Directory enumeration: {path}",
                            description=entry.get("line") or f"Status {entry.get('status')}",
                            host=target.ip,
                            port=target.port,
                            url=path,
                            evidence=f"Status {entry.get('status')}",
                            raw_data=entry,
                        )
                    )
                discovered_urls.extend(result.get("discovered_urls", []))
            except Exception as e:
                logger.warning(f"[{scan_id}] Directory enumeration failed for {target.url}: {e}")
                self.active_scans[scan_id].progress.errors.append(f"Direnum {target.url}: {e}")

        # Deduplicate discovered URLs
        discovered_urls = list(dict.fromkeys(discovered_urls))
        await self._update_progress(
            scan_id, ScanPhase.DIRECTORY_ENUMERATION, 100,
            f"Directory enumeration complete ({len(findings)} findings)"
        )

        return findings, discovered_urls

    async def _run_wapiti_scan(
        self,
        scan_id: str,
        targets: List[ServiceTarget],
        level: int = 2,
    ) -> List[ScanFinding]:
        """Run Wapiti against web targets."""
        findings: List[ScanFinding] = []
        scanner_info = await self._get_scanner_info()
        available = self._scanner_tool_available(scanner_info, "wapiti")
        if available is False:
            warning = "Wapiti not available in scanner sidecar."
            logger.warning(f"[{scan_id}] {warning}")
            self.active_scans[scan_id].progress.errors.append(warning)
            return findings

        for i, target in enumerate(targets):
            if not target.url:
                continue
            await self._update_progress(
                scan_id, ScanPhase.WAPITI_SCANNING,
                int((i / len(targets)) * 100),
                f"Running Wapiti scan on {target.url}..."
            )

            payload = {
                "target": target.url,
                "level": level,
                "timeout": 600,
            }

            try:
                response = await self.http_client.post(
                    f"{self.scanner_url}/scan/wapiti",
                    json=payload,
                    timeout=60.0,
                )
                if response.status_code != 200:
                    raise Exception(f"Scanner returned HTTP {response.status_code}")

                data = response.json()
                scan_job_id = data.get("scan_id")
                if not scan_job_id:
                    raise Exception("Scanner did not return scan_id for wapiti")
                self._register_tool_scan(scan_id, "wapiti", scan_job_id)

                status_data = await self._poll_scanner_job(
                    scan_job_id,
                    timeout_seconds=payload["timeout"] + 60,
                )
                if status_data.get("status") != "completed":
                    raise Exception(status_data.get("error") or "Wapiti scan failed")

                result = status_data.get("result", {})
                for entry in result.get("findings", []):
                    severity = (entry.get("level") or "info").lower()
                    findings.append(
                        ScanFinding(
                            source="wapiti",
                            severity=severity,
                            title=entry.get("name") or f"Wapiti {severity}",
                            description=entry.get("description") or "",
                            host=target.ip,
                            port=target.port,
                            url=entry.get("url"),
                            evidence=entry.get("description"),
                            raw_data=entry,
                        )
                    )
            except Exception as e:
                logger.warning(f"[{scan_id}] Wapiti scan failed for {target.url}: {e}")
                self.active_scans[scan_id].progress.errors.append(f"Wapiti {target.url}: {e}")

        await self._update_progress(
            scan_id, ScanPhase.WAPITI_SCANNING, 100,
            f"Wapiti scans complete ({len(findings)} findings)"
        )

        return findings

    async def _run_sqlmap_scan(
        self,
        scan_id: str,
        urls: List[str],
        level: int = 2,
        risk: int = 2,
        method: str = "GET",
        data: Optional[str] = None,
        threads: int = 1,
    ) -> List[ScanFinding]:
        """Run SQLMap on discovered URLs."""
        findings: List[ScanFinding] = []
        scanner_info = await self._get_scanner_info()
        available = self._scanner_tool_available(scanner_info, "sqlmap")
        if available is False:
            warning = "SQLMap not available in scanner sidecar."
            logger.warning(f"[{scan_id}] {warning}")
            self.active_scans[scan_id].progress.errors.append(warning)
            return findings
        unique_urls = list(dict.fromkeys(urls))[:10]

        if not unique_urls:
            await self._update_progress(
                scan_id, ScanPhase.SQLMAP_SCANNING, 100,
                "SQLMap skipped (no URLs discovered)"
            )
            return findings

        for i, url in enumerate(unique_urls):
            await self._update_progress(
                scan_id, ScanPhase.SQLMAP_SCANNING,
                int((i / len(unique_urls)) * 100),
                f"Running SQLMap on {url}..."
            )

            payload = {
                "target": url,
                "method": method,
                "data": data,
                "level": level,
                "risk": risk,
                "threads": threads,
                "timeout": 900,
            }

            try:
                response = await self.http_client.post(
                    f"{self.scanner_url}/scan/sqlmap",
                    json=payload,
                    timeout=90.0,
                )
                if response.status_code != 200:
                    raise Exception(f"Scanner returned HTTP {response.status_code}")

                data_resp = response.json()
                scan_job_id = data_resp.get("scan_id")
                if not scan_job_id:
                    raise Exception("Scanner did not return scan_id for SQLMap")
                self._register_tool_scan(scan_id, "sqlmap", scan_job_id)

                status_data = await self._poll_scanner_job(
                    scan_job_id,
                    timeout_seconds=payload.get("timeout", 900) + 60,
                )
                if status_data.get("status") != "completed":
                    raise Exception(status_data.get("error") or "SQLMap scan failed")

                result = status_data.get("result", {})
                for entry in result.get("findings", []):
                    details = entry.get("detail")
                    if isinstance(details, list):
                        evidence = "\n".join(details)
                    else:
                        evidence = details or ""
                    raw_entry = dict(entry) if isinstance(entry, dict) else {"detail": entry}
                    raw_entry["method"] = method
                    findings.append(
                        ScanFinding(
                            source="sqlmap",
                            severity=entry.get("risk", "high"),
                            title=f"SQLMap injection: {entry.get('url')}",
                            description=entry.get("description"),
                            host=urlparse(entry.get("url") or url).hostname or url,
                            port=None,
                            url=entry.get("url") or url,
                            evidence=evidence,
                            raw_data=raw_entry,
                        )
                    )
            except Exception as e:
                logger.warning(f"[{scan_id}] SQLMap scan failed for {url}: {e}")
                self.active_scans[scan_id].progress.errors.append(f"SQLMap {url}: {e}")

        await self._update_progress(
            scan_id, ScanPhase.SQLMAP_SCANNING, 100,
            f"SQLMap scans complete ({len(findings)} findings)"
        )

        return findings
    
    async def _map_exploits(self, scan_id: str):
        """Map findings to available exploits."""
        try:
            from backend.services.exploit_db_service import ExploitDBService
            
            exploit_service = ExploitDBService()
            scan = self.active_scans[scan_id]
            
            for i, finding in enumerate(scan.findings):
                progress = int((i / len(scan.findings)) * 100)
                await self._update_progress(
                    scan_id, ScanPhase.EXPLOIT_MAPPING, progress,
                    f"Looking up exploits ({i+1}/{len(scan.findings)})"
                )
                
                # Look up by CVE
                if finding.cve_id:
                    exploits = await exploit_service.search_by_cve(finding.cve_id)
                    if exploits:
                        finding.exploit_available = True
                        finding.exploit_info = exploits[0]  # Best match
                        
                        # Add to exploit commands
                        if exploits[0].get("msf_module"):
                            if "metasploit" not in scan.exploit_commands:
                                scan.exploit_commands["metasploit"] = []
                            scan.exploit_commands["metasploit"].append(
                                f"use {exploits[0]['msf_module']}\nset RHOSTS {finding.host}\nrun"
                            )
                
                # Look up by service/version
                elif finding.source == "nmap" and finding.raw_data:
                    product = finding.raw_data.get("product", "")
                    version = finding.raw_data.get("version", "")
                    if product:
                        exploits = await exploit_service.search_by_product(product, version)
                        if exploits:
                            finding.exploit_available = True
                            finding.exploit_info = exploits[0]
            
            await self._update_progress(
                scan_id, ScanPhase.EXPLOIT_MAPPING, 100,
                f"Exploit mapping complete"
            )
            
        except ImportError:
            logger.warning("Exploit DB service not available")
        except Exception as e:
            logger.error(f"Exploit mapping failed: {e}")
    
    async def _run_ai_analysis(self, scan_id: str):
        """Generate AI attack narrative and recommendations."""
        try:
            from backend.services.dynamic_scan_agent import DynamicScanAgent
            
            agent = DynamicScanAgent()
            scan = self.active_scans[scan_id]
            
            await self._update_progress(
                scan_id, ScanPhase.AI_ANALYSIS, 30,
                "AI analyzing findings..."
            )
            
            # Generate analysis
            analysis = await agent.analyze_scan_results(scan)
            
            scan.executive_summary = analysis.get("executive_summary", "")
            scan.attack_narrative = analysis.get("attack_narrative", "")
            scan.risk_summary = analysis.get("risk_summary", "")
            scan.exploit_chains = analysis.get("exploit_chains", [])
            scan.recommendations = analysis.get("recommendations", [])
            
            # Add exploit commands from AI
            if "commands" in analysis:
                for tool, cmds in analysis["commands"].items():
                    if tool not in scan.exploit_commands:
                        scan.exploit_commands[tool] = []
                    scan.exploit_commands[tool].extend(cmds)
            
            await self._update_progress(
                scan_id, ScanPhase.AI_ANALYSIS, 100,
                "AI analysis complete"
            )
            
        except ImportError:
            logger.warning("AI agent not available")
            self.active_scans[scan_id].attack_narrative = "AI analysis unavailable"
            self.active_scans[scan_id].executive_summary = "AI analysis is not available. Please review findings manually."
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            self.active_scans[scan_id].attack_narrative = "AI analysis failed. Review findings manually."
            self.active_scans[scan_id].executive_summary = "AI analysis failed. Review findings manually."
    
    async def _save_scan_snapshot(self, scan_id: str, db: Session):
        """Persist an in-progress snapshot of the scan without finalizing findings."""
        try:
            scan = self.active_scans.get(scan_id)
            if not scan:
                return
            db_scan = db.query(DynamicScan).filter(DynamicScan.scan_id == scan_id).first()
            if not db_scan:
                return
            db_scan.status = scan.status.value
            if scan.started_at and not db_scan.started_at:
                try:
                    db_scan.started_at = datetime.fromisoformat(scan.started_at)
                except ValueError:
                    pass
            if scan.status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}:
                db_scan.completed_at = datetime.utcnow()
            db_scan.results = json.dumps(asdict(scan))
            db_scan.current_phase = scan.progress.phase.value
            db_scan.progress_percent = scan.progress.overall_progress
            db_scan.hosts_discovered = scan.progress.hosts_discovered
            db_scan.web_targets = scan.progress.web_targets
            db_scan.network_targets = scan.progress.network_targets
            db_scan.total_findings = len(scan.findings)
            db_scan.critical_findings = sum(
                1 for f in scan.findings if (f.severity or "").lower() == "critical"
            )
            db_scan.high_findings = sum(
                1 for f in scan.findings if (f.severity or "").lower() == "high"
            )
            db_scan.exploitable_findings = sum(1 for f in scan.findings if f.exploit_available)
            db_scan.duration_seconds = scan.duration_seconds
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to persist scan snapshot: {e}")

    async def _save_results_to_db(self, scan_id: str, db: Session):
        """Persist scan results to database."""
        try:
            scan = self.active_scans[scan_id]
            
            # Update scan record
            db_scan = db.query(DynamicScan).filter(DynamicScan.scan_id == scan_id).first()
            if db_scan:
                db_scan.status = scan.status.value
                db_scan.completed_at = datetime.utcnow()
                db_scan.results = json.dumps(asdict(scan))
                db_scan.current_phase = scan.progress.phase.value
                db_scan.progress_percent = scan.progress.overall_progress
                db_scan.hosts_discovered = scan.progress.hosts_discovered
                db_scan.web_targets = scan.progress.web_targets
                db_scan.network_targets = scan.progress.network_targets
                db_scan.total_findings = len(scan.findings)
                db_scan.critical_findings = sum(
                    1 for f in scan.findings if (f.severity or "").lower() == "critical"
                )
                db_scan.high_findings = sum(
                    1 for f in scan.findings if (f.severity or "").lower() == "high"
                )
                db_scan.exploitable_findings = sum(1 for f in scan.findings if f.exploit_available)
                db_scan.duration_seconds = scan.duration_seconds
                
                # Save findings
                for finding in scan.findings:
                    db_finding = DynamicScanFinding(
                        scan_id=db_scan.id,
                        source=finding.source,
                        severity=finding.severity,
                        title=finding.title,
                        description=finding.description,
                        host=finding.host,
                        port=finding.port,
                        cve_id=finding.cve_id,
                        exploit_available=finding.exploit_available,
                        raw_data=json.dumps(finding.raw_data) if finding.raw_data else None,
                    )
                    db.add(db_finding)
                
                db.commit()
                self.active_scans.pop(scan_id, None)
                
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
    
    def get_scan_status(self, scan_id: str) -> Optional[DynamicScanResult]:
        """Get current status of a scan."""
        return self.active_scans.get(scan_id)
    
    def _mark_db_scan_cancelled(self, scan_id: str, db: Session) -> bool:
        if not db:
            return False
        db_scan = db.query(DynamicScan).filter(DynamicScan.scan_id == scan_id).first()
        if not db_scan or db_scan.status in {ScanStatus.COMPLETED.value, ScanStatus.FAILED.value, ScanStatus.CANCELLED.value}:
            return False
        db_scan.status = ScanStatus.CANCELLED.value
        db_scan.completed_at = datetime.utcnow()
        db.commit()
        return True

    def cancel_scan(self, scan_id: str, db: Optional[Session] = None) -> bool:
        """Cancel a running scan."""
        scan = self.active_scans.get(scan_id)
        if not scan:
            return self._mark_db_scan_cancelled(scan_id, db)
        
        if scan.status not in {ScanStatus.RUNNING, ScanStatus.PENDING, ScanStatus.PAUSED}:
            return False

        scan.status = ScanStatus.CANCELLED
        scan.progress.phase = ScanPhase.CANCELLED
        scan.progress.errors.append("Cancelled by user")

        task = self.scan_tasks.get(scan_id)
        if task and not task.done():
            task.cancel()

        self._mark_db_scan_cancelled(scan_id, db)
        try:
            asyncio.create_task(self._cancel_sidecar_scans(scan_id))
        except RuntimeError:
            logger.warning(f"[{scan_id}] Unable to dispatch sidecar cancellation task")
        return True
    
    def list_scans(self) -> List[Dict[str, Any]]:
        """List all active scans."""
        active_statuses = {ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.PAUSED}
        return [
            {
                "scan_id": s.scan_id,
                "target": s.target,
                "status": s.status.value,
                "phase": s.progress.phase.value,
                "progress": s.progress.overall_progress,
                "findings_count": len(s.findings),
                "started_at": s.started_at,
            }
            for s in self.active_scans.values()
            if s.status in active_statuses
        ]


# Singleton instance
_dynamic_scan_service: Optional[DynamicScanService] = None


def get_dynamic_scan_service() -> DynamicScanService:
    """Get or create the singleton service instance."""
    global _dynamic_scan_service
    if _dynamic_scan_service is None:
        _dynamic_scan_service = DynamicScanService()
    return _dynamic_scan_service
