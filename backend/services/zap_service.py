"""
OWASP ZAP Integration Service

Full integration with OWASP ZAP for dynamic application security testing (DAST).
Provides spider, active scanner, passive scanner, and AJAX spider functionality.

Features:
- Spider crawling for endpoint discovery
- Active vulnerability scanning
- Passive security analysis
- AJAX spider for JavaScript-heavy apps
- Scan policies and configurations
- Alert management and export
- Session management
- Integration with Agentic Fuzzer findings
- Database persistence for scan state
- Retry logic with exponential backoff
"""

import asyncio
import json
import logging
import random
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, AsyncGenerator, Tuple
from pathlib import Path

import httpx

from backend.core.config import settings

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

# ZAP connection settings - configurable via environment
ZAP_BASE_URL = settings.zap_url if hasattr(settings, 'zap_url') else "http://zap:8080"
ZAP_API_KEY = settings.zap_api_key if hasattr(settings, 'zap_api_key') else ""  # Empty if disabled

# Timeouts
ZAP_TIMEOUT = 30.0
ZAP_LONG_TIMEOUT = 300.0  # For scan operations

# Retry configuration
ZAP_MAX_RETRIES = 3
ZAP_RETRY_BASE_DELAY = 1.0  # Base delay in seconds
ZAP_RETRY_MAX_DELAY = 30.0  # Max delay between retries


# =============================================================================
# ENUMS & DATA CLASSES
# =============================================================================

class ZAPScanType(str, Enum):
    """Types of ZAP scans."""
    SPIDER = "spider"
    AJAX_SPIDER = "ajax_spider"
    ACTIVE_SCAN = "active_scan"
    PASSIVE_SCAN = "passive_scan"
    FULL_SCAN = "full_scan"  # Spider + Active + Passive


class ZAPAlertRisk(str, Enum):
    """ZAP alert risk levels."""
    INFORMATIONAL = "0"
    LOW = "1"
    MEDIUM = "2"
    HIGH = "3"


class ZAPScanStatus(str, Enum):
    """ZAP scan status."""
    NOT_STARTED = "not_started"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"
    INTERRUPTED = "interrupted"  # For resumable scans


class ZAPAuthMethod(str, Enum):
    """ZAP authentication methods."""
    FORM_BASED = "formBasedAuthentication"
    HTTP_BASIC = "httpAuthentication"
    JSON_BASED = "jsonBasedAuthentication"
    SCRIPT_BASED = "scriptBasedAuthentication"
    MANUAL = "manualAuthentication"


class ZAPScanPhase(str, Enum):
    """Scan phases for checkpoint-based resume."""
    INIT = "init"
    SPIDER = "spider"
    AJAX_SPIDER = "ajax_spider"
    ACTIVE_SCAN = "active_scan"
    PASSIVE_SCAN = "passive_scan"
    COMPLETE = "complete"


@dataclass
class ZAPAuthConfig:
    """Authentication configuration for ZAP scans."""
    method: ZAPAuthMethod
    login_url: Optional[str] = None
    
    # Form-based auth
    login_request_data: Optional[str] = None  # username={%username%}&password={%password%}
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    
    # HTTP Basic auth
    hostname: Optional[str] = None
    realm: Optional[str] = None
    port: Optional[int] = None
    
    # JSON-based auth
    login_page_url: Optional[str] = None
    json_template: Optional[str] = None  # {"user":"{%username%}","pass":"{%password%}"}
    
    # Script-based auth (for OAuth/OIDC)
    script_name: Optional[str] = None
    script_params: Optional[Dict[str, str]] = None
    
    # Credentials
    username: Optional[str] = None
    password: Optional[str] = None
    
    # Session indicators
    logged_in_indicator: Optional[str] = None  # Regex pattern
    logged_out_indicator: Optional[str] = None  # Regex pattern
    
    # Token handling (for OAuth/JWT)
    token_endpoint: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    scope: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ZAPScanPolicy:
    """Scan policy configuration."""
    name: str
    description: Optional[str] = None
    
    # Attack strength: LOW, MEDIUM, HIGH, INSANE
    default_attack_strength: str = "MEDIUM"
    # Alert threshold: OFF, LOW, MEDIUM, HIGH
    default_alert_threshold: str = "MEDIUM"
    
    # Scanner-specific settings (plugin_id -> enabled)
    enabled_scanners: Optional[List[int]] = None
    disabled_scanners: Optional[List[int]] = None
    
    # Scanner-specific strength/threshold overrides
    scanner_configs: Optional[Dict[int, Dict[str, str]]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ZAPScanCheckpoint:
    """Checkpoint for resumable scans."""
    phase: ZAPScanPhase
    phase_progress: int = 0  # Progress within current phase (0-100)
    
    # Spider checkpoint
    spider_id: Optional[str] = None
    spider_urls_found: List[str] = field(default_factory=list)
    
    # AJAX Spider checkpoint
    ajax_spider_completed: bool = False
    ajax_urls_found: List[str] = field(default_factory=list)
    
    # Active scan checkpoint
    active_scan_id: Optional[str] = None
    scanned_urls: List[str] = field(default_factory=list)
    pending_urls: List[str] = field(default_factory=list)
    
    # Findings so far
    alerts_found: List[Dict[str, Any]] = field(default_factory=list)
    
    # Timestamps
    last_updated: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ZAPAlert:
    """Represents a ZAP security alert."""
    id: str
    plugin_id: str
    alert_name: str
    risk: str
    risk_code: int
    confidence: str
    confidence_code: int
    url: str
    method: str
    parameter: Optional[str]
    attack: Optional[str]
    evidence: Optional[str]
    description: str
    solution: str
    reference: str
    cwe_id: Optional[int]
    wasc_id: Optional[int]
    tags: Dict[str, str] = field(default_factory=dict)
    
    @classmethod
    def from_zap_response(cls, data: Dict[str, Any]) -> 'ZAPAlert':
        """Create from ZAP API response."""
        # Handle risk_code - can be string or int
        risk_code = data.get("riskcode", data.get("risk_code", 0))
        if isinstance(risk_code, str):
            risk_code = int(risk_code) if risk_code.isdigit() else 0
        
        # Handle confidence_code - can be string or int
        confidence_code = data.get("confidencecode", data.get("confidence_code", 0))
        if isinstance(confidence_code, str):
            confidence_code = int(confidence_code) if confidence_code.isdigit() else 0
        
        # Handle CWE/WASC IDs safely
        cwe_id = data.get("cweid", data.get("cwe_id"))
        if cwe_id:
            cwe_id = int(cwe_id) if str(cwe_id).isdigit() else None
        
        wasc_id = data.get("wascid", data.get("wasc_id"))
        if wasc_id:
            wasc_id = int(wasc_id) if str(wasc_id).isdigit() else None
        
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            plugin_id=data.get("pluginId", data.get("plugin_id", "")),
            alert_name=data.get("alert", data.get("name", "Unknown")),
            risk=data.get("risk", "Informational"),
            risk_code=risk_code,
            confidence=data.get("confidence", "Low"),
            confidence_code=confidence_code,
            url=data.get("url", ""),
            method=data.get("method", "GET"),
            parameter=data.get("param", data.get("parameter")),
            attack=data.get("attack"),
            evidence=data.get("evidence"),
            description=data.get("description", ""),
            solution=data.get("solution", ""),
            reference=data.get("reference", ""),
            cwe_id=cwe_id,
            wasc_id=wasc_id,
            tags=data.get("tags", {}),
        )
    
    def to_finding_dict(self) -> Dict[str, Any]:
        """Convert to format compatible with Agentic Fuzzer findings."""
        severity_map = {0: "info", 1: "low", 2: "medium", 3: "high"}
        return {
            "id": f"zap_{self.id}",
            "technique": "zap_dast",
            "severity": severity_map.get(self.risk_code, "info"),
            "title": self.alert_name,
            "description": self.description,
            "payload": self.attack or "",
            "evidence": [self.evidence] if self.evidence else [],
            "endpoint": self.url,
            "parameter": self.parameter,
            "recommendation": self.solution,
            "confidence": self.confidence_code / 3.0,  # Normalize to 0-1
            "exploitable": self.risk_code >= 2,
            "cwe_id": f"CWE-{self.cwe_id}" if self.cwe_id else None,
            "source": "owasp_zap",
            "references": self.reference.split("\n") if self.reference else [],
        }


@dataclass
class ZAPScanSession:
    """Represents a ZAP scan session."""
    id: str
    target_url: str
    scan_type: ZAPScanType
    status: ZAPScanStatus
    progress: int = 0
    spider_id: Optional[str] = None
    ajax_spider_running: bool = False
    active_scan_id: Optional[str] = None
    alerts: List[ZAPAlert] = field(default_factory=list)
    urls_found: List[str] = field(default_factory=list)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
    stats: Dict[str, Any] = field(default_factory=dict)
    
    # Checkpoint for resumable scans
    checkpoint: Optional[ZAPScanCheckpoint] = None
    # Authentication context
    context_id: Optional[str] = None
    user_id_zap: Optional[str] = None  # ZAP's internal user ID
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target_url": self.target_url,
            "scan_type": self.scan_type.value,
            "status": self.status.value,
            "progress": self.progress,
            "spider_id": self.spider_id,
            "ajax_spider_running": self.ajax_spider_running,
            "active_scan_id": self.active_scan_id,
            "alerts_count": len(self.alerts),
            "alerts_by_risk": self._count_alerts_by_risk(),
            "urls_found": len(self.urls_found),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "stats": self.stats,
            "checkpoint": self.checkpoint.to_dict() if self.checkpoint else None,
            "context_id": self.context_id,
            "is_resumable": self.checkpoint is not None and self.status == ZAPScanStatus.INTERRUPTED,
        }
    
    def _count_alerts_by_risk(self) -> Dict[str, int]:
        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for alert in self.alerts:
            if alert.risk_code == 3:
                counts["high"] += 1
            elif alert.risk_code == 2:
                counts["medium"] += 1
            elif alert.risk_code == 1:
                counts["low"] += 1
            else:
                counts["info"] += 1
        return counts


@dataclass
class ZAPScanConfig:
    """Configuration for a ZAP scan."""
    target_url: str
    scan_type: ZAPScanType = ZAPScanType.FULL_SCAN
    
    # Spider options
    max_depth: int = 5
    max_children: int = 0  # 0 = unlimited
    subtree_only: bool = True
    
    # AJAX Spider options
    enable_ajax_spider: bool = True
    ajax_spider_max_duration: int = 60  # minutes
    ajax_spider_max_crawl_depth: int = 10
    browser_id: str = "firefox-headless"  # firefox-headless, chrome-headless
    
    # Active scan options
    scan_policy: Optional[str] = None  # None = default policy
    scan_policy_config: Optional[ZAPScanPolicy] = None  # Custom policy config
    recurse: bool = True
    in_scope_only: bool = True
    delay_in_ms: int = 0
    max_scan_duration_mins: int = 0  # 0 = unlimited
    
    # Authentication - legacy simple fields
    context_name: Optional[str] = None
    user_name: Optional[str] = None
    
    # Authentication - full config
    auth_config: Optional[ZAPAuthConfig] = None
    
    # Scope
    include_regexes: List[str] = field(default_factory=list)
    exclude_regexes: List[str] = field(default_factory=list)
    
    # Resume from checkpoint
    resume_from_checkpoint: Optional[ZAPScanCheckpoint] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        # Handle nested dataclasses
        if self.scan_policy_config:
            result['scan_policy_config'] = self.scan_policy_config.to_dict()
        if self.auth_config:
            result['auth_config'] = self.auth_config.to_dict()
        if self.resume_from_checkpoint:
            result['resume_from_checkpoint'] = self.resume_from_checkpoint.to_dict()
        return result


# =============================================================================
# ZAP CLIENT
# =============================================================================

class ZAPClient:
    """
    Async client for OWASP ZAP API.
    Handles all communication with the ZAP daemon.
    """
    
    def __init__(self, base_url: str = None, api_key: str = None):
        self.base_url = (base_url or ZAP_BASE_URL).rstrip("/")
        self.api_key = api_key or ZAP_API_KEY
        self._client: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=ZAP_TIMEOUT)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
    
    def _build_url(self, component: str, view_or_action: str, endpoint: str) -> str:
        """Build ZAP API URL."""
        return f"{self.base_url}/JSON/{component}/{view_or_action}/{endpoint}/"
    
    def _add_api_key(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Add API key to parameters if configured."""
        if self.api_key:
            params["apikey"] = self.api_key
        return params
    
    async def _request(
        self, 
        component: str, 
        view_or_action: str, 
        endpoint: str, 
        params: Dict[str, Any] = None,
        timeout: float = None,
        retries: int = None
    ) -> Dict[str, Any]:
        """
        Make a request to ZAP API with retry logic.
        
        Uses exponential backoff with jitter for resilient connections.
        """
        if not self._client:
            self._client = httpx.AsyncClient(timeout=timeout or ZAP_TIMEOUT)
        
        url = self._build_url(component, view_or_action, endpoint)
        params = self._add_api_key(params or {})
        max_retries = retries if retries is not None else ZAP_MAX_RETRIES
        
        last_exception = None
        
        for attempt in range(max_retries + 1):
            try:
                response = await self._client.get(url, params=params, timeout=timeout or ZAP_TIMEOUT)
                response.raise_for_status()
                return response.json()
                
            except httpx.HTTPStatusError as e:
                # Don't retry on client errors (4xx)
                if 400 <= e.response.status_code < 500:
                    logger.error(f"ZAP API client error: {e.response.status_code} - {e.response.text}")
                    raise ZAPError(f"ZAP API error: {e.response.status_code}") from e
                
                last_exception = e
                logger.warning(f"ZAP API server error (attempt {attempt + 1}/{max_retries + 1}): {e.response.status_code}")
                
            except httpx.RequestError as e:
                last_exception = e
                logger.warning(f"ZAP connection error (attempt {attempt + 1}/{max_retries + 1}): {e}")
            
            except Exception as e:
                last_exception = e
                logger.warning(f"ZAP unexpected error (attempt {attempt + 1}/{max_retries + 1}): {e}")
            
            # Calculate delay with exponential backoff and jitter
            if attempt < max_retries:
                delay = min(
                    ZAP_RETRY_BASE_DELAY * (2 ** attempt) + random.uniform(0, 1),
                    ZAP_RETRY_MAX_DELAY
                )
                logger.info(f"Retrying ZAP request in {delay:.2f}s...")
                await asyncio.sleep(delay)
        
        # All retries exhausted
        if isinstance(last_exception, httpx.HTTPStatusError):
            raise ZAPError(f"ZAP API error after {max_retries + 1} attempts: {last_exception.response.status_code}") from last_exception
        elif isinstance(last_exception, httpx.RequestError):
            raise ZAPConnectionError(f"Cannot connect to ZAP after {max_retries + 1} attempts: {last_exception}") from last_exception
        else:
            raise ZAPError(f"ZAP request failed after {max_retries + 1} attempts: {last_exception}") from last_exception
    
    # -------------------------------------------------------------------------
    # Core API
    # -------------------------------------------------------------------------
    
    async def get_version(self) -> str:
        """Get ZAP version."""
        result = await self._request("core", "view", "version")
        return result.get("version", "unknown")
    
    async def get_hosts(self) -> List[str]:
        """Get all hosts that have been accessed."""
        result = await self._request("core", "view", "hosts")
        return result.get("hosts", [])
    
    async def get_sites(self) -> List[str]:
        """Get all sites that have been accessed."""
        result = await self._request("core", "view", "sites")
        return result.get("sites", [])
    
    async def get_urls(self, base_url: str = None) -> List[str]:
        """Get all URLs discovered for a site."""
        params = {}
        if base_url:
            params["baseurl"] = base_url
        result = await self._request("core", "view", "urls", params)
        return result.get("urls", [])
    
    async def access_url(self, url: str, follow_redirects: bool = True) -> Dict[str, Any]:
        """Access a URL through ZAP proxy (for adding to site tree)."""
        params = {"url": url, "followRedirects": str(follow_redirects).lower()}
        return await self._request("core", "action", "accessUrl", params)
    
    async def new_session(self, name: str = None, overwrite: bool = True) -> Dict[str, Any]:
        """Create a new ZAP session."""
        params = {"overwrite": str(overwrite).lower()}
        if name:
            params["name"] = name
        return await self._request("core", "action", "newSession", params)
    
    async def load_session(self, path: str) -> Dict[str, Any]:
        """Load an existing ZAP session."""
        return await self._request("core", "action", "loadSession", {"path": path})
    
    async def save_session(self, path: str, overwrite: bool = True) -> Dict[str, Any]:
        """Save the current ZAP session."""
        return await self._request("core", "action", "saveSession", {
            "name": path,
            "overwrite": str(overwrite).lower()
        })
    
    async def shutdown(self) -> Dict[str, Any]:
        """Shutdown ZAP (use with caution!)."""
        return await self._request("core", "action", "shutdown")
    
    # -------------------------------------------------------------------------
    # Spider API
    # -------------------------------------------------------------------------
    
    async def spider_scan(
        self, 
        url: str, 
        max_children: int = 0,
        recurse: bool = True,
        context_name: str = None,
        subtree_only: bool = True
    ) -> str:
        """Start a spider scan. Returns scan ID."""
        params = {
            "url": url,
            "maxChildren": str(max_children),
            "recurse": str(recurse).lower(),
            "subtreeOnly": str(subtree_only).lower(),
        }
        if context_name:
            params["contextName"] = context_name
        
        result = await self._request("spider", "action", "scan", params)
        return result.get("scan", "")
    
    async def spider_status(self, scan_id: str) -> int:
        """Get spider scan progress (0-100)."""
        result = await self._request("spider", "view", "status", {"scanId": scan_id})
        return int(result.get("status", 0))
    
    async def spider_results(self, scan_id: str) -> List[str]:
        """Get URLs found by spider."""
        result = await self._request("spider", "view", "results", {"scanId": scan_id})
        return result.get("results", [])
    
    async def spider_stop(self, scan_id: str) -> Dict[str, Any]:
        """Stop a spider scan."""
        return await self._request("spider", "action", "stop", {"scanId": scan_id})
    
    async def spider_pause(self, scan_id: str) -> Dict[str, Any]:
        """Pause a spider scan."""
        return await self._request("spider", "action", "pause", {"scanId": scan_id})
    
    async def spider_resume(self, scan_id: str) -> Dict[str, Any]:
        """Resume a paused spider scan."""
        return await self._request("spider", "action", "resume", {"scanId": scan_id})
    
    async def spider_set_option_max_depth(self, depth: int) -> Dict[str, Any]:
        """Set spider max depth."""
        return await self._request("spider", "action", "setOptionMaxDepth", {"Integer": str(depth)})
    
    async def spider_full_results(self, scan_id: str) -> Dict[str, Any]:
        """Get full spider results including metadata."""
        result = await self._request("spider", "view", "fullResults", {"scanId": scan_id})
        return result
    
    # -------------------------------------------------------------------------
    # AJAX Spider API
    # -------------------------------------------------------------------------
    
    async def ajax_spider_scan(
        self,
        url: str,
        in_scope: bool = True,
        context_name: str = None,
        subtree_only: bool = True
    ) -> Dict[str, Any]:
        """Start AJAX spider scan for JavaScript-heavy apps."""
        params = {
            "url": url,
            "inScope": str(in_scope).lower(),
            "subtreeOnly": str(subtree_only).lower(),
        }
        if context_name:
            params["contextName"] = context_name
        
        return await self._request("ajaxSpider", "action", "scan", params)
    
    async def ajax_spider_status(self) -> str:
        """Get AJAX spider status (running/stopped)."""
        result = await self._request("ajaxSpider", "view", "status")
        return result.get("status", "stopped")
    
    async def ajax_spider_results(self, start: int = 0, count: int = 100) -> List[Dict[str, Any]]:
        """Get AJAX spider results."""
        result = await self._request("ajaxSpider", "view", "results", {
            "start": str(start),
            "count": str(count)
        })
        return result.get("results", [])
    
    async def ajax_spider_stop(self) -> Dict[str, Any]:
        """Stop AJAX spider."""
        return await self._request("ajaxSpider", "action", "stop")
    
    async def ajax_spider_set_option_max_duration(self, mins: int) -> Dict[str, Any]:
        """Set max duration for AJAX spider."""
        return await self._request("ajaxSpider", "action", "setOptionMaxDuration", {"Integer": str(mins)})
    
    async def ajax_spider_set_option_browser_id(self, browser: str) -> Dict[str, Any]:
        """Set browser for AJAX spider (firefox-headless, chrome-headless)."""
        return await self._request("ajaxSpider", "action", "setOptionBrowserId", {"String": browser})
    
    # -------------------------------------------------------------------------
    # Active Scan API
    # -------------------------------------------------------------------------
    
    async def active_scan(
        self,
        url: str,
        recurse: bool = True,
        in_scope_only: bool = True,
        scan_policy_name: str = None,
        method: str = None,
        post_data: str = None,
        context_id: str = None,
        user_id: str = None
    ) -> str:
        """Start active vulnerability scan. Returns scan ID."""
        params = {
            "url": url,
            "recurse": str(recurse).lower(),
            "inScopeOnly": str(in_scope_only).lower(),
        }
        if scan_policy_name:
            params["scanPolicyName"] = scan_policy_name
        if method:
            params["method"] = method
        if post_data:
            params["postData"] = post_data
        if context_id:
            params["contextId"] = context_id
        if user_id:
            params["userId"] = user_id
        
        result = await self._request("ascan", "action", "scan", params, timeout=ZAP_LONG_TIMEOUT)
        return result.get("scan", "")
    
    async def active_scan_status(self, scan_id: str) -> int:
        """Get active scan progress (0-100)."""
        result = await self._request("ascan", "view", "status", {"scanId": scan_id})
        return int(result.get("status", 0))
    
    async def active_scan_stop(self, scan_id: str) -> Dict[str, Any]:
        """Stop an active scan."""
        return await self._request("ascan", "action", "stop", {"scanId": scan_id})
    
    async def active_scan_pause(self, scan_id: str) -> Dict[str, Any]:
        """Pause an active scan."""
        return await self._request("ascan", "action", "pause", {"scanId": scan_id})
    
    async def active_scan_resume(self, scan_id: str) -> Dict[str, Any]:
        """Resume a paused active scan."""
        return await self._request("ascan", "action", "resume", {"scanId": scan_id})
    
    async def active_scan_alerts_ids(self, scan_id: str) -> List[int]:
        """Get alert IDs for a scan."""
        result = await self._request("ascan", "view", "alertsIds", {"scanId": scan_id})
        return result.get("alertsIds", [])
    
    async def active_scan_messages_ids(self, scan_id: str) -> List[int]:
        """Get message IDs for a scan."""
        result = await self._request("ascan", "view", "messagesIds", {"scanId": scan_id})
        return result.get("messagesIds", [])
    
    async def active_scan_set_option_delay(self, delay_ms: int) -> Dict[str, Any]:
        """Set delay between requests in ms."""
        return await self._request("ascan", "action", "setOptionDelayInMs", {"Integer": str(delay_ms)})
    
    async def active_scan_set_option_max_duration(self, mins: int) -> Dict[str, Any]:
        """Set max scan duration in minutes (0 = unlimited)."""
        return await self._request("ascan", "action", "setOptionMaxScanDurationInMins", {"Integer": str(mins)})
    
    # -------------------------------------------------------------------------
    # Passive Scan API
    # -------------------------------------------------------------------------
    
    async def passive_scan_records_to_scan(self) -> int:
        """Get number of records left to scan passively."""
        result = await self._request("pscan", "view", "recordsToScan")
        return int(result.get("recordsToScan", 0))
    
    async def passive_scan_enable_all_scanners(self) -> Dict[str, Any]:
        """Enable all passive scanners."""
        return await self._request("pscan", "action", "enableAllScanners")
    
    async def passive_scan_disable_all_scanners(self) -> Dict[str, Any]:
        """Disable all passive scanners."""
        return await self._request("pscan", "action", "disableAllScanners")
    
    async def passive_scan_set_enabled(self, enabled: bool) -> Dict[str, Any]:
        """Enable or disable passive scanning."""
        return await self._request("pscan", "action", "setEnabled", {
            "enabled": str(enabled).lower()
        })
    
    # -------------------------------------------------------------------------
    # Alerts API
    # -------------------------------------------------------------------------
    
    async def get_alerts(
        self,
        base_url: str = None,
        start: int = 0,
        count: int = 100,
        risk_id: str = None
    ) -> List[Dict[str, Any]]:
        """Get security alerts."""
        params = {"start": str(start), "count": str(count)}
        if base_url:
            params["baseurl"] = base_url
        if risk_id:
            params["riskId"] = risk_id
        
        result = await self._request("alert", "view", "alerts", params)
        return result.get("alerts", [])
    
    async def get_alerts_summary(self, base_url: str = None) -> Dict[str, int]:
        """Get summary of alerts by risk level."""
        params = {}
        if base_url:
            params["baseurl"] = base_url
        
        result = await self._request("alert", "view", "alertsSummary", params)
        return result.get("alertsSummary", {})
    
    async def get_alert(self, alert_id: str) -> Dict[str, Any]:
        """Get a specific alert by ID."""
        result = await self._request("alert", "view", "alert", {"id": alert_id})
        return result.get("alert", {})
    
    async def delete_all_alerts(self) -> Dict[str, Any]:
        """Delete all alerts."""
        return await self._request("alert", "action", "deleteAllAlerts")
    
    async def delete_alert(self, alert_id: str) -> Dict[str, Any]:
        """Delete a specific alert."""
        return await self._request("alert", "action", "deleteAlert", {"id": alert_id})
    
    # -------------------------------------------------------------------------
    # Context API
    # -------------------------------------------------------------------------
    
    async def context_new(self, name: str) -> str:
        """Create a new context. Returns context ID."""
        result = await self._request("context", "action", "newContext", {"contextName": name})
        return result.get("contextId", "")
    
    async def context_include_in_context(self, context_name: str, regex: str) -> Dict[str, Any]:
        """Include URLs matching regex in context."""
        return await self._request("context", "action", "includeInContext", {
            "contextName": context_name,
            "regex": regex
        })
    
    async def context_exclude_from_context(self, context_name: str, regex: str) -> Dict[str, Any]:
        """Exclude URLs matching regex from context."""
        return await self._request("context", "action", "excludeFromContext", {
            "contextName": context_name,
            "regex": regex
        })
    
    async def context_list(self) -> List[str]:
        """List all contexts."""
        result = await self._request("context", "view", "contextList")
        return result.get("contextList", [])
    
    async def context_get(self, context_name: str) -> Dict[str, Any]:
        """Get context details."""
        return await self._request("context", "view", "context", {"contextName": context_name})
    
    async def context_remove(self, context_name: str) -> Dict[str, Any]:
        """Remove a context."""
        return await self._request("context", "action", "removeContext", {"contextName": context_name})
    
    # -------------------------------------------------------------------------
    # Authentication API - Comprehensive
    # -------------------------------------------------------------------------
    
    async def set_authentication_method(
        self,
        context_id: str,
        auth_method_name: str,
        auth_method_config_params: str
    ) -> Dict[str, Any]:
        """Set authentication method for a context."""
        return await self._request("authentication", "action", "setAuthenticationMethod", {
            "contextId": context_id,
            "authMethodName": auth_method_name,
            "authMethodConfigParams": auth_method_config_params
        })
    
    async def set_logged_in_indicator(self, context_id: str, regex: str) -> Dict[str, Any]:
        """Set regex pattern that indicates user is logged in."""
        return await self._request("authentication", "action", "setLoggedInIndicator", {
            "contextId": context_id,
            "loggedInIndicatorRegex": regex
        })
    
    async def set_logged_out_indicator(self, context_id: str, regex: str) -> Dict[str, Any]:
        """Set regex pattern that indicates user is logged out."""
        return await self._request("authentication", "action", "setLoggedOutIndicator", {
            "contextId": context_id,
            "loggedOutIndicatorRegex": regex
        })
    
    async def get_authentication_method(self, context_id: str) -> Dict[str, Any]:
        """Get current authentication method for context."""
        return await self._request("authentication", "view", "getAuthenticationMethod", {
            "contextId": context_id
        })
    
    async def get_supported_auth_methods(self) -> List[str]:
        """Get list of supported authentication methods."""
        result = await self._request("authentication", "view", "getSupportedAuthenticationMethods")
        return result.get("supportedMethods", [])
    
    # -------------------------------------------------------------------------
    # Users API - For authenticated scanning
    # -------------------------------------------------------------------------
    
    async def users_new_user(self, context_id: str, name: str) -> str:
        """Create a new user in context. Returns user ID."""
        result = await self._request("users", "action", "newUser", {
            "contextId": context_id,
            "name": name
        })
        return result.get("userId", "")
    
    async def users_set_user_enabled(self, context_id: str, user_id: str, enabled: bool) -> Dict[str, Any]:
        """Enable or disable a user."""
        return await self._request("users", "action", "setUserEnabled", {
            "contextId": context_id,
            "userId": user_id,
            "enabled": str(enabled).lower()
        })
    
    async def users_set_auth_credentials(
        self,
        context_id: str,
        user_id: str,
        auth_credentials_config_params: str
    ) -> Dict[str, Any]:
        """Set authentication credentials for a user."""
        return await self._request("users", "action", "setAuthenticationCredentials", {
            "contextId": context_id,
            "userId": user_id,
            "authCredentialsConfigParams": auth_credentials_config_params
        })
    
    async def users_list(self, context_id: str) -> List[Dict[str, Any]]:
        """List all users in a context."""
        result = await self._request("users", "view", "usersList", {"contextId": context_id})
        return result.get("usersList", [])
    
    async def users_remove_user(self, context_id: str, user_id: str) -> Dict[str, Any]:
        """Remove a user from context."""
        return await self._request("users", "action", "removeUser", {
            "contextId": context_id,
            "userId": user_id
        })
    
    async def forced_user_set(self, context_id: str, user_id: str) -> Dict[str, Any]:
        """Set the forced user for a context (all requests use this user)."""
        return await self._request("forcedUser", "action", "setForcedUser", {
            "contextId": context_id,
            "userId": user_id
        })
    
    async def forced_user_set_enabled(self, enabled: bool) -> Dict[str, Any]:
        """Enable or disable forced user mode."""
        return await self._request("forcedUser", "action", "setForcedUserModeEnabled", {
            "boolean": str(enabled).lower()
        })
    
    # -------------------------------------------------------------------------
    # Session Management API
    # -------------------------------------------------------------------------
    
    async def session_management_set_method(
        self,
        context_id: str,
        method_name: str,
        method_config_params: str = ""
    ) -> Dict[str, Any]:
        """Set session management method for context."""
        params = {"contextId": context_id, "methodName": method_name}
        if method_config_params:
            params["methodConfigParams"] = method_config_params
        return await self._request("sessionManagement", "action", "setSessionManagementMethod", params)
    
    async def http_sessions_create_empty_session(self, site: str, session_name: str) -> Dict[str, Any]:
        """Create an empty HTTP session."""
        return await self._request("httpSessions", "action", "createEmptySession", {
            "site": site,
            "session": session_name
        })
    
    async def http_sessions_set_active_session(self, site: str, session_name: str) -> Dict[str, Any]:
        """Set the active HTTP session for a site."""
        return await self._request("httpSessions", "action", "setActiveSession", {
            "site": site,
            "session": session_name
        })
    
    async def http_sessions_add_session_token(self, site: str, session_token: str) -> Dict[str, Any]:
        """Add a session token to track."""
        return await self._request("httpSessions", "action", "addSessionToken", {
            "site": site,
            "sessionToken": session_token
        })
    
    # -------------------------------------------------------------------------
    # Script API - For OAuth/OIDC and custom auth
    # -------------------------------------------------------------------------
    
    async def script_list(self) -> List[Dict[str, Any]]:
        """List all loaded scripts."""
        result = await self._request("script", "view", "listScripts")
        return result.get("scripts", [])
    
    async def script_load(
        self,
        script_name: str,
        script_type: str,
        script_engine: str,
        file_name: str,
        description: str = ""
    ) -> Dict[str, Any]:
        """Load a script from file."""
        return await self._request("script", "action", "load", {
            "scriptName": script_name,
            "scriptType": script_type,
            "scriptEngine": script_engine,
            "fileName": file_name,
            "scriptDescription": description
        })
    
    async def script_enable(self, script_name: str) -> Dict[str, Any]:
        """Enable a script."""
        return await self._request("script", "action", "enable", {"scriptName": script_name})
    
    async def script_disable(self, script_name: str) -> Dict[str, Any]:
        """Disable a script."""
        return await self._request("script", "action", "disable", {"scriptName": script_name})
    
    async def script_run_standalone(self, script_name: str) -> Dict[str, Any]:
        """Run a standalone script."""
        return await self._request("script", "action", "runStandAloneScript", {"scriptName": script_name})
    
    # -------------------------------------------------------------------------
    # Scan Policy API
    # -------------------------------------------------------------------------
    
    async def ascan_list_policies(self) -> List[Dict[str, Any]]:
        """List all scan policies."""
        result = await self._request("ascan", "view", "policies")
        return result.get("policies", [])
    
    async def ascan_add_policy(self, name: str, alert_threshold: str = None, attack_strength: str = None) -> str:
        """Add a new scan policy. Returns policy ID."""
        params = {"scanPolicyName": name}
        if alert_threshold:
            params["alertThreshold"] = alert_threshold
        if attack_strength:
            params["attackStrength"] = attack_strength
        result = await self._request("ascan", "action", "addScanPolicy", params)
        return result.get("policyId", "")
    
    async def ascan_remove_policy(self, name: str) -> Dict[str, Any]:
        """Remove a scan policy."""
        return await self._request("ascan", "action", "removeScanPolicy", {"scanPolicyName": name})
    
    async def ascan_update_policy(
        self,
        name: str,
        alert_threshold: str = None,
        attack_strength: str = None
    ) -> Dict[str, Any]:
        """Update scan policy settings."""
        params = {"scanPolicyName": name}
        if alert_threshold:
            params["alertThreshold"] = alert_threshold
        if attack_strength:
            params["attackStrength"] = attack_strength
        return await self._request("ascan", "action", "updateScanPolicy", params)
    
    async def ascan_list_scanners(self, policy_name: str = None) -> List[Dict[str, Any]]:
        """List all scanners, optionally for a specific policy."""
        params = {}
        if policy_name:
            params["scanPolicyName"] = policy_name
        result = await self._request("ascan", "view", "scanners", params)
        return result.get("scanners", [])
    
    async def ascan_set_scanner_alert_threshold(
        self,
        scanner_id: int,
        alert_threshold: str,
        policy_name: str = None
    ) -> Dict[str, Any]:
        """Set alert threshold for a scanner (OFF, LOW, MEDIUM, HIGH)."""
        params = {"id": str(scanner_id), "alertThreshold": alert_threshold}
        if policy_name:
            params["scanPolicyName"] = policy_name
        return await self._request("ascan", "action", "setScannerAlertThreshold", params)
    
    async def ascan_set_scanner_attack_strength(
        self,
        scanner_id: int,
        attack_strength: str,
        policy_name: str = None
    ) -> Dict[str, Any]:
        """Set attack strength for a scanner (LOW, MEDIUM, HIGH, INSANE)."""
        params = {"id": str(scanner_id), "attackStrength": attack_strength}
        if policy_name:
            params["scanPolicyName"] = policy_name
        return await self._request("ascan", "action", "setScannerAttackStrength", params)
    
    async def ascan_enable_scanners(self, scanner_ids: List[int], policy_name: str = None) -> Dict[str, Any]:
        """Enable specific scanners."""
        params = {"ids": ",".join(str(id) for id in scanner_ids)}
        if policy_name:
            params["scanPolicyName"] = policy_name
        return await self._request("ascan", "action", "enableScanners", params)
    
    async def ascan_disable_scanners(self, scanner_ids: List[int], policy_name: str = None) -> Dict[str, Any]:
        """Disable specific scanners."""
        params = {"ids": ",".join(str(id) for id in scanner_ids)}
        if policy_name:
            params["scanPolicyName"] = policy_name
        return await self._request("ascan", "action", "disableScanners", params)
    
    async def ascan_enable_all_scanners(self, policy_name: str = None) -> Dict[str, Any]:
        """Enable all scanners."""
        params = {}
        if policy_name:
            params["scanPolicyName"] = policy_name
        return await self._request("ascan", "action", "enableAllScanners", params)
    
    async def ascan_disable_all_scanners(self, policy_name: str = None) -> Dict[str, Any]:
        """Disable all scanners."""
        params = {}
        if policy_name:
            params["scanPolicyName"] = policy_name
        return await self._request("ascan", "action", "disableAllScanners", params)
    
    async def ascan_get_policy_alert_threshold(self, policy_name: str) -> str:
        """Get the default alert threshold for a policy."""
        result = await self._request("ascan", "view", "policyAlertThreshold", {"scanPolicyName": policy_name})
        return result.get("alertThreshold", "MEDIUM")
    
    async def ascan_get_policy_attack_strength(self, policy_name: str) -> str:
        """Get the default attack strength for a policy."""
        result = await self._request("ascan", "view", "policyAttackStrength", {"scanPolicyName": policy_name})
        return result.get("attackStrength", "MEDIUM")
    
    # -------------------------------------------------------------------------
    # Report API
    # -------------------------------------------------------------------------
    
    async def html_report(self) -> str:
        """Generate HTML report."""
        url = f"{self.base_url}/OTHER/core/other/htmlreport/"
        if self.api_key:
            url += f"?apikey={self.api_key}"
        
        if not self._client:
            self._client = httpx.AsyncClient(timeout=ZAP_TIMEOUT)
        
        response = await self._client.get(url, timeout=ZAP_LONG_TIMEOUT)
        return response.text
    
    async def json_report(self) -> Dict[str, Any]:
        """Generate JSON report."""
        url = f"{self.base_url}/OTHER/core/other/jsonreport/"
        if self.api_key:
            url += f"?apikey={self.api_key}"
        
        if not self._client:
            self._client = httpx.AsyncClient(timeout=ZAP_TIMEOUT)
        
        response = await self._client.get(url, timeout=ZAP_LONG_TIMEOUT)
        return response.json()
    
    async def xml_report(self) -> str:
        """Generate XML report."""
        url = f"{self.base_url}/OTHER/core/other/xmlreport/"
        if self.api_key:
            url += f"?apikey={self.api_key}"
        
        if not self._client:
            self._client = httpx.AsyncClient(timeout=ZAP_TIMEOUT)
        
        response = await self._client.get(url, timeout=ZAP_LONG_TIMEOUT)
        return response.text
    
    async def markdown_report(self) -> str:
        """Generate Markdown report."""
        url = f"{self.base_url}/OTHER/core/other/mdreport/"
        if self.api_key:
            url += f"?apikey={self.api_key}"
        
        if not self._client:
            self._client = httpx.AsyncClient(timeout=ZAP_TIMEOUT)
        
        response = await self._client.get(url, timeout=ZAP_LONG_TIMEOUT)
        return response.text
    
    # -------------------------------------------------------------------------
    # WebSocket API
    # -------------------------------------------------------------------------
    
    async def websocket_channels(self) -> List[Dict[str, Any]]:
        """Get all WebSocket channels."""
        result = await self._request("websocket", "view", "channels")
        return result.get("channels", [])
    
    async def websocket_messages(
        self,
        channel_id: int = None,
        start: int = None,
        count: int = None,
        payload_preview_length: int = None
    ) -> List[Dict[str, Any]]:
        """Get WebSocket messages, optionally filtered by channel."""
        params = {}
        if channel_id is not None:
            params["channelId"] = str(channel_id)
        if start is not None:
            params["start"] = str(start)
        if count is not None:
            params["count"] = str(count)
        if payload_preview_length is not None:
            params["payloadPreviewLength"] = str(payload_preview_length)
        result = await self._request("websocket", "view", "messages", params)
        return result.get("messages", [])
    
    async def websocket_message(self, message_id: int, channel_id: int) -> Dict[str, Any]:
        """Get a specific WebSocket message."""
        params = {"messageId": str(message_id), "channelId": str(channel_id)}
        result = await self._request("websocket", "view", "message", params)
        return result.get("message", {})
    
    async def websocket_break_text_message(self) -> Dict[str, Any]:
        """Get current break text message pattern."""
        result = await self._request("websocket", "view", "breakTextMessage")
        return result
    
    async def websocket_send_text_message(
        self,
        channel_id: int,
        outgoing: bool,
        message: str
    ) -> Dict[str, Any]:
        """Send a WebSocket text message."""
        params = {
            "channelId": str(channel_id),
            "outgoing": str(outgoing).lower(),
            "message": message
        }
        return await self._request("websocket", "action", "sendTextMessage", params)
    
    async def websocket_set_break_text_message(
        self,
        message: str,
        outgoing: bool
    ) -> Dict[str, Any]:
        """Set break on WebSocket text message pattern."""
        params = {
            "message": message,
            "outgoing": str(outgoing).lower()
        }
        return await self._request("websocket", "action", "setBreakTextMessage", params)
    
    # -------------------------------------------------------------------------
    # GraphQL API
    # -------------------------------------------------------------------------
    
    async def graphql_option_argjson_enabled(self) -> bool:
        """Check if JSON arguments are enabled for GraphQL testing."""
        result = await self._request("graphql", "view", "optionArgsType")
        return result.get("argsType", "INLINE") == "JSON"
    
    async def graphql_option_lenient_max_query_depth(self) -> int:
        """Get the maximum query depth for lenient mode."""
        result = await self._request("graphql", "view", "optionLenientMaxQueryDepthEnabled")
        return result.get("LenientMaxQueryDepthEnabled", False)
    
    async def graphql_option_max_args_depth(self) -> int:
        """Get the maximum argument depth."""
        result = await self._request("graphql", "view", "optionMaxArgsDepth")
        return int(result.get("MaxArgsDepth", 5))
    
    async def graphql_option_max_query_depth(self) -> int:
        """Get the maximum query depth."""
        result = await self._request("graphql", "view", "optionMaxQueryDepth")
        return int(result.get("MaxQueryDepth", 5))
    
    async def graphql_option_optional_args_enabled(self) -> bool:
        """Check if optional arguments are enabled."""
        result = await self._request("graphql", "view", "optionOptionalArgsEnabled")
        return result.get("OptionalArgsEnabled", False)
    
    async def graphql_option_query_split_type(self) -> str:
        """Get the query split type (LEAF, ROOT_FIELD, OPERATION)."""
        result = await self._request("graphql", "view", "optionQuerySplitType")
        return result.get("QuerySplitType", "LEAF")
    
    async def graphql_option_request_method(self) -> str:
        """Get the request method (POST_JSON, POST_GRAPHQL, GET)."""
        result = await self._request("graphql", "view", "optionRequestMethod")
        return result.get("RequestMethod", "POST_JSON")
    
    async def graphql_import_url(
        self,
        url: str,
        endpoint_url: str = None
    ) -> Dict[str, Any]:
        """
        Import a GraphQL schema from a URL (introspection query).
        The url parameter should be the endpoint that accepts GraphQL queries.
        """
        params = {"url": url}
        if endpoint_url:
            params["endurl"] = endpoint_url
        return await self._request("graphql", "action", "importUrl", params)
    
    async def graphql_import_file(
        self,
        file_path: str,
        endpoint_url: str = None
    ) -> Dict[str, Any]:
        """Import a GraphQL schema from a local file."""
        params = {"file": file_path}
        if endpoint_url:
            params["endurl"] = endpoint_url
        return await self._request("graphql", "action", "importFile", params)
    
    async def graphql_set_option_args_type(self, args_type: str) -> Dict[str, Any]:
        """Set argument type (INLINE, JSON, BOTH)."""
        return await self._request("graphql", "action", "setOptionArgsType", {"String": args_type})
    
    async def graphql_set_option_max_args_depth(self, depth: int) -> Dict[str, Any]:
        """Set maximum argument depth."""
        return await self._request("graphql", "action", "setOptionMaxArgsDepth", {"Integer": str(depth)})
    
    async def graphql_set_option_max_query_depth(self, depth: int) -> Dict[str, Any]:
        """Set maximum query depth."""
        return await self._request("graphql", "action", "setOptionMaxQueryDepth", {"Integer": str(depth)})
    
    async def graphql_set_option_optional_args(self, enabled: bool) -> Dict[str, Any]:
        """Enable/disable optional arguments."""
        return await self._request("graphql", "action", "setOptionOptionalArgsEnabled", {"Boolean": str(enabled).lower()})
    
    async def graphql_set_option_query_split_type(self, split_type: str) -> Dict[str, Any]:
        """Set query split type (LEAF, ROOT_FIELD, OPERATION)."""
        return await self._request("graphql", "action", "setOptionQuerySplitType", {"String": split_type})
    
    async def graphql_set_option_request_method(self, method: str) -> Dict[str, Any]:
        """Set request method (POST_JSON, POST_GRAPHQL, GET)."""
        return await self._request("graphql", "action", "setOptionRequestMethod", {"String": method})
    
    async def graphql_set_option_lenient_max_query_depth(self, enabled: bool) -> Dict[str, Any]:
        """Enable/disable lenient max query depth."""
        return await self._request("graphql", "action", "setOptionLenientMaxQueryDepthEnabled", {"Boolean": str(enabled).lower()})
    
    # -------------------------------------------------------------------------
    # OpenAPI/Swagger Import API
    # -------------------------------------------------------------------------
    
    async def openapi_import_url(
        self,
        url: str,
        host_override: str = None,
        context_id: int = None
    ) -> Dict[str, Any]:
        """
        Import an OpenAPI/Swagger definition from a URL.
        
        Args:
            url: URL to the OpenAPI/Swagger definition (JSON or YAML)
            host_override: Optional host to override the one in the definition
            context_id: Optional ZAP context to associate endpoints with
        """
        params = {"url": url}
        if host_override:
            params["hostOverride"] = host_override
        if context_id is not None:
            params["contextId"] = str(context_id)
        return await self._request("openapi", "action", "importUrl", params)
    
    async def openapi_import_file(
        self,
        file_path: str,
        target_url: str = None,
        context_id: int = None
    ) -> Dict[str, Any]:
        """
        Import an OpenAPI/Swagger definition from a local file.
        
        Args:
            file_path: Path to the OpenAPI/Swagger file
            target_url: Target URL if not specified in the definition
            context_id: Optional ZAP context to associate endpoints with
        """
        params = {"file": file_path}
        if target_url:
            params["target"] = target_url
        if context_id is not None:
            params["contextId"] = str(context_id)
        return await self._request("openapi", "action", "importFile", params)
    
    # -------------------------------------------------------------------------
    # Manual Request Editor API (Requester Add-on)
    # -------------------------------------------------------------------------
    
    async def send_request(
        self,
        request: str,
        follow_redirects: bool = True
    ) -> Dict[str, Any]:
        """
        Send a manual HTTP request through ZAP.
        
        Args:
            request: Full HTTP request including headers (raw format)
            follow_redirects: Whether to follow redirects
        
        Returns:
            Response details including status, headers, and body
        """
        params = {
            "request": request,
            "followRedirects": str(follow_redirects).lower()
        }
        return await self._request("core", "action", "sendRequest", params)
    
    async def get_message(self, message_id: int) -> Dict[str, Any]:
        """Get a specific message (request/response) by ID."""
        result = await self._request("core", "view", "message", {"id": str(message_id)})
        return result.get("message", {})
    
    async def get_messages(
        self,
        base_url: str = None,
        start: int = None,
        count: int = None
    ) -> List[Dict[str, Any]]:
        """Get messages from history, optionally filtered by base URL."""
        params = {}
        if base_url:
            params["baseurl"] = base_url
        if start is not None:
            params["start"] = str(start)
        if count is not None:
            params["count"] = str(count)
        result = await self._request("core", "view", "messages", params)
        return result.get("messages", [])
    
    async def get_request_header(self, message_id: int) -> str:
        """Get the request header for a specific message."""
        result = await self._request("core", "view", "requestHeader", {"id": str(message_id)})
        return result.get("requestHeader", "")
    
    async def get_request_body(self, message_id: int) -> str:
        """Get the request body for a specific message."""
        result = await self._request("core", "view", "requestBody", {"id": str(message_id)})
        return result.get("requestBody", "")
    
    async def get_response_header(self, message_id: int) -> str:
        """Get the response header for a specific message."""
        result = await self._request("core", "view", "responseHeader", {"id": str(message_id)})
        return result.get("responseHeader", "")
    
    async def get_response_body(self, message_id: int) -> str:
        """Get the response body for a specific message."""
        result = await self._request("core", "view", "responseBody", {"id": str(message_id)})
        return result.get("responseBody", "")
    
    async def set_option_default_user_agent(self, user_agent: str) -> Dict[str, Any]:
        """Set the default user agent for requests."""
        return await self._request("core", "action", "setOptionDefaultUserAgent", {"String": user_agent})
    
    async def get_option_default_user_agent(self) -> str:
        """Get the current default user agent."""
        result = await self._request("core", "view", "optionDefaultUserAgent")
        return result.get("DefaultUserAgent", "")
    
    # -------------------------------------------------------------------------
    # Context Management API (Extended)
    # -------------------------------------------------------------------------
    
    async def context_export(self, context_name: str, file_path: str) -> Dict[str, Any]:
        """Export a context to file."""
        return await self._request("context", "action", "exportContext", {
            "contextName": context_name,
            "contextFile": file_path
        })
    
    async def context_import(self, file_path: str) -> Dict[str, Any]:
        """Import a context from file."""
        return await self._request("context", "action", "importContext", {
            "contextFile": file_path
        })
    
    async def context_set_in_scope(self, context_name: str, in_scope: bool) -> Dict[str, Any]:
        """Set whether context is in scope."""
        return await self._request("context", "action", "setContextInScope", {
            "contextName": context_name,
            "booleanInScope": str(in_scope).lower()
        })
    
    async def context_get_include_regexes(self, context_name: str) -> List[str]:
        """Get include regexes for a context."""
        result = await self._request("context", "view", "includeRegexs", {"contextName": context_name})
        return result.get("includeRegexs", [])
    
    async def context_get_exclude_regexes(self, context_name: str) -> List[str]:
        """Get exclude regexes for a context."""
        result = await self._request("context", "view", "excludeRegexs", {"contextName": context_name})
        return result.get("excludeRegexs", [])
    
    async def context_get_technology_list(self) -> List[str]:
        """Get list of all available technologies."""
        result = await self._request("context", "view", "technologyList")
        return result.get("technologyList", [])
    
    async def context_get_included_technology(self, context_name: str) -> List[str]:
        """Get technologies included in context."""
        result = await self._request("context", "view", "includedTechnologyList", {"contextName": context_name})
        return result.get("includedTechnologyList", [])
    
    async def context_get_excluded_technology(self, context_name: str) -> List[str]:
        """Get technologies excluded from context."""
        result = await self._request("context", "view", "excludedTechnologyList", {"contextName": context_name})
        return result.get("excludedTechnologyList", [])
    
    async def context_include_technology(self, context_name: str, tech_names: List[str]) -> Dict[str, Any]:
        """Include technologies in context."""
        return await self._request("context", "action", "includeContextTechnologies", {
            "contextName": context_name,
            "technologyNames": ",".join(tech_names)
        })
    
    async def context_exclude_technology(self, context_name: str, tech_names: List[str]) -> Dict[str, Any]:
        """Exclude technologies from context."""
        return await self._request("context", "action", "excludeContextTechnologies", {
            "contextName": context_name,
            "technologyNames": ",".join(tech_names)
        })
    
    async def context_include_all_technologies(self, context_name: str) -> Dict[str, Any]:
        """Include all technologies in context."""
        return await self._request("context", "action", "includeAllContextTechnologies", {
            "contextName": context_name
        })
    
    async def context_exclude_all_technologies(self, context_name: str) -> Dict[str, Any]:
        """Exclude all technologies from context."""
        return await self._request("context", "action", "excludeAllContextTechnologies", {
            "contextName": context_name
        })
    
    # -------------------------------------------------------------------------
    # Forced Browse / Directory Discovery API
    # -------------------------------------------------------------------------
    
    async def forcedBrowse_scan(
        self,
        url: str,
        recurse: bool = True
    ) -> Dict[str, Any]:
        """
        Start a forced browse scan to discover hidden files/directories.
        Uses built-in wordlists.
        """
        params = {"url": url, "recurse": str(recurse).lower()}
        return await self._request("forcedBrowse", "action", "scan", params)
    
    async def forcedBrowse_scan_site(self, site: str, recurse: bool = True) -> Dict[str, Any]:
        """Forced browse a site."""
        params = {"site": site, "recurse": str(recurse).lower()}
        return await self._request("forcedBrowse", "action", "scanSite", params)
    
    async def forcedBrowse_status(self) -> int:
        """Get forced browse scan progress (0-100)."""
        result = await self._request("forcedBrowse", "view", "status")
        return int(result.get("status", 0))
    
    async def forcedBrowse_stop(self) -> Dict[str, Any]:
        """Stop forced browse scan."""
        return await self._request("forcedBrowse", "action", "stop")
    
    async def forcedBrowse_pause(self) -> Dict[str, Any]:
        """Pause forced browse scan."""
        return await self._request("forcedBrowse", "action", "pause")
    
    async def forcedBrowse_unpause(self) -> Dict[str, Any]:
        """Resume forced browse scan."""
        return await self._request("forcedBrowse", "action", "unpause")
    
    async def forcedBrowse_add_custom_file(self, file_path: str) -> Dict[str, Any]:
        """Add a custom wordlist file for forced browsing."""
        return await self._request("forcedBrowse", "action", "addCustomForceBrowseFile", {
            "file": file_path
        })
    
    async def forcedBrowse_set_option_fail_case_string(self, fail_string: str) -> Dict[str, Any]:
        """Set the string that indicates a failed request (404 detection)."""
        return await self._request("forcedBrowse", "action", "setOptionFailCaseString", {
            "String": fail_string
        })
    
    async def forcedBrowse_set_option_threads(self, threads: int) -> Dict[str, Any]:
        """Set number of threads for forced browsing."""
        return await self._request("forcedBrowse", "action", "setOptionThreadPerScan", {
            "Integer": str(threads)
        })
    
    async def forcedBrowse_set_option_recursive(self, recursive: bool) -> Dict[str, Any]:
        """Enable/disable recursive forced browsing."""
        return await self._request("forcedBrowse", "action", "setOptionRecursive", {
            "Boolean": str(recursive).lower()
        })
    
    async def forcedBrowse_get_option_default_file(self) -> str:
        """Get the default wordlist file."""
        result = await self._request("forcedBrowse", "view", "optionDefaultFile")
        return result.get("DefaultFile", "")
    
    async def forcedBrowse_list_files(self) -> List[str]:
        """List available wordlist files."""
        result = await self._request("forcedBrowse", "view", "forcedBrowseFilesList")
        return result.get("forcedBrowseFilesList", [])
    
    # -------------------------------------------------------------------------
    # Script Console API (Extended)
    # -------------------------------------------------------------------------
    
    async def script_list_engines(self) -> List[Dict[str, Any]]:
        """List available script engines (JavaScript, Python, etc.)."""
        result = await self._request("script", "view", "listEngines")
        return result.get("listEngines", [])
    
    async def script_list_types(self) -> List[str]:
        """List available script types (standalone, proxy, active, passive, etc.)."""
        result = await self._request("script", "view", "listTypes")
        return result.get("listTypes", [])
    
    async def script_global_var(self, var_key: str) -> str:
        """Get a global script variable."""
        result = await self._request("script", "view", "globalVar", {"varKey": var_key})
        return result.get("globalVar", "")
    
    async def script_global_vars(self) -> Dict[str, str]:
        """Get all global script variables."""
        result = await self._request("script", "view", "globalVars")
        return result.get("globalVars", {})
    
    async def script_global_custom_var(self, var_key: str) -> str:
        """Get a global custom variable."""
        result = await self._request("script", "view", "globalCustomVar", {"varKey": var_key})
        return result.get("globalCustomVar", "")
    
    async def script_global_custom_vars(self) -> Dict[str, str]:
        """Get all global custom variables."""
        result = await self._request("script", "view", "globalCustomVars")
        return result.get("globalCustomVars", {})
    
    async def script_set_global_var(self, var_key: str, var_value: str) -> Dict[str, Any]:
        """Set a global script variable."""
        return await self._request("script", "action", "setGlobalVar", {
            "varKey": var_key,
            "varValue": var_value
        })
    
    async def script_clear_global_var(self, var_key: str) -> Dict[str, Any]:
        """Clear a global script variable."""
        return await self._request("script", "action", "clearGlobalVar", {"varKey": var_key})
    
    async def script_clear_global_vars(self) -> Dict[str, Any]:
        """Clear all global script variables."""
        return await self._request("script", "action", "clearGlobalVars")
    
    async def script_clear_global_custom_var(self, var_key: str) -> Dict[str, Any]:
        """Clear a global custom variable."""
        return await self._request("script", "action", "clearGlobalCustomVar", {"varKey": var_key})
    
    async def script_remove(self, script_name: str) -> Dict[str, Any]:
        """Remove a script."""
        return await self._request("script", "action", "remove", {"scriptName": script_name})

    # -------------------------------------------------------------------------
    # Passive Scan Rule Configuration API
    # -------------------------------------------------------------------------
    
    async def pscan_scanners(self) -> List[Dict[str, Any]]:
        """List all passive scan rules/scanners."""
        result = await self._request("pscan", "view", "scanners")
        return result.get("scanners", [])
    
    async def pscan_scanner_alerts_ids(self, scanner_id: int) -> List[int]:
        """Get alert IDs generated by a specific passive scanner."""
        result = await self._request("pscan", "view", "scannerAlertsIds", {"id": str(scanner_id)})
        return result.get("scannerAlertsIds", [])
    
    async def pscan_records_to_scan(self) -> int:
        """Get number of records left to scan."""
        result = await self._request("pscan", "view", "recordsToScan")
        return int(result.get("recordsToScan", 0))
    
    async def pscan_current_rule(self) -> Dict[str, Any]:
        """Get the current passive scan rule being executed."""
        result = await self._request("pscan", "view", "currentRule")
        return result.get("currentRule", {})
    
    async def pscan_current_tasks(self) -> Dict[str, Any]:
        """Get current passive scan tasks."""
        result = await self._request("pscan", "view", "currentTasks")
        return result
    
    async def pscan_max_alerts_per_rule(self) -> int:
        """Get max alerts per rule."""
        result = await self._request("pscan", "view", "maxAlertsPerRule")
        return int(result.get("maxAlertsPerRule", 0))
    
    async def pscan_scan_only_in_scope(self) -> bool:
        """Check if passive scanning is limited to scope."""
        result = await self._request("pscan", "view", "scanOnlyInScope")
        return result.get("scanOnlyInScope", "false").lower() == "true"
    
    async def pscan_enable_all_scanners(self) -> Dict[str, Any]:
        """Enable all passive scan rules."""
        return await self._request("pscan", "action", "enableAllScanners")
    
    async def pscan_disable_all_scanners(self) -> Dict[str, Any]:
        """Disable all passive scan rules."""
        return await self._request("pscan", "action", "disableAllScanners")
    
    async def pscan_enable_scanners(self, ids: str) -> Dict[str, Any]:
        """Enable specific passive scanners by comma-separated IDs."""
        return await self._request("pscan", "action", "enableScanners", {"ids": ids})
    
    async def pscan_disable_scanners(self, ids: str) -> Dict[str, Any]:
        """Disable specific passive scanners by comma-separated IDs."""
        return await self._request("pscan", "action", "disableScanners", {"ids": ids})
    
    async def pscan_set_scanner_alert_threshold(self, scanner_id: int, threshold: str) -> Dict[str, Any]:
        """Set alert threshold for a scanner (OFF, DEFAULT, LOW, MEDIUM, HIGH)."""
        return await self._request("pscan", "action", "setScannerAlertThreshold", {
            "id": str(scanner_id),
            "alertThreshold": threshold
        })
    
    async def pscan_set_max_alerts_per_rule(self, max_alerts: int) -> Dict[str, Any]:
        """Set maximum alerts per passive scan rule."""
        return await self._request("pscan", "action", "setMaxAlertsPerRule", {
            "maxAlerts": str(max_alerts)
        })
    
    async def pscan_set_scan_only_in_scope(self, only_in_scope: bool) -> Dict[str, Any]:
        """Set whether to scan only URLs in scope."""
        return await self._request("pscan", "action", "setScanOnlyInScope", {
            "onlyInScope": str(only_in_scope).lower()
        })
    
    async def pscan_clear_queue(self) -> Dict[str, Any]:
        """Clear the passive scan queue."""
        return await self._request("pscan", "action", "clearQueue")
    
    # -------------------------------------------------------------------------
    # Statistics & Progress Dashboard API
    # -------------------------------------------------------------------------
    
    async def stats_site_stats(self, site: str = None, in_scope: bool = False) -> Dict[str, Any]:
        """Get statistics for a site or all sites."""
        params = {}
        if site:
            params["site"] = site
        if in_scope:
            params["inScope"] = "true"
        result = await self._request("stats", "view", "siteStats", params)
        return result.get("siteStats", {})
    
    async def stats_all_sites_stats(self) -> List[Dict[str, Any]]:
        """Get statistics for all sites."""
        result = await self._request("stats", "view", "allSitesStats")
        return result.get("allSitesStats", [])
    
    async def stats_option_statsd_enabled(self) -> bool:
        """Check if statsd is enabled."""
        result = await self._request("stats", "view", "optionStatsdEnabled")
        return result.get("StatsdEnabled", "false").lower() == "true"
    
    async def stats_clear(self, site: str = None) -> Dict[str, Any]:
        """Clear statistics for a site or all sites."""
        params = {}
        if site:
            params["site"] = site
        return await self._request("stats", "action", "clearStats", params)
    
    async def core_number_of_alerts(self, base_url: str = None, risk_id: int = None) -> int:
        """Get number of alerts, optionally filtered by URL and risk."""
        params = {}
        if base_url:
            params["baseurl"] = base_url
        if risk_id is not None:
            params["riskId"] = str(risk_id)
        result = await self._request("core", "view", "numberOfAlerts", params)
        return int(result.get("numberOfAlerts", 0))
    
    async def core_number_of_messages(self) -> int:
        """Get total number of HTTP messages."""
        result = await self._request("core", "view", "numberOfMessages")
        return int(result.get("numberOfMessages", 0))
    
    async def core_hosts(self) -> List[str]:
        """Get list of all hosts."""
        result = await self._request("core", "view", "hosts")
        return result.get("hosts", [])
    
    async def core_sites(self) -> List[str]:
        """Get list of all sites in the site tree."""
        result = await self._request("core", "view", "sites")
        return result.get("sites", [])
    
    async def core_urls(self, base_url: str = None) -> List[str]:
        """Get URLs, optionally filtered by base URL."""
        params = {}
        if base_url:
            params["baseurl"] = base_url
        result = await self._request("core", "view", "urls", params)
        return result.get("urls", [])
    
    async def core_mode(self) -> str:
        """Get current ZAP mode (safe, protect, standard, attack)."""
        result = await self._request("core", "view", "mode")
        return result.get("mode", "standard")
    
    async def core_version(self) -> str:
        """Get ZAP version."""
        result = await self._request("core", "view", "version")
        return result.get("version", "unknown")
    
    async def core_zap_home_path(self) -> str:
        """Get ZAP home directory path."""
        result = await self._request("core", "view", "zapHomePath")
        return result.get("zapHomePath", "")
    
    async def spider_status(self, scan_id: str = None) -> int:
        """Get spider progress (0-100)."""
        params = {}
        if scan_id:
            params["scanId"] = scan_id
        result = await self._request("spider", "view", "status", params)
        return int(result.get("status", 0))
    
    async def spider_results(self, scan_id: str = None) -> List[str]:
        """Get URLs found by the spider."""
        params = {}
        if scan_id:
            params["scanId"] = scan_id
        result = await self._request("spider", "view", "results", params)
        return result.get("results", [])
    
    async def ascan_status(self, scan_id: str = None) -> int:
        """Get active scan progress (0-100)."""
        params = {}
        if scan_id:
            params["scanId"] = scan_id
        result = await self._request("ascan", "view", "status", params)
        return int(result.get("status", 0))
    
    async def ascan_alerts_ids(self, scan_id: str = None) -> List[int]:
        """Get alert IDs from an active scan."""
        params = {}
        if scan_id:
            params["scanId"] = scan_id
        result = await self._request("ascan", "view", "alertsIds", params)
        return result.get("alertsIds", [])
    
    async def ascan_scans(self) -> List[Dict[str, Any]]:
        """Get list of all active scans."""
        result = await self._request("ascan", "view", "scans")
        return result.get("scans", [])
    
    async def ascan_messages_ids(self, scan_id: str) -> List[int]:
        """Get message IDs from an active scan."""
        result = await self._request("ascan", "view", "messagesIds", {"scanId": scan_id})
        return result.get("messagesIds", [])


# =============================================================================
# EXCEPTIONS
# =============================================================================

class ZAPError(Exception):
    """Base exception for ZAP errors."""
    pass


class ZAPConnectionError(ZAPError):
    """Cannot connect to ZAP."""
    pass


class ZAPScanError(ZAPError):
    """Error during scan."""
    pass


# =============================================================================
# ZAP SCANNER SERVICE
# =============================================================================

class ZAPScanner:
    """
    High-level ZAP scanner that orchestrates spider, active scan, and passive analysis.
    Provides streaming progress updates and finding consolidation.
    
    Features:
    - Database persistence for scan state (crash recovery)
    - In-memory caching for active scans
    - Retry logic on connection failures
    """
    
    def __init__(self, base_url: str = None, api_key: str = None):
        self.base_url = base_url or ZAP_BASE_URL
        self.api_key = api_key or ZAP_API_KEY
        self._sessions: Dict[str, ZAPScanSession] = {}
    
    def client(self) -> ZAPClient:
        """Get a ZAPClient instance for direct API calls."""
        return ZAPClient(self.base_url, self.api_key)
    
    # -------------------------------------------------------------------------
    # Database Persistence Methods
    # -------------------------------------------------------------------------
    
    def _get_db_session(self):
        """Get a database session. Import here to avoid circular imports."""
        from backend.core.database import SessionLocal
        return SessionLocal()
    
    async def _persist_scan_to_db(
        self,
        session: ZAPScanSession,
        user_id: int,
        project_id: Optional[int] = None
    ) -> int:
        """
        Persist scan session to database.
        Returns the database record ID.
        """
        from backend.models import models
        
        db = self._get_db_session()
        try:
            # Check if scan already exists
            existing = db.query(models.ZAPScan).filter(
                models.ZAPScan.session_id == session.id
            ).first()
            
            alerts_by_risk = session._count_alerts_by_risk()
            alerts_data = [asdict(a) if hasattr(a, '__dataclass_fields__') else a.to_finding_dict() for a in session.alerts]
            
            if existing:
                # Update existing record
                existing.status = session.status.value
                existing.urls_found = len(session.urls_found)
                existing.alerts_high = alerts_by_risk.get("high", 0)
                existing.alerts_medium = alerts_by_risk.get("medium", 0)
                existing.alerts_low = alerts_by_risk.get("low", 0)
                existing.alerts_info = alerts_by_risk.get("info", 0)
                existing.alerts_data = alerts_data
                existing.urls_data = session.urls_found
                existing.stats = session.stats
                if session.completed_at:
                    existing.completed_at = datetime.fromisoformat(session.completed_at)
                db.commit()
                return existing.id
            else:
                # Create new record
                db_scan = models.ZAPScan(
                    session_id=session.id,
                    user_id=user_id,
                    project_id=project_id,
                    title=f"ZAP Scan: {session.target_url[:50]}",
                    target_url=session.target_url,
                    scan_type=session.scan_type.value,
                    status=session.status.value,
                    started_at=datetime.fromisoformat(session.started_at) if session.started_at else None,
                    completed_at=datetime.fromisoformat(session.completed_at) if session.completed_at else None,
                    urls_found=len(session.urls_found),
                    alerts_high=alerts_by_risk.get("high", 0),
                    alerts_medium=alerts_by_risk.get("medium", 0),
                    alerts_low=alerts_by_risk.get("low", 0),
                    alerts_info=alerts_by_risk.get("info", 0),
                    alerts_data=alerts_data,
                    urls_data=session.urls_found,
                    stats=session.stats,
                )
                db.add(db_scan)
                db.commit()
                db.refresh(db_scan)
                return db_scan.id
        except Exception as e:
            logger.error(f"Failed to persist ZAP scan to database: {e}")
            db.rollback()
            raise
        finally:
            db.close()
    
    async def _update_scan_status(
        self,
        session_id: str,
        status: ZAPScanStatus,
        error: Optional[str] = None
    ):
        """Update scan status in database."""
        from backend.models import models
        
        db = self._get_db_session()
        try:
            scan = db.query(models.ZAPScan).filter(
                models.ZAPScan.session_id == session_id
            ).first()
            
            if scan:
                scan.status = status.value
                if status in (ZAPScanStatus.COMPLETED, ZAPScanStatus.FAILED, ZAPScanStatus.STOPPED):
                    scan.completed_at = datetime.utcnow()
                if error:
                    if scan.stats is None:
                        scan.stats = {}
                    scan.stats["error"] = error
                db.commit()
        except Exception as e:
            logger.error(f"Failed to update ZAP scan status: {e}")
            db.rollback()
        finally:
            db.close()
    
    async def _load_scan_from_db(self, session_id: str) -> Optional[ZAPScanSession]:
        """Load a scan session from database."""
        from backend.models import models
        
        db = self._get_db_session()
        try:
            scan = db.query(models.ZAPScan).filter(
                models.ZAPScan.session_id == session_id
            ).first()
            
            if not scan:
                return None
            
            # Reconstruct ZAPScanSession from database
            session = ZAPScanSession(
                id=scan.session_id,
                target_url=scan.target_url,
                scan_type=ZAPScanType(scan.scan_type),
                status=ZAPScanStatus(scan.status),
                started_at=scan.started_at.isoformat() if scan.started_at else None,
                completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
                urls_found=scan.urls_data or [],
                stats=scan.stats or {},
            )
            
            # Reconstruct alerts from stored data
            if scan.alerts_data:
                for alert_data in scan.alerts_data:
                    session.alerts.append(ZAPAlert.from_zap_response(alert_data))
            
            return session
        except Exception as e:
            logger.error(f"Failed to load ZAP scan from database: {e}")
            return None
        finally:
            db.close()
    
    async def get_scan_from_db(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Get a scan by database ID."""
        from backend.models import models
        
        db = self._get_db_session()
        try:
            scan = db.query(models.ZAPScan).filter(
                models.ZAPScan.id == scan_id
            ).first()
            
            if not scan:
                return None
            
            return {
                "id": scan.id,
                "session_id": scan.session_id,
                "target_url": scan.target_url,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "urls_found": scan.urls_found,
                "alerts_high": scan.alerts_high,
                "alerts_medium": scan.alerts_medium,
                "alerts_low": scan.alerts_low,
                "alerts_info": scan.alerts_info,
                "alerts_data": scan.alerts_data,
                "stats": scan.stats,
            }
        finally:
            db.close()
    
    async def list_scans_from_db(
        self,
        user_id: int,
        project_id: Optional[int] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List scans from database."""
        from backend.models import models
        
        db = self._get_db_session()
        try:
            query = db.query(models.ZAPScan).filter(
                models.ZAPScan.user_id == user_id
            )
            
            if project_id:
                query = query.filter(models.ZAPScan.project_id == project_id)
            
            scans = query.order_by(models.ZAPScan.created_at.desc()).limit(limit).all()
            
            return [{
                "id": s.id,
                "session_id": s.session_id,
                "title": s.title,
                "target_url": s.target_url,
                "scan_type": s.scan_type,
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "alerts": {
                    "high": s.alerts_high,
                    "medium": s.alerts_medium,
                    "low": s.alerts_low,
                    "info": s.alerts_info,
                    "total": (s.alerts_high or 0) + (s.alerts_medium or 0) + (s.alerts_low or 0) + (s.alerts_info or 0),
                },
            } for s in scans]
        finally:
            db.close()
    
    # -------------------------------------------------------------------------
    # Health & Status
    # -------------------------------------------------------------------------
    
    async def is_available(self) -> Tuple[bool, str]:
        """Check if ZAP is available and get version."""
        try:
            async with ZAPClient(self.base_url, self.api_key) as client:
                version = await client.get_version()
                return True, version
        except Exception as e:
            return False, str(e)
    
    async def get_health(self) -> Dict[str, Any]:
        """Get ZAP health status."""
        available, version_or_error = await self.is_available()
        return {
            "available": available,
            "version": version_or_error if available else None,
            "error": version_or_error if not available else None,
            "base_url": self.base_url,
            "active_sessions": len(self._sessions),
        }
    
    # -------------------------------------------------------------------------
    # Authentication Setup
    # -------------------------------------------------------------------------
    
    async def setup_authentication(
        self,
        auth_config: ZAPAuthConfig,
        target_url: str,
        context_name: str = None
    ) -> Dict[str, Any]:
        """
        Configure authentication for a scan context.
        
        Supports:
        - Form-based authentication
        - HTTP Basic authentication
        - JSON-based authentication (API login)
        - Script-based authentication (OAuth/OIDC)
        
        Returns context_id and user_id for use in scans.
        """
        context_name = context_name or f"auth_context_{uuid.uuid4().hex[:8]}"
        
        async with ZAPClient(self.base_url, self.api_key) as client:
            # Create context
            context_id = await client.context_new(context_name)
            logger.info(f"Created ZAP context: {context_name} (ID: {context_id})")
            
            # Add target URL to context scope
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            scope_regex = f"{parsed.scheme}://{parsed.netloc}.*"
            await client.context_include_in_context(context_name, scope_regex)
            
            # Set session management to cookie-based
            await client.session_management_set_method(context_id, "cookieBasedSessionManagement")
            
            # Configure authentication method based on type
            auth_method_config = ""
            
            if auth_config.method == ZAPAuthMethod.FORM_BASED:
                # Form-based authentication
                auth_method_config = f"loginUrl={auth_config.login_url}"
                if auth_config.login_request_data:
                    auth_method_config += f"&loginRequestData={auth_config.login_request_data}"
                await client.set_authentication_method(context_id, "formBasedAuthentication", auth_method_config)
                
            elif auth_config.method == ZAPAuthMethod.HTTP_BASIC:
                # HTTP Basic authentication
                auth_method_config = f"hostname={auth_config.hostname or parsed.netloc}"
                if auth_config.realm:
                    auth_method_config += f"&realm={auth_config.realm}"
                if auth_config.port:
                    auth_method_config += f"&port={auth_config.port}"
                await client.set_authentication_method(context_id, "httpAuthentication", auth_method_config)
                
            elif auth_config.method == ZAPAuthMethod.JSON_BASED:
                # JSON-based authentication (API)
                auth_method_config = f"loginUrl={auth_config.login_url or auth_config.token_endpoint}"
                if auth_config.json_template:
                    auth_method_config += f"&loginRequestData={auth_config.json_template}"
                await client.set_authentication_method(context_id, "jsonBasedAuthentication", auth_method_config)
                
            elif auth_config.method == ZAPAuthMethod.SCRIPT_BASED:
                # Script-based authentication (OAuth/OIDC/custom)
                if auth_config.script_name:
                    auth_method_config = f"scriptName={auth_config.script_name}"
                    if auth_config.script_params:
                        for key, value in auth_config.script_params.items():
                            auth_method_config += f"&{key}={value}"
                    await client.set_authentication_method(context_id, "scriptBasedAuthentication", auth_method_config)
            
            # Set login indicators
            if auth_config.logged_in_indicator:
                await client.set_logged_in_indicator(context_id, auth_config.logged_in_indicator)
            
            if auth_config.logged_out_indicator:
                await client.set_logged_out_indicator(context_id, auth_config.logged_out_indicator)
            
            # Create user and set credentials
            user_id = None
            if auth_config.username:
                user_name = auth_config.username.split("@")[0][:20]  # Clean username
                user_id = await client.users_new_user(context_id, user_name)
                
                # Set credentials based on auth method
                if auth_config.method in (ZAPAuthMethod.FORM_BASED, ZAPAuthMethod.HTTP_BASIC):
                    creds = f"username={auth_config.username}&password={auth_config.password or ''}"
                elif auth_config.method == ZAPAuthMethod.JSON_BASED:
                    creds = f"username={auth_config.username}&password={auth_config.password or ''}"
                else:
                    creds = f"username={auth_config.username}"
                
                await client.users_set_auth_credentials(context_id, user_id, creds)
                await client.users_set_user_enabled(context_id, user_id, True)
                
                # Set as forced user for all requests
                await client.forced_user_set(context_id, user_id)
                await client.forced_user_set_enabled(True)
            
            return {
                "context_id": context_id,
                "context_name": context_name,
                "user_id": user_id,
                "auth_method": auth_config.method.value,
                "scope_regex": scope_regex,
            }
    
    async def setup_oauth_authentication(
        self,
        target_url: str,
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        scope: str = "openid profile",
        grant_type: str = "client_credentials",
        context_name: str = None
    ) -> Dict[str, Any]:
        """
        Convenience method for OAuth2 client credentials flow.
        
        For OAuth2 Authorization Code flow, use setup_authentication with
        script-based auth and a custom OAuth script.
        """
        # For client credentials, we can obtain token directly and inject it
        import httpx
        
        # Get OAuth token
        async with httpx.AsyncClient() as http_client:
            token_response = await http_client.post(
                token_endpoint,
                data={
                    "grant_type": grant_type,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": scope,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if token_response.status_code != 200:
                raise ZAPError(f"Failed to obtain OAuth token: {token_response.text}")
            
            token_data = token_response.json()
            access_token = token_data.get("access_token")
        
        if not access_token:
            raise ZAPError("No access_token in OAuth response")
        
        # Configure ZAP to use the token
        context_name = context_name or f"oauth_context_{uuid.uuid4().hex[:8]}"
        
        async with ZAPClient(self.base_url, self.api_key) as client:
            # Create context
            context_id = await client.context_new(context_name)
            
            # Add target to scope
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            scope_regex = f"{parsed.scheme}://{parsed.netloc}.*"
            await client.context_include_in_context(context_name, scope_regex)
            
            # Set a custom header with the token using a replacer rule
            # This adds Authorization header to all requests in scope
            await client._request("replacer", "action", "addRule", {
                "description": "OAuth Bearer Token",
                "enabled": "true",
                "matchType": "REQ_HEADER",
                "matchRegex": "false",
                "matchString": "Authorization",
                "replacement": f"Bearer {access_token}",
                "initiators": "",
                "url": scope_regex,
            })
            
            return {
                "context_id": context_id,
                "context_name": context_name,
                "auth_method": "oauth2_client_credentials",
                "token_type": token_data.get("token_type", "Bearer"),
                "expires_in": token_data.get("expires_in"),
                "scope": scope,
            }
    
    async def list_auth_methods(self) -> List[str]:
        """Get list of supported authentication methods."""
        async with ZAPClient(self.base_url, self.api_key) as client:
            return await client.get_supported_auth_methods()
    
    async def remove_authentication_context(self, context_name: str) -> bool:
        """Remove an authentication context."""
        try:
            async with ZAPClient(self.base_url, self.api_key) as client:
                await client.forced_user_set_enabled(False)
                await client.context_remove(context_name)
                return True
        except Exception as e:
            logger.error(f"Failed to remove auth context: {e}")
            return False
    
    # -------------------------------------------------------------------------
    # Scan Policy Management
    # -------------------------------------------------------------------------
    
    async def list_scan_policies(self) -> List[Dict[str, Any]]:
        """List all available scan policies."""
        async with ZAPClient(self.base_url, self.api_key) as client:
            return await client.ascan_list_policies()
    
    async def create_scan_policy(self, policy: ZAPScanPolicy) -> Dict[str, Any]:
        """
        Create a new scan policy with custom settings.
        
        Args:
            policy: ZAPScanPolicy configuration
            
        Returns:
            Policy details including ID
        """
        async with ZAPClient(self.base_url, self.api_key) as client:
            # Create the policy
            policy_id = await client.ascan_add_policy(
                policy.name,
                alert_threshold=policy.default_alert_threshold,
                attack_strength=policy.default_attack_strength
            )
            
            # Configure scanners if specified
            if policy.disabled_scanners:
                await client.ascan_disable_scanners(policy.disabled_scanners, policy.name)
            
            if policy.enabled_scanners:
                await client.ascan_enable_scanners(policy.enabled_scanners, policy.name)
            
            # Apply scanner-specific configs
            if policy.scanner_configs:
                for scanner_id, config in policy.scanner_configs.items():
                    if "alertThreshold" in config:
                        await client.ascan_set_scanner_alert_threshold(
                            scanner_id, config["alertThreshold"], policy.name
                        )
                    if "attackStrength" in config:
                        await client.ascan_set_scanner_attack_strength(
                            scanner_id, config["attackStrength"], policy.name
                        )
            
            return {
                "policy_id": policy_id,
                "name": policy.name,
                "attack_strength": policy.default_attack_strength,
                "alert_threshold": policy.default_alert_threshold,
            }
    
    async def get_scan_policy_details(self, policy_name: str) -> Dict[str, Any]:
        """Get detailed information about a scan policy."""
        async with ZAPClient(self.base_url, self.api_key) as client:
            scanners = await client.ascan_list_scanners(policy_name)
            attack_strength = await client.ascan_get_policy_attack_strength(policy_name)
            alert_threshold = await client.ascan_get_policy_alert_threshold(policy_name)
            
            return {
                "name": policy_name,
                "attack_strength": attack_strength,
                "alert_threshold": alert_threshold,
                "scanners_count": len(scanners),
                "scanners": scanners,
            }
    
    async def delete_scan_policy(self, policy_name: str) -> bool:
        """Delete a scan policy."""
        try:
            async with ZAPClient(self.base_url, self.api_key) as client:
                await client.ascan_remove_policy(policy_name)
                return True
        except Exception as e:
            logger.error(f"Failed to delete policy: {e}")
            return False
    
    async def list_scanners(self, policy_name: str = None) -> List[Dict[str, Any]]:
        """List all available scanners."""
        async with ZAPClient(self.base_url, self.api_key) as client:
            return await client.ascan_list_scanners(policy_name)
    
    async def create_quick_policy(
        self,
        name: str,
        strength: str = "MEDIUM",
        categories: List[str] = None
    ) -> Dict[str, Any]:
        """
        Create a quick policy by enabling/disabling scanner categories.
        
        Categories: sql_injection, xss, path_traversal, command_injection,
                   remote_file_inclusion, server_side_include, etc.
        """
        # Scanner category to plugin ID mapping (common scanners)
        category_scanners = {
            "sql_injection": [40018, 40019, 40020, 40021, 40022, 40024],
            "xss": [40012, 40014, 40016, 40017],
            "path_traversal": [6, 7],
            "command_injection": [90020],
            "remote_file_inclusion": [7, 90017],
            "ldap_injection": [40015],
            "xml_injection": [90023],
            "script_injection": [40013],
            "server_side_include": [40009],
            "information_disclosure": [10045, 10040],
            "authentication": [10101, 10102, 10103],
        }
        
        policy = ZAPScanPolicy(
            name=name,
            default_attack_strength=strength,
            default_alert_threshold="MEDIUM",
        )
        
        # If categories specified, only enable those scanners
        if categories:
            enabled = []
            for cat in categories:
                if cat in category_scanners:
                    enabled.extend(category_scanners[cat])
            policy.enabled_scanners = list(set(enabled))
        
        return await self.create_scan_policy(policy)
    
    # -------------------------------------------------------------------------
    # Scan Resume (True Checkpoint-based)
    # -------------------------------------------------------------------------
    
    async def _save_checkpoint(
        self,
        session: ZAPScanSession,
        phase: ZAPScanPhase,
        phase_progress: int = 0
    ) -> None:
        """Save a scan checkpoint for resume capability."""
        checkpoint = ZAPScanCheckpoint(
            phase=phase,
            phase_progress=phase_progress,
            spider_id=session.spider_id,
            spider_urls_found=session.urls_found[:1000],  # Limit size
            ajax_spider_completed=not session.ajax_spider_running,
            active_scan_id=session.active_scan_id,
            alerts_found=[a.to_finding_dict() for a in session.alerts[:500]],
            last_updated=datetime.utcnow().isoformat(),
        )
        session.checkpoint = checkpoint
        
        # Persist to database
        from backend.models import models
        db = self._get_db_session()
        try:
            scan = db.query(models.ZAPScan).filter(
                models.ZAPScan.session_id == session.id
            ).first()
            
            if scan:
                # Store checkpoint in stats JSON field
                scan.stats = scan.stats or {}
                scan.stats["checkpoint"] = checkpoint.to_dict()
                db.commit()
                logger.debug(f"Saved checkpoint for session {session.id} at phase {phase.value}")
        except Exception as e:
            logger.warning(f"Failed to persist checkpoint: {e}")
            db.rollback()
        finally:
            db.close()
    
    async def _load_checkpoint(self, session_id: str) -> Optional[ZAPScanCheckpoint]:
        """Load checkpoint from database."""
        from backend.models import models
        db = self._get_db_session()
        try:
            scan = db.query(models.ZAPScan).filter(
                models.ZAPScan.session_id == session_id
            ).first()
            
            if scan and scan.stats and "checkpoint" in scan.stats:
                cp_data = scan.stats["checkpoint"]
                return ZAPScanCheckpoint(
                    phase=ZAPScanPhase(cp_data.get("phase", "init")),
                    phase_progress=cp_data.get("phase_progress", 0),
                    spider_id=cp_data.get("spider_id"),
                    spider_urls_found=cp_data.get("spider_urls_found", []),
                    ajax_spider_completed=cp_data.get("ajax_spider_completed", False),
                    active_scan_id=cp_data.get("active_scan_id"),
                    scanned_urls=cp_data.get("scanned_urls", []),
                    pending_urls=cp_data.get("pending_urls", []),
                    alerts_found=cp_data.get("alerts_found", []),
                    last_updated=cp_data.get("last_updated"),
                )
            return None
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            return None
        finally:
            db.close()
    
    async def resume_scan(
        self,
        session_id: str,
        user_id: Optional[int] = None,
        project_id: Optional[int] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Resume an interrupted scan from its last checkpoint.
        
        This performs true resume by:
        1. Loading checkpoint from database
        2. Restoring ZAP state (urls, alerts)
        3. Continuing from the interrupted phase
        """
        # Load the original session and checkpoint
        original_session = await self._load_scan_from_db(session_id)
        if not original_session:
            yield {"type": "error", "error": f"Session {session_id} not found"}
            return
        
        checkpoint = await self._load_checkpoint(session_id)
        if not checkpoint:
            yield {"type": "error", "error": "No checkpoint found - cannot resume"}
            return
        
        yield {
            "type": "resume_started",
            "message": f"Resuming scan from phase: {checkpoint.phase.value}",
            "original_session_id": session_id,
            "checkpoint_phase": checkpoint.phase.value,
            "checkpoint_progress": checkpoint.phase_progress,
            "urls_recovered": len(checkpoint.spider_urls_found),
            "alerts_recovered": len(checkpoint.alerts_found),
        }
        
        # Create new session for the resume
        new_session = ZAPScanSession(
            id=str(uuid.uuid4()),
            target_url=original_session.target_url,
            scan_type=original_session.scan_type,
            status=ZAPScanStatus.RUNNING,
            started_at=datetime.utcnow().isoformat(),
            urls_found=checkpoint.spider_urls_found,  # Restore discovered URLs
            checkpoint=checkpoint,
        )
        self._sessions[new_session.id] = new_session
        
        # Persist new session
        db_scan_id = None
        if user_id:
            try:
                db_scan_id = await self._persist_scan_to_db(new_session, user_id, project_id)
            except Exception as e:
                logger.warning(f"Failed to persist resume session: {e}")
        
        yield {
            "type": "session_created",
            "session_id": new_session.id,
            "db_scan_id": db_scan_id,
        }
        
        try:
            async with ZAPClient(self.base_url, self.api_key) as client:
                # Restore ZAP state - access target and seed URLs
                yield {"type": "phase_started", "phase": "restore", "message": "Restoring scan state"}
                
                await client.access_url(original_session.target_url)
                
                # Seed previously discovered URLs
                seeded = 0
                for url in checkpoint.spider_urls_found[:100]:  # Seed first 100 URLs
                    try:
                        await client.access_url(url)
                        seeded += 1
                    except:
                        pass
                
                yield {"type": "restore_complete", "urls_seeded": seeded}
                
                # Determine which phase to resume from
                skip_spider = checkpoint.phase in (ZAPScanPhase.AJAX_SPIDER, ZAPScanPhase.ACTIVE_SCAN, ZAPScanPhase.COMPLETE)
                skip_ajax = checkpoint.phase in (ZAPScanPhase.ACTIVE_SCAN, ZAPScanPhase.COMPLETE) or checkpoint.ajax_spider_completed
                
                # Resume Spider if needed
                if not skip_spider and original_session.scan_type in (ZAPScanType.SPIDER, ZAPScanType.FULL_SCAN):
                    yield {"type": "phase_started", "phase": "spider", "message": "Resuming spider crawl"}
                    
                    spider_id = await client.spider_scan(url=original_session.target_url)
                    new_session.spider_id = spider_id
                    
                    while True:
                        progress = await client.spider_status(spider_id)
                        new_session.progress = progress
                        await self._save_checkpoint(new_session, ZAPScanPhase.SPIDER, progress)
                        
                        yield {"type": "spider_progress", "progress": progress}
                        
                        if progress >= 100:
                            break
                        await asyncio.sleep(2)
                    
                    urls = await client.spider_results(spider_id)
                    new_session.urls_found = list(set(new_session.urls_found + urls))
                    
                    yield {"type": "spider_complete", "urls_found": len(new_session.urls_found)}
                
                # Resume AJAX Spider if needed
                if not skip_ajax and original_session.scan_type == ZAPScanType.FULL_SCAN:
                    yield {"type": "phase_started", "phase": "ajax_spider", "message": "Resuming AJAX spider"}
                    new_session.ajax_spider_running = True
                    
                    # Create context and add URL to scope for AJAX spider
                    context_name = f"resume_scan_{new_session.id}"
                    try:
                        await client.context_new(context_name)
                        from urllib.parse import urlparse
                        parsed = urlparse(original_session.target_url)
                        scope_regex = f"{parsed.scheme}://{parsed.netloc}.*"
                        await client.context_include_in_context(context_name, scope_regex)
                    except Exception as e:
                        logger.warning(f"Failed to create context for AJAX spider: {e}")
                        context_name = None
                    
                    await client.ajax_spider_scan(
                        url=original_session.target_url,
                        context_name=context_name,
                        in_scope=context_name is not None,
                    )
                    
                    ajax_start = time.time()
                    while True:
                        status = await client.ajax_spider_status()
                        await self._save_checkpoint(new_session, ZAPScanPhase.AJAX_SPIDER)
                        
                        yield {"type": "ajax_spider_progress", "status": status}
                        
                        if status == "stopped" or time.time() - ajax_start > 600:  # 10 min max
                            break
                        await asyncio.sleep(5)
                    
                    new_session.ajax_spider_running = False
                    yield {"type": "ajax_spider_complete"}
                
                # Resume Active Scan
                if checkpoint.phase != ZAPScanPhase.COMPLETE and original_session.scan_type in (ZAPScanType.ACTIVE_SCAN, ZAPScanType.FULL_SCAN):
                    yield {"type": "phase_started", "phase": "active_scan", "message": "Resuming active scan"}
                    
                    scan_id = await client.active_scan(url=original_session.target_url)
                    new_session.active_scan_id = scan_id
                    
                    while True:
                        progress = await client.active_scan_status(scan_id)
                        new_session.progress = progress
                        await self._save_checkpoint(new_session, ZAPScanPhase.ACTIVE_SCAN, progress)
                        
                        yield {"type": "active_scan_progress", "progress": progress}
                        
                        if progress >= 100:
                            break
                        await asyncio.sleep(3)
                    
                    yield {"type": "active_scan_complete"}
                
                # Get final alerts
                alerts_data = await client.get_alerts(base_url=original_session.target_url)
                new_session.alerts = [ZAPAlert.from_zap_response(a) for a in alerts_data]
                new_session.status = ZAPScanStatus.COMPLETED
                new_session.completed_at = datetime.utcnow().isoformat()
                
                await self._save_checkpoint(new_session, ZAPScanPhase.COMPLETE, 100)
                
                # Update database
                if user_id:
                    await self._update_scan_status(new_session, user_id, project_id)
                
                yield {
                    "type": "scan_complete",
                    "session_id": new_session.id,
                    "original_session_id": session_id,
                    "urls_found": len(new_session.urls_found),
                    "alerts": new_session._count_alerts_by_risk(),
                    "resumed_from": checkpoint.phase.value,
                }
                
        except Exception as e:
            logger.exception(f"Error during scan resume: {e}")
            new_session.status = ZAPScanStatus.FAILED
            new_session.error = str(e)
            
            yield {"type": "error", "error": str(e), "session_id": new_session.id}
    
    async def full_scan(
        self,
        config: ZAPScanConfig,
        progress_callback: Optional[callable] = None,
        user_id: Optional[int] = None,
        project_id: Optional[int] = None,
        persist_to_db: bool = True
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Run a full ZAP scan (spider + active scan) with streaming progress.
        
        Args:
            config: Scan configuration
            progress_callback: Optional callback for progress updates
            user_id: User ID for database persistence (required if persist_to_db=True)
            project_id: Optional project ID for association
            persist_to_db: Whether to persist scan state to database
        
        Yields progress events for SSE streaming.
        """
        session = ZAPScanSession(
            id=str(uuid.uuid4()),
            target_url=config.target_url,
            scan_type=config.scan_type,
            status=ZAPScanStatus.NOT_STARTED,
            started_at=datetime.utcnow().isoformat(),
        )
        self._sessions[session.id] = session
        
        # Persist initial scan state if user_id provided
        db_scan_id = None
        if persist_to_db and user_id:
            try:
                db_scan_id = await self._persist_scan_to_db(session, user_id, project_id)
                logger.info(f"ZAP scan persisted to database with ID: {db_scan_id}")
            except Exception as e:
                logger.warning(f"Failed to persist initial scan state: {e}")
        
        yield {
            "type": "scan_started",
            "session_id": session.id,
            "db_scan_id": db_scan_id,
            "target_url": config.target_url,
            "scan_type": config.scan_type.value,
        }
        
        try:
            async with ZAPClient(self.base_url, self.api_key) as client:
                # Create new session
                await client.new_session()
                session.status = ZAPScanStatus.RUNNING
                
                # Update database status
                if persist_to_db and user_id:
                    await self._update_scan_status(session.id, ZAPScanStatus.RUNNING)
                
                yield {
                    "type": "phase_started",
                    "phase": "initialization",
                    "message": "ZAP session initialized",
                }
                
                # Save initial checkpoint
                await self._save_checkpoint(session, ZAPScanPhase.INIT)
                
                # Setup authentication if configured
                if config.auth_config:
                    yield {
                        "type": "phase_started",
                        "phase": "authentication_setup",
                        "message": f"Configuring {config.auth_config.method.value} authentication",
                    }
                    auth_result = await self.setup_authentication(
                        config.auth_config,
                        config.target_url,
                        config.context_name
                    )
                    session.context_id = auth_result.get("context_id")
                    session.user_id_zap = auth_result.get("user_id")
                    yield {
                        "type": "authentication_configured",
                        "context_id": session.context_id,
                        "auth_method": config.auth_config.method.value,
                    }
                
                # Setup scan policy if configured
                if config.scan_policy_config:
                    yield {
                        "type": "phase_started",
                        "phase": "policy_setup",
                        "message": f"Creating scan policy: {config.scan_policy_config.name}",
                    }
                    await self.create_scan_policy(config.scan_policy_config)
                    config.scan_policy = config.scan_policy_config.name
                    yield {
                        "type": "policy_configured",
                        "policy_name": config.scan_policy,
                    }
                
                # Access the target URL first
                yield {
                    "type": "phase_started",
                    "phase": "access_target",
                    "message": f"Accessing target: {config.target_url}",
                }
                await client.access_url(config.target_url)
                
                # Spider phase
                if config.scan_type in (ZAPScanType.SPIDER, ZAPScanType.FULL_SCAN):
                    yield {
                        "type": "phase_started",
                        "phase": "spider",
                        "message": "Starting spider crawl",
                    }
                    
                    # Set spider options
                    await client.spider_set_option_max_depth(config.max_depth)
                    
                    # Start spider
                    spider_id = await client.spider_scan(
                        url=config.target_url,
                        max_children=config.max_children,
                        subtree_only=config.subtree_only,
                    )
                    session.spider_id = spider_id
                    
                    # Monitor spider progress
                    while True:
                        progress = await client.spider_status(spider_id)
                        session.progress = progress
                        
                        # Save checkpoint periodically
                        if progress % 20 == 0:  # Every 20%
                            await self._save_checkpoint(session, ZAPScanPhase.SPIDER, progress)
                        
                        yield {
                            "type": "spider_progress",
                            "progress": progress,
                            "spider_id": spider_id,
                        }
                        
                        if progress >= 100:
                            break
                        
                        await asyncio.sleep(2)
                    
                    # Get spider results
                    urls = await client.spider_results(spider_id)
                    session.urls_found = urls
                    
                    # Save checkpoint after spider completion
                    await self._save_checkpoint(session, ZAPScanPhase.SPIDER, 100)
                    
                    yield {
                        "type": "spider_complete",
                        "urls_found": len(urls),
                        "sample_urls": urls[:20],
                    }
                
                # AJAX Spider phase
                if config.enable_ajax_spider and config.scan_type in (ZAPScanType.AJAX_SPIDER, ZAPScanType.FULL_SCAN):
                    yield {
                        "type": "phase_started",
                        "phase": "ajax_spider",
                        "message": "Starting AJAX spider for JavaScript content",
                    }
                    
                    # Create context and add URL to scope for AJAX spider
                    # AJAX spider requires URLs to be in scope when in_scope=True
                    context_name = config.context_name or f"scan_{session.id}"
                    try:
                        await client.context_new(context_name)
                        # Add target URL pattern to context scope
                        from urllib.parse import urlparse
                        parsed = urlparse(config.target_url)
                        scope_regex = f"{parsed.scheme}://{parsed.netloc}.*"
                        await client.context_include_in_context(context_name, scope_regex)
                        logger.info(f"Created context '{context_name}' with scope: {scope_regex}")
                    except Exception as e:
                        logger.warning(f"Failed to create context for AJAX spider, will try with in_scope=False: {e}")
                        context_name = None
                    
                    # Configure AJAX spider
                    await client.ajax_spider_set_option_max_duration(config.ajax_spider_max_duration)
                    await client.ajax_spider_set_option_browser_id(config.browser_id)
                    
                    # Start AJAX spider
                    await client.ajax_spider_scan(
                        url=config.target_url,
                        subtree_only=config.subtree_only,
                        context_name=context_name,
                        in_scope=context_name is not None,  # Only require scope if context was created
                    )
                    session.ajax_spider_running = True
                    
                    # Monitor AJAX spider
                    ajax_start_time = time.time()
                    max_ajax_seconds = config.ajax_spider_max_duration * 60
                    checkpoint_interval = 30  # Save checkpoint every 30 seconds
                    last_checkpoint = time.time()
                    
                    while True:
                        status = await client.ajax_spider_status()
                        
                        # Save checkpoint periodically
                        if time.time() - last_checkpoint > checkpoint_interval:
                            await self._save_checkpoint(session, ZAPScanPhase.AJAX_SPIDER)
                            last_checkpoint = time.time()
                        
                        yield {
                            "type": "ajax_spider_progress",
                            "status": status,
                            "elapsed_seconds": int(time.time() - ajax_start_time),
                        }
                        
                        if status == "stopped":
                            break
                        
                        if time.time() - ajax_start_time > max_ajax_seconds:
                            await client.ajax_spider_stop()
                            break
                        
                        await asyncio.sleep(5)
                    
                    session.ajax_spider_running = False
                    
                    # Get AJAX spider results
                    ajax_results = await client.ajax_spider_results(count=500)
                    
                    # Save checkpoint after AJAX spider
                    await self._save_checkpoint(session, ZAPScanPhase.AJAX_SPIDER)
                    
                    yield {
                        "type": "ajax_spider_complete",
                        "results_count": len(ajax_results),
                    }
                
                # Active Scan phase
                if config.scan_type in (ZAPScanType.ACTIVE_SCAN, ZAPScanType.FULL_SCAN):
                    yield {
                        "type": "phase_started",
                        "phase": "active_scan",
                        "message": "Starting active vulnerability scan",
                    }
                    
                    # Configure active scan
                    if config.delay_in_ms > 0:
                        await client.active_scan_set_option_delay(config.delay_in_ms)
                    if config.max_scan_duration_mins > 0:
                        await client.active_scan_set_option_max_duration(config.max_scan_duration_mins)
                    
                    # Start active scan
                    scan_id = await client.active_scan(
                        url=config.target_url,
                        recurse=config.recurse,
                        in_scope_only=config.in_scope_only,
                        scan_policy_name=config.scan_policy,
                        context_id=session.context_id,  # Use auth context if set
                        user_id=session.user_id_zap,    # Use authenticated user if set
                    )
                    session.active_scan_id = scan_id
                    
                    # Monitor active scan
                    while True:
                        progress = await client.active_scan_status(scan_id)
                        session.progress = progress
                        
                        # Get current alerts during scan
                        alerts_data = await client.get_alerts(base_url=config.target_url, count=100)
                        current_alerts = [ZAPAlert.from_zap_response(a) for a in alerts_data]
                        session.alerts = current_alerts
                        
                        # Save checkpoint periodically
                        if progress % 10 == 0:  # Every 10%
                            await self._save_checkpoint(session, ZAPScanPhase.ACTIVE_SCAN, progress)
                        
                        yield {
                            "type": "active_scan_progress",
                            "progress": progress,
                            "scan_id": scan_id,
                            "alerts_found": len(current_alerts),
                        }
                        
                        if progress >= 100:
                            break
                        
                        await asyncio.sleep(5)
                    
                    # Save checkpoint after active scan
                    await self._save_checkpoint(session, ZAPScanPhase.ACTIVE_SCAN, 100)
                    
                    yield {
                        "type": "active_scan_complete",
                        "scan_id": scan_id,
                    }
                
                # Wait for passive scan to complete
                yield {
                    "type": "phase_started",
                    "phase": "passive_scan",
                    "message": "Waiting for passive analysis to complete",
                }
                
                max_passive_wait = 60  # Max 60 seconds
                passive_start = time.time()
                
                while True:
                    records = await client.passive_scan_records_to_scan()
                    
                    yield {
                        "type": "passive_scan_progress",
                        "records_remaining": records,
                    }
                    
                    if records == 0:
                        break
                    
                    if time.time() - passive_start > max_passive_wait:
                        break
                    
                    await asyncio.sleep(2)
                
                # Collect all alerts
                yield {
                    "type": "phase_started",
                    "phase": "collecting_results",
                    "message": "Collecting all findings",
                }
                
                all_alerts_data = await client.get_alerts(base_url=config.target_url, count=1000)
                session.alerts = [ZAPAlert.from_zap_response(a) for a in all_alerts_data]
                
                # Get summary
                summary = await client.get_alerts_summary(base_url=config.target_url)
                
                # Update URLs if not already collected
                if not session.urls_found:
                    session.urls_found = await client.get_urls(config.target_url)
                
                session.status = ZAPScanStatus.COMPLETED
                session.completed_at = datetime.utcnow().isoformat()
                session.stats = {
                    "urls_scanned": len(session.urls_found),
                    "alerts_summary": summary,
                    "total_alerts": len(session.alerts),
                }
                
                # Persist final scan state to database
                if persist_to_db and user_id:
                    try:
                        await self._persist_scan_to_db(session, user_id, project_id)
                        logger.info(f"ZAP scan {session.id} completed and persisted to database")
                    except Exception as e:
                        logger.warning(f"Failed to persist completed scan state: {e}")
                
                yield {
                    "type": "scan_complete",
                    "session_id": session.id,
                    "db_scan_id": db_scan_id,
                    "alerts_count": len(session.alerts),
                    "alerts_by_risk": session._count_alerts_by_risk(),
                    "urls_found": len(session.urls_found),
                    "duration_seconds": int(
                        (datetime.fromisoformat(session.completed_at) - 
                         datetime.fromisoformat(session.started_at)).total_seconds()
                    ),
                }
                
                # Yield all findings
                yield {
                    "type": "findings",
                    "findings": [alert.to_finding_dict() for alert in session.alerts],
                }
                
        except Exception as e:
            logger.exception(f"ZAP scan error: {e}")
            session.status = ZAPScanStatus.FAILED
            session.error = str(e)
            
            # Persist error state to database
            if persist_to_db and user_id:
                try:
                    await self._update_scan_status(session.id, ZAPScanStatus.FAILED, error=str(e))
                except Exception as db_err:
                    logger.warning(f"Failed to persist error state: {db_err}")
            
            yield {
                "type": "scan_error",
                "session_id": session.id,
                "error": str(e),
            }
    
    async def quick_scan(
        self,
        url: str,
        max_duration_mins: int = 5,
        user_id: Optional[int] = None,
        project_id: Optional[int] = None,
        persist_to_db: bool = False
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Quick scan with limited duration."""
        config = ZAPScanConfig(
            target_url=url,
            scan_type=ZAPScanType.FULL_SCAN,
            max_depth=3,
            enable_ajax_spider=False,  # Skip for speed
            max_scan_duration_mins=max_duration_mins,
        )
        
        async for event in self.full_scan(
            config,
            user_id=user_id,
            project_id=project_id,
            persist_to_db=persist_to_db
        ):
            yield event
    
    async def spider_only(
        self,
        url: str,
        max_depth: int = 5,
        include_ajax: bool = True,
        user_id: Optional[int] = None,
        project_id: Optional[int] = None,
        persist_to_db: bool = False
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Spider-only scan for endpoint discovery."""
        config = ZAPScanConfig(
            target_url=url,
            scan_type=ZAPScanType.SPIDER,
            max_depth=max_depth,
            enable_ajax_spider=include_ajax,
            ajax_spider_max_duration=10,  # 10 mins max for AJAX
        )
        
        async for event in self.full_scan(
            config,
            user_id=user_id,
            project_id=project_id,
            persist_to_db=persist_to_db
        ):
            yield event
    
    async def stop_scan(self, session_id: str) -> bool:
        """Stop a running scan."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        
        try:
            async with ZAPClient(self.base_url, self.api_key) as client:
                if session.spider_id:
                    await client.spider_stop(session.spider_id)
                
                if session.ajax_spider_running:
                    await client.ajax_spider_stop()
                
                if session.active_scan_id:
                    await client.active_scan_stop(session.active_scan_id)
                
                session.status = ZAPScanStatus.STOPPED
                return True
                
        except Exception as e:
            logger.error(f"Error stopping ZAP scan: {e}")
            return False
    
    async def get_session(self, session_id: str) -> Optional[ZAPScanSession]:
        """Get a scan session."""
        return self._sessions.get(session_id)
    
    async def get_all_sessions(self) -> List[Dict[str, Any]]:
        """Get all scan sessions."""
        return [s.to_dict() for s in self._sessions.values()]
    
    async def get_alerts(
        self,
        url: str = None,
        min_risk: int = 0
    ) -> List[ZAPAlert]:
        """Get alerts from ZAP."""
        try:
            async with ZAPClient(self.base_url, self.api_key) as client:
                alerts_data = await client.get_alerts(base_url=url, count=1000)
                alerts = [ZAPAlert.from_zap_response(a) for a in alerts_data]
                
                if min_risk > 0:
                    alerts = [a for a in alerts if a.risk_code >= min_risk]
                
                return alerts
                
        except Exception as e:
            logger.error(f"Error getting ZAP alerts: {e}")
            return []
    
    async def generate_report(self, format: str = "json") -> Any:
        """Generate a ZAP report."""
        try:
            async with ZAPClient(self.base_url, self.api_key) as client:
                if format == "html":
                    return await client.html_report()
                elif format == "xml":
                    return await client.xml_report()
                elif format == "markdown":
                    return await client.markdown_report()
                else:
                    return await client.json_report()
                    
        except Exception as e:
            logger.error(f"Error generating ZAP report: {e}")
            raise ZAPError(f"Failed to generate report: {e}")
    
    async def clear_session(self) -> bool:
        """Clear ZAP session and start fresh."""
        try:
            async with ZAPClient(self.base_url, self.api_key) as client:
                await client.new_session()
                await client.delete_all_alerts()
                return True
        except Exception as e:
            logger.error(f"Error clearing ZAP session: {e}")
            return False


# =============================================================================
# GLOBAL SCANNER INSTANCE
# =============================================================================

_zap_scanner: Optional[ZAPScanner] = None


def get_zap_scanner() -> ZAPScanner:
    """Get global ZAP scanner instance."""
    global _zap_scanner
    if _zap_scanner is None:
        _zap_scanner = ZAPScanner()
    return _zap_scanner


async def zap_health_check() -> Dict[str, Any]:
    """Quick health check for ZAP service."""
    scanner = get_zap_scanner()
    return await scanner.get_health()


async def zap_full_scan(
    url: str,
    scan_type: str = "full",
    max_depth: int = 5,
    enable_ajax: bool = True,
    max_duration_mins: int = 0
) -> AsyncGenerator[Dict[str, Any], None]:
    """
    Convenience function to run a ZAP scan with common options.
    """
    scanner = get_zap_scanner()
    
    config = ZAPScanConfig(
        target_url=url,
        scan_type=ZAPScanType(scan_type) if scan_type in [e.value for e in ZAPScanType] else ZAPScanType.FULL_SCAN,
        max_depth=max_depth,
        enable_ajax_spider=enable_ajax,
        max_scan_duration_mins=max_duration_mins,
    )
    
    async for event in scanner.full_scan(config):
        yield event


async def zap_get_findings(url: str = None) -> List[Dict[str, Any]]:
    """Get ZAP findings in Agentic Fuzzer compatible format."""
    scanner = get_zap_scanner()
    alerts = await scanner.get_alerts(url=url)
    return [alert.to_finding_dict() for alert in alerts]


# =============================================================================
# INTEGRATION WITH AGENTIC FUZZER
# =============================================================================

async def merge_zap_findings_with_fuzzer(
    zap_findings: List[Dict[str, Any]],
    fuzzer_findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Merge ZAP findings with Agentic Fuzzer findings, deduplicating similar issues.
    """
    merged = list(fuzzer_findings)
    
    # Create a set of existing finding signatures
    existing_signatures = set()
    for f in fuzzer_findings:
        sig = f"{f.get('endpoint', '')}:{f.get('parameter', '')}:{f.get('technique', '')}"
        existing_signatures.add(sig.lower())
    
    # Add ZAP findings that don't already exist
    for zf in zap_findings:
        sig = f"{zf.get('endpoint', '')}:{zf.get('parameter', '')}:{zf.get('technique', '')}"
        if sig.lower() not in existing_signatures:
            merged.append(zf)
            existing_signatures.add(sig.lower())
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    merged.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 4))
    
    return merged
