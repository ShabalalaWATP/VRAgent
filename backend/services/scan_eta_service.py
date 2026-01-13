"""
Scan ETA Estimation Service

Provides real-time ETA estimation for security scans with:
- Pre-scan estimation based on target complexity
- Dynamic ETA updates during scan execution
- Historical tracking for improved accuracy
- Phase-based time estimation
- Learning from past scan durations
"""

import json
import logging
import statistics
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import hashlib

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================

# Default time estimates per phase (in seconds)
DEFAULT_PHASE_TIMES = {
    "reconnaissance": 15,
    "fingerprinting": 10,
    "discovery": 60,
    "technique_selection": 5,
    "payload_generation": 10,
    "payload_execution": 120,  # Highly variable
    "result_analysis": 20,
    "blind_detection": 90,  # Time-based detection is slow
    "waf_evasion": 45,
    "chain_exploitation": 60,
    "poc_generation": 15,
    "exploitation": 30,
    "reporting": 10,
    "completed": 0,
}

# Time per technique type (seconds per payload)
TECHNIQUE_TIME_FACTORS = {
    "sql_injection": 0.5,
    "xss": 0.3,
    "command_injection": 0.6,
    "path_traversal": 0.3,
    "ssti": 0.4,
    "xxe": 0.5,
    "ssrf": 0.8,  # Often needs external callbacks
    "idor": 0.2,
    "auth_bypass": 0.4,
    "jwt_attack": 0.3,
    "http_smuggling": 2.0,  # Complex multi-request
    "race_condition": 1.5,  # Parallel requests
    "blind_sqli": 3.0,  # Time-based delays
    "blind_ssrf": 2.5,
    "blind_xxe": 2.5,
    "nosql_injection": 0.4,
    "default": 0.4,
}

# Average payloads per technique
PAYLOADS_PER_TECHNIQUE = {
    "sql_injection": 50,
    "xss": 40,
    "command_injection": 30,
    "path_traversal": 35,
    "ssti": 25,
    "xxe": 20,
    "ssrf": 25,
    "idor": 15,
    "auth_bypass": 20,
    "jwt_attack": 15,
    "http_smuggling": 10,
    "race_condition": 5,
    "default": 25,
}

# Profile speed multipliers
PROFILE_SPEED_MULTIPLIERS = {
    "quick": 0.4,
    "standard": 1.0,
    "full": 2.5,
    "owasp_top_10": 1.0,
    "owasp_api_top_10": 0.8,
    "api_focused": 0.9,
    "auth_focused": 0.7,
    "injection_focused": 1.2,
    "xss_focused": 0.8,
    "passive_only": 0.2,
    "stealth": 3.0,  # Slow and careful
    "aggressive": 0.3,  # Fast
    "compliance_pci": 1.5,
    "compliance_hipaa": 1.5,
}

# History storage
HISTORY_FILE = Path("/tmp/vragent_scan_history.json")
MAX_HISTORY_ENTRIES = 1000


# =============================================================================
# DATA CLASSES
# =============================================================================

class ETAConfidence(str, Enum):
    """Confidence level of ETA estimate."""
    HIGH = "high"        # Based on many similar scans
    MEDIUM = "medium"    # Some historical data
    LOW = "low"          # First-time estimate
    UNKNOWN = "unknown"  # Cannot estimate


@dataclass
class PhaseETA:
    """ETA for a specific scan phase."""
    phase: str
    estimated_seconds: float
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    actual_seconds: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanETA:
    """Complete ETA information for a scan."""
    scan_id: str
    started_at: str
    
    # Time estimates
    estimated_total_seconds: float
    estimated_completion_time: str
    remaining_seconds: float
    elapsed_seconds: float
    
    # Progress
    progress_percent: float
    current_phase: str
    phases_completed: int
    total_phases: int
    
    # Per-phase breakdown
    phase_estimates: List[PhaseETA] = field(default_factory=list)
    
    # Confidence
    confidence: ETAConfidence = ETAConfidence.LOW
    confidence_reason: str = ""
    
    # Dynamic updates
    last_updated: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updates_count: int = 0
    
    # Speed metrics
    requests_per_second: float = 0.0
    avg_response_time_ms: float = 0.0
    
    # Warnings
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "estimated_total_seconds": round(self.estimated_total_seconds, 1),
            "estimated_completion_time": self.estimated_completion_time,
            "remaining_seconds": round(self.remaining_seconds, 1),
            "remaining_formatted": self._format_duration(self.remaining_seconds),
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "elapsed_formatted": self._format_duration(self.elapsed_seconds),
            "progress_percent": round(self.progress_percent, 1),
            "current_phase": self.current_phase,
            "phases_completed": self.phases_completed,
            "total_phases": self.total_phases,
            "phase_estimates": [p.to_dict() for p in self.phase_estimates],
            "confidence": self.confidence.value,
            "confidence_reason": self.confidence_reason,
            "last_updated": self.last_updated,
            "updates_count": self.updates_count,
            "requests_per_second": round(self.requests_per_second, 2),
            "avg_response_time_ms": round(self.avg_response_time_ms, 1),
            "warnings": self.warnings,
        }
    
    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format seconds as human-readable duration."""
        if seconds < 0:
            return "calculating..."
        if seconds < 60:
            return f"{int(seconds)}s"
        if seconds < 3600:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


@dataclass
class ScanHistoryEntry:
    """Historical record of a completed scan."""
    scan_id: str
    target_hash: str  # Hash of target URL for matching similar scans
    profile_name: Optional[str]
    techniques_count: int
    endpoints_count: int
    parameters_count: int
    total_duration_seconds: float
    requests_made: int
    findings_count: int
    completed_at: str
    phase_durations: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# ETA SERVICE
# =============================================================================

class ScanETAService:
    """
    Service for estimating scan duration and providing real-time ETA updates.
    
    Features:
    - Pre-scan estimation based on configuration
    - Dynamic ETA updates during execution
    - Historical learning for improved accuracy
    - Phase-based time tracking
    - Confidence scoring
    """
    
    def __init__(self):
        """Initialize the ETA service."""
        self._active_scans: Dict[str, ScanETA] = {}
        self._phase_start_times: Dict[str, Dict[str, float]] = {}
        self._request_counts: Dict[str, int] = {}
        self._response_times: Dict[str, List[float]] = {}
        self._history: List[ScanHistoryEntry] = []
        self._load_history()
    
    def _load_history(self):
        """Load scan history from file."""
        try:
            if HISTORY_FILE.exists():
                with open(HISTORY_FILE, 'r') as f:
                    data = json.load(f)
                    self._history = [
                        ScanHistoryEntry(**entry) for entry in data
                    ]
                logger.info(f"Loaded {len(self._history)} historical scan entries")
        except Exception as e:
            logger.warning(f"Failed to load scan history: {e}")
            self._history = []
    
    def _save_history(self):
        """Save scan history to file."""
        try:
            # Keep only recent entries
            if len(self._history) > MAX_HISTORY_ENTRIES:
                self._history = self._history[-MAX_HISTORY_ENTRIES:]
            
            with open(HISTORY_FILE, 'w') as f:
                json.dump([h.to_dict() for h in self._history], f)
        except Exception as e:
            logger.warning(f"Failed to save scan history: {e}")
    
    def _hash_target(self, url: str) -> str:
        """Create a hash for target URL to match similar scans."""
        # Extract domain for matching
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        return hashlib.md5(domain.encode()).hexdigest()[:16]
    
    def _find_similar_scans(
        self,
        target_hash: str,
        profile_name: Optional[str],
        techniques_count: int,
    ) -> List[ScanHistoryEntry]:
        """Find historical scans similar to current configuration."""
        similar = []
        
        for entry in self._history:
            # Exact match on target domain
            if entry.target_hash == target_hash:
                similar.append(entry)
                continue
            
            # Similar profile and technique count
            if (entry.profile_name == profile_name and 
                abs(entry.techniques_count - techniques_count) <= 5):
                similar.append(entry)
        
        return similar[-10:]  # Last 10 similar scans
    
    def estimate_scan_duration(
        self,
        scan_id: str,
        target_url: str,
        techniques: List[str],
        max_iterations: int,
        profile_name: Optional[str] = None,
        crawl_enabled: bool = True,
        crawl_max_pages: int = 100,
        blind_detection_enabled: bool = True,
        chain_attacks_enabled: bool = True,
        endpoints_count: int = 1,
        parameters_count: int = 5,
    ) -> ScanETA:
        """
        Estimate total scan duration before scan starts.
        
        Args:
            scan_id: Unique scan identifier
            target_url: Target URL
            techniques: List of techniques to use
            max_iterations: Maximum LLM iterations
            profile_name: Scan profile name (affects speed)
            crawl_enabled: Whether crawling is enabled
            crawl_max_pages: Maximum pages to crawl
            blind_detection_enabled: Whether blind detection is enabled
            chain_attacks_enabled: Whether attack chaining is enabled
            endpoints_count: Known endpoint count
            parameters_count: Known parameter count
            
        Returns:
            ScanETA with pre-scan estimate
        """
        started_at = datetime.utcnow()
        
        # Calculate target hash for historical matching
        target_hash = self._hash_target(target_url)
        
        # Find similar historical scans
        similar_scans = self._find_similar_scans(
            target_hash, profile_name, len(techniques)
        )
        
        # Base estimation
        total_seconds = 0.0
        phase_estimates: List[PhaseETA] = []
        confidence = ETAConfidence.LOW
        confidence_reason = "First-time estimate based on configuration"
        
        # If we have historical data, use it
        if similar_scans:
            avg_duration = statistics.mean(s.total_duration_seconds for s in similar_scans)
            confidence = ETAConfidence.HIGH if len(similar_scans) >= 5 else ETAConfidence.MEDIUM
            confidence_reason = f"Based on {len(similar_scans)} similar historical scans"
            
            # Use historical phase durations if available
            phase_durations_list = [s.phase_durations for s in similar_scans if s.phase_durations]
            if phase_durations_list:
                for phase in DEFAULT_PHASE_TIMES.keys():
                    phase_times = [d.get(phase, DEFAULT_PHASE_TIMES[phase]) 
                                  for d in phase_durations_list]
                    avg_phase_time = statistics.mean(phase_times) if phase_times else DEFAULT_PHASE_TIMES[phase]
                    phase_estimates.append(PhaseETA(
                        phase=phase,
                        estimated_seconds=avg_phase_time,
                    ))
                    total_seconds += avg_phase_time
            else:
                total_seconds = avg_duration
        else:
            # Calculate from first principles
            
            # 1. Reconnaissance phase
            recon_time = DEFAULT_PHASE_TIMES["reconnaissance"]
            phase_estimates.append(PhaseETA(phase="reconnaissance", estimated_seconds=recon_time))
            total_seconds += recon_time
            
            # 2. Fingerprinting
            fingerprint_time = DEFAULT_PHASE_TIMES["fingerprinting"]
            phase_estimates.append(PhaseETA(phase="fingerprinting", estimated_seconds=fingerprint_time))
            total_seconds += fingerprint_time
            
            # 3. Discovery/Crawling
            if crawl_enabled:
                # Assume 0.5s per page crawled
                discovery_time = min(crawl_max_pages * 0.5, 300)  # Cap at 5 minutes
            else:
                discovery_time = DEFAULT_PHASE_TIMES["discovery"] * 0.2
            phase_estimates.append(PhaseETA(phase="discovery", estimated_seconds=discovery_time))
            total_seconds += discovery_time
            
            # 4. Payload execution (main time consumer)
            execution_time = 0.0
            for technique in techniques:
                payloads = PAYLOADS_PER_TECHNIQUE.get(technique, PAYLOADS_PER_TECHNIQUE["default"])
                time_factor = TECHNIQUE_TIME_FACTORS.get(technique, TECHNIQUE_TIME_FACTORS["default"])
                execution_time += payloads * time_factor * max(1, parameters_count)
            
            # Cap at reasonable maximum
            execution_time = min(execution_time, max_iterations * 30)
            phase_estimates.append(PhaseETA(phase="payload_execution", estimated_seconds=execution_time))
            total_seconds += execution_time
            
            # 5. Result analysis (LLM time)
            analysis_time = max_iterations * 2  # ~2s per LLM call
            phase_estimates.append(PhaseETA(phase="result_analysis", estimated_seconds=analysis_time))
            total_seconds += analysis_time
            
            # 6. Blind detection
            if blind_detection_enabled:
                blind_time = DEFAULT_PHASE_TIMES["blind_detection"]
                phase_estimates.append(PhaseETA(phase="blind_detection", estimated_seconds=blind_time))
                total_seconds += blind_time
            
            # 7. WAF evasion
            waf_time = DEFAULT_PHASE_TIMES["waf_evasion"]
            phase_estimates.append(PhaseETA(phase="waf_evasion", estimated_seconds=waf_time))
            total_seconds += waf_time
            
            # 8. Chain exploitation
            if chain_attacks_enabled:
                chain_time = DEFAULT_PHASE_TIMES["chain_exploitation"]
                phase_estimates.append(PhaseETA(phase="chain_exploitation", estimated_seconds=chain_time))
                total_seconds += chain_time
            
            # 9. Reporting
            report_time = DEFAULT_PHASE_TIMES["reporting"]
            phase_estimates.append(PhaseETA(phase="reporting", estimated_seconds=report_time))
            total_seconds += report_time
        
        # Apply profile speed multiplier
        if profile_name:
            multiplier = PROFILE_SPEED_MULTIPLIERS.get(profile_name, 1.0)
            total_seconds *= multiplier
            for pe in phase_estimates:
                pe.estimated_seconds *= multiplier
        
        # Build warnings
        warnings = []
        if total_seconds > 3600:
            warnings.append("Estimated duration exceeds 1 hour - consider using Quick profile")
        if blind_detection_enabled and "blind_" in " ".join(techniques):
            warnings.append("Blind detection techniques add significant time due to timing analysis")
        if "http_smuggling" in techniques or "race_condition" in techniques:
            warnings.append("Advanced techniques (smuggling/race) require multiple sequential requests")
        
        # Calculate completion time
        completion_time = started_at + timedelta(seconds=total_seconds)
        
        # Create ETA object
        eta = ScanETA(
            scan_id=scan_id,
            started_at=started_at.isoformat(),
            estimated_total_seconds=total_seconds,
            estimated_completion_time=completion_time.isoformat(),
            remaining_seconds=total_seconds,
            elapsed_seconds=0.0,
            progress_percent=0.0,
            current_phase="initializing",
            phases_completed=0,
            total_phases=len(phase_estimates),
            phase_estimates=phase_estimates,
            confidence=confidence,
            confidence_reason=confidence_reason,
            warnings=warnings,
        )
        
        # Store for updates
        self._active_scans[scan_id] = eta
        self._phase_start_times[scan_id] = {}
        self._request_counts[scan_id] = 0
        self._response_times[scan_id] = []
        
        logger.info(
            f"Scan {scan_id} ETA: {eta._format_duration(total_seconds)} "
            f"(confidence: {confidence.value})"
        )
        
        return eta
    
    def update_eta(
        self,
        scan_id: str,
        current_phase: str,
        iteration: int,
        max_iterations: int,
        requests_made: int = 0,
        last_response_time_ms: Optional[float] = None,
        findings_count: int = 0,
        endpoints_discovered: int = 0,
    ) -> Optional[ScanETA]:
        """
        Update ETA based on current scan progress.
        
        Args:
            scan_id: Scan identifier
            current_phase: Current phase name
            iteration: Current iteration number
            max_iterations: Maximum iterations
            requests_made: Total requests made so far
            last_response_time_ms: Last response time in milliseconds
            findings_count: Number of findings so far
            endpoints_discovered: Number of endpoints discovered
            
        Returns:
            Updated ScanETA or None if scan not found
        """
        eta = self._active_scans.get(scan_id)
        if not eta:
            return None
        
        now = datetime.utcnow()
        started = datetime.fromisoformat(eta.started_at)
        elapsed = (now - started).total_seconds()
        
        # Track phase transitions
        if current_phase != eta.current_phase:
            # Mark previous phase as completed
            prev_phase_start = self._phase_start_times[scan_id].get(eta.current_phase)
            if prev_phase_start:
                phase_duration = time.time() - prev_phase_start
                for pe in eta.phase_estimates:
                    if pe.phase == eta.current_phase:
                        pe.actual_seconds = phase_duration
                        pe.completed_at = now.isoformat()
                        break
            
            # Start new phase
            self._phase_start_times[scan_id][current_phase] = time.time()
            for pe in eta.phase_estimates:
                if pe.phase == current_phase:
                    pe.started_at = now.isoformat()
                    break
            
            eta.phases_completed += 1
        
        # Update request tracking
        if requests_made > self._request_counts[scan_id]:
            self._request_counts[scan_id] = requests_made
        
        if last_response_time_ms:
            self._response_times[scan_id].append(last_response_time_ms)
            # Keep only last 100 response times
            if len(self._response_times[scan_id]) > 100:
                self._response_times[scan_id] = self._response_times[scan_id][-100:]
        
        # Calculate speed metrics
        if elapsed > 0:
            eta.requests_per_second = requests_made / elapsed
        
        if self._response_times[scan_id]:
            eta.avg_response_time_ms = statistics.mean(self._response_times[scan_id])
        
        # Calculate progress based on iterations
        if max_iterations > 0:
            eta.progress_percent = min((iteration / max_iterations) * 100, 99.9)
        
        # Recalculate remaining time
        if eta.progress_percent > 5:  # Need some progress to estimate
            # Use actual elapsed time to project remaining
            projected_total = elapsed / (eta.progress_percent / 100)
            eta.remaining_seconds = max(0, projected_total - elapsed)
            
            # Adjust total estimate based on actual progress
            eta.estimated_total_seconds = projected_total
            eta.estimated_completion_time = (
                now + timedelta(seconds=eta.remaining_seconds)
            ).isoformat()
            
            # Improve confidence if we have real data
            if eta.confidence == ETAConfidence.LOW and elapsed > 60:
                eta.confidence = ETAConfidence.MEDIUM
                eta.confidence_reason = "Adjusted based on actual scan progress"
        else:
            eta.remaining_seconds = eta.estimated_total_seconds - elapsed
        
        # Update metadata
        eta.current_phase = current_phase
        eta.elapsed_seconds = elapsed
        eta.last_updated = now.isoformat()
        eta.updates_count += 1
        
        return eta
    
    def phase_started(self, scan_id: str, phase: str) -> Optional[ScanETA]:
        """Mark a phase as started."""
        eta = self._active_scans.get(scan_id)
        if not eta:
            return None
        
        now = datetime.utcnow()
        self._phase_start_times[scan_id][phase] = time.time()
        
        for pe in eta.phase_estimates:
            if pe.phase == phase:
                pe.started_at = now.isoformat()
                break
        
        eta.current_phase = phase
        eta.last_updated = now.isoformat()
        
        return eta
    
    def phase_completed(self, scan_id: str, phase: str) -> Optional[ScanETA]:
        """Mark a phase as completed."""
        eta = self._active_scans.get(scan_id)
        if not eta:
            return None
        
        now = datetime.utcnow()
        phase_start = self._phase_start_times[scan_id].get(phase)
        
        if phase_start:
            duration = time.time() - phase_start
            for pe in eta.phase_estimates:
                if pe.phase == phase:
                    pe.actual_seconds = duration
                    pe.completed_at = now.isoformat()
                    break
        
        eta.phases_completed += 1
        eta.last_updated = now.isoformat()
        
        return eta
    
    def complete_scan(
        self,
        scan_id: str,
        total_requests: int,
        findings_count: int,
        endpoints_count: int,
        parameters_count: int,
        techniques_used: List[str],
        profile_name: Optional[str] = None,
        target_url: str = "",
    ) -> Optional[ScanETA]:
        """
        Mark scan as complete and save to history.
        
        Args:
            scan_id: Scan identifier
            total_requests: Total requests made
            findings_count: Number of findings
            endpoints_count: Endpoints scanned
            parameters_count: Parameters tested
            techniques_used: Techniques that were used
            profile_name: Profile name used
            target_url: Target URL
            
        Returns:
            Final ScanETA
        """
        eta = self._active_scans.get(scan_id)
        if not eta:
            return None
        
        now = datetime.utcnow()
        started = datetime.fromisoformat(eta.started_at)
        total_duration = (now - started).total_seconds()
        
        # Finalize ETA
        eta.elapsed_seconds = total_duration
        eta.remaining_seconds = 0
        eta.progress_percent = 100.0
        eta.current_phase = "completed"
        eta.estimated_completion_time = now.isoformat()
        eta.last_updated = now.isoformat()
        
        # Collect phase durations
        phase_durations = {}
        for pe in eta.phase_estimates:
            if pe.actual_seconds:
                phase_durations[pe.phase] = pe.actual_seconds
        
        # Save to history
        history_entry = ScanHistoryEntry(
            scan_id=scan_id,
            target_hash=self._hash_target(target_url) if target_url else "",
            profile_name=profile_name,
            techniques_count=len(techniques_used),
            endpoints_count=endpoints_count,
            parameters_count=parameters_count,
            total_duration_seconds=total_duration,
            requests_made=total_requests,
            findings_count=findings_count,
            completed_at=now.isoformat(),
            phase_durations=phase_durations,
        )
        
        self._history.append(history_entry)
        self._save_history()
        
        # Cleanup
        del self._active_scans[scan_id]
        if scan_id in self._phase_start_times:
            del self._phase_start_times[scan_id]
        if scan_id in self._request_counts:
            del self._request_counts[scan_id]
        if scan_id in self._response_times:
            del self._response_times[scan_id]
        
        logger.info(
            f"Scan {scan_id} completed in {eta._format_duration(total_duration)} "
            f"({findings_count} findings, {total_requests} requests)"
        )
        
        return eta
    
    def get_eta(self, scan_id: str) -> Optional[ScanETA]:
        """Get current ETA for a scan."""
        return self._active_scans.get(scan_id)
    
    def cancel_scan(self, scan_id: str):
        """Remove scan from active tracking without saving history."""
        if scan_id in self._active_scans:
            del self._active_scans[scan_id]
        if scan_id in self._phase_start_times:
            del self._phase_start_times[scan_id]
        if scan_id in self._request_counts:
            del self._request_counts[scan_id]
        if scan_id in self._response_times:
            del self._response_times[scan_id]
    
    def get_history_stats(self) -> Dict[str, Any]:
        """Get statistics from scan history."""
        if not self._history:
            return {
                "total_scans": 0,
                "avg_duration_seconds": 0,
                "avg_findings": 0,
                "avg_requests": 0,
            }
        
        return {
            "total_scans": len(self._history),
            "avg_duration_seconds": statistics.mean(h.total_duration_seconds for h in self._history),
            "avg_findings": statistics.mean(h.findings_count for h in self._history),
            "avg_requests": statistics.mean(h.requests_made for h in self._history),
            "by_profile": self._history_by_profile(),
        }
    
    def _history_by_profile(self) -> Dict[str, Dict[str, float]]:
        """Group history statistics by profile."""
        profiles: Dict[str, List[ScanHistoryEntry]] = {}
        
        for entry in self._history:
            profile = entry.profile_name or "custom"
            if profile not in profiles:
                profiles[profile] = []
            profiles[profile].append(entry)
        
        return {
            profile: {
                "count": len(entries),
                "avg_duration": statistics.mean(e.total_duration_seconds for e in entries),
                "avg_findings": statistics.mean(e.findings_count for e in entries),
            }
            for profile, entries in profiles.items()
        }


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

_eta_service = ScanETAService()


def get_eta_service() -> ScanETAService:
    """Get the global ETA service instance."""
    return _eta_service


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def estimate_scan_duration(
    scan_id: str,
    target_url: str,
    techniques: List[str],
    max_iterations: int,
    **kwargs,
) -> ScanETA:
    """Convenience function to estimate scan duration."""
    return _eta_service.estimate_scan_duration(
        scan_id=scan_id,
        target_url=target_url,
        techniques=techniques,
        max_iterations=max_iterations,
        **kwargs,
    )


def update_eta(scan_id: str, **kwargs) -> Optional[ScanETA]:
    """Convenience function to update ETA."""
    return _eta_service.update_eta(scan_id, **kwargs)


def complete_scan(scan_id: str, **kwargs) -> Optional[ScanETA]:
    """Convenience function to complete scan."""
    return _eta_service.complete_scan(scan_id, **kwargs)


def get_eta(scan_id: str) -> Optional[ScanETA]:
    """Convenience function to get ETA."""
    return _eta_service.get_eta(scan_id)
