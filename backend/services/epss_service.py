"""
EPSS (Exploit Prediction Scoring System) Service

Retrieves EPSS scores from FIRST (Forum of Incident Response and Security Teams)
to help prioritize vulnerabilities based on likelihood of exploitation.

Supports:
- Live lookups via the FIRST EPSS API
- Offline fallback using a local SQLite database
- APP_OFFLINE_MODE to force local-only behavior in air-gapped deployments
"""

import os
import sqlite3
import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import httpx

from backend.core.config import settings
from backend.core.logging import get_logger
from backend.core.cache import cache

logger = get_logger(__name__)

# EPSS API endpoint
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# Local offline database path
LOCAL_EPSS_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data", "offline", "epss", "epss.db"
)

# Cache namespace for EPSS lookups
CACHE_NAMESPACE = "epss"

# Legacy in-memory cache (kept for backward compatibility, but Redis is preferred)
_epss_cache: Dict[str, Tuple[float, float, datetime]] = {}
CACHE_TTL = timedelta(hours=24)


@dataclass
class EPSSScore:
    """EPSS score data for a CVE."""
    cve_id: str
    score: float  # Probability of exploitation (0-1)
    percentile: float  # Percentile ranking (0-100)
    date: Optional[str] = None
    
    @property
    def score_percent(self) -> float:
        """Return score as percentage."""
        return self.score * 100
    
    @property
    def priority(self) -> str:
        """
        Get priority level based on EPSS score.
        
        Based on FIRST recommendations:
        - > 0.7 (70%): Critical - Very high likelihood of exploitation
        - > 0.4 (40%): High - Significant likelihood
        - > 0.1 (10%): Medium - Moderate likelihood
        - <= 0.1: Low - Lower likelihood
        """
        if self.score >= 0.7:
            return "critical"
        elif self.score >= 0.4:
            return "high"
        elif self.score >= 0.1:
            return "medium"
        else:
            return "low"


def _normalize_cve_id(cve_id: str) -> str:
    """Normalize CVE IDs to the canonical CVE-YYYY-NNNN form."""
    normalized = (cve_id or "").strip().upper()
    if normalized and not normalized.startswith("CVE-"):
        normalized = f"CVE-{normalized}"
    return normalized


def _check_local_epss_db_available() -> bool:
    """Check whether the local offline EPSS database exists."""
    return os.path.exists(LOCAL_EPSS_DB)


def is_epss_offline_data_available() -> bool:
    """Return True when local EPSS data is available for offline use."""
    return _check_local_epss_db_available()


def _cache_local_score(score: EPSSScore) -> None:
    """Cache a locally resolved EPSS score."""
    _cache_score(score.cve_id, score.score, score.percentile, score.date)


def _lookup_epss_local(cve_id: str) -> Optional[EPSSScore]:
    """Look up a single EPSS score from the local offline database."""
    if not _check_local_epss_db_available():
        return None

    normalized = _normalize_cve_id(cve_id)
    if not normalized:
        return None

    try:
        conn = sqlite3.connect(LOCAL_EPSS_DB)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT cve_id, epss_score, percentile, score_date
            FROM epss_scores
            WHERE cve_id = ?
            """,
            (normalized,),
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        score = EPSSScore(
            cve_id=row["cve_id"],
            score=float(row["epss_score"]),
            percentile=float(row["percentile"]),
            date=row["score_date"],
        )
        _cache_local_score(score)
        return score
    except Exception as e:
        logger.warning(f"Local EPSS lookup error for {normalized}: {e}")
        return None


def _lookup_epss_local_batch(cve_ids: List[str]) -> Dict[str, EPSSScore]:
    """Look up EPSS scores for multiple CVEs from the local offline database."""
    normalized_ids = [_normalize_cve_id(cve_id) for cve_id in cve_ids if _normalize_cve_id(cve_id)]
    if not normalized_ids or not _check_local_epss_db_available():
        return {}

    try:
        conn = sqlite3.connect(LOCAL_EPSS_DB)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        placeholders = ",".join("?" for _ in normalized_ids)
        cursor.execute(
            f"""
            SELECT cve_id, epss_score, percentile, score_date
            FROM epss_scores
            WHERE cve_id IN ({placeholders})
            """,
            normalized_ids,
        )
        rows = cursor.fetchall()
        conn.close()

        results: Dict[str, EPSSScore] = {}
        for row in rows:
            score = EPSSScore(
                cve_id=row["cve_id"],
                score=float(row["epss_score"]),
                percentile=float(row["percentile"]),
                date=row["score_date"],
            )
            results[score.cve_id] = score
            _cache_local_score(score)

        return results
    except Exception as e:
        logger.warning(f"Local EPSS batch lookup error: {e}")
        return {}


def get_local_epss_db_stats() -> Dict[str, Any]:
    """Return availability and freshness information for the local EPSS database."""
    if not _check_local_epss_db_available():
        return {"available": False, "path": LOCAL_EPSS_DB}

    try:
        conn = sqlite3.connect(LOCAL_EPSS_DB)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS count FROM epss_scores")
        count_row = cursor.fetchone()
        cursor.execute("SELECT value FROM sync_info WHERE key = 'last_sync'")
        last_sync_row = cursor.fetchone()
        cursor.execute("SELECT value FROM sync_info WHERE key = 'score_date'")
        score_date_row = cursor.fetchone()
        cursor.execute("SELECT value FROM sync_info WHERE key = 'source_url'")
        source_url_row = cursor.fetchone()
        cursor.execute("SELECT value FROM sync_info WHERE key = 'model_version'")
        model_row = cursor.fetchone()
        conn.close()

        return {
            "available": True,
            "path": LOCAL_EPSS_DB,
            "entries": int(count_row["count"]) if count_row else 0,
            "last_sync": last_sync_row["value"] if last_sync_row else None,
            "score_date": score_date_row["value"] if score_date_row else None,
            "source_url": source_url_row["value"] if source_url_row else None,
            "model_version": model_row["value"] if model_row else None,
            "size_mb": round(os.path.getsize(LOCAL_EPSS_DB) / (1024 * 1024), 2),
        }
    except Exception as e:
        return {"available": False, "path": LOCAL_EPSS_DB, "error": str(e)}


def _get_cached_score(cve_id: str) -> Optional[EPSSScore]:
    """Get cached EPSS score if still valid (checks Redis first, then in-memory)."""
    # Check Redis cache first
    if cache.is_connected:
        cached = cache.get(CACHE_NAMESPACE, cve_id)
        if cached is not None:
            return EPSSScore(
                cve_id=cve_id, 
                score=cached["score"], 
                percentile=cached["percentile"],
                date=cached.get("date")
            )
    
    # Fall back to in-memory cache
    if cve_id in _epss_cache:
        score, percentile, timestamp = _epss_cache[cve_id]
        if datetime.now() - timestamp < CACHE_TTL:
            return EPSSScore(cve_id=cve_id, score=score, percentile=percentile)
    return None


def _cache_score(cve_id: str, score: float, percentile: float, date: Optional[str] = None) -> None:
    """Cache an EPSS score (to both Redis and in-memory)."""
    # Cache to Redis (preferred)
    cache.set(CACHE_NAMESPACE, cve_id, {
        "score": score,
        "percentile": percentile,
        "date": date
    })
    
    # Also cache in-memory as backup
    _epss_cache[cve_id] = (score, percentile, datetime.now())


async def get_epss_score(cve_id: str) -> Optional[EPSSScore]:
    """
    Get EPSS score for a single CVE.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
        
    Returns:
        EPSSScore object or None if not found
    """
    cve_id = _normalize_cve_id(cve_id)
    if not cve_id:
        return None

    # Check cache first
    cached = _get_cached_score(cve_id)
    if cached:
        return cached

    if settings.app_offline_mode:
        local = _lookup_epss_local(cve_id)
        if local is None:
            logger.info(f"APP_OFFLINE_MODE enabled and no local EPSS data for {cve_id}")
        return local
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                EPSS_API_URL,
                params={"cve": cve_id}
            )
            response.raise_for_status()
            
            data = response.json()
            
            if data.get("status") == "OK" and data.get("data"):
                epss_data = data["data"][0]
                score = float(epss_data.get("epss", 0))
                percentile = float(epss_data.get("percentile", 0)) * 100
                date = epss_data.get("date")
                
                # Cache the result
                _cache_score(cve_id, score, percentile, date)
                
                return EPSSScore(
                    cve_id=cve_id,
                    score=score,
                    percentile=percentile,
                    date=date,
                )
            
            logger.debug(f"No EPSS data found for {cve_id}")
            return None
            
    except httpx.TimeoutException:
        logger.warning(f"EPSS API timeout for {cve_id}")
        return _lookup_epss_local(cve_id)
    except httpx.HTTPStatusError as e:
        logger.warning(f"EPSS API HTTP error for {cve_id}: {e.response.status_code}")
        return _lookup_epss_local(cve_id)
    except Exception as e:
        logger.error(f"EPSS API error for {cve_id}: {e}")
        return _lookup_epss_local(cve_id)


async def get_epss_scores_batch(cve_ids: List[str]) -> Dict[str, EPSSScore]:
    """
    Get EPSS scores for multiple CVEs in a single request.
    
    Args:
        cve_ids: List of CVE identifiers
        
    Returns:
        Dictionary mapping CVE IDs to EPSSScore objects
    """
    if not cve_ids:
        return {}
    
    # Normalize CVE IDs
    normalized_ids = [_normalize_cve_id(cve_id) for cve_id in cve_ids]
    normalized_ids = [cve_id for cve_id in normalized_ids if cve_id]
    
    # Check cache for already-fetched scores (batch lookup from Redis)
    results: Dict[str, EPSSScore] = {}
    ids_to_fetch = []
    
    if cache.is_connected:
        cached_data = cache.get_many(CACHE_NAMESPACE, normalized_ids)
        for cve_id in normalized_ids:
            if cve_id in cached_data:
                data = cached_data[cve_id]
                results[cve_id] = EPSSScore(
                    cve_id=cve_id,
                    score=data["score"],
                    percentile=data["percentile"],
                    date=data.get("date")
                )
            else:
                ids_to_fetch.append(cve_id)
    else:
        # Fall back to in-memory cache check
        for cve_id in normalized_ids:
            cached = _get_cached_score(cve_id)
            if cached:
                results[cve_id] = cached
            else:
                ids_to_fetch.append(cve_id)
    
    if not ids_to_fetch:
        logger.info(f"All {len(normalized_ids)} EPSS scores found in cache")
        return results

    if settings.app_offline_mode:
        local_results = _lookup_epss_local_batch(ids_to_fetch)
        if local_results:
            results.update(local_results)
            logger.info(
                f"APP_OFFLINE_MODE enabled - resolved {len(local_results)}/{len(ids_to_fetch)} EPSS scores from local database"
            )
        else:
            logger.info("APP_OFFLINE_MODE enabled - local EPSS database unavailable or had no matching CVEs")
        return results
    
    # Batch API request (API supports up to 100 CVEs per request)
    batch_size = 100
    items_to_cache: Dict[str, dict] = {}
    
    for i in range(0, len(ids_to_fetch), batch_size):
        batch = ids_to_fetch[i:i + batch_size]
        cve_param = ",".join(batch)
        
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    EPSS_API_URL,
                    params={"cve": cve_param}
                )
                response.raise_for_status()
                
                data = response.json()
                
                if data.get("status") == "OK" and data.get("data"):
                    for epss_data in data["data"]:
                        cve_id = epss_data.get("cve", "").upper()
                        if cve_id:
                            score = float(epss_data.get("epss", 0))
                            percentile = float(epss_data.get("percentile", 0)) * 100
                            date = epss_data.get("date")
                            
                            # Store for batch caching
                            items_to_cache[cve_id] = {
                                "score": score,
                                "percentile": percentile,
                                "date": date
                            }
                            
                            # Also cache in-memory
                            _epss_cache[cve_id] = (score, percentile, datetime.now())
                            
                            results[cve_id] = EPSSScore(
                                cve_id=cve_id,
                                score=score,
                                percentile=percentile,
                                date=date,
                            )
                            
        except Exception as e:
            logger.error(f"EPSS batch API error: {e}")
            continue

    missing_ids = [cve_id for cve_id in ids_to_fetch if cve_id not in results]
    if missing_ids:
        local_results = _lookup_epss_local_batch(missing_ids)
        if local_results:
            results.update(local_results)
            logger.info(
                f"Resolved {len(local_results)}/{len(missing_ids)} EPSS scores from local fallback database"
            )
    
    # Batch cache to Redis
    if items_to_cache and cache.is_connected:
        cached_count = cache.set_many(CACHE_NAMESPACE, items_to_cache)
        if cached_count > 0:
            logger.debug(f"Cached {cached_count} EPSS scores to Redis")
    
    logger.info(f"Retrieved EPSS scores for {len(results)}/{len(normalized_ids)} CVEs")
    return results


async def enrich_vulnerabilities_with_epss(
    vulnerabilities: List[dict]
) -> List[dict]:
    """
    Enrich vulnerability data with EPSS scores.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries with 'external_id' field
        
    Returns:
        List of vulnerabilities with added EPSS data
    """
    # Extract CVE IDs
    cve_ids = []
    for vuln in vulnerabilities:
        external_id = vuln.get("external_id", "")
        if external_id and external_id.upper().startswith("CVE"):
            cve_ids.append(external_id)
    
    if not cve_ids:
        return vulnerabilities
    
    # Get EPSS scores
    epss_scores = await get_epss_scores_batch(cve_ids)
    
    # Enrich vulnerabilities
    for vuln in vulnerabilities:
        external_id = vuln.get("external_id", "").upper()
        if external_id in epss_scores:
            epss = epss_scores[external_id]
            vuln["epss_score"] = epss.score
            vuln["epss_percentile"] = epss.percentile
            vuln["epss_priority"] = epss.priority
    
    return vulnerabilities


def prioritize_vulnerabilities(
    vulnerabilities: List[dict],
    weights: Optional[Dict[str, float]] = None,
) -> List[dict]:
    """
    Sort vulnerabilities by a combined priority score using CVSS and EPSS.
    
    The combined score helps prioritize vulnerabilities that are both
    severe (high CVSS) AND likely to be exploited (high EPSS).
    
    Args:
        vulnerabilities: List of vulnerability dicts with cvss_score and epss_score
        weights: Optional weights for scoring (default: CVSS 0.4, EPSS 0.6)
        
    Returns:
        Sorted list of vulnerabilities with priority_score added
    """
    if not weights:
        weights = {"cvss": 0.4, "epss": 0.6}
    
    for vuln in vulnerabilities:
        cvss = vuln.get("cvss_score") or 0
        epss = vuln.get("epss_score") or 0
        
        # Normalize CVSS to 0-1 scale (CVSS is 0-10)
        cvss_normalized = cvss / 10.0
        
        # Calculate combined score
        combined = (weights["cvss"] * cvss_normalized) + (weights["epss"] * epss)
        vuln["priority_score"] = round(combined, 4)
        
        # Determine priority label
        if combined >= 0.7:
            vuln["priority_label"] = "critical"
        elif combined >= 0.5:
            vuln["priority_label"] = "high"
        elif combined >= 0.3:
            vuln["priority_label"] = "medium"
        else:
            vuln["priority_label"] = "low"
    
    # Sort by priority score (descending)
    vulnerabilities.sort(key=lambda v: v.get("priority_score", 0), reverse=True)
    
    return vulnerabilities


def get_epss_summary(vulnerabilities: List[dict]) -> dict:
    """
    Generate a summary of EPSS data for vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerability dicts with EPSS data
        
    Returns:
        Summary statistics dictionary
    """
    epss_vulns = [v for v in vulnerabilities if v.get("epss_score") is not None]
    
    if not epss_vulns:
        return {
            "total_with_epss": 0,
            "high_risk_count": 0,
            "average_epss": 0,
            "max_epss": 0,
            "by_priority": {},
        }
    
    scores = [v["epss_score"] for v in epss_vulns]
    
    by_priority: Dict[str, int] = {}
    high_risk_count = 0
    
    for vuln in epss_vulns:
        priority = vuln.get("epss_priority", "unknown")
        by_priority[priority] = by_priority.get(priority, 0) + 1
        if vuln.get("epss_score", 0) >= 0.1:  # 10% threshold for "high risk"
            high_risk_count += 1
    
    return {
        "total_with_epss": len(epss_vulns),
        "high_risk_count": high_risk_count,
        "average_epss": round(sum(scores) / len(scores), 4),
        "max_epss": round(max(scores), 4),
        "by_priority": by_priority,
    }
