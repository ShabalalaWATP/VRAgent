"""
NVD (National Vulnerability Database) API Service.

This service enriches CVE data with detailed information from NIST's NVD,
including full CVSS vectors, CWE mappings, references, and KEV status.

The NVD API is used as a supplementary source to OSV.dev:
- OSV.dev: Primary source for package → vulnerability lookups (faster, package-native)
- NVD: Enrichment source for detailed CVE information (authoritative, comprehensive)

API Documentation: https://nvd.nist.gov/developers/vulnerabilities
Rate Limits (without API key): 5 requests per 30 seconds
Rate Limits (with API key): 50 requests per 30 seconds
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from functools import lru_cache

import httpx

from backend.core.config import settings
from backend.core.logging import get_logger
from backend.core.cache import cache

logger = get_logger(__name__)

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 30
MAX_CONCURRENT_REQUESTS = 3  # Conservative to respect rate limits
RATE_LIMIT_DELAY = 6.5  # Seconds between requests (5 req/30s without API key)

# Cache namespace for NVD lookups
CACHE_NAMESPACE = "nvd"

# Legacy in-memory cache (kept for backward compatibility, but Redis is preferred)
_cve_cache: Dict[str, Dict[str, Any]] = {}
_cache_expiry: Dict[str, datetime] = {}
CACHE_TTL_HOURS = 24


def _get_api_headers() -> Dict[str, str]:
    """Get headers for NVD API requests, including API key if configured."""
    headers = {
        "Accept": "application/json",
        "User-Agent": "VRAgent/1.0 (Security Scanner)"
    }
    
    # Add API key if configured (allows higher rate limits)
    # Note: settings uses lowercase nvd_api_key
    api_key = settings.nvd_api_key
    if api_key:
        headers["apiKey"] = api_key
    
    return headers


def _is_cache_valid(cve_id: str) -> bool:
    """Check if cached CVE data is still valid (checks Redis first, then in-memory)."""
    # Check Redis cache first
    if cache.is_connected:
        cached = cache.get(CACHE_NAMESPACE, cve_id)
        if cached is not None:
            return True
    
    # Fall back to in-memory cache
    if cve_id not in _cve_cache or cve_id not in _cache_expiry:
        return False
    return datetime.utcnow() < _cache_expiry[cve_id]


def _get_cached_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """Get cached CVE data (checks Redis first, then in-memory)."""
    # Check Redis cache first
    if cache.is_connected:
        cached = cache.get(CACHE_NAMESPACE, cve_id)
        if cached is not None:
            return cached
    
    # Fall back to in-memory cache
    if cve_id in _cve_cache and _is_cache_valid(cve_id):
        return _cve_cache[cve_id]
    return None


def _cache_cve(cve_id: str, data: Dict[str, Any]) -> None:
    """Cache CVE data with TTL (to both Redis and in-memory)."""
    # Cache to Redis (preferred)
    cache.set(CACHE_NAMESPACE, cve_id, data)
    
    # Also cache in-memory as backup
    _cve_cache[cve_id] = data
    _cache_expiry[cve_id] = datetime.utcnow() + timedelta(hours=CACHE_TTL_HOURS)


def _parse_cvss_v3(metrics: Dict) -> Optional[Dict[str, Any]]:
    """Parse CVSS v3.x metrics from NVD response."""
    cvss_v31 = metrics.get("cvssMetricV31", [])
    cvss_v30 = metrics.get("cvssMetricV30", [])
    
    # Prefer v3.1 over v3.0
    cvss_list = cvss_v31 if cvss_v31 else cvss_v30
    
    if not cvss_list:
        return None
    
    # Get primary (NVD) score, or first available
    for cvss in cvss_list:
        if cvss.get("type") == "Primary":
            cvss_data = cvss.get("cvssData", {})
            return {
                "version": cvss_data.get("version"),
                "vector_string": cvss_data.get("vectorString"),
                "base_score": cvss_data.get("baseScore"),
                "base_severity": cvss_data.get("baseSeverity"),
                "attack_vector": cvss_data.get("attackVector"),
                "attack_complexity": cvss_data.get("attackComplexity"),
                "privileges_required": cvss_data.get("privilegesRequired"),
                "user_interaction": cvss_data.get("userInteraction"),
                "scope": cvss_data.get("scope"),
                "confidentiality_impact": cvss_data.get("confidentialityImpact"),
                "integrity_impact": cvss_data.get("integrityImpact"),
                "availability_impact": cvss_data.get("availabilityImpact"),
                "exploitability_score": cvss.get("exploitabilityScore"),
                "impact_score": cvss.get("impactScore"),
            }
    
    # Fallback to first available
    if cvss_list:
        cvss_data = cvss_list[0].get("cvssData", {})
        return {
            "version": cvss_data.get("version"),
            "vector_string": cvss_data.get("vectorString"),
            "base_score": cvss_data.get("baseScore"),
            "base_severity": cvss_data.get("baseSeverity"),
        }
    
    return None


def _parse_cvss_v4(metrics: Dict) -> Optional[Dict[str, Any]]:
    """Parse CVSS v4.0 metrics from NVD response."""
    cvss_v4 = metrics.get("cvssMetricV40", [])
    
    if not cvss_v4:
        return None
    
    for cvss in cvss_v4:
        cvss_data = cvss.get("cvssData", {})
        return {
            "version": cvss_data.get("version"),
            "vector_string": cvss_data.get("vectorString"),
            "base_score": cvss_data.get("baseScore"),
            "base_severity": cvss_data.get("baseSeverity"),
        }
    
    return None


def _parse_weaknesses(weaknesses: List[Dict]) -> List[str]:
    """Extract CWE IDs from weakness data."""
    cwe_ids = []
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                value = desc.get("value", "")
                if value.startswith("CWE-") or value.startswith("NVD-CWE"):
                    cwe_ids.append(value)
    return list(set(cwe_ids))


def _parse_references(references: List[Dict]) -> List[Dict[str, Any]]:
    """Parse reference links from NVD response."""
    parsed = []
    for ref in references[:10]:  # Limit to 10 references
        parsed.append({
            "url": ref.get("url"),
            "source": ref.get("source"),
            "tags": ref.get("tags", []),
        })
    return parsed


async def lookup_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Look up detailed CVE information from NVD.
    Uses Redis cache to avoid redundant API calls.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
        
    Returns:
        Dictionary with enriched CVE data, or None if not found
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return None
    
    # Check cache first (Redis or in-memory)
    cached = _get_cached_cve(cve_id)
    if cached is not None:
        logger.debug(f"Cache hit for {cve_id}")
        return cached
    
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                NVD_CVE_API,
                params={"cveId": cve_id},
                headers=_get_api_headers()
            )
            
            if resp.status_code == 404:
                logger.debug(f"CVE not found in NVD: {cve_id}")
                return None
            
            if resp.status_code == 403:
                logger.warning("NVD API rate limit exceeded. Consider adding NVD_API_KEY to .env")
                return None
            
            resp.raise_for_status()
            data = resp.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None
            
            cve_data = vulnerabilities[0].get("cve", {})
            
            # Parse the response
            metrics = cve_data.get("metrics", {})
            
            enriched = {
                "cve_id": cve_id,
                "source_identifier": cve_data.get("sourceIdentifier"),
                "published": cve_data.get("published"),
                "last_modified": cve_data.get("lastModified"),
                "vuln_status": cve_data.get("vulnStatus"),
                
                # Description
                "description": next(
                    (d.get("value") for d in cve_data.get("descriptions", []) 
                     if d.get("lang") == "en"),
                    None
                ),
                
                # CVSS Scores
                "cvss_v3": _parse_cvss_v3(metrics),
                "cvss_v4": _parse_cvss_v4(metrics),
                
                # Weaknesses (CWE)
                "cwes": _parse_weaknesses(cve_data.get("weaknesses", [])),
                
                # References
                "references": _parse_references(cve_data.get("references", [])),
                
                # Configurations (affected products)
                "has_configurations": bool(cve_data.get("configurations")),
            }
            
            # Cache the result
            _cache_cve(cve_id, enriched)
            logger.debug(f"Fetched and cached NVD data for {cve_id}")
            
            return enriched
            
    except httpx.TimeoutException:
        logger.warning(f"NVD API timeout for {cve_id}")
        return None
    except httpx.HTTPStatusError as e:
        logger.error(f"NVD API HTTP error for {cve_id}: {e.response.status_code}")
        return None
    except Exception as e:
        logger.error(f"NVD API error for {cve_id}: {e}")
        return None


async def lookup_cves_batch(cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Look up multiple CVEs from NVD with rate limiting.
    
    Args:
        cve_ids: List of CVE identifiers
        
    Returns:
        Dictionary mapping CVE ID to enriched data
    """
    if not cve_ids:
        return {}
    
    # Filter to valid CVE IDs and deduplicate
    valid_ids = list(set(cve_id for cve_id in cve_ids if cve_id and cve_id.startswith("CVE-")))
    
    if not valid_ids:
        return {}
    
    logger.info(f"Looking up {len(valid_ids)} CVEs from NVD")
    
    results: Dict[str, Dict[str, Any]] = {}
    
    # Check cache first (batch lookup from Redis)
    uncached_ids = []
    if cache.is_connected:
        cached_data = cache.get_many(CACHE_NAMESPACE, valid_ids)
        for cve_id in valid_ids:
            if cve_id in cached_data:
                results[cve_id] = cached_data[cve_id]
            else:
                uncached_ids.append(cve_id)
    else:
        # Fall back to in-memory cache check
        for cve_id in valid_ids:
            cached = _get_cached_cve(cve_id)
            if cached is not None:
                results[cve_id] = cached
            else:
                uncached_ids.append(cve_id)
    
    if not uncached_ids:
        logger.info(f"All {len(valid_ids)} CVEs found in cache")
        return results
    
    logger.info(f"Fetching {len(uncached_ids)} uncached CVEs from NVD (cached: {len(results)})")
    
    # Check API key for rate limit
    has_api_key = bool(settings.nvd_api_key)
    
    # With API key: 50 req/30s = ~1.7 req/s, use 3 concurrent with 0.6s delay
    # Without API key: 5 req/30s = ~0.17 req/s, use 1 concurrent with 6s delay
    if has_api_key:
        max_concurrent = 3
        delay_between_batches = 0.6
    else:
        max_concurrent = 1
        delay_between_batches = 6.0
    
    # Process with controlled concurrency
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def fetch_with_rate_limit(cve_id: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        async with semaphore:
            result = await lookup_cve(cve_id)
            # Small delay between concurrent requests
            await asyncio.sleep(delay_between_batches / max_concurrent)
            return cve_id, result
    
    # Process in smaller batches for better progress tracking
    batch_size = 10 if has_api_key else 5
    
    for i in range(0, len(uncached_ids), batch_size):
        batch = uncached_ids[i:i + batch_size]
        
        # Fetch batch concurrently
        tasks = [fetch_with_rate_limit(cve_id) for cve_id in batch]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for item in batch_results:
            if isinstance(item, Exception):
                logger.warning(f"NVD batch error: {item}")
                continue
            cve_id, result = item
            if result:
                results[cve_id] = result
        
        # Delay between batches to respect rate limits
        if i + batch_size < len(uncached_ids):
            await asyncio.sleep(delay_between_batches)
    
    logger.info(f"Retrieved {len(results)} CVE details from NVD")
    return results


async def check_kev_status(cve_ids: List[str]) -> Dict[str, bool]:
    """
    Check if CVEs are in CISA's Known Exploited Vulnerabilities catalog.
    
    The KEV catalog contains vulnerabilities that are actively being exploited
    in the wild and should be prioritized for patching.
    
    Args:
        cve_ids: List of CVE identifiers to check
        
    Returns:
        Dictionary mapping CVE ID to KEV status (True if in catalog)
    """
    if not cve_ids:
        return {}
    
    # NVD API supports hasKev parameter but only for full queries
    # For efficiency, we'll query KEV CVEs and check membership
    # This is a simplified approach - for production, consider caching the full KEV list
    
    results = {cve_id: False for cve_id in cve_ids}
    
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            # Get a sample of KEV CVEs to check against
            # In production, you'd want to maintain a local KEV cache
            resp = await client.get(
                NVD_CVE_API,
                params={"hasKev": "", "resultsPerPage": 2000},
                headers=_get_api_headers()
            )
            
            if resp.status_code != 200:
                logger.warning(f"Failed to fetch KEV data: {resp.status_code}")
                return results
            
            data = resp.json()
            kev_cves = set()
            
            for vuln in data.get("vulnerabilities", []):
                kev_cves.add(vuln.get("cve", {}).get("id"))
            
            for cve_id in cve_ids:
                if cve_id in kev_cves:
                    results[cve_id] = True
                    logger.info(f"CVE {cve_id} is in CISA KEV catalog!")
            
    except Exception as e:
        logger.error(f"Error checking KEV status: {e}")
    
    return results


async def enrich_vulnerabilities_with_nvd(
    vulnerabilities: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Enrich vulnerability data with detailed NVD information.
    
    This function takes vulnerabilities found via OSV and adds:
    - Full CVSS v3/v4 vectors and breakdown
    - CWE weakness mappings
    - Reference links
    - KEV (Known Exploited Vulnerabilities) status
    
    Args:
        vulnerabilities: List of vulnerability dicts with 'external_id' field
        
    Returns:
        Enriched vulnerability list
    """
    if not vulnerabilities:
        return vulnerabilities
    
    # Extract CVE IDs
    cve_ids = [
        v.get("external_id") 
        for v in vulnerabilities 
        if v.get("external_id", "").startswith("CVE-")
    ]
    
    if not cve_ids:
        logger.debug("No CVE IDs to enrich from NVD")
        return vulnerabilities
    
    # Fetch NVD data
    nvd_data = await lookup_cves_batch(cve_ids)
    
    # Enrich vulnerabilities
    for vuln in vulnerabilities:
        cve_id = vuln.get("external_id")
        if cve_id in nvd_data:
            nvd = nvd_data[cve_id]
            
            # Add NVD enrichment data
            vuln["nvd_enrichment"] = {
                "description": nvd.get("description"),
                "cvss_v3": nvd.get("cvss_v3"),
                "cvss_v4": nvd.get("cvss_v4"),
                "cwes": nvd.get("cwes"),
                "references": nvd.get("references"),
                "vuln_status": nvd.get("vuln_status"),
                "published": nvd.get("published"),
                "last_modified": nvd.get("last_modified"),
            }
            
            # Update CVSS score if NVD has better data
            if nvd.get("cvss_v3") and nvd["cvss_v3"].get("base_score"):
                vuln["cvss_score"] = nvd["cvss_v3"]["base_score"]
                vuln["cvss_vector"] = nvd["cvss_v3"].get("vector_string")
    
    return vulnerabilities
