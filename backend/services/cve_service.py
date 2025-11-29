import asyncio
from typing import Dict, List, Optional, Tuple

import httpx

from backend import models
from backend.core.exceptions import OSVAPIError
from backend.core.logging import get_logger

logger = get_logger(__name__)

OSV_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# Batch processing settings
BATCH_SIZE = 100  # OSV batch API supports up to 1000, but 100 is safer
MAX_CONCURRENT_BATCHES = 5  # Rate limiting for concurrent requests
REQUEST_TIMEOUT = 30  # Timeout per request


def _parse_severity(entry: dict) -> Tuple[Optional[str], Optional[float]]:
    """Parse severity and CVSS score from OSV entry."""
    severity = None
    cvss_score = None
    
    if entry.get("severity"):
        for sev in entry["severity"]:
            if sev.get("type") == "CVSS_V3":
                cvss_score = float(sev.get("score", 0)) if sev.get("score") else None
                if cvss_score:
                    if cvss_score >= 9.0:
                        severity = "critical"
                    elif cvss_score >= 7.0:
                        severity = "high"
                    elif cvss_score >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"
                break
    
    # Fallback: check database_specific for severity
    if not severity and entry.get("database_specific", {}).get("severity"):
        severity = entry["database_specific"]["severity"].lower()
    
    return severity, cvss_score


async def lookup_dependency(dep: models.Dependency) -> List[models.Vulnerability]:
    """
    Look up known vulnerabilities for a single dependency using the OSV API.
    
    Args:
        dep: Dependency model to look up
        
    Returns:
        List of Vulnerability models found for the dependency
    """
    payload = {"package": {"name": dep.name, "ecosystem": dep.ecosystem}, "version": dep.version}
    
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.post(OSV_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
            vulns = []
            
            for entry in data.get("vulns", []):
                severity, cvss_score = _parse_severity(entry)
                
                vulns.append(
                    models.Vulnerability(
                        project_id=dep.project_id,
                        dependency_id=dep.id,
                        source="osv",
                        external_id=entry.get("id"),
                        title=entry.get("summary") or entry.get("id") or dep.name,
                        description=entry.get("details"),
                        severity=severity,
                        cvss_score=cvss_score,
                    )
                )
            
            logger.debug(f"Found {len(vulns)} vulnerabilities for {dep.name}@{dep.version}")
            return vulns
            
    except httpx.TimeoutException:
        logger.warning(f"OSV API timeout for {dep.name}@{dep.version}")
        return []
    except httpx.HTTPStatusError as e:
        logger.error(f"OSV API HTTP error for {dep.name}: {e.response.status_code}")
        return []
    except Exception as e:
        logger.error(f"OSV API error for {dep.name}: {e}")
        return []


async def _lookup_batch(
    client: httpx.AsyncClient, 
    deps: List[models.Dependency]
) -> Dict[int, List[models.Vulnerability]]:
    """
    Look up vulnerabilities for a batch of dependencies using OSV batch API.
    
    Args:
        client: Reusable HTTP client
        deps: List of dependencies to look up
        
    Returns:
        Dictionary mapping dependency ID to list of vulnerabilities
    """
    if not deps:
        return {}
    
    # Build batch query
    queries = [
        {"package": {"name": dep.name, "ecosystem": dep.ecosystem}, "version": dep.version}
        for dep in deps
    ]
    
    try:
        resp = await client.post(OSV_BATCH_URL, json={"queries": queries})
        resp.raise_for_status()
        data = resp.json()
        
        results: Dict[int, List[models.Vulnerability]] = {}
        
        for idx, result in enumerate(data.get("results", [])):
            dep = deps[idx]
            vulns = []
            
            for entry in result.get("vulns", []):
                severity, cvss_score = _parse_severity(entry)
                
                vulns.append(
                    models.Vulnerability(
                        project_id=dep.project_id,
                        dependency_id=dep.id,
                        source="osv",
                        external_id=entry.get("id"),
                        title=entry.get("summary") or entry.get("id") or dep.name,
                        description=entry.get("details"),
                        severity=severity,
                        cvss_score=cvss_score,
                    )
                )
            
            results[dep.id] = vulns
        
        return results
        
    except httpx.TimeoutException:
        logger.warning(f"OSV batch API timeout for {len(deps)} dependencies")
        return {}
    except httpx.HTTPStatusError as e:
        logger.error(f"OSV batch API HTTP error: {e.response.status_code}")
        return {}
    except Exception as e:
        logger.error(f"OSV batch API error: {e}")
        return {}


async def lookup_dependencies(deps: List[models.Dependency]) -> List[models.Vulnerability]:
    """
    Look up vulnerabilities for multiple dependencies using batch API.
    
    Uses OSV's batch endpoint to significantly reduce API calls.
    For 500 dependencies, this makes ~5 requests instead of 500.
    
    Args:
        deps: List of dependencies to look up
        
    Returns:
        Combined list of all vulnerabilities found
    """
    if not deps:
        return []
    
    # Split into batches
    batches = [deps[i:i + BATCH_SIZE] for i in range(0, len(deps), BATCH_SIZE)]
    logger.info(f"Looking up {len(deps)} dependencies in {len(batches)} batches")
    
    all_vulns: List[models.Vulnerability] = []
    
    # Process batches with concurrency limit
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_BATCHES)
    
    async def process_batch(batch: List[models.Dependency]) -> Dict[int, List[models.Vulnerability]]:
        async with semaphore:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                return await _lookup_batch(client, batch)
    
    # Run batches concurrently (with rate limiting)
    batch_results = await asyncio.gather(*[process_batch(batch) for batch in batches])
    
    # Combine results
    for result_dict in batch_results:
        for vulns in result_dict.values():
            all_vulns.extend(vulns)
    
    logger.info(f"Looked up {len(deps)} dependencies, found {len(all_vulns)} vulnerabilities")
    return all_vulns
