"""
CVE/Vulnerability Service for VRAgent.

This service provides vulnerability lookups via OSV.dev API with optimizations:
- Batch querying (up to 1000 deps per request)
- Redis caching with 24hr TTL
- Version range caching for local matching
- Smart prefetching based on tech stack
- Parallel ecosystem querying

OSV API Documentation: https://osv.dev/docs/
"""

import asyncio
import re
from typing import Dict, List, Optional, Tuple, Set
from packaging import version as pkg_version
from packaging.specifiers import SpecifierSet

import httpx

from backend import models
from backend.core.exceptions import OSVAPIError
from backend.core.logging import get_logger
from backend.core.cache import cache

logger = get_logger(__name__)

OSV_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULNS_URL = "https://api.osv.dev/v1/vulns"  # For fetching vuln details by ID

# Batch processing settings - OSV supports up to 1000, we use larger batches for efficiency
BATCH_SIZE = 500  # Increased from 100 - OSV handles this well
MAX_CONCURRENT_BATCHES = 10  # Increased concurrency for faster lookups
REQUEST_TIMEOUT = 45  # Slightly longer timeout for larger batches

# Cache namespaces
CACHE_NAMESPACE = "osv"
VERSION_RANGE_CACHE = "osv_ranges"  # For caching version ranges for local matching
ECOSYSTEM_CACHE = "osv_ecosystem"  # For ecosystem-wide CVE prefetching


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


def _extract_version_ranges(entry: dict) -> List[dict]:
    """
    Extract version ranges from OSV entry for local matching.
    
    Returns list of dicts with 'introduced', 'fixed', 'last_affected' fields.
    This allows checking if a version is affected without API calls.
    """
    ranges = []
    for affected in entry.get("affected", []):
        for range_info in affected.get("ranges", []):
            if range_info.get("type") == "SEMVER" or range_info.get("type") == "ECOSYSTEM":
                events = range_info.get("events", [])
                current_range = {}
                
                for event in events:
                    if "introduced" in event:
                        if current_range:
                            ranges.append(current_range)
                        current_range = {"introduced": event["introduced"]}
                    elif "fixed" in event:
                        current_range["fixed"] = event["fixed"]
                        ranges.append(current_range)
                        current_range = {}
                    elif "last_affected" in event:
                        current_range["last_affected"] = event["last_affected"]
                        ranges.append(current_range)
                        current_range = {}
                
                if current_range:
                    ranges.append(current_range)
        
        # Also capture versions list if available (exact affected versions)
        if affected.get("versions"):
            for ver in affected["versions"]:
                ranges.append({"exact": ver})
    
    return ranges


def _is_version_affected(version_str: str, ranges: List[dict]) -> bool:
    """
    Check if a specific version is affected by vulnerability version ranges.
    
    This allows local matching without API calls when we have cached version ranges.
    """
    if not version_str or not ranges:
        return False
    
    try:
        # Try to parse as semver-like version
        # Strip any leading 'v' or common prefixes
        clean_version = re.sub(r'^[vV]?', '', version_str)
        
        for range_info in ranges:
            # Exact version match
            if range_info.get("exact"):
                if clean_version == range_info["exact"] or version_str == range_info["exact"]:
                    return True
                continue
            
            introduced = range_info.get("introduced", "0")
            fixed = range_info.get("fixed")
            last_affected = range_info.get("last_affected")
            
            try:
                ver = pkg_version.parse(clean_version)
                intro = pkg_version.parse(introduced) if introduced != "0" else pkg_version.parse("0")
                
                # Version must be >= introduced
                if ver < intro:
                    continue
                
                # If fixed version exists, version must be < fixed
                if fixed:
                    fix = pkg_version.parse(fixed)
                    if ver < fix:
                        return True
                elif last_affected:
                    # If last_affected exists, version must be <= last_affected
                    last = pkg_version.parse(last_affected)
                    if ver <= last:
                        return True
                else:
                    # No fix available, all versions >= introduced are affected
                    return True
                    
            except Exception:
                # Version parsing failed, fall back to string comparison
                if range_info.get("exact") == clean_version:
                    return True
                    
    except Exception as e:
        logger.debug(f"Version comparison error for {version_str}: {e}")
    
    return False


def _make_cache_key(name: str, ecosystem: str, version: str) -> str:
    """Create a cache key for a dependency lookup."""
    return f"{ecosystem}:{name}:{version}"


def _parse_osv_vulns(dep: models.Dependency, osv_data: List[dict]) -> List[models.Vulnerability]:
    """Parse OSV vulnerability data into Vulnerability models."""
    vulns = []
    for entry in osv_data:
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
    return vulns


def _cache_version_ranges(ecosystem: str, name: str, osv_data: List[dict]) -> None:
    """
    Cache version ranges from OSV response for future local matching.
    
    This allows us to check if new versions of the same package are affected
    without making additional API calls.
    """
    if not osv_data:
        return
    
    cache_key = f"{ecosystem}:{name.lower()}"
    ranges_data = []
    
    for entry in osv_data:
        vuln_ranges = _extract_version_ranges(entry)
        if vuln_ranges:
            ranges_data.append({
                "id": entry.get("id"),
                "severity": _parse_severity(entry),
                "ranges": vuln_ranges,
                "summary": entry.get("summary"),
            })
    
    if ranges_data:
        # Cache for 7 days since vulnerability ranges rarely change
        cache.set(VERSION_RANGE_CACHE, cache_key, ranges_data, ttl=60*60*24*7)


def _check_local_cache(ecosystem: str, name: str, version: str) -> Optional[List[dict]]:
    """
    Check if we can determine vulnerability status from cached version ranges.
    
    Returns list of matching vulnerability data if found locally, None if API needed.
    """
    cache_key = f"{ecosystem}:{name.lower()}"
    cached_ranges = cache.get(VERSION_RANGE_CACHE, cache_key)
    
    if cached_ranges is None:
        return None
    
    # Check each cached vulnerability's version ranges
    matching_vulns = []
    for vuln_data in cached_ranges:
        ranges = vuln_data.get("ranges", [])
        if _is_version_affected(version, ranges):
            # Reconstruct minimal OSV-like data for parsing
            severity_tuple = vuln_data.get("severity", (None, None))
            matching_vulns.append({
                "id": vuln_data.get("id"),
                "summary": vuln_data.get("summary"),
                "severity": [{"type": "CVSS_V3", "score": severity_tuple[1]}] if severity_tuple[1] else None,
            })
    
    return matching_vulns if matching_vulns else []


async def lookup_dependency(dep: models.Dependency) -> List[models.Vulnerability]:
    """
    Look up known vulnerabilities for a single dependency using the OSV API.
    Uses multi-tier caching:
    1. Direct cache hit (exact version match)
    2. Version range cache (local version matching)
    3. API call (with caching of results and version ranges)
    
    Args:
        dep: Dependency model to look up
        
    Returns:
        List of Vulnerability models found for the dependency
    """
    cache_key = _make_cache_key(dep.name, dep.ecosystem, dep.version)
    
    # Tier 1: Check direct cache (exact version match)
    cached_data = cache.get(CACHE_NAMESPACE, cache_key)
    if cached_data is not None:
        logger.debug(f"Cache hit (exact) for {dep.name}@{dep.version}")
        return _parse_osv_vulns(dep, cached_data)
    
    # Tier 2: Check version range cache (local matching)
    if dep.version:
        local_match = _check_local_cache(dep.ecosystem, dep.name, dep.version)
        if local_match is not None:
            logger.debug(f"Cache hit (range) for {dep.name}@{dep.version}: {len(local_match)} vulns")
            cache.set(CACHE_NAMESPACE, cache_key, local_match)  # Cache the result
            return _parse_osv_vulns(dep, local_match)
    
    # Tier 3: API call
    payload = {"package": {"name": dep.name, "ecosystem": dep.ecosystem}, "version": dep.version}
    
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.post(OSV_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
            
            # Cache the raw OSV response (not the model objects)
            osv_vulns = data.get("vulns", [])
            cache.set(CACHE_NAMESPACE, cache_key, osv_vulns)
            
            # Also cache version ranges for future local matching
            _cache_version_ranges(dep.ecosystem, dep.name, osv_vulns)
            
            vulns = _parse_osv_vulns(dep, osv_vulns)
            
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
    
    Uses multi-tier caching:
    1. Direct cache hit (exact version match)
    2. Version range cache (local version matching)  
    3. API call (with caching of results and version ranges)
    
    Args:
        client: Reusable HTTP client
        deps: List of dependencies to look up
        
    Returns:
        Dictionary mapping dependency ID to list of vulnerabilities
    """
    if not deps:
        return {}
    
    results: Dict[int, List[models.Vulnerability]] = {}
    deps_to_fetch: List[models.Dependency] = []
    dep_cache_keys: Dict[int, str] = {}
    
    # Tier 1: Check direct cache for exact version matches
    cache_keys = [_make_cache_key(dep.name, dep.ecosystem, dep.version) for dep in deps]
    cached_data = cache.get_many(CACHE_NAMESPACE, cache_keys)
    
    for dep, cache_key in zip(deps, cache_keys):
        dep_cache_keys[dep.id] = cache_key
        if cache_key in cached_data:
            # Direct cache hit
            results[dep.id] = _parse_osv_vulns(dep, cached_data[cache_key])
        else:
            # Tier 2: Try local version range matching
            if dep.version:
                local_match = _check_local_cache(dep.ecosystem, dep.name, dep.version)
                if local_match is not None:
                    results[dep.id] = _parse_osv_vulns(dep, local_match)
                    # Cache this result for future exact matches
                    cache.set(CACHE_NAMESPACE, cache_key, local_match)
                    continue
            
            # Need API call
            deps_to_fetch.append(dep)
    
    if not deps_to_fetch:
        logger.debug(f"All {len(deps)} dependencies resolved from cache")
        return results
    
    cache_hits = len(deps) - len(deps_to_fetch)
    if cache_hits > 0:
        logger.info(f"OSV cache: {cache_hits} hits (exact+range), {len(deps_to_fetch)} API calls needed")
    
    # Tier 3: Build batch query for remaining dependencies
    queries = [
        {"package": {"name": dep.name, "ecosystem": dep.ecosystem}, "version": dep.version}
        for dep in deps_to_fetch
    ]
    
    try:
        resp = await client.post(OSV_BATCH_URL, json={"queries": queries})
        resp.raise_for_status()
        data = resp.json()
        
        # Items to cache
        items_to_cache: Dict[str, List[dict]] = {}
        
        for idx, result in enumerate(data.get("results", [])):
            dep = deps_to_fetch[idx]
            osv_vulns = result.get("vulns", [])
            
            # Cache the raw OSV response
            cache_key = dep_cache_keys[dep.id]
            items_to_cache[cache_key] = osv_vulns
            
            # Cache version ranges for this package
            _cache_version_ranges(dep.ecosystem, dep.name, osv_vulns)
            
            # Parse into model objects
            results[dep.id] = _parse_osv_vulns(dep, osv_vulns)
        
        # Batch cache the results
        if items_to_cache:
            cached_count = cache.set_many(CACHE_NAMESPACE, items_to_cache)
            if cached_count > 0:
                logger.debug(f"Cached {cached_count} OSV lookups")
        
        return results
        
    except httpx.TimeoutException:
        logger.warning(f"OSV batch API timeout for {len(deps_to_fetch)} dependencies")
        return results
    except httpx.HTTPStatusError as e:
        logger.error(f"OSV batch API HTTP error: {e.response.status_code}")
        return results
    except Exception as e:
        logger.error(f"OSV batch API error: {e}")
        return results


async def lookup_dependencies(deps: List[models.Dependency]) -> List[models.Vulnerability]:
    """
    Look up vulnerabilities for multiple dependencies using batch API.
    
    Uses OSV's batch endpoint to significantly reduce API calls.
    For 500 dependencies, this makes ~1 request instead of 500.
    
    Features:
    - Large batch sizes (500 deps per request)
    - Multi-tier caching (exact match + version range)
    - Parallel batch processing
    - Automatic version range caching for future lookups
    
    Args:
        deps: List of dependencies to look up
        
    Returns:
        Combined list of all vulnerabilities found
    """
    if not deps:
        return []
    
    # Split into batches
    batches = [deps[i:i + BATCH_SIZE] for i in range(0, len(deps), BATCH_SIZE)]
    logger.info(f"Looking up {len(deps)} dependencies in {len(batches)} batches (batch size: {BATCH_SIZE})")
    
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


async def prefetch_ecosystem_vulns(ecosystems: List[str], packages: List[str] = None) -> int:
    """
    Prefetch vulnerability data for an ecosystem to warm the cache.
    
    This is useful when you know you'll be scanning many projects with
    similar tech stacks. Prefetching popular packages reduces API calls.
    
    Args:
        ecosystems: List of ecosystems to prefetch (e.g., ["PyPI", "npm"])
        packages: Optional list of specific package names to prefetch
        
    Returns:
        Number of vulnerabilities prefetched
    """
    # Popular packages by ecosystem (most likely to have vulnerabilities)
    POPULAR_PACKAGES = {
        "PyPI": [
            "requests", "django", "flask", "numpy", "pandas", "tensorflow",
            "pytorch", "pillow", "urllib3", "cryptography", "pyyaml", "jinja2",
            "sqlalchemy", "aiohttp", "boto3", "celery", "redis", "psycopg2"
        ],
        "npm": [
            "lodash", "express", "axios", "moment", "react", "vue", "angular",
            "webpack", "babel", "typescript", "jquery", "underscore", "async",
            "request", "commander", "chalk", "fs-extra", "debug", "uuid"
        ],
        "Maven": [
            "org.apache.logging.log4j:log4j-core", "org.springframework:spring-core",
            "com.fasterxml.jackson.core:jackson-databind", "org.apache.commons:commons-lang3",
            "com.google.guava:guava", "org.apache.httpcomponents:httpclient",
            "org.slf4j:slf4j-api", "commons-io:commons-io"
        ],
        "Go": [
            "github.com/gin-gonic/gin", "github.com/gorilla/mux", "github.com/sirupsen/logrus",
            "github.com/spf13/cobra", "github.com/spf13/viper", "github.com/stretchr/testify"
        ],
        "crates.io": [
            "serde", "tokio", "actix-web", "reqwest", "clap", "rand", "regex",
            "chrono", "log", "env_logger"
        ],
        "RubyGems": [
            "rails", "rack", "nokogiri", "devise", "sidekiq", "puma", "pg",
            "redis", "activerecord", "actionpack"
        ],
        "Packagist": [
            "laravel/framework", "symfony/symfony", "guzzlehttp/guzzle",
            "monolog/monolog", "phpunit/phpunit", "doctrine/orm"
        ],
    }
    
    prefetch_count = 0
    
    for ecosystem in ecosystems:
        pkgs = packages if packages else POPULAR_PACKAGES.get(ecosystem, [])
        if not pkgs:
            continue
        
        logger.info(f"Prefetching {len(pkgs)} packages for {ecosystem}")
        
        # Query each package without version to get all known vulnerabilities
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                queries = [{"package": {"name": pkg, "ecosystem": ecosystem}} for pkg in pkgs]
                
                # Batch query
                resp = await client.post(OSV_BATCH_URL, json={"queries": queries})
                resp.raise_for_status()
                data = resp.json()
                
                for idx, result in enumerate(data.get("results", [])):
                    osv_vulns = result.get("vulns", [])
                    if osv_vulns:
                        # Cache version ranges for local matching
                        _cache_version_ranges(ecosystem, pkgs[idx], osv_vulns)
                        prefetch_count += len(osv_vulns)
                        
        except Exception as e:
            logger.warning(f"Prefetch error for {ecosystem}: {e}")
    
    logger.info(f"Prefetched {prefetch_count} vulnerability records")
    return prefetch_count


async def get_ecosystem_summary(ecosystem: str) -> Dict:
    """
    Get a summary of vulnerability data for an ecosystem.
    
    Returns statistics about cached data and API availability.
    """
    cache_key = f"summary:{ecosystem}"
    cached = cache.get(ECOSYSTEM_CACHE, cache_key)
    
    if cached:
        return cached
    
    # Get sample packages to check API health
    SAMPLE_PACKAGES = {
        "PyPI": "requests",
        "npm": "lodash",
        "Maven": "org.apache.logging.log4j:log4j-core",
    }
    
    sample_pkg = SAMPLE_PACKAGES.get(ecosystem, "test")
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                OSV_URL,
                json={"package": {"name": sample_pkg, "ecosystem": ecosystem}}
            )
            api_available = resp.status_code == 200
            
            summary = {
                "ecosystem": ecosystem,
                "api_available": api_available,
                "sample_package": sample_pkg,
                "sample_vuln_count": len(resp.json().get("vulns", [])) if api_available else 0,
            }
            
            cache.set(ECOSYSTEM_CACHE, cache_key, summary, ttl=3600)
            return summary
            
    except Exception as e:
        return {
            "ecosystem": ecosystem,
            "api_available": False,
            "error": str(e),
        }


def get_cache_stats() -> Dict:
    """Get statistics about the CVE cache."""
    stats = cache.get_stats()
    
    # Add CVE-specific metrics
    if stats.get("connected"):
        stats["cve_cache"] = {
            "exact_matches": stats.get("keys_by_namespace", {}).get("osv", 0),
            "version_ranges": 0,  # Would need to scan VERSION_RANGE_CACHE
        }
    
    return stats


async def lookup_from_sbom(
    sbom: Dict,
    project_id: int
) -> List[models.Vulnerability]:
    """
    Look up vulnerabilities for all components in an SBOM.
    
    Supports CycloneDX format. Extracts package info from purls
    and performs optimized batch queries.
    
    Args:
        sbom: CycloneDX SBOM dictionary
        project_id: Project ID for the vulnerabilities
        
    Returns:
        List of Vulnerability models
    """
    components = sbom.get("components", [])
    if not components:
        logger.debug("No components in SBOM")
        return []
    
    # Parse purls from components
    deps_to_lookup: List[models.Dependency] = []
    
    for idx, component in enumerate(components):
        purl = component.get("purl", "")
        name = component.get("name")
        version = component.get("version")
        
        # Parse purl to get ecosystem
        ecosystem = None
        if purl:
            # purl format: pkg:type/namespace/name@version
            # e.g., pkg:pypi/requests@2.28.0
            purl_match = re.match(r'pkg:([^/]+)/(.+?)(?:@(.+))?$', purl)
            if purl_match:
                purl_type = purl_match.group(1)
                purl_name = purl_match.group(2).replace("%2F", "/")
                purl_version = purl_match.group(3)
                
                # Map purl type to OSV ecosystem
                PURL_TO_ECOSYSTEM = {
                    "pypi": "PyPI",
                    "npm": "npm",
                    "maven": "Maven",
                    "golang": "Go",
                    "gem": "RubyGems",
                    "cargo": "crates.io",
                    "composer": "Packagist",
                    "nuget": "NuGet",
                }
                ecosystem = PURL_TO_ECOSYSTEM.get(purl_type.lower())
                name = name or purl_name
                version = version or purl_version
        
        # Try to infer ecosystem from group if not from purl
        if not ecosystem:
            group = component.get("group", "")
            if group:
                ECOSYSTEM_MAP = {
                    "pypi": "PyPI",
                    "npm": "npm", 
                    "maven": "Maven",
                    "go": "Go",
                    "rubygems": "RubyGems",
                    "crates.io": "crates.io",
                }
                ecosystem = ECOSYSTEM_MAP.get(group.lower(), group)
        
        if name and ecosystem:
            # Create a mock dependency for lookup
            dep = models.Dependency(
                id=idx,  # Temporary ID
                project_id=project_id,
                name=name,
                version=version or "",
                ecosystem=ecosystem,
            )
            deps_to_lookup.append(dep)
    
    if not deps_to_lookup:
        logger.warning("Could not extract any dependencies from SBOM")
        return []
    
    logger.info(f"Looking up vulnerabilities for {len(deps_to_lookup)} SBOM components")
    
    # Use the optimized batch lookup
    vulns = await lookup_dependencies(deps_to_lookup)
    
    # Update project_id for returned vulnerabilities
    for vuln in vulns:
        vuln.project_id = project_id
    
    return vulns


async def lookup_from_purl(
    purl: str,
    project_id: int
) -> List[models.Vulnerability]:
    """
    Look up vulnerabilities for a single package URL (purl).
    
    Args:
        purl: Package URL (e.g., "pkg:pypi/requests@2.28.0")
        project_id: Project ID for the vulnerabilities
        
    Returns:
        List of Vulnerability models
    """
    # Parse purl
    purl_match = re.match(r'pkg:([^/]+)/(.+?)(?:@(.+))?$', purl)
    if not purl_match:
        logger.warning(f"Invalid purl format: {purl}")
        return []
    
    purl_type = purl_match.group(1)
    name = purl_match.group(2).replace("%2F", "/")
    version = purl_match.group(3) or ""
    
    # Map purl type to OSV ecosystem
    PURL_TO_ECOSYSTEM = {
        "pypi": "PyPI",
        "npm": "npm",
        "maven": "Maven",
        "golang": "Go",
        "gem": "RubyGems",
        "cargo": "crates.io",
        "composer": "Packagist",
        "nuget": "NuGet",
        "deb": "Debian",
        "alpine": "Alpine",
    }
    
    ecosystem = PURL_TO_ECOSYSTEM.get(purl_type.lower())
    if not ecosystem:
        logger.warning(f"Unknown purl type: {purl_type}")
        return []
    
    # Create mock dependency
    dep = models.Dependency(
        id=0,
        project_id=project_id,
        name=name,
        version=version,
        ecosystem=ecosystem,
    )
    
    return await lookup_dependency(dep)


# Summary of improvements in this module:
# 
# 1. BATCH SIZE: Increased from 100 to 500 (OSV can handle 1000)
#    - 5x fewer API calls for large projects
#
# 2. VERSION RANGE CACHING: Cache vulnerability ranges, not just results
#    - Enables local matching for new versions of known packages
#    - Reduces API calls for version upgrades
#
# 3. MULTI-TIER CACHE: 
#    - Tier 1: Exact version match (fastest)
#    - Tier 2: Local version range matching (no API call)
#    - Tier 3: API call (with result + range caching)
#
# 4. ECOSYSTEM PREFETCHING: prefetch_ecosystem_vulns()
#    - Warm cache for popular packages before scanning
#    - Useful for CI/CD pipelines with similar tech stacks
#
# 5. SBOM INTEGRATION: lookup_from_sbom(), lookup_from_purl()
#    - Direct vulnerability lookup from CycloneDX SBOMs
#    - Supports package URL (purl) format
#
# 6. CONCURRENT BATCHES: Increased from 5 to 10
#    - Better parallelization for large projects
