#!/usr/bin/env python3
"""Quick test for crawler inside Docker container."""

import asyncio
import sys

# Add backend to path when running from /app
sys.path.insert(0, "/app/backend")

async def test_crawler():
    print("Testing Endpoint Discovery for: http://192.168.1.1")
    print("=" * 60)
    
    from services.intelligent_crawler_service import (
        crawl_target,
        get_high_value_endpoints,
        get_attack_surface_summary,
        prioritize_endpoints_for_testing,
    )
    
    def progress_callback(data):
        if data.get("type") == "crawl_progress":
            crawled = data.get("urls_crawled", 0)
            pending = data.get("urls_pending", 0)
            print(f"  Crawled: {crawled} | Pending: {pending}")
    
    print("Starting crawl...")
    sitemap = await crawl_target(
        url="http://192.168.1.1",
        max_depth=3,
        max_pages=100,
        delay_ms=100,
        timeout_seconds=30.0,
        progress_callback=progress_callback,
    )
    
    stats = sitemap.get("statistics", {})
    print(f"\nResults:")
    print(f"  URLs crawled: {stats.get('total_urls_crawled', 0)}")
    print(f"  Parameters found: {stats.get('total_parameters', 0)}")
    print(f"  Forms found: {stats.get('total_forms', 0)}")
    print(f"  Duration: {stats.get('crawl_duration_seconds', 0):.2f}s")
    
    endpoints = sitemap.get("endpoints", [])
    print(f"\nEndpoints found: {len(endpoints)}")
    
    for i, ep in enumerate(endpoints[:20]):
        interest = ep.get("security_interest", "?")
        ep_type = ep.get("endpoint_type", "?")
        url = ep.get("url", "")[:70]
        params = len(ep.get("parameters", []))
        forms = len(ep.get("forms", []))
        print(f"  {i+1:2}. [{interest:8}] [{ep_type:6}] {url}")
        if params:
            param_names = [p.get("name") for p in ep.get("parameters", [])][:5]
            print(f"      Params: {param_names}")
        if forms:
            print(f"      Forms: {forms}")
    
    # High value endpoints
    high_value = get_high_value_endpoints(sitemap)
    print(f"\nHigh-Value Endpoints: {len(high_value)}")
    for i, ep in enumerate(high_value[:10]):
        print(f"  {i+1}. {ep.get('url', '')[:60]}")
        indicators = ep.get("security_indicators", [])[:3]
        if indicators:
            print(f"     Indicators: {indicators}")
    
    # Attack surface summary
    summary = get_attack_surface_summary(sitemap)
    print(f"\nAttack Surface Summary:")
    print(f"  Total endpoints: {summary.get('total_endpoints', 0)}")
    print(f"  Auth endpoints: {summary.get('auth_endpoints_count', 0)}")
    print(f"  API endpoints: {summary.get('api_endpoints_count', 0)}")
    print(f"  File upload: {summary.get('file_upload_count', 0)}")
    print(f"  Admin endpoints: {summary.get('admin_endpoints_count', 0)}")
    print(f"  Interest breakdown: {summary.get('interest_breakdown', {})}")
    
    # Prioritized for testing
    prioritized = prioritize_endpoints_for_testing(sitemap)
    print(f"\nTop 10 Prioritized for Testing:")
    for i, ep in enumerate(prioritized[:10]):
        score = ep.get("priority_score", 0)
        url = ep.get("url", "")[:50]
        techs = ep.get("recommended_techniques", [])[:3]
        print(f"  {i+1}. Score: {score:3} | {url}")
        print(f"     Recommended: {techs}")
    
    print("\n" + "=" * 60)
    print("DONE")

if __name__ == "__main__":
    asyncio.run(test_crawler())
