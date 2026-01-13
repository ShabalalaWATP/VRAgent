#!/usr/bin/env python3
"""
Quick test script to verify endpoint discovery is working.
Run with: python test_crawler.py http://192.168.1.1
"""

import asyncio
import sys
import json

# Add the backend to path
sys.path.insert(0, '.')

async def test_crawler(url: str):
    """Test the intelligent crawler against a target."""
    print(f"\n{'='*60}")
    print(f"Testing Endpoint Discovery for: {url}")
    print('='*60)
    
    try:
        from services.intelligent_crawler_service import (
            crawl_target,
            get_high_value_endpoints,
            get_attack_surface_summary,
            prioritize_endpoints_for_testing,
            HTTPX_AVAILABLE,
            BS4_AVAILABLE,
        )
        
        print(f"\n[+] Dependencies:")
        print(f"    - HTTPX available: {HTTPX_AVAILABLE}")
        print(f"    - BeautifulSoup available: {BS4_AVAILABLE}")
        
        if not HTTPX_AVAILABLE:
            print("\n[!] HTTPX not available - crawler may not work properly")
            return
        
        def progress_callback(data):
            if data.get("type") == "crawl_progress":
                print(f"    Crawled: {data.get('urls_crawled', 0)} | Pending: {data.get('urls_pending', 0)} | Current: {data.get('current_url', '')[:50]}...")
        
        print(f"\n[+] Starting crawl...")
        print(f"    Max depth: 3")
        print(f"    Max pages: 100")
        print(f"    Delay: 100ms")
        print()
        
        sitemap = await crawl_target(
            url=url,
            max_depth=3,
            max_pages=100,
            include_subdomains=False,
            extract_forms=True,
            extract_api_endpoints=True,
            delay_ms=100,
            timeout_seconds=30.0,
            progress_callback=progress_callback,
        )
        
        print(f"\n[+] Crawl Complete!")
        print(f"\n{'='*60}")
        print("RESULTS")
        print('='*60)
        
        stats = sitemap.get("statistics", {})
        print(f"\n[+] Statistics:")
        print(f"    Total URLs found: {stats.get('total_urls_found', 0)}")
        print(f"    Total URLs crawled: {stats.get('total_urls_crawled', 0)}")
        print(f"    Total parameters: {stats.get('total_parameters', 0)}")
        print(f"    Total forms: {stats.get('total_forms', 0)}")
        print(f"    Duration: {stats.get('crawl_duration_seconds', 0):.2f}s")
        
        endpoints = sitemap.get("endpoints", [])
        print(f"\n[+] Endpoints Discovered: {len(endpoints)}")
        
        if endpoints:
            print(f"\n    First 20 endpoints:")
            for i, ep in enumerate(endpoints[:20]):
                interest = ep.get("security_interest", "medium")
                ep_type = ep.get("endpoint_type", "page")
                params = len(ep.get("parameters", []))
                forms = len(ep.get("forms", []))
                url_short = ep.get("url", "")[:70]
                print(f"    {i+1:2}. [{interest:8}] [{ep_type:6}] {url_short}...")
                if params:
                    param_names = [p.get("name") for p in ep.get("parameters", [])][:5]
                    print(f"        Params: {param_names}")
                if forms:
                    print(f"        Forms: {forms}")
        
        # High value endpoints
        high_value = get_high_value_endpoints(sitemap)
        print(f"\n[+] High-Value Endpoints: {len(high_value)}")
        for i, ep in enumerate(high_value[:10]):
            print(f"    {i+1}. {ep.get('url', '')[:60]}")
            print(f"       Interest: {ep.get('security_interest')} | Indicators: {ep.get('security_indicators', [])[:3]}")
        
        # Attack surface summary
        summary = get_attack_surface_summary(sitemap)
        print(f"\n[+] Attack Surface Summary:")
        print(f"    Total endpoints: {summary.get('total_endpoints', 0)}")
        print(f"    Total parameters: {summary.get('total_parameters', 0)}")
        print(f"    Total forms: {summary.get('total_forms', 0)}")
        print(f"    Auth endpoints: {summary.get('auth_endpoints_count', 0)}")
        print(f"    API endpoints: {summary.get('api_endpoints_count', 0)}")
        print(f"    File upload endpoints: {summary.get('file_upload_count', 0)}")
        print(f"    Admin endpoints: {summary.get('admin_endpoints_count', 0)}")
        print(f"    Interest breakdown: {summary.get('interest_breakdown', {})}")
        print(f"    Type breakdown: {summary.get('type_breakdown', {})}")
        
        # Prioritized for testing
        prioritized = prioritize_endpoints_for_testing(sitemap)
        print(f"\n[+] Top 10 Prioritized for Testing:")
        for i, ep in enumerate(prioritized[:10]):
            print(f"    {i+1}. Score: {ep.get('priority_score', 0):3} | {ep.get('url', '')[:50]}")
            print(f"       Recommended: {ep.get('recommended_techniques', [])[:3]}")
        
        # Special endpoint categories
        print(f"\n[+] Special Endpoint Categories:")
        print(f"    Auth endpoints: {sitemap.get('auth_endpoints', [])[:5]}")
        print(f"    API endpoints: {sitemap.get('api_endpoints', [])[:5]}")
        print(f"    File upload: {sitemap.get('file_upload_endpoints', [])[:5]}")
        print(f"    Admin endpoints: {sitemap.get('admin_endpoints', [])[:5]}")
        
        # Technologies detected
        techs = sitemap.get("technologies", [])
        if techs:
            print(f"\n[+] Technologies Detected: {techs}")
        
        print(f"\n{'='*60}")
        print("ENDPOINT DISCOVERY TEST COMPLETE")
        print('='*60)
        
        return sitemap
        
    except ImportError as e:
        print(f"\n[!] Import error: {e}")
        print("    Make sure you're in the backend directory")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_crawler.py <url>")
        print("Example: python test_crawler.py http://192.168.1.1")
        sys.exit(1)
    
    url = sys.argv[1]
    asyncio.run(test_crawler(url))
