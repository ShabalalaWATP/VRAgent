#!/usr/bin/env python3
"""Debug crawler link extraction."""

import asyncio
import httpx
import re
import sys
sys.path.insert(0, '/app/backend')

from services.intelligent_crawler_service import (
    extract_links_from_html,
    extract_forms_from_html,
    extract_api_endpoints_from_javascript,
    CrawlConfig,
    BS4_AVAILABLE,
)

async def debug_crawler():
    print("Debug Crawler Link Extraction")
    print("=" * 60)
    print(f"BeautifulSoup available: {BS4_AVAILABLE}")
    
    # Fetch the page
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False) as client:
        resp = await client.get('http://192.168.1.1/')
        html = resp.text
        base_url = 'http://192.168.1.1/'
        
        print(f"\nPage size: {len(html)} bytes")
        print(f"Status: {resp.status_code}")
        
        # Extract links using the crawler's function
        links = extract_links_from_html(html, base_url)
        print(f"\n[1] Links extracted by crawler: {len(links)}")
        for url, method in links[:30]:
            print(f"  - {method} {url}")
        
        # Extract forms
        forms = extract_forms_from_html(html, base_url)
        print(f"\n[2] Forms extracted: {len(forms)}")
        for form in forms:
            print(f"  - {form.method} {form.action} (fields: {len(form.fields)})")
        
        # Check if .css and .js are being filtered
        config = CrawlConfig()
        print(f"\n[3] Excluded extensions: {config.exclude_extensions}")
        
        # Manual regex to find ALL URLs in HTML+JS
        print("\n[4] Manual URL extraction from page:")
        
        # Find URLs in JavaScript code
        js_url_patterns = [
            r'["\'](/[a-zA-Z0-9_/.-]+\.(?:lp|php|asp|cgi|html|htm|do|action|api))["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'\.load\s*\(\s*["\']([^"\']+)["\']',
            r'\.ajax\s*\(\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'action\s*[=:]\s*["\']([^"\']+)["\']',
            r'url\s*[=:]\s*["\']([^"\']+)["\']',
        ]
        
        all_urls = set()
        for pattern in js_url_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if match.startswith('/') or match.startswith('http'):
                    full_url = match if match.startswith('http') else f'http://192.168.1.1{match}'
                    all_urls.add(full_url)
                    print(f"    Pattern '{pattern[:30]}...' found: {match}")
        
        print(f"\n  Total unique URLs found in JS: {len(all_urls)}")
        for url in sorted(all_urls):
            print(f"    - {url}")
        
        # Look for inline forms (the page uses JavaScript for login)
        print("\n[5] Looking for JavaScript-based forms/submissions:")
        submit_patterns = [
            r'\.submit\s*\(',
            r'doLogin',
            r'authenticate',
            r'CSRFtoken',
        ]
        
        for pattern in submit_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                print(f"    Found '{pattern}': {len(matches)} times")
        
        # Check for API endpoints
        print("\n[6] API endpoint patterns:")
        api_patterns = [
            r'["\']([^"\']*(?:api|ajax|json|rpc|rest)[^"\']*)["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches[:10]:
                print(f"    - {match}")

asyncio.run(debug_crawler())
