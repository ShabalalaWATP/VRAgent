#!/usr/bin/env python3
"""Deeper crawl - check JS files for more endpoints."""

import asyncio
import httpx
import re
import sys
sys.path.insert(0, '/app/backend')

async def deep_crawl():
    print("Deep Endpoint Discovery for: http://192.168.1.1")
    print("=" * 60)
    
    js_files = [
        '/js/main-min.js',
        '/js/srp-min.js', 
        '/js/validator-min.js',
        '/js/global-min.js',
        '/js/footer.js',
    ]
    
    all_endpoints = set()
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False) as client:
        for js_file in js_files:
            try:
                resp = await client.get(f'http://192.168.1.1{js_file}')
                if resp.status_code == 200:
                    content = resp.text
                    print(f"\n[JS] {js_file} ({len(content)} bytes)")
                    
                    # Find URLs/endpoints in JS
                    patterns = [
                        r'["\'](/[a-zA-Z0-9_/.-]+\.(?:lp|php|asp|cgi|html|do))["\']',
                        r'["\'](/(?:api|ajax|cgi-bin|modals)/[^"\']*)["\']',
                        r'url\s*[:=]\s*["\']([^"\']+)["\']',
                        r'\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
                        r'location\.href\s*=\s*["\']([^"\']+)["\']',
                    ]
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if match and (match.startswith('/') or match.startswith('http')):
                                all_endpoints.add(match)
                                print(f"     Found: {match}")
            except Exception as e:
                print(f"   Error: {e}")
        
        # Also check the login page for more endpoints
        print("\n[HTML] /login.lp")
        try:
            resp = await client.get('http://192.168.1.1/login.lp')
            if resp.status_code == 200:
                content = resp.text
                print(f"  Size: {len(content)} bytes")
                
                # Find all endpoints
                for pattern in [r'["\'](/[a-zA-Z0-9_/.-]+\.(?:lp|php|asp|cgi|html|do))["\']']:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        all_endpoints.add(match)
                        print(f"     Found: {match}")
        except Exception as e:
            print(f"   Error: {e}")
    
    print(f"\n{'='*60}")
    print(f"Total unique endpoints found in JS+HTML: {len(all_endpoints)}")
    for ep in sorted(all_endpoints):
        print(f"  - {ep}")

asyncio.run(deep_crawl())
