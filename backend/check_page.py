#!/usr/bin/env python3
"""Check what's on the target page."""

import asyncio
import httpx
import re
import sys
sys.path.insert(0, '/app/backend')

async def check_page():
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False) as client:
        resp = await client.get('http://192.168.1.1/')
        print(f'Status: {resp.status_code}')
        print(f'Content-Type: {resp.headers.get("content-type", "?")}')
        print(f'Content-Length: {len(resp.text)}')
        print()
        
        # Count links
        links = re.findall(r'href=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        print(f'Links found (href): {len(links)}')
        for link in links[:30]:
            print(f'  href: {link}')
        
        # Count src attributes
        srcs = re.findall(r'src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        print(f'\nSrc attributes found: {len(srcs)}')
        for src in srcs[:20]:
            print(f'  src: {src}')
        
        # Check for forms
        forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        print(f'\nForms found: {len(forms)}')
        for form in forms[:10]:
            print(f'  form action: {form}')
        
        # Check for JavaScript URLs
        js_urls = re.findall(r'["\']((?:/|https?://)[^"\']+\.(?:js|php|asp|cgi|lp|html))["\']', resp.text, re.IGNORECASE)
        print(f'\nJS/Page URLs found: {len(js_urls)}')
        for url in js_urls[:20]:
            print(f'  url: {url}')
        
        print('\n' + '='*60)
        print('First 3000 chars of HTML:')
        print('='*60)
        print(resp.text[:3000])

asyncio.run(check_page())
