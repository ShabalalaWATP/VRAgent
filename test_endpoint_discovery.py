"""
Comprehensive endpoint discovery test.
Tests all phases of endpoint discovery without running fuzzing.
"""
import asyncio
import aiohttp
import re
from urllib.parse import urljoin, urlparse

TARGET_URL = "http://192.168.1.1"

async def test_endpoint_discovery():
    """Test all endpoint discovery mechanisms."""
    print("=" * 80)
    print("ENDPOINT DISCOVERY TEST")
    print("=" * 80)
    
    discovered_endpoints = set()
    js_endpoints = set()
    form_endpoints = set()
    
    async with aiohttp.ClientSession() as session:
        # Phase 1: Crawl main page
        print("\n[Phase 1] Crawling main page...")
        try:
            async with session.get(TARGET_URL, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                content = await resp.text()
                content_type = resp.headers.get('Content-Type', '')
                print(f"  Status: {resp.status}")
                print(f"  Content-Type: {content_type}")
                print(f"  Content length: {len(content)} chars")
                
                # Extract all links
                # href attributes
                for match in re.finditer(r'href=["\']([^"\']+)["\']', content, re.IGNORECASE):
                    url = match.group(1)
                    if not url.startswith(('#', 'javascript:', 'mailto:', 'data:')):
                        full_url = urljoin(TARGET_URL, url)
                        if urlparse(full_url).netloc == urlparse(TARGET_URL).netloc:
                            discovered_endpoints.add(full_url)
                
                # src attributes
                for match in re.finditer(r'src=["\']([^"\']+)["\']', content, re.IGNORECASE):
                    url = match.group(1)
                    full_url = urljoin(TARGET_URL, url)
                    if urlparse(full_url).netloc == urlparse(TARGET_URL).netloc:
                        discovered_endpoints.add(full_url)
                
                # action attributes
                for match in re.finditer(r'action=["\']([^"\']+)["\']', content, re.IGNORECASE):
                    url = match.group(1)
                    full_url = urljoin(TARGET_URL, url)
                    if urlparse(full_url).netloc == urlparse(TARGET_URL).netloc:
                        form_endpoints.add(full_url)
                        discovered_endpoints.add(full_url)
                
                # JavaScript URLs in HTML
                js_patterns = [
                    r'["\'](/[a-zA-Z0-9_/.-]+\.(?:lp|php|asp|html|htm))["\']',
                    r'location\.href\s*=\s*["\']([^"\']+)["\']',
                    r'window\.location\s*=\s*["\']([^"\']+)["\']',
                ]
                for pattern in js_patterns:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        url = match.group(1)
                        full_url = urljoin(TARGET_URL, url)
                        if urlparse(full_url).netloc == urlparse(TARGET_URL).netloc:
                            discovered_endpoints.add(full_url)
                
        except Exception as e:
            print(f"  Error: {e}")
            return
        
        print(f"\n  Discovered {len(discovered_endpoints)} endpoints from main page")
        
        # Phase 2: Analyze JavaScript files
        print("\n[Phase 2] Analyzing JavaScript files...")
        js_files = [url for url in discovered_endpoints if '.js' in url.lower()]
        print(f"  Found {len(js_files)} JS files to analyze")
        
        for js_url in js_files:
            try:
                async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        js_content = await resp.text()
                        print(f"\n  Analyzing: {js_url}")
                        print(f"  Size: {len(js_content)} chars")
                        
                        # Extract endpoints from JS
                        patterns = [
                            # Page endpoints
                            (r'["\'](/[a-zA-Z0-9_/.-]+\.(?:lp|php|asp|aspx|jsp|cgi|html|htm|do|action))["\']', "GET"),
                            # location assignments
                            (r'location\.href\s*=\s*["\']([^"\']+)["\']', "GET"),
                            (r'window\.location\s*=\s*["\']([^"\']+)["\']', "GET"),
                            # URL variables
                            (r'url\s*[:=]\s*["\']([^"\']+)["\']', "GET"),
                            (r'href\s*[:=]\s*["\']([^"\']+)["\']', "GET"),
                            # AJAX paths
                            (r'["\'](/(?:ajax|cgi-bin|modals|handlers?)/[^"\']*)["\']', "GET"),
                            # fetch/axios
                            (r'fetch\s*\(\s*["\']([^"\']+)["\']', "GET"),
                            (r'axios\s*\.\s*(?:get|post)\s*\(\s*["\']([^"\']+)["\']', "GET"),
                            # API paths
                            (r'["\'](/api/[^"\']+)["\']', "GET"),
                        ]
                        
                        file_endpoints = set()
                        for pattern, method in patterns:
                            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                                url = match.group(1)
                                if url and not url.startswith(('#', 'javascript:', 'mailto:')):
                                    if url.startswith('/'):
                                        full_url = urljoin(TARGET_URL, url)
                                        if urlparse(full_url).netloc == urlparse(TARGET_URL).netloc:
                                            file_endpoints.add(full_url)
                                            js_endpoints.add(full_url)
                        
                        if file_endpoints:
                            print(f"  Found {len(file_endpoints)} endpoints:")
                            for ep in sorted(file_endpoints)[:10]:
                                print(f"    - {ep}")
                            if len(file_endpoints) > 10:
                                print(f"    ... and {len(file_endpoints) - 10} more")
                        else:
                            print(f"  No page endpoints found")
                            
            except Exception as e:
                print(f"  Error fetching {js_url}: {e}")
        
        # Phase 3: Crawl discovered pages
        print("\n[Phase 3] Crawling discovered pages for more endpoints...")
        pages_to_crawl = [url for url in discovered_endpoints if not any(ext in url.lower() for ext in ['.js', '.css', '.png', '.jpg', '.gif', '.ico', '.svg', '.woff', '.ttf'])]
        print(f"  {len(pages_to_crawl)} pages to check")
        
        new_endpoints = set()
        for page_url in sorted(pages_to_crawl)[:20]:  # Limit to 20
            if page_url == TARGET_URL:
                continue
            try:
                async with session.get(page_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        # Quick link extraction
                        for match in re.finditer(r'href=["\']([^"\']+)["\']', content, re.IGNORECASE):
                            url = match.group(1)
                            if not url.startswith(('#', 'javascript:', 'mailto:', 'data:')):
                                full_url = urljoin(page_url, url)
                                if urlparse(full_url).netloc == urlparse(TARGET_URL).netloc:
                                    if full_url not in discovered_endpoints:
                                        new_endpoints.add(full_url)
                        
                        for match in re.finditer(r'action=["\']([^"\']+)["\']', content, re.IGNORECASE):
                            url = match.group(1)
                            full_url = urljoin(page_url, url)
                            if urlparse(full_url).netloc == urlparse(TARGET_URL).netloc:
                                if full_url not in discovered_endpoints:
                                    new_endpoints.add(full_url)
                                    form_endpoints.add(full_url)
                        
                        # Check for JS endpoints
                        for match in re.finditer(r'["\'](/[a-zA-Z0-9_/.-]+\.(?:lp|php))["\']', content, re.IGNORECASE):
                            url = match.group(1)
                            full_url = urljoin(page_url, url)
                            if urlparse(full_url).netloc == urlparse(TARGET_URL).netloc:
                                if full_url not in discovered_endpoints:
                                    new_endpoints.add(full_url)
                                    
            except Exception as e:
                pass  # Silent fail for secondary crawls
        
        print(f"  Found {len(new_endpoints)} new endpoints from page crawling")
        discovered_endpoints.update(new_endpoints)
        
        # Summary
        print("\n" + "=" * 80)
        print("DISCOVERY SUMMARY")
        print("=" * 80)
        
        all_endpoints = discovered_endpoints | js_endpoints
        
        # Categorize
        pages = sorted([e for e in all_endpoints if any(ext in e.lower() for ext in ['.lp', '.php', '.asp', '.html', '.htm'])])
        scripts = sorted([e for e in all_endpoints if '.js' in e.lower()])
        styles = sorted([e for e in all_endpoints if '.css' in e.lower()])
        images = sorted([e for e in all_endpoints if any(ext in e.lower() for ext in ['.png', '.jpg', '.gif', '.ico', '.svg'])])
        other = sorted([e for e in all_endpoints if e not in pages and e not in scripts and e not in styles and e not in images])
        
        print(f"\nTotal unique endpoints: {len(all_endpoints)}")
        print(f"\n[Pages/Application endpoints] ({len(pages)}):")
        for p in pages:
            print(f"  - {p}")
        
        print(f"\n[JavaScript files] ({len(scripts)}):")
        for s in scripts:
            print(f"  - {s}")
        
        print(f"\n[CSS files] ({len(styles)}):")
        for s in styles[:5]:
            print(f"  - {s}")
        if len(styles) > 5:
            print(f"  ... and {len(styles) - 5} more")
        
        print(f"\n[Images/Assets] ({len(images)}):")
        if images:
            print(f"  (skipping {len(images)} image files)")
        
        print(f"\n[Other endpoints] ({len(other)}):")
        for o in other[:10]:
            print(f"  - {o}")
        if len(other) > 10:
            print(f"  ... and {len(other) - 10} more")
        
        print(f"\n[Form action endpoints] ({len(form_endpoints)}):")
        for f in sorted(form_endpoints):
            print(f"  - {f}")
        
        print(f"\n[Endpoints from JavaScript analysis] ({len(js_endpoints)}):")
        for j in sorted(js_endpoints):
            print(f"  - {j}")
        
        # Final stats
        print("\n" + "=" * 80)
        print("FUZZING TARGETS")
        print("=" * 80)
        fuzz_targets = set()
        fuzz_targets.update(pages)
        fuzz_targets.update(form_endpoints)
        fuzz_targets.update([e for e in js_endpoints if any(ext in e.lower() for ext in ['.lp', '.php', '.asp', '.html'])])
        fuzz_targets.update([e for e in other if not any(ext in e.lower() for ext in ['.js', '.css', '.png', '.jpg', '.gif', '.ico', '.svg', '.woff', '.ttf'])])
        
        print(f"\nTotal unique fuzzing targets: {len(fuzz_targets)}")
        for t in sorted(fuzz_targets):
            print(f"  - {t}")

if __name__ == "__main__":
    asyncio.run(test_endpoint_discovery())
