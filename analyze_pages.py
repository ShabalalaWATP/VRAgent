"""
Analyze what we get when we access discovered endpoints.
"""
import asyncio
import aiohttp
import re
from urllib.parse import urljoin, urlparse

TARGET_URL = "http://192.168.1.1"

async def analyze_pages():
    """Access each discovered page and extract more endpoints."""
    pages_to_check = [
        "/login.lp",
        "/home.lp", 
    ]
    
    all_endpoints = set()
    
    async with aiohttp.ClientSession() as session:
        for page in pages_to_check:
            url = urljoin(TARGET_URL, page)
            print(f"\n{'='*60}")
            print(f"Analyzing: {url}")
            print('='*60)
            
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    print(f"Status: {resp.status}")
                    content = await resp.text()
                    print(f"Content length: {len(content)} chars")
                    
                    if resp.status == 200:
                        # Show first part of content
                        print(f"\nFirst 500 chars:")
                        print("-" * 40)
                        print(content[:500])
                        print("-" * 40)
                        
                        # Extract any new endpoints
                        endpoints = set()
                        
                        # href
                        for match in re.finditer(r'href=["\']([^"\']+)["\']', content, re.IGNORECASE):
                            url_found = match.group(1)
                            if not url_found.startswith(('#', 'javascript:', 'mailto:')):
                                full = urljoin(url, url_found)
                                if urlparse(full).netloc == urlparse(TARGET_URL).netloc:
                                    endpoints.add(full)
                        
                        # src
                        for match in re.finditer(r'src=["\']([^"\']+)["\']', content, re.IGNORECASE):
                            url_found = match.group(1)
                            full = urljoin(url, url_found)
                            if urlparse(full).netloc == urlparse(TARGET_URL).netloc:
                                endpoints.add(full)
                        
                        # action
                        for match in re.finditer(r'action=["\']([^"\']+)["\']', content, re.IGNORECASE):
                            url_found = match.group(1)
                            full = urljoin(url, url_found)
                            if urlparse(full).netloc == urlparse(TARGET_URL).netloc:
                                endpoints.add(full)
                        
                        # JS references to .lp files
                        for match in re.finditer(r'["\'](/[^"\']+\.lp)["\']', content, re.IGNORECASE):
                            url_found = match.group(1)
                            full = urljoin(url, url_found)
                            if urlparse(full).netloc == urlparse(TARGET_URL).netloc:
                                endpoints.add(full)
                        
                        # Check for iframe src
                        for match in re.finditer(r'<iframe[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE):
                            url_found = match.group(1)
                            full = urljoin(url, url_found)
                            if urlparse(full).netloc == urlparse(TARGET_URL).netloc:
                                endpoints.add(full)
                        
                        # Look for any modals/ paths
                        for match in re.finditer(r'["\'](/modals/[^"\']+)["\']', content, re.IGNORECASE):
                            url_found = match.group(1)
                            full = urljoin(url, url_found)
                            if urlparse(full).netloc == urlparse(TARGET_URL).netloc:
                                endpoints.add(full)
                        
                        print(f"\nEndpoints found on this page: {len(endpoints)}")
                        # Sort and categorize
                        lp_files = sorted([e for e in endpoints if '.lp' in e])
                        js_files = sorted([e for e in endpoints if '.js' in e])
                        css_files = sorted([e for e in endpoints if '.css' in e])
                        other = sorted([e for e in endpoints if e not in lp_files and e not in js_files and e not in css_files])
                        
                        if lp_files:
                            print(f"\n.lp pages ({len(lp_files)}):")
                            for e in lp_files:
                                print(f"  {e}")
                                
                        if js_files:
                            print(f"\nJS files ({len(js_files)}):")
                            for e in js_files[:5]:
                                print(f"  {e}")
                            if len(js_files) > 5:
                                print(f"  ... and {len(js_files) - 5} more")
                        
                        if other:
                            print(f"\nOther ({len(other)}):")
                            for e in other[:5]:
                                print(f"  {e}")
                            if len(other) > 5:
                                print(f"  ... and {len(other) - 5} more")
                        
                        all_endpoints.update(endpoints)
                    else:
                        print(f"Response: {content[:200]}")
                        
            except Exception as e:
                print(f"Error: {e}")
        
        print(f"\n{'='*60}")
        print("TOTAL UNIQUE ENDPOINTS FROM ALL PAGES")
        print('='*60)
        
        # Categorize all
        lp_files = sorted([e for e in all_endpoints if '.lp' in e])
        print(f"\n.lp pages ({len(lp_files)}):")
        for e in lp_files:
            print(f"  {e}")
        
        print(f"\nTotal: {len(all_endpoints)} unique endpoints")

if __name__ == "__main__":
    asyncio.run(analyze_pages())
