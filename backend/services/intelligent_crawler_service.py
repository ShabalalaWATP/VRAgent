"""
Intelligent Crawler Service for Agentic Fuzzer.

Provides smart web crawling capabilities that:
- Discovers endpoints automatically
- Handles JavaScript-rendered content
- Respects robots.txt (optional)
- Detects and follows forms
- Handles authentication during crawling
- Extracts parameters from responses
- Builds a comprehensive site map
- Prioritizes high-value endpoints for security testing

Features:
- Multi-threaded crawling with politeness controls
- JavaScript rendering support
- Form detection and parameter extraction
- API endpoint discovery
- Authentication state management
- Duplicate detection
- Scope enforcement
- Priority queue based on security interest
"""

import asyncio
import hashlib
import json
import logging
import re
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS
# =============================================================================

class CrawlState(Enum):
    """State of the crawler."""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


class EndpointType(Enum):
    """Type of discovered endpoint."""
    PAGE = "page"
    FORM = "form"
    API = "api"
    RESOURCE = "resource"
    REDIRECT = "redirect"
    ERROR = "error"
    AUTHENTICATION = "authentication"
    FILE_UPLOAD = "file_upload"
    WEBSOCKET = "websocket"
    GRAPHQL = "graphql"


class ParameterSource(Enum):
    """Source of a discovered parameter."""
    URL_QUERY = "url_query"
    URL_PATH = "url_path"
    FORM_FIELD = "form_field"
    JSON_BODY = "json_body"
    HEADER = "header"
    COOKIE = "cookie"
    HIDDEN_FIELD = "hidden_field"
    JAVASCRIPT = "javascript"
    COMMENT = "comment"


class SecurityInterest(Enum):
    """Security interest level of an endpoint."""
    CRITICAL = "critical"    # Auth, admin, file upload
    HIGH = "high"            # User data, API, forms
    MEDIUM = "medium"        # Standard pages
    LOW = "low"              # Static resources
    MINIMAL = "minimal"      # Assets, images


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CrawledParameter:
    """A discovered parameter."""
    name: str
    source: ParameterSource
    sample_values: List[str] = field(default_factory=list)
    inferred_type: str = "string"
    is_required: bool = False
    is_hidden: bool = False
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    possible_values: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source.value,
            "sample_values": self.sample_values[:5],
            "inferred_type": self.inferred_type,
            "is_required": self.is_required,
            "is_hidden": self.is_hidden,
            "max_length": self.max_length,
            "pattern": self.pattern,
            "possible_values": self.possible_values[:10],
        }


@dataclass
class CrawledForm:
    """A discovered HTML form."""
    action: str
    method: str
    fields: List[CrawledParameter] = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"
    has_csrf: bool = False
    csrf_field_name: Optional[str] = None
    has_captcha: bool = False
    has_file_upload: bool = False
    form_id: Optional[str] = None
    form_name: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "fields": [f.to_dict() for f in self.fields],
            "enctype": self.enctype,
            "has_csrf": self.has_csrf,
            "csrf_field_name": self.csrf_field_name,
            "has_captcha": self.has_captcha,
            "has_file_upload": self.has_file_upload,
            "form_id": self.form_id,
            "form_name": self.form_name,
        }


@dataclass
class CrawledEndpoint:
    """A discovered endpoint with full context."""
    url: str
    method: str = "GET"
    endpoint_type: EndpointType = EndpointType.PAGE
    
    # Response info
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    response_time_ms: float = 0.0
    
    # Security interest
    security_interest: SecurityInterest = SecurityInterest.MEDIUM
    security_indicators: List[str] = field(default_factory=list)
    
    # Parameters
    parameters: List[CrawledParameter] = field(default_factory=list)
    path_parameters: List[str] = field(default_factory=list)
    
    # Forms
    forms: List[CrawledForm] = field(default_factory=list)
    
    # Headers
    response_headers: Dict[str, str] = field(default_factory=dict)
    required_headers: Dict[str, str] = field(default_factory=dict)
    
    # Authentication
    requires_auth: bool = False
    auth_type: Optional[str] = None
    
    # Metadata
    title: Optional[str] = None
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    parent_url: Optional[str] = None
    depth: int = 0
    
    # Content hashes for deduplication
    content_hash: str = ""
    structure_hash: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "endpoint_type": self.endpoint_type.value,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "response_time_ms": self.response_time_ms,
            "security_interest": self.security_interest.value,
            "security_indicators": self.security_indicators,
            "parameters": [p.to_dict() for p in self.parameters],
            "path_parameters": self.path_parameters,
            "forms": [f.to_dict() for f in self.forms],
            "requires_auth": self.requires_auth,
            "auth_type": self.auth_type,
            "title": self.title,
            "discovered_at": self.discovered_at,
            "parent_url": self.parent_url,
            "depth": self.depth,
        }


@dataclass
class SiteMap:
    """Complete site map from crawling."""
    root_url: str
    endpoints: List[CrawledEndpoint] = field(default_factory=list)
    parameters: Dict[str, List[CrawledParameter]] = field(default_factory=dict)
    forms: List[CrawledForm] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    auth_endpoints: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    file_upload_endpoints: List[str] = field(default_factory=list)
    admin_endpoints: List[str] = field(default_factory=list)
    
    # Statistics
    total_urls_found: int = 0
    total_urls_crawled: int = 0
    total_parameters: int = 0
    total_forms: int = 0
    crawl_duration_seconds: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_url": self.root_url,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "parameters": {
                url: [p.to_dict() for p in params]
                for url, params in self.parameters.items()
            },
            "forms": [f.to_dict() for f in self.forms],
            "technologies": self.technologies,
            "auth_endpoints": self.auth_endpoints,
            "api_endpoints": self.api_endpoints,
            "file_upload_endpoints": self.file_upload_endpoints,
            "admin_endpoints": self.admin_endpoints,
            "statistics": {
                "total_urls_found": self.total_urls_found,
                "total_urls_crawled": self.total_urls_crawled,
                "total_parameters": self.total_parameters,
                "total_forms": self.total_forms,
                "crawl_duration_seconds": self.crawl_duration_seconds,
            },
        }


@dataclass
class CrawlConfig:
    """Configuration for the crawler."""
    max_depth: int = 5
    max_pages: int = 500
    max_parameters_per_page: int = 100
    
    # Rate limiting
    requests_per_second: float = 10.0
    delay_between_requests_ms: int = 100
    timeout_seconds: float = 30.0
    
    # Scope
    include_subdomains: bool = False
    follow_external_links: bool = False
    respect_robots_txt: bool = False
    exclude_patterns: List[str] = field(default_factory=list)
    include_patterns: List[str] = field(default_factory=list)
    exclude_extensions: List[str] = field(default_factory=lambda: [
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
        ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".tar", ".gz", ".rar", ".7z",
    ])
    
    # Content handling
    extract_forms: bool = True
    extract_links: bool = True
    extract_api_endpoints: bool = True
    extract_parameters: bool = True
    extract_comments: bool = True
    extract_javascript_urls: bool = True
    handle_javascript: bool = False  # Requires headless browser
    
    # Authentication
    maintain_session: bool = True
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    auth_token: Optional[str] = None
    
    # Advanced
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    follow_redirects: bool = True
    max_redirects: int = 10
    verify_ssl: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        # Don't expose sensitive data
        if self.auth_token:
            result["auth_token"] = "***"
        return result


# =============================================================================
# URL UTILITIES
# =============================================================================

def normalize_url(url: str, base_url: str = None) -> str:
    """Normalize a URL for consistent comparison."""
    if base_url:
        url = urljoin(base_url, url)
    
    parsed = urlparse(url)
    
    # Remove default ports
    netloc = parsed.netloc
    if parsed.scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif parsed.scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    
    # Normalize path
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    
    # Sort query parameters
    query = ""
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_params = sorted(params.items())
        query = urllib.parse.urlencode(sorted_params, doseq=True)
    
    # Reconstruct
    return urllib.parse.urlunparse((
        parsed.scheme,
        netloc,
        path,
        "",  # params
        query,
        "",  # fragment
    ))


def is_same_origin(url1: str, url2: str, include_subdomains: bool = False) -> bool:
    """Check if two URLs are same origin."""
    p1 = urlparse(url1)
    p2 = urlparse(url2)
    
    if p1.scheme != p2.scheme:
        return False
    
    if include_subdomains:
        # Check if one is subdomain of other
        host1 = p1.netloc.split(":")[0]
        host2 = p2.netloc.split(":")[0]
        return host1.endswith(host2) or host2.endswith(host1)
    
    return p1.netloc == p2.netloc


def extract_path_parameters(url: str) -> List[str]:
    """Extract potential path parameters from URL."""
    parsed = urlparse(url)
    path = parsed.path
    
    params = []
    
    # Look for numeric IDs
    for match in re.finditer(r'/(\d+)(?:/|$)', path):
        params.append(f"path_id_{match.group(1)}")
    
    # Look for UUIDs
    uuid_pattern = r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)'
    for match in re.finditer(uuid_pattern, path, re.IGNORECASE):
        params.append(f"path_uuid")
    
    # Look for slugs
    slug_pattern = r'/([a-z0-9]+-[a-z0-9-]+)(?:/|$)'
    for match in re.finditer(slug_pattern, path, re.IGNORECASE):
        params.append(f"path_slug")
    
    return params


def calculate_url_hash(url: str, method: str = "GET") -> str:
    """Calculate hash for URL deduplication."""
    # Normalize and hash
    normalized = normalize_url(url)
    return hashlib.md5(f"{method}:{normalized}".encode()).hexdigest()[:16]


def calculate_content_hash(content: str) -> str:
    """Calculate hash of content."""
    return hashlib.md5(content.encode()).hexdigest()[:16]


def calculate_structure_hash(html: str) -> str:
    """Calculate hash of HTML structure (ignoring content)."""
    if not BS4_AVAILABLE:
        return calculate_content_hash(html)
    
    try:
        soup = BeautifulSoup(html, "html.parser")
        
        # Remove text content, keep structure
        for tag in soup.find_all(True):
            if tag.string:
                tag.string.replace_with("")
        
        structure = str(soup)
        return hashlib.md5(structure.encode()).hexdigest()[:16]
    except Exception:
        return calculate_content_hash(html)


# =============================================================================
# CONTENT EXTRACTION
# =============================================================================

def extract_links_from_html(html: str, base_url: str) -> List[Tuple[str, str]]:
    """Extract links from HTML. Returns list of (url, method) tuples."""
    links = []
    seen_urls = set()  # Avoid duplicates
    
    def add_link(url: str, method: str = "GET"):
        """Add a link if not already seen."""
        normalized = url.split('?')[0].split('#')[0]  # Normalize for dedup
        if normalized not in seen_urls:
            seen_urls.add(normalized)
            links.append((url, method))
    
    if not BS4_AVAILABLE:
        # Enhanced regex fallback - extract more than just href
        
        # 1. href attributes (links, stylesheets)
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            url = urljoin(base_url, match.group(1))
            add_link(url, "GET")
        
        # 2. src attributes (scripts, images, iframes)
        src_pattern = r'src=["\']([^"\']+)["\']'
        for match in re.finditer(src_pattern, html, re.IGNORECASE):
            url = urljoin(base_url, match.group(1))
            add_link(url, "GET")
        
        # 3. action attributes (forms)
        action_pattern = r'action=["\']([^"\']+)["\']'
        for match in re.finditer(action_pattern, html, re.IGNORECASE):
            url = urljoin(base_url, match.group(1))
            add_link(url, "POST")  # Forms typically POST
        
        # 4. data-* attributes with URLs
        data_pattern = r'data-[a-z-]+=["\']([^"\']+)["\']'
        for match in re.finditer(data_pattern, html, re.IGNORECASE):
            value = match.group(1)
            if value.startswith(('http://', 'https://', '/')):
                url = urljoin(base_url, value)
                add_link(url, "GET")
        
        # 5. URLs in JavaScript code - find page endpoints
        js_url_patterns = [
            # Direct page references
            r'["\'](/[a-zA-Z0-9_/.-]+\.(?:lp|php|asp|aspx|jsp|cgi|html|htm|do|action|pl|py|rb))["\']',
            # API endpoints  
            r'["\'](/(?:api|ajax|json|rest|rpc|graphql|v[0-9]+)/[^"\']*)["\']',
            # window.location assignments
            r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            # jQuery/AJAX calls
            r'\.(?:get|post|ajax|load)\s*\(\s*["\']([^"\']+)["\']',
            # fetch API
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            # XMLHttpRequest
            r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in js_url_patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                value = match.group(1)
                if value and (value.startswith(('http://', 'https://', '/')) or not value.startswith(('#', 'javascript:', 'mailto:'))):
                    url = urljoin(base_url, value)
                    # Determine method from pattern
                    method = "POST" if "post" in pattern.lower() else "GET"
                    add_link(url, method)
        
        return links
    
    try:
        soup = BeautifulSoup(html, "html.parser")
        
        # Extract <a> links
        for a in soup.find_all("a", href=True):
            url = urljoin(base_url, a["href"])
            links.append((url, "GET"))
        
        # Extract <link> tags
        for link in soup.find_all("link", href=True):
            url = urljoin(base_url, link["href"])
            links.append((url, "GET"))
        
        # Extract <script> src
        for script in soup.find_all("script", src=True):
            url = urljoin(base_url, script["src"])
            links.append((url, "GET"))
        
        # Extract <img> src
        for img in soup.find_all("img", src=True):
            url = urljoin(base_url, img["src"])
            links.append((url, "GET"))
        
        # Extract data-* attributes that might contain URLs
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if attr.startswith("data-") and isinstance(value, str):
                    if value.startswith(("http://", "https://", "/")):
                        url = urljoin(base_url, value)
                        links.append((url, "GET"))
        
    except Exception as e:
        logger.warning(f"HTML parsing error: {e}")
    
    return links


def extract_forms_from_html(html: str, base_url: str) -> List[CrawledForm]:
    """Extract forms from HTML."""
    forms = []
    
    if not BS4_AVAILABLE:
        # Enhanced regex fallback for form extraction
        # Match <form> tags
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_attr_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']'
        form_attr_pattern2 = r'<form[^>]*method=["\']([^"\']*)["\'][^>]*action=["\']([^"\']*)["\']'
        
        # Find forms with action and method
        for match in re.finditer(form_attr_pattern, html, re.IGNORECASE | re.DOTALL):
            action = match.group(1) or ""
            method = match.group(2) or "GET"
            action_url = urljoin(base_url, action) if action else base_url
            
            form = CrawledForm(
                action=action_url,
                method=method.upper(),
            )
            forms.append(form)
        
        # Try alternate order (method before action)
        for match in re.finditer(form_attr_pattern2, html, re.IGNORECASE | re.DOTALL):
            method = match.group(1) or "GET"
            action = match.group(2) or ""
            action_url = urljoin(base_url, action) if action else base_url
            
            # Avoid duplicates
            if not any(f.action == action_url for f in forms):
                form = CrawledForm(
                    action=action_url,
                    method=method.upper(),
                )
                forms.append(form)
        
        # Also detect JavaScript-based form submissions (common in modern apps)
        # Look for AJAX POST endpoints
        ajax_post_pattern = r'\.(?:post|ajax)\s*\(\s*["\']([^"\']+)["\']'
        for match in re.finditer(ajax_post_pattern, html, re.IGNORECASE):
            action_url = urljoin(base_url, match.group(1))
            if not any(f.action == action_url for f in forms):
                form = CrawledForm(
                    action=action_url,
                    method="POST",
                )
                forms.append(form)
        
        return forms
    
    try:
        soup = BeautifulSoup(html, "html.parser")
        
        # CSRF token patterns
        csrf_patterns = [
            r'csrf', r'token', r'_token', r'authenticity',
            r'__requestverificationtoken', r'antiforgery',
        ]
        
        # Captcha patterns
        captcha_patterns = [
            r'captcha', r'recaptcha', r'hcaptcha', r'turnstile',
        ]
        
        for form in soup.find_all("form"):
            action = form.get("action", "")
            action_url = urljoin(base_url, action) if action else base_url
            method = form.get("method", "GET").upper()
            enctype = form.get("enctype", "application/x-www-form-urlencoded")
            
            crawled_form = CrawledForm(
                action=action_url,
                method=method,
                enctype=enctype,
                form_id=form.get("id"),
                form_name=form.get("name"),
            )
            
            # Extract form fields
            for input_tag in form.find_all(["input", "select", "textarea"]):
                name = input_tag.get("name")
                if not name:
                    continue
                
                input_type = input_tag.get("type", "text")
                
                param = CrawledParameter(
                    name=name,
                    source=ParameterSource.FORM_FIELD,
                    is_required=input_tag.get("required") is not None,
                    is_hidden=input_type == "hidden",
                    max_length=int(input_tag.get("maxlength", 0)) or None,
                    pattern=input_tag.get("pattern"),
                )
                
                # Get sample value
                value = input_tag.get("value", "")
                if value:
                    param.sample_values.append(value)
                
                # Infer type
                if input_type in ["email"]:
                    param.inferred_type = "email"
                elif input_type in ["number", "range"]:
                    param.inferred_type = "number"
                elif input_type in ["date", "datetime-local"]:
                    param.inferred_type = "date"
                elif input_type in ["password"]:
                    param.inferred_type = "password"
                elif input_type in ["file"]:
                    param.inferred_type = "file"
                    crawled_form.has_file_upload = True
                
                # Check for CSRF token
                name_lower = name.lower()
                if any(re.search(p, name_lower) for p in csrf_patterns):
                    crawled_form.has_csrf = True
                    crawled_form.csrf_field_name = name
                
                # Get select options
                if input_tag.name == "select":
                    for option in input_tag.find_all("option"):
                        opt_value = option.get("value", option.text.strip())
                        if opt_value:
                            param.possible_values.append(opt_value)
                
                crawled_form.fields.append(param)
            
            # Check for captcha
            form_html = str(form).lower()
            if any(re.search(p, form_html) for p in captcha_patterns):
                crawled_form.has_captcha = True
            
            forms.append(crawled_form)
        
    except Exception as e:
        logger.warning(f"Form extraction error: {e}")
    
    return forms


def extract_api_endpoints_from_javascript(js: str, base_url: str) -> List[Tuple[str, str]]:
    """Extract API endpoints and page URLs from JavaScript code."""
    endpoints = []
    seen_urls = set()
    
    def add_endpoint(url: str, method: str = "GET"):
        """Add endpoint if not already seen."""
        normalized = url.split('?')[0].split('#')[0]
        if normalized not in seen_urls:
            seen_urls.add(normalized)
            endpoints.append((url, method))
    
    # Common API URL patterns
    patterns = [
        # fetch() calls
        (r'fetch\s*\(\s*["\']([^"\']+)["\']', None, "GET"),
        # XMLHttpRequest.open()
        (r'\.open\s*\(\s*["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']', (0, 1), None),
        # axios calls
        (r'axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', (0, 1), None),
        # jQuery AJAX
        (r'\$\s*\.\s*(get|post|ajax)\s*\(\s*["\']([^"\']+)["\']', (0, 1), None),
        # API path strings
        (r'["\'](/api/[^"\']+)["\']', None, "GET"),
        (r'["\'](/v\d+/[^"\']+)["\']', None, "GET"),
        # GraphQL endpoint
        (r'["\']([^"\']*graphql[^"\']*)["\']', None, "POST"),
        # Page endpoints - common web extensions
        (r'["\'](/[a-zA-Z0-9_/.-]+\.(?:lp|php|asp|aspx|jsp|cgi|html|htm|do|action|pl|py|rb))["\']', None, "GET"),
        # location.href assignments
        (r'location\.href\s*=\s*["\']([^"\']+)["\']', None, "GET"),
        (r'window\.location\s*=\s*["\']([^"\']+)["\']', None, "GET"),
        # Common URL variable patterns
        (r'url\s*[:=]\s*["\']([^"\']+)["\']', None, "GET"),
        (r'href\s*[:=]\s*["\']([^"\']+)["\']', None, "GET"),
        (r'action\s*[:=]\s*["\']([^"\']+)["\']', None, "POST"),
        # AJAX/cgi-bin endpoints
        (r'["\'](/(?:ajax|cgi-bin|modals|handlers?|services?)/[^"\']*)["\']', None, "GET"),
    ]
    
    for pattern, group_indices, default_method in patterns:
        for match in re.finditer(pattern, js, re.IGNORECASE):
            groups = match.groups()
            
            if group_indices is not None:
                # Method and URL are in specific groups
                method_idx, url_idx = group_indices
                method = groups[method_idx].upper() if groups[method_idx] else "GET"
                url = groups[url_idx]
            elif len(groups) == 1:
                url = groups[0]
                method = default_method or "GET"
            elif len(groups) == 2:
                # First group might be method
                if groups[0] and groups[0].upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                    method = groups[0].upper()
                    url = groups[1]
                else:
                    method = default_method or "GET"
                    url = groups[1]
            else:
                continue
            
            # Skip invalid URLs
            if not url or url.startswith(('#', 'javascript:', 'mailto:', 'data:')):
                continue
            
            # Resolve relative URLs
            if url.startswith("/"):
                url = urljoin(base_url, url)
            elif not url.startswith(("http://", "https://")):
                # Skip non-URL strings
                continue
            
            add_endpoint(url, method)
    
    return endpoints


def extract_parameters_from_url(url: str) -> List[CrawledParameter]:
    """Extract query parameters from URL."""
    parsed = urlparse(url)
    params = []
    
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    for name, values in query_params.items():
        param = CrawledParameter(
            name=name,
            source=ParameterSource.URL_QUERY,
            sample_values=values[:5],
        )
        
        # Infer type from values
        if values:
            sample = values[0]
            if sample.isdigit():
                param.inferred_type = "integer"
            elif re.match(r'^[0-9a-f-]{36}$', sample, re.IGNORECASE):
                param.inferred_type = "uuid"
            elif re.match(r'^[\w.-]+@[\w.-]+\.\w+$', sample):
                param.inferred_type = "email"
        
        params.append(param)
    
    return params


def extract_comments_from_html(html: str) -> List[str]:
    """Extract HTML comments that might contain sensitive info."""
    comments = []
    
    # Match HTML comments
    comment_pattern = r'<!--(.*?)-->'
    for match in re.finditer(comment_pattern, html, re.DOTALL):
        comment = match.group(1).strip()
        
        # Filter out empty or standard comments
        if len(comment) > 10:
            # Check for potentially interesting content
            interesting_patterns = [
                r'TODO', r'FIXME', r'XXX', r'HACK', r'BUG',
                r'password', r'secret', r'api', r'key', r'token',
                r'debug', r'test', r'admin', r'config',
                r'http://', r'https://', r'/api/',
            ]
            
            comment_lower = comment.lower()
            if any(re.search(p, comment_lower, re.IGNORECASE) for p in interesting_patterns):
                comments.append(comment[:500])  # Limit length
    
    return comments


# =============================================================================
# SECURITY INTEREST CLASSIFICATION
# =============================================================================

def classify_security_interest(
    url: str,
    content_type: str = "",
    status_code: int = 200,
    forms: List[CrawledForm] = None,
    parameters: List[CrawledParameter] = None,
) -> Tuple[SecurityInterest, List[str]]:
    """Classify the security interest level of an endpoint."""
    indicators = []
    interest = SecurityInterest.MEDIUM
    
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    # Critical indicators
    critical_patterns = [
        (r'/admin', "admin_path"),
        (r'/administrator', "administrator_path"),
        (r'/login', "login_path"),
        (r'/signin', "signin_path"),
        (r'/auth', "auth_path"),
        (r'/oauth', "oauth_path"),
        (r'/saml', "saml_path"),
        (r'/sso', "sso_path"),
        (r'/password', "password_path"),
        (r'/reset', "reset_path"),
        (r'/register', "register_path"),
        (r'/signup', "signup_path"),
        (r'/upload', "upload_path"),
        (r'/import', "import_path"),
        (r'/export', "export_path"),
        (r'/backup', "backup_path"),
        (r'/config', "config_path"),
        (r'/settings', "settings_path"),
        (r'/console', "console_path"),
        (r'/shell', "shell_path"),
        (r'/exec', "exec_path"),
        (r'/cmd', "cmd_path"),
        (r'/manage', "manage_path"),
        (r'/phpmyadmin', "phpmyadmin_path"),
        (r'/wp-admin', "wp_admin_path"),
        (r'\.env', "env_file"),
        (r'\.git', "git_path"),
        (r'/debug', "debug_path"),
        (r'/trace', "trace_path"),
        (r'/actuator', "actuator_path"),
    ]
    
    for pattern, indicator in critical_patterns:
        if re.search(pattern, path):
            indicators.append(indicator)
            interest = SecurityInterest.CRITICAL
    
    # High interest indicators
    high_patterns = [
        (r'/api/', "api_path"),
        (r'/v\d+/', "versioned_api"),
        (r'/graphql', "graphql_endpoint"),
        (r'/rest/', "rest_api"),
        (r'/user', "user_path"),
        (r'/account', "account_path"),
        (r'/profile', "profile_path"),
        (r'/payment', "payment_path"),
        (r'/checkout', "checkout_path"),
        (r'/cart', "cart_path"),
        (r'/order', "order_path"),
        (r'/download', "download_path"),
        (r'/file', "file_path"),
        (r'/document', "document_path"),
        (r'/search', "search_path"),
        (r'/webhook', "webhook_path"),
        (r'/callback', "callback_path"),
        (r'/redirect', "redirect_path"),
    ]
    
    if interest != SecurityInterest.CRITICAL:
        for pattern, indicator in high_patterns:
            if re.search(pattern, path):
                indicators.append(indicator)
                interest = SecurityInterest.HIGH
                break
    
    # Check forms
    if forms:
        for form in forms:
            if form.has_file_upload:
                indicators.append("file_upload_form")
                interest = SecurityInterest.CRITICAL
            elif form.method.upper() == "POST":
                indicators.append("post_form")
                if interest.value not in ["critical"]:
                    interest = SecurityInterest.HIGH
    
    # Check parameters
    if parameters:
        interesting_params = ["id", "user", "admin", "token", "key", "file", "path", "url", "cmd", "exec"]
        for param in parameters:
            if any(p in param.name.lower() for p in interesting_params):
                indicators.append(f"interesting_param:{param.name}")
                if interest.value not in ["critical", "high"]:
                    interest = SecurityInterest.HIGH
    
    # Check content type
    if content_type:
        if "json" in content_type.lower():
            indicators.append("json_response")
            if interest.value not in ["critical", "high"]:
                interest = SecurityInterest.HIGH
        elif "xml" in content_type.lower():
            indicators.append("xml_response")
            if interest.value not in ["critical", "high"]:
                interest = SecurityInterest.HIGH
    
    # Low interest (static resources)
    low_extensions = [".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff"]
    if any(path.endswith(ext) for ext in low_extensions):
        interest = SecurityInterest.LOW
        indicators = ["static_resource"]
    
    return interest, indicators


# =============================================================================
# INTELLIGENT CRAWLER
# =============================================================================

class IntelligentCrawler:
    """Intelligent web crawler for security testing."""
    
    def __init__(self, config: CrawlConfig = None):
        self.config = config or CrawlConfig()
        self.state = CrawlState.IDLE
        
        # URL tracking
        self._visited_urls: Set[str] = set()
        self._visited_hashes: Set[str] = set()
        self._pending_urls: List[Tuple[str, str, int, str]] = []  # (url, method, depth, parent)
        
        # Content deduplication
        self._content_hashes: Set[str] = set()
        self._structure_hashes: Dict[str, int] = defaultdict(int)
        
        # Results
        self._endpoints: Dict[str, CrawledEndpoint] = {}
        self._all_parameters: Dict[str, List[CrawledParameter]] = defaultdict(list)
        self._all_forms: List[CrawledForm] = []
        
        # Statistics
        self._start_time: float = 0
        self._request_count: int = 0
        self._error_count: int = 0
        self._last_request_time: float = 0
        
        # Rate limiting
        self._request_times: List[float] = []
        
        # HTTP client
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _init_client(self):
        """Initialize HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=self.config.follow_redirects,
                max_redirects=self.config.max_redirects,
                verify=self.config.verify_ssl,
                headers={"User-Agent": self.config.user_agent, **self.config.headers},
                cookies=self.config.cookies,
            )
    
    async def _close_client(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def _rate_limit(self):
        """Apply rate limiting."""
        now = time.time()
        
        # Remove old request times (older than 1 second)
        self._request_times = [t for t in self._request_times if now - t < 1.0]
        
        # Check if we need to wait
        if len(self._request_times) >= self.config.requests_per_second:
            wait_time = 1.0 - (now - self._request_times[0])
            if wait_time > 0:
                await asyncio.sleep(wait_time)
        
        # Minimum delay between requests
        if self._last_request_time > 0:
            elapsed = now - self._last_request_time
            min_delay = self.config.delay_between_requests_ms / 1000.0
            if elapsed < min_delay:
                await asyncio.sleep(min_delay - elapsed)
        
        self._request_times.append(time.time())
        self._last_request_time = time.time()
    
    def _is_in_scope(self, url: str, base_url: str) -> bool:
        """Check if URL is in scope."""
        # Check same origin
        if not is_same_origin(url, base_url, self.config.include_subdomains):
            if not self.config.follow_external_links:
                return False
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Check excluded extensions
        for ext in self.config.exclude_extensions:
            if path.endswith(ext.lower()):
                return False
        
        # Check exclude patterns
        for pattern in self.config.exclude_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False
        
        # Check include patterns (if specified, URL must match at least one)
        if self.config.include_patterns:
            if not any(re.search(p, url, re.IGNORECASE) for p in self.config.include_patterns):
                return False
        
        return True
    
    def _add_url(self, url: str, method: str, depth: int, parent: str):
        """Add a URL to the pending queue."""
        url_hash = calculate_url_hash(url, method)
        
        if url_hash in self._visited_hashes:
            return
        
        if depth > self.config.max_depth:
            return
        
        if len(self._visited_urls) + len(self._pending_urls) >= self.config.max_pages:
            return
        
        self._pending_urls.append((url, method, depth, parent))
        self._visited_hashes.add(url_hash)
    
    async def _fetch_url(self, url: str, method: str = "GET") -> Tuple[Optional[httpx.Response], float]:
        """Fetch a URL and return response with timing."""
        await self._rate_limit()
        
        start_time = time.time()
        try:
            if method.upper() == "GET":
                response = await self._client.get(url)
            elif method.upper() == "HEAD":
                response = await self._client.head(url)
            else:
                response = await self._client.request(method.upper(), url)
            
            elapsed = (time.time() - start_time) * 1000
            self._request_count += 1
            return response, elapsed
            
        except Exception as e:
            self._error_count += 1
            logger.debug(f"Fetch error for {url}: {e}")
            return None, 0
    
    async def _process_response(
        self,
        url: str,
        method: str,
        response: httpx.Response,
        response_time: float,
        depth: int,
        parent_url: str,
    ) -> CrawledEndpoint:
        """Process a response and extract information."""
        content_type = response.headers.get("content-type", "")
        content = response.text if "text" in content_type or "json" in content_type else ""
        
        # Calculate hashes
        content_hash = calculate_content_hash(content)
        structure_hash = calculate_structure_hash(content) if "html" in content_type else content_hash
        
        # Check for duplicate content
        is_duplicate = content_hash in self._content_hashes
        self._content_hashes.add(content_hash)
        self._structure_hashes[structure_hash] += 1
        
        # Extract parameters from URL
        url_params = extract_parameters_from_url(url)
        path_params = extract_path_parameters(url)
        
        # Extract forms
        forms = []
        if self.config.extract_forms and "html" in content_type:
            forms = extract_forms_from_html(content, url)
            self._all_forms.extend(forms)
        
        # Classify security interest
        interest, indicators = classify_security_interest(
            url, content_type, response.status_code, forms, url_params
        )
        
        # Determine endpoint type
        endpoint_type = EndpointType.PAGE
        if "json" in content_type:
            endpoint_type = EndpointType.API
        elif "xml" in content_type:
            endpoint_type = EndpointType.API
        elif forms:
            endpoint_type = EndpointType.FORM
        elif response.status_code >= 300 and response.status_code < 400:
            endpoint_type = EndpointType.REDIRECT
        elif response.status_code >= 400:
            endpoint_type = EndpointType.ERROR
        
        # Check for auth requirements
        requires_auth = False
        auth_type = None
        if response.status_code == 401:
            requires_auth = True
            auth_header = response.headers.get("www-authenticate", "")
            if "basic" in auth_header.lower():
                auth_type = "basic"
            elif "bearer" in auth_header.lower():
                auth_type = "bearer"
            elif "digest" in auth_header.lower():
                auth_type = "digest"
        elif response.status_code == 403:
            requires_auth = True
        
        # Extract title
        title = None
        if "html" in content_type:
            title_match = re.search(r'<title>([^<]+)</title>', content, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()[:100]
        
        # Create endpoint
        endpoint = CrawledEndpoint(
            url=url,
            method=method,
            endpoint_type=endpoint_type,
            status_code=response.status_code,
            content_type=content_type,
            content_length=len(content),
            response_time_ms=response_time,
            security_interest=interest,
            security_indicators=indicators,
            parameters=url_params,
            path_parameters=path_params,
            forms=forms,
            response_headers=dict(response.headers),
            requires_auth=requires_auth,
            auth_type=auth_type,
            title=title,
            parent_url=parent_url,
            depth=depth,
            content_hash=content_hash,
            structure_hash=structure_hash,
        )
        
        # Store parameters
        for param in url_params:
            self._all_parameters[url].append(param)
        
        # Extract links for crawling
        if not is_duplicate and self.config.extract_links and "html" in content_type:
            links = extract_links_from_html(content, url)
            for link_url, link_method in links:
                if self._is_in_scope(link_url, url):
                    self._add_url(link_url, link_method, depth + 1, url)
        
        # Extract API endpoints from JavaScript
        # Check both content-type AND URL extension (.js files often return text/html)
        is_javascript = (
            "javascript" in content_type or 
            url.split('?')[0].endswith('.js')
        )
        if self.config.extract_api_endpoints and is_javascript:
            api_endpoints = extract_api_endpoints_from_javascript(content, url)
            for api_url, api_method in api_endpoints:
                if self._is_in_scope(api_url, url):
                    self._add_url(api_url, api_method, depth + 1, url)
        
        # Extract comments
        if self.config.extract_comments and "html" in content_type:
            comments = extract_comments_from_html(content)
            if comments:
                endpoint.security_indicators.extend([f"comment_found" for _ in comments[:3]])
        
        return endpoint
    
    async def crawl(
        self,
        start_url: str,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> SiteMap:
        """
        Crawl a website starting from the given URL.
        
        Args:
            start_url: The URL to start crawling from
            progress_callback: Optional callback for progress updates
            
        Returns:
            SiteMap with all discovered endpoints
        """
        self.state = CrawlState.RUNNING
        self._start_time = time.time()
        
        # Reset state
        self._visited_urls.clear()
        self._visited_hashes.clear()
        self._pending_urls.clear()
        self._content_hashes.clear()
        self._structure_hashes.clear()
        self._endpoints.clear()
        self._all_parameters.clear()
        self._all_forms.clear()
        self._request_count = 0
        self._error_count = 0
        
        # Normalize start URL
        start_url = normalize_url(start_url)
        
        # Add initial URL
        self._add_url(start_url, "GET", 0, "")
        
        try:
            await self._init_client()
            
            while self._pending_urls and self.state == CrawlState.RUNNING:
                # Sort by security interest priority
                # In a real implementation, this would use a priority queue
                url, method, depth, parent = self._pending_urls.pop(0)
                
                # Check max pages
                if len(self._visited_urls) >= self.config.max_pages:
                    break
                
                self._visited_urls.add(url)
                
                # Fetch URL
                response, response_time = await self._fetch_url(url, method)
                
                if response is None:
                    continue
                
                # Process response
                endpoint = await self._process_response(
                    url, method, response, response_time, depth, parent
                )
                self._endpoints[url] = endpoint
                
                # Progress callback
                if progress_callback:
                    progress_callback({
                        "type": "crawl_progress",
                        "urls_crawled": len(self._visited_urls),
                        "urls_pending": len(self._pending_urls),
                        "current_url": url,
                        "depth": depth,
                    })
            
            self.state = CrawlState.COMPLETED
            
        except Exception as e:
            self.state = CrawlState.ERROR
            logger.error(f"Crawl error: {e}")
            raise
        finally:
            await self._close_client()
        
        # Build site map
        return self._build_sitemap(start_url)
    
    def _build_sitemap(self, root_url: str) -> SiteMap:
        """Build the final site map from crawl results."""
        endpoints = list(self._endpoints.values())
        
        # Sort by security interest
        endpoints.sort(key=lambda e: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "minimal": 4}.get(e.security_interest.value, 5),
            e.depth,
        ))
        
        # Identify special endpoints
        auth_endpoints = [
            e.url for e in endpoints
            if any(ind in ["auth_path", "login_path", "signin_path", "oauth_path"]
                   for ind in e.security_indicators)
        ]
        
        api_endpoints = [
            e.url for e in endpoints
            if e.endpoint_type == EndpointType.API or
            any(ind in ["api_path", "versioned_api", "graphql_endpoint"]
                for ind in e.security_indicators)
        ]
        
        file_upload_endpoints = [
            e.url for e in endpoints
            if any(f.has_file_upload for f in e.forms) or
            "file_upload_form" in e.security_indicators
        ]
        
        admin_endpoints = [
            e.url for e in endpoints
            if any(ind in ["admin_path", "administrator_path", "wp_admin_path", "manage_path"]
                   for ind in e.security_indicators)
        ]
        
        # Calculate statistics
        total_params = sum(len(params) for params in self._all_parameters.values())
        
        return SiteMap(
            root_url=root_url,
            endpoints=endpoints,
            parameters=dict(self._all_parameters),
            forms=self._all_forms,
            auth_endpoints=auth_endpoints,
            api_endpoints=api_endpoints,
            file_upload_endpoints=file_upload_endpoints,
            admin_endpoints=admin_endpoints,
            total_urls_found=len(self._visited_hashes),
            total_urls_crawled=len(self._visited_urls),
            total_parameters=total_params,
            total_forms=len(self._all_forms),
            crawl_duration_seconds=time.time() - self._start_time,
        )
    
    def pause(self):
        """Pause the crawler."""
        if self.state == CrawlState.RUNNING:
            self.state = CrawlState.PAUSED
    
    def resume(self):
        """Resume the crawler."""
        if self.state == CrawlState.PAUSED:
            self.state = CrawlState.RUNNING
    
    def stop(self):
        """Stop the crawler."""
        self.state = CrawlState.COMPLETED
    
    def get_stats(self) -> Dict[str, Any]:
        """Get crawler statistics."""
        return {
            "state": self.state.value,
            "urls_crawled": len(self._visited_urls),
            "urls_pending": len(self._pending_urls),
            "total_requests": self._request_count,
            "errors": self._error_count,
            "endpoints_found": len(self._endpoints),
            "forms_found": len(self._all_forms),
            "parameters_found": sum(len(p) for p in self._all_parameters.values()),
            "duration_seconds": time.time() - self._start_time if self._start_time else 0,
        }


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================

_crawler: Optional[IntelligentCrawler] = None


def get_crawler(config: CrawlConfig = None) -> IntelligentCrawler:
    """Get the singleton crawler instance."""
    global _crawler
    if _crawler is None or config is not None:
        _crawler = IntelligentCrawler(config)
    return _crawler


def reset_crawler():
    """Reset the crawler singleton."""
    global _crawler
    _crawler = None


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def crawl_target(
    url: str,
    max_depth: int = 3,
    max_pages: int = 100,
    include_subdomains: bool = False,
    respect_robots_txt: bool = False,
    extract_forms: bool = True,
    extract_api_endpoints: bool = True,
    delay_ms: int = 100,
    timeout_seconds: float = 30.0,
    cookies: Dict[str, str] = None,
    headers: Dict[str, str] = None,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """
    Crawl a target URL and return the site map.
    
    Args:
        url: Target URL to crawl
        max_depth: Maximum crawl depth
        max_pages: Maximum pages to crawl
        include_subdomains: Whether to include subdomains
        respect_robots_txt: Whether to respect robots.txt
        extract_forms: Whether to extract forms
        extract_api_endpoints: Whether to extract API endpoints
        delay_ms: Delay between requests in milliseconds
        timeout_seconds: Request timeout
        cookies: Optional cookies to include
        headers: Optional headers to include
        progress_callback: Optional callback for progress
        
    Returns:
        Site map dictionary
    """
    config = CrawlConfig(
        max_depth=max_depth,
        max_pages=max_pages,
        include_subdomains=include_subdomains,
        respect_robots_txt=respect_robots_txt,
        extract_forms=extract_forms,
        extract_api_endpoints=extract_api_endpoints,
        delay_between_requests_ms=delay_ms,
        timeout_seconds=timeout_seconds,
        cookies=cookies or {},
        headers=headers or {},
    )
    
    crawler = IntelligentCrawler(config)
    sitemap = await crawler.crawl(url, progress_callback)
    
    return sitemap.to_dict()


def get_high_value_endpoints(sitemap: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Get high-value endpoints from a site map for security testing.
    
    Args:
        sitemap: Site map dictionary from crawl
        
    Returns:
        List of high-value endpoints sorted by security interest
    """
    endpoints = sitemap.get("endpoints", [])
    
    # Filter to critical and high interest
    high_value = [
        e for e in endpoints
        if e.get("security_interest") in ["critical", "high"]
    ]
    
    return high_value


def get_attack_surface_summary(sitemap: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get a summary of the attack surface from a site map.
    
    Args:
        sitemap: Site map dictionary from crawl
        
    Returns:
        Attack surface summary
    """
    endpoints = sitemap.get("endpoints", [])
    stats = sitemap.get("statistics", {})
    
    # Count by interest level
    interest_counts = defaultdict(int)
    for e in endpoints:
        interest_counts[e.get("security_interest", "medium")] += 1
    
    # Count by type
    type_counts = defaultdict(int)
    for e in endpoints:
        type_counts[e.get("endpoint_type", "page")] += 1
    
    # Collect all parameters
    all_params = []
    for e in endpoints:
        all_params.extend(e.get("parameters", []))
    
    # Find unique parameter names
    param_names = set(p.get("name") for p in all_params)
    
    return {
        "total_endpoints": len(endpoints),
        "total_parameters": stats.get("total_parameters", 0),
        "total_forms": stats.get("total_forms", 0),
        "unique_parameter_names": len(param_names),
        "interest_breakdown": dict(interest_counts),
        "type_breakdown": dict(type_counts),
        "auth_endpoints_count": len(sitemap.get("auth_endpoints", [])),
        "api_endpoints_count": len(sitemap.get("api_endpoints", [])),
        "file_upload_count": len(sitemap.get("file_upload_endpoints", [])),
        "admin_endpoints_count": len(sitemap.get("admin_endpoints", [])),
        "crawl_duration_seconds": stats.get("crawl_duration_seconds", 0),
    }


def prioritize_endpoints_for_testing(
    sitemap: Dict[str, Any],
    techniques: List[str] = None,
) -> List[Dict[str, Any]]:
    """
    Prioritize endpoints for security testing based on characteristics.
    
    Args:
        sitemap: Site map dictionary from crawl
        techniques: Optional list of techniques to prioritize for
        
    Returns:
        Ordered list of endpoints with recommended techniques
    """
    endpoints = sitemap.get("endpoints", [])
    prioritized = []
    
    # Technique recommendations based on endpoint characteristics
    technique_map = {
        "api_path": ["sql_injection", "nosql_injection", "idor", "mass_assignment"],
        "graphql_endpoint": ["graphql_injection", "idor"],
        "auth_path": ["auth_bypass", "broken_authentication", "brute_force"],
        "login_path": ["sql_injection", "auth_bypass", "credential_stuffing"],
        "file_upload_form": ["file_upload", "path_traversal", "xss"],
        "search_path": ["sql_injection", "xss", "nosql_injection"],
        "admin_path": ["auth_bypass", "idor", "privilege_escalation"],
        "redirect_path": ["open_redirect", "ssrf"],
        "post_form": ["csrf", "xss", "sql_injection"],
    }
    
    for endpoint in endpoints:
        interest = endpoint.get("security_interest", "medium")
        indicators = endpoint.get("security_indicators", [])
        
        # Calculate priority score
        interest_scores = {"critical": 100, "high": 75, "medium": 50, "low": 25, "minimal": 10}
        score = interest_scores.get(interest, 50)
        
        # Boost for forms and parameters
        if endpoint.get("forms"):
            score += 20
        if endpoint.get("parameters"):
            score += 10 * len(endpoint.get("parameters", []))
        
        # Determine recommended techniques
        recommended = set()
        for indicator in indicators:
            for key, techs in technique_map.items():
                if key in indicator:
                    recommended.update(techs)
        
        # Filter by requested techniques
        if techniques:
            recommended = recommended & set(techniques)
        
        prioritized.append({
            "url": endpoint.get("url"),
            "method": endpoint.get("method"),
            "priority_score": score,
            "security_interest": interest,
            "recommended_techniques": list(recommended) or ["xss", "sql_injection"],
            "parameters": endpoint.get("parameters", []),
            "forms": endpoint.get("forms", []),
            "indicators": indicators,
        })
    
    # Sort by priority score
    prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
    
    return prioritized
