"""
Man-in-the-Middle Workbench Service
Intercept, inspect, and modify network traffic between application components.
"""

import asyncio
import socket
import ssl
import threading
import time
import uuid
import json
import re
import gzip
import zlib
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class InterceptionMode(str, Enum):
    PASSTHROUGH = "passthrough"  # Just observe, don't modify
    INTERCEPT = "intercept"      # Hold for manual inspection/modification
    AUTO_MODIFY = "auto_modify"  # Apply rules automatically


class Protocol(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"
    WEBSOCKET = "websocket"


@dataclass
class InterceptionRule:
    """Rule for automatic traffic modification"""
    id: str
    name: str
    enabled: bool = True
    
    # Match conditions
    match_host: Optional[str] = None  # Regex pattern
    match_path: Optional[str] = None  # Regex pattern
    match_method: Optional[str] = None
    match_content_type: Optional[str] = None
    match_body: Optional[str] = None  # Regex pattern
    match_header: Optional[Dict[str, str]] = None
    match_status_code: Optional[int] = None
    match_direction: str = "both"  # "request", "response", "both"
    
    # Actions
    action: str = "modify"  # "modify", "drop", "delay", "replace"
    
    # Modification actions
    modify_headers: Optional[Dict[str, str]] = None  # Headers to add/replace
    remove_headers: Optional[List[str]] = None
    modify_body: Optional[str] = None  # New body content
    body_find_replace: Optional[Dict[str, str]] = None  # Find/replace in body
    modify_status_code: Optional[int] = None
    modify_path: Optional[str] = None
    
    # Delay action
    delay_ms: int = 0
    
    # Stats
    hit_count: int = 0


@dataclass
class InterceptedRequest:
    """Captured HTTP request"""
    id: str
    timestamp: datetime
    client_ip: str
    client_port: int
    
    # Request details
    method: str
    url: str
    path: str
    host: str
    port: int
    protocol: Protocol
    http_version: str
    headers: Dict[str, str]
    body: Optional[bytes] = None
    body_text: Optional[str] = None
    
    # State
    intercepted: bool = False
    modified: bool = False
    forwarded: bool = False
    
    # Timing
    received_at: float = 0
    forwarded_at: float = 0


@dataclass
class InterceptedResponse:
    """Captured HTTP response"""
    id: str
    request_id: str
    timestamp: datetime
    
    # Response details
    status_code: int
    status_message: str
    http_version: str
    headers: Dict[str, str]
    body: Optional[bytes] = None
    body_text: Optional[str] = None
    content_length: int = 0
    
    # State
    intercepted: bool = False
    modified: bool = False
    forwarded: bool = False
    
    # Timing
    received_at: float = 0
    forwarded_at: float = 0
    response_time_ms: float = 0


@dataclass
class TrafficEntry:
    """Complete request/response pair"""
    id: str
    request: InterceptedRequest
    response: Optional[InterceptedResponse] = None
    error: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    notes: str = ""


class MITMProxy:
    """TCP/HTTP Proxy for traffic interception"""
    
    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        target_host: str = "localhost",
        target_port: int = 80,
        mode: InterceptionMode = InterceptionMode.PASSTHROUGH,
        tls_enabled: bool = False
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.mode = mode
        self.tls_enabled = tls_enabled
        
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.traffic_log: List[TrafficEntry] = []
        self.rules: List[InterceptionRule] = []
        self.pending_requests: Dict[str, InterceptedRequest] = {}
        self.pending_responses: Dict[str, InterceptedResponse] = {}
        
        # Callbacks for real-time streaming
        self.on_request: Optional[Callable] = None
        self.on_response: Optional[Callable] = None
        self.on_error: Optional[Callable] = None
        
        # Stats
        self.stats = {
            "requests_total": 0,
            "responses_total": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "errors": 0,
            "rules_applied": 0,
            "start_time": None
        }
        
        self._lock = threading.Lock()
    
    def start(self):
        """Start the proxy server"""
        if self.running:
            return
        
        self.running = True
        self.stats["start_time"] = time.time()
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.listen_host, self.listen_port))
        self.server_socket.listen(100)
        self.server_socket.settimeout(1.0)
        
        # Start accept thread
        self._accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
        self._accept_thread.start()
        
        logger.info(f"MITM Proxy started on {self.listen_host}:{self.listen_port} -> {self.target_host}:{self.target_port}")
    
    def stop(self):
        """Stop the proxy server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        logger.info("MITM Proxy stopped")
    
    def _accept_connections(self):
        """Accept incoming connections"""
        while self.running:
            try:
                client_socket, client_addr = self.server_socket.accept()
                # Handle each connection in a new thread
                handler = threading.Thread(
                    target=self._handle_connection,
                    args=(client_socket, client_addr),
                    daemon=True
                )
                handler.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Accept error: {e}")
    
    def _handle_connection(self, client_socket: socket.socket, client_addr: tuple):
        """Handle a single client connection"""
        target_socket = None
        try:
            # Connect to target
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect((self.target_host, self.target_port))
            
            if self.tls_enabled:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                target_socket = context.wrap_socket(target_socket, server_hostname=self.target_host)
            
            # Bidirectional proxy
            client_to_target = threading.Thread(
                target=self._proxy_data,
                args=(client_socket, target_socket, client_addr, "request"),
                daemon=True
            )
            target_to_client = threading.Thread(
                target=self._proxy_data,
                args=(target_socket, client_socket, client_addr, "response"),
                daemon=True
            )
            
            client_to_target.start()
            target_to_client.start()
            
            client_to_target.join()
            target_to_client.join()
            
        except Exception as e:
            self.stats["errors"] += 1
            if self.on_error:
                self.on_error(str(e), client_addr)
        finally:
            try:
                client_socket.close()
            except:
                pass
            try:
                if target_socket:
                    target_socket.close()
            except:
                pass
    
    def _proxy_data(self, src: socket.socket, dst: socket.socket, client_addr: tuple, direction: str):
        """Proxy data between sockets with interception"""
        try:
            while self.running:
                src.settimeout(30.0)
                data = src.recv(65536)
                if not data:
                    break
                
                # Process and potentially modify data
                if direction == "request":
                    data, entry = self._process_request(data, client_addr)
                    self.stats["requests_total"] += 1
                    self.stats["bytes_sent"] += len(data)
                else:
                    data, entry = self._process_response(data, client_addr)
                    self.stats["responses_total"] += 1
                    self.stats["bytes_received"] += len(data)
                
                # Forward data
                dst.sendall(data)
                
        except socket.timeout:
            pass
        except Exception as e:
            if self.running:
                logger.debug(f"Proxy data error: {e}")
    
    def _process_request(self, data: bytes, client_addr: tuple) -> tuple:
        """Process and potentially modify a request"""
        entry_id = str(uuid.uuid4())
        
        try:
            # Parse HTTP request
            request = self._parse_http_request(data, client_addr, entry_id)
            
            # Apply rules
            modified_data = data
            if self.mode == InterceptionMode.AUTO_MODIFY:
                modified_data, applied = self._apply_rules_to_request(data, request)
                if applied:
                    request.modified = True
            
            # Create traffic entry
            entry = TrafficEntry(id=entry_id, request=request)
            with self._lock:
                self.traffic_log.append(entry)
                if len(self.traffic_log) > 1000:
                    self.traffic_log = self.traffic_log[-500:]
            
            # Callback
            if self.on_request:
                self.on_request(request)
            
            return modified_data, entry
            
        except Exception as e:
            logger.error(f"Request processing error: {e}")
            return data, None
    
    def _process_response(self, data: bytes, client_addr: tuple) -> tuple:
        """Process and potentially modify a response"""
        entry_id = str(uuid.uuid4())
        
        try:
            # Parse HTTP response
            response = self._parse_http_response(data, entry_id)
            
            # Apply rules
            modified_data = data
            if self.mode == InterceptionMode.AUTO_MODIFY:
                modified_data, applied = self._apply_rules_to_response(data, response)
                if applied:
                    response.modified = True
            
            # Callback
            if self.on_response:
                self.on_response(response)
            
            return modified_data, None
            
        except Exception as e:
            logger.error(f"Response processing error: {e}")
            return data, None
    
    def _parse_http_request(self, data: bytes, client_addr: tuple, entry_id: str) -> InterceptedRequest:
        """Parse raw HTTP request data"""
        lines = data.split(b"\r\n")
        request_line = lines[0].decode("utf-8", errors="replace")
        parts = request_line.split(" ")
        
        method = parts[0] if len(parts) > 0 else "UNKNOWN"
        path = parts[1] if len(parts) > 1 else "/"
        http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"
        
        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == b"":
                body_start = i + 1
                break
            try:
                header_line = line.decode("utf-8", errors="replace")
                if ":" in header_line:
                    key, value = header_line.split(":", 1)
                    headers[key.strip()] = value.strip()
            except:
                pass
        
        # Extract body
        body = None
        body_text = None
        if body_start > 0 and body_start < len(lines):
            body = b"\r\n".join(lines[body_start:])
            try:
                body_text = body.decode("utf-8", errors="replace")
            except:
                pass
        
        host = headers.get("Host", self.target_host)
        
        return InterceptedRequest(
            id=entry_id,
            timestamp=datetime.now(),
            client_ip=client_addr[0],
            client_port=client_addr[1],
            method=method,
            url=f"http://{host}{path}",
            path=path,
            host=host,
            port=self.target_port,
            protocol=Protocol.HTTPS if self.tls_enabled else Protocol.HTTP,
            http_version=http_version,
            headers=headers,
            body=body,
            body_text=body_text,
            received_at=time.time()
        )
    
    def _parse_http_response(self, data: bytes, entry_id: str) -> InterceptedResponse:
        """Parse raw HTTP response data"""
        lines = data.split(b"\r\n")
        status_line = lines[0].decode("utf-8", errors="replace")
        parts = status_line.split(" ", 2)
        
        http_version = parts[0] if len(parts) > 0 else "HTTP/1.1"
        status_code = int(parts[1]) if len(parts) > 1 else 0
        status_message = parts[2] if len(parts) > 2 else ""
        
        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == b"":
                body_start = i + 1
                break
            try:
                header_line = line.decode("utf-8", errors="replace")
                if ":" in header_line:
                    key, value = header_line.split(":", 1)
                    headers[key.strip()] = value.strip()
            except:
                pass
        
        # Extract body
        body = None
        body_text = None
        content_length = 0
        if body_start > 0 and body_start < len(lines):
            body = b"\r\n".join(lines[body_start:])
            content_length = len(body)
            
            # Try to decode body
            content_encoding = headers.get("Content-Encoding", "").lower()
            try:
                if content_encoding == "gzip":
                    body_text = gzip.decompress(body).decode("utf-8", errors="replace")
                elif content_encoding == "deflate":
                    body_text = zlib.decompress(body).decode("utf-8", errors="replace")
                else:
                    body_text = body.decode("utf-8", errors="replace")
            except:
                pass
        
        return InterceptedResponse(
            id=str(uuid.uuid4()),
            request_id=entry_id,
            timestamp=datetime.now(),
            status_code=status_code,
            status_message=status_message,
            http_version=http_version,
            headers=headers,
            body=body,
            body_text=body_text,
            content_length=content_length,
            received_at=time.time()
        )
    
    def _apply_rules_to_request(self, data: bytes, request: InterceptedRequest) -> tuple:
        """Apply interception rules to a request"""
        modified = False
        result = data
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            if rule.match_direction not in ["request", "both"]:
                continue
            
            if self._rule_matches_request(rule, request):
                result = self._apply_rule_modifications(result, rule, "request")
                rule.hit_count += 1
                self.stats["rules_applied"] += 1
                modified = True
        
        return result, modified
    
    def _apply_rules_to_response(self, data: bytes, response: InterceptedResponse) -> tuple:
        """Apply interception rules to a response"""
        modified = False
        result = data
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            if rule.match_direction not in ["response", "both"]:
                continue
            
            if self._rule_matches_response(rule, response):
                result = self._apply_rule_modifications(result, rule, "response")
                rule.hit_count += 1
                self.stats["rules_applied"] += 1
                modified = True
        
        return result, modified
    
    def _rule_matches_request(self, rule: InterceptionRule, request: InterceptedRequest) -> bool:
        """Check if a rule matches a request"""
        if rule.match_host and not re.search(rule.match_host, request.host, re.IGNORECASE):
            return False
        if rule.match_path and not re.search(rule.match_path, request.path, re.IGNORECASE):
            return False
        if rule.match_method and request.method.upper() != rule.match_method.upper():
            return False
        if rule.match_body and request.body_text:
            if not re.search(rule.match_body, request.body_text, re.IGNORECASE):
                return False
        if rule.match_header:
            for key, pattern in rule.match_header.items():
                if key not in request.headers:
                    return False
                if not re.search(pattern, request.headers[key], re.IGNORECASE):
                    return False
        return True
    
    def _rule_matches_response(self, rule: InterceptionRule, response: InterceptedResponse) -> bool:
        """Check if a rule matches a response"""
        if rule.match_status_code and response.status_code != rule.match_status_code:
            return False
        if rule.match_content_type:
            ct = response.headers.get("Content-Type", "")
            if not re.search(rule.match_content_type, ct, re.IGNORECASE):
                return False
        if rule.match_body and response.body_text:
            if not re.search(rule.match_body, response.body_text, re.IGNORECASE):
                return False
        return True
    
    def _apply_rule_modifications(self, data: bytes, rule: InterceptionRule, direction: str) -> bytes:
        """Apply rule modifications to data"""
        result = data
        
        # Delay
        if rule.delay_ms > 0:
            time.sleep(rule.delay_ms / 1000.0)
        
        # Drop
        if rule.action == "drop":
            return b""
        
        # Body find/replace
        if rule.body_find_replace:
            try:
                text = result.decode("utf-8", errors="replace")
                for find, replace in rule.body_find_replace.items():
                    text = text.replace(find, replace)
                result = text.encode("utf-8")
            except:
                pass
        
        # Header modifications would require full HTTP parsing/reconstruction
        # For simplicity, we'll do basic string replacements
        if rule.modify_headers:
            try:
                text = result.decode("utf-8", errors="replace")
                for header, value in rule.modify_headers.items():
                    # Add or replace header
                    pattern = rf"^{re.escape(header)}:.*$"
                    replacement = f"{header}: {value}"
                    if re.search(pattern, text, re.MULTILINE | re.IGNORECASE):
                        text = re.sub(pattern, replacement, text, flags=re.MULTILINE | re.IGNORECASE)
                    else:
                        # Add header before body
                        text = text.replace("\r\n\r\n", f"\r\n{replacement}\r\n\r\n", 1)
                result = text.encode("utf-8")
            except:
                pass
        
        if rule.remove_headers:
            try:
                text = result.decode("utf-8", errors="replace")
                for header in rule.remove_headers:
                    pattern = rf"^{re.escape(header)}:.*\r\n"
                    text = re.sub(pattern, "", text, flags=re.MULTILINE | re.IGNORECASE)
                result = text.encode("utf-8")
            except:
                pass
        
        return result
    
    def add_rule(self, rule: InterceptionRule):
        """Add an interception rule"""
        self.rules.append(rule)
    
    def remove_rule(self, rule_id: str):
        """Remove an interception rule"""
        self.rules = [r for r in self.rules if r.id != rule_id]
    
    def get_traffic_log(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Get traffic log entries"""
        with self._lock:
            entries = self.traffic_log[-(offset + limit):]
            if offset > 0:
                entries = entries[:-offset]
            entries = entries[-limit:]
        
        return [self._traffic_entry_to_dict(e) for e in entries]
    
    def _traffic_entry_to_dict(self, entry: TrafficEntry) -> Dict:
        """Convert traffic entry to dictionary"""
        return {
            "id": entry.id,
            "request": {
                "id": entry.request.id,
                "timestamp": entry.request.timestamp.isoformat(),
                "client_ip": entry.request.client_ip,
                "client_port": entry.request.client_port,
                "method": entry.request.method,
                "url": entry.request.url,
                "path": entry.request.path,
                "host": entry.request.host,
                "port": entry.request.port,
                "protocol": entry.request.protocol.value,
                "http_version": entry.request.http_version,
                "headers": entry.request.headers,
                "body_text": entry.request.body_text[:10000] if entry.request.body_text else None,
                "modified": entry.request.modified
            },
            "response": {
                "id": entry.response.id,
                "status_code": entry.response.status_code,
                "status_message": entry.response.status_message,
                "headers": entry.response.headers,
                "body_text": entry.response.body_text[:10000] if entry.response.body_text else None,
                "content_length": entry.response.content_length,
                "response_time_ms": entry.response.response_time_ms,
                "modified": entry.response.modified
            } if entry.response else None,
            "error": entry.error,
            "tags": entry.tags,
            "notes": entry.notes
        }
    
    def clear_traffic_log(self):
        """Clear the traffic log"""
        with self._lock:
            self.traffic_log.clear()
    
    def get_stats(self) -> Dict:
        """Get proxy statistics"""
        uptime = 0
        if self.stats["start_time"]:
            uptime = time.time() - self.stats["start_time"]
        
        return {
            **self.stats,
            "uptime_seconds": uptime,
            "running": self.running,
            "mode": self.mode.value,
            "rules_count": len(self.rules),
            "traffic_log_size": len(self.traffic_log)
        }


class MITMService:
    """Service for managing MITM proxy instances"""
    
    def __init__(self):
        self.proxies: Dict[str, MITMProxy] = {}
        self._lock = threading.Lock()
    
    def create_proxy(
        self,
        proxy_id: str,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        target_host: str = "localhost",
        target_port: int = 80,
        mode: str = "passthrough",
        tls_enabled: bool = False
    ) -> Dict:
        """Create a new MITM proxy"""
        with self._lock:
            if proxy_id in self.proxies:
                raise ValueError(f"Proxy {proxy_id} already exists")
            
            proxy = MITMProxy(
                listen_host=listen_host,
                listen_port=listen_port,
                target_host=target_host,
                target_port=target_port,
                mode=InterceptionMode(mode),
                tls_enabled=tls_enabled
            )
            
            self.proxies[proxy_id] = proxy
            
            return {
                "id": proxy_id,
                "listen_host": listen_host,
                "listen_port": listen_port,
                "target_host": target_host,
                "target_port": target_port,
                "mode": mode,
                "tls_enabled": tls_enabled,
                "status": "created"
            }
    
    def start_proxy(self, proxy_id: str) -> Dict:
        """Start a proxy"""
        proxy = self._get_proxy(proxy_id)
        proxy.start()
        return {"status": "started", "id": proxy_id}
    
    def stop_proxy(self, proxy_id: str) -> Dict:
        """Stop a proxy"""
        proxy = self._get_proxy(proxy_id)
        proxy.stop()
        return {"status": "stopped", "id": proxy_id}
    
    def delete_proxy(self, proxy_id: str) -> Dict:
        """Delete a proxy"""
        with self._lock:
            if proxy_id in self.proxies:
                self.proxies[proxy_id].stop()
                del self.proxies[proxy_id]
        return {"status": "deleted", "id": proxy_id}
    
    def get_proxy_status(self, proxy_id: str) -> Dict:
        """Get proxy status and stats"""
        proxy = self._get_proxy(proxy_id)
        return {
            "id": proxy_id,
            "listen_host": proxy.listen_host,
            "listen_port": proxy.listen_port,
            "target_host": proxy.target_host,
            "target_port": proxy.target_port,
            "mode": proxy.mode.value,
            "tls_enabled": proxy.tls_enabled,
            **proxy.get_stats()
        }
    
    def list_proxies(self) -> List[Dict]:
        """List all proxies"""
        with self._lock:
            return [
                {
                    "id": pid,
                    "listen_port": p.listen_port,
                    "target_host": p.target_host,
                    "target_port": p.target_port,
                    "running": p.running,
                    "mode": p.mode.value
                }
                for pid, p in self.proxies.items()
            ]
    
    def get_traffic(self, proxy_id: str, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Get traffic log for a proxy"""
        proxy = self._get_proxy(proxy_id)
        return proxy.get_traffic_log(limit, offset)
    
    def clear_traffic(self, proxy_id: str) -> Dict:
        """Clear traffic log for a proxy"""
        proxy = self._get_proxy(proxy_id)
        proxy.clear_traffic_log()
        return {"status": "cleared", "id": proxy_id}
    
    def set_mode(self, proxy_id: str, mode: str) -> Dict:
        """Set proxy interception mode"""
        proxy = self._get_proxy(proxy_id)
        proxy.mode = InterceptionMode(mode)
        return {"status": "updated", "mode": mode}
    
    def add_rule(self, proxy_id: str, rule_data: Dict) -> Dict:
        """Add an interception rule"""
        proxy = self._get_proxy(proxy_id)
        
        rule = InterceptionRule(
            id=str(uuid.uuid4()),
            name=rule_data.get("name", "Unnamed Rule"),
            enabled=rule_data.get("enabled", True),
            match_host=rule_data.get("match_host"),
            match_path=rule_data.get("match_path"),
            match_method=rule_data.get("match_method"),
            match_content_type=rule_data.get("match_content_type"),
            match_body=rule_data.get("match_body"),
            match_header=rule_data.get("match_header"),
            match_status_code=rule_data.get("match_status_code"),
            match_direction=rule_data.get("match_direction", "both"),
            action=rule_data.get("action", "modify"),
            modify_headers=rule_data.get("modify_headers"),
            remove_headers=rule_data.get("remove_headers"),
            modify_body=rule_data.get("modify_body"),
            body_find_replace=rule_data.get("body_find_replace"),
            modify_status_code=rule_data.get("modify_status_code"),
            delay_ms=rule_data.get("delay_ms", 0)
        )
        
        proxy.add_rule(rule)
        
        return {
            "status": "added",
            "rule_id": rule.id,
            "rule_name": rule.name
        }
    
    def remove_rule(self, proxy_id: str, rule_id: str) -> Dict:
        """Remove an interception rule"""
        proxy = self._get_proxy(proxy_id)
        proxy.remove_rule(rule_id)
        return {"status": "removed", "rule_id": rule_id}
    
    def get_rules(self, proxy_id: str) -> List[Dict]:
        """Get all rules for a proxy"""
        proxy = self._get_proxy(proxy_id)
        return [
            {
                "id": r.id,
                "name": r.name,
                "enabled": r.enabled,
                "match_host": r.match_host,
                "match_path": r.match_path,
                "match_method": r.match_method,
                "match_direction": r.match_direction,
                "action": r.action,
                "hit_count": r.hit_count
            }
            for r in proxy.rules
        ]
    
    def toggle_rule(self, proxy_id: str, rule_id: str, enabled: bool) -> Dict:
        """Enable/disable a rule"""
        proxy = self._get_proxy(proxy_id)
        for rule in proxy.rules:
            if rule.id == rule_id:
                rule.enabled = enabled
                return {"status": "updated", "rule_id": rule_id, "enabled": enabled}
        raise ValueError(f"Rule {rule_id} not found")
    
    def _get_proxy(self, proxy_id: str) -> MITMProxy:
        """Get a proxy by ID"""
        with self._lock:
            if proxy_id not in self.proxies:
                raise ValueError(f"Proxy {proxy_id} not found")
            return self.proxies[proxy_id]


# Global service instance
mitm_service = MITMService()


# ============================================================================
# AI Analysis for MITM Traffic
# ============================================================================

async def analyze_mitm_traffic(
    traffic_log: List[Dict],
    rules: List[Dict],
    proxy_config: Dict
) -> Dict:
    """
    AI-powered analysis of MITM intercepted traffic.
    
    Analyzes:
    - Security vulnerabilities in traffic
    - Sensitive data exposure
    - Authentication weaknesses
    - API security issues
    - Common attack patterns
    """
    from backend.core.config import settings
    
    if not traffic_log:
        return {
            "summary": "No traffic to analyze",
            "risk_score": 0,
            "findings": [],
            "recommendations": []
        }
    
    # Analyze traffic without AI first (pattern-based)
    findings = []
    
    for entry in traffic_log[:100]:  # Limit analysis
        request = entry.get("request", {})
        response = entry.get("response", {})
        
        # Check for sensitive data in requests
        request_body = request.get("body_text", "") or ""
        request_headers = request.get("headers", {})
        
        # Check for credentials in clear text
        sensitive_patterns = [
            ("password", "Password transmitted in clear text"),
            ("api_key", "API key exposed in request"),
            ("secret", "Secret value in request"),
            ("token", "Token exposed in request"),
            ("authorization", "Authorization header exposed"),
            ("credit_card", "Credit card data detected"),
            ("ssn", "SSN pattern detected"),
        ]
        
        for pattern, message in sensitive_patterns:
            if pattern in request_body.lower():
                findings.append({
                    "severity": "high",
                    "category": "sensitive_data",
                    "title": message,
                    "description": f"Sensitive data pattern '{pattern}' found in request body",
                    "evidence": f"Request to {request.get('path', 'unknown')}",
                    "recommendation": "Encrypt sensitive data or use secure transport"
                })
        
        # Check for missing security headers in responses
        if response:
            response_headers = response.get("headers", {})
            header_lower = {k.lower(): v for k, v in response_headers.items()}
            
            security_headers = [
                ("content-security-policy", "Missing Content-Security-Policy header"),
                ("x-content-type-options", "Missing X-Content-Type-Options header"),
                ("x-frame-options", "Missing X-Frame-Options header"),
                ("strict-transport-security", "Missing HSTS header"),
                ("x-xss-protection", "Missing X-XSS-Protection header"),
            ]
            
            for header, message in security_headers:
                if header not in header_lower:
                    findings.append({
                        "severity": "medium",
                        "category": "headers",
                        "title": message,
                        "description": f"Response missing security header: {header}",
                        "evidence": f"Response from {request.get('path', 'unknown')}",
                        "recommendation": f"Add {header} header to response"
                    })
        
        # Check for insecure cookies
        set_cookie = response.get("headers", {}).get("Set-Cookie", "") if response else ""
        if set_cookie:
            if "httponly" not in set_cookie.lower():
                findings.append({
                    "severity": "medium",
                    "category": "cookies",
                    "title": "Cookie without HttpOnly flag",
                    "description": "Cookie set without HttpOnly flag, vulnerable to XSS",
                    "evidence": f"Set-Cookie: {set_cookie[:50]}...",
                    "recommendation": "Add HttpOnly flag to cookies"
                })
            if "secure" not in set_cookie.lower():
                findings.append({
                    "severity": "medium",
                    "category": "cookies",
                    "title": "Cookie without Secure flag",
                    "description": "Cookie set without Secure flag, may be sent over HTTP",
                    "evidence": f"Set-Cookie: {set_cookie[:50]}...",
                    "recommendation": "Add Secure flag to cookies"
                })
        
        # Check for CORS misconfigurations
        acao = response.get("headers", {}).get("Access-Control-Allow-Origin", "") if response else ""
        if acao == "*":
            findings.append({
                "severity": "high",
                "category": "cors",
                "title": "Overly permissive CORS policy",
                "description": "CORS allows any origin (*), potentially allowing cross-site attacks",
                "evidence": "Access-Control-Allow-Origin: *",
                "recommendation": "Restrict CORS to specific trusted origins"
            })
        
        # Check for error information disclosure
        if response and response.get("status_code", 0) >= 500:
            body = response.get("body_text", "") or ""
            if any(x in body.lower() for x in ["stacktrace", "exception", "traceback", "error at"]):
                findings.append({
                    "severity": "medium",
                    "category": "information_disclosure",
                    "title": "Stack trace exposed in error response",
                    "description": "Server error reveals internal stack trace information",
                    "evidence": f"500 error on {request.get('path', 'unknown')}",
                    "recommendation": "Implement generic error messages in production"
                })
    
    # Deduplicate findings
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["title"], f["category"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    
    # Calculate risk score
    severity_weights = {"critical": 40, "high": 25, "medium": 10, "low": 5, "info": 1}
    risk_score = min(100, sum(severity_weights.get(f["severity"], 5) for f in unique_findings))
    
    # Generate recommendations
    recommendations = []
    categories_found = set(f["category"] for f in unique_findings)
    
    if "sensitive_data" in categories_found:
        recommendations.append("Implement encryption for sensitive data in transit")
    if "headers" in categories_found:
        recommendations.append("Add comprehensive security headers to all responses")
    if "cookies" in categories_found:
        recommendations.append("Review and secure all cookie configurations")
    if "cors" in categories_found:
        recommendations.append("Implement restrictive CORS policy with explicit origins")
    if "information_disclosure" in categories_found:
        recommendations.append("Configure generic error handling for production")
    
    # AI-powered analysis if available
    ai_analysis = None
    if settings.gemini_api_key and len(traffic_log) > 0:
        try:
            from google import genai
            from google.genai import types
            
            client = genai.Client(api_key=settings.gemini_api_key)
            
            # Prepare traffic summary for AI
            traffic_summary = []
            for entry in traffic_log[:20]:
                req = entry.get("request", {})
                resp = entry.get("response", {})
                traffic_summary.append({
                    "method": req.get("method"),
                    "path": req.get("path"),
                    "status": resp.get("status_code") if resp else None,
                    "modified": entry.get("modified", False)
                })
            
            prompt = f"""Analyze this intercepted HTTP traffic from a Man-in-the-Middle proxy for security issues.

TRAFFIC SUMMARY ({len(traffic_log)} requests intercepted):
{json.dumps(traffic_summary, indent=2)}

RULES APPLIED: {len(rules)} interception rules active

PATTERN-BASED FINDINGS ALREADY IDENTIFIED:
{json.dumps([{"title": f["title"], "severity": f["severity"]} for f in unique_findings[:10]], indent=2)}

Provide a brief security analysis (150 words max) covering:
1. Overall security posture assessment
2. Key concerns or attack vectors identified
3. Specific recommendations for the application being tested

Focus on actionable insights for a security tester using this MITM workbench."""

            response = client.models.generate_content(
                model=settings.gemini_model_id,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3,
                    max_output_tokens=500,
                )
            )
            
            if response and response.text:
                ai_analysis = response.text
                
        except Exception as e:
            logger.warning(f"AI analysis failed: {e}")
    
    return {
        "summary": f"Analyzed {len(traffic_log)} traffic entries, found {len(unique_findings)} security issues",
        "risk_score": risk_score,
        "risk_level": "critical" if risk_score >= 70 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low",
        "findings": unique_findings,
        "recommendations": recommendations,
        "ai_analysis": ai_analysis,
        "traffic_analyzed": len(traffic_log),
        "rules_active": len(rules)
    }


# ============================================================================
# Export MITM Analysis Reports
# ============================================================================

def generate_mitm_markdown_report(
    proxy_config: Dict,
    traffic_log: List[Dict],
    rules: List[Dict],
    analysis: Dict
) -> str:
    """Generate comprehensive Markdown report for MITM analysis."""
    lines = []
    
    # Header
    lines.extend([
        "# 🔐 Man-in-the-Middle Traffic Analysis Report",
        "",
        "---",
        "",
        "## 📋 Executive Summary",
        "",
        f"**Risk Level:** {analysis.get('risk_level', 'unknown').upper()}",
        f"**Risk Score:** {analysis.get('risk_score', 0)}/100",
        f"**Traffic Analyzed:** {analysis.get('traffic_analyzed', 0)} requests",
        f"**Security Issues Found:** {len(analysis.get('findings', []))}",
        "",
    ])
    
    if analysis.get("summary"):
        lines.extend([analysis["summary"], ""])
    
    # Proxy Configuration
    lines.extend([
        "---",
        "",
        "## ⚙️ Proxy Configuration",
        "",
        "| Property | Value |",
        "|----------|-------|",
        f"| Listen Address | `{proxy_config.get('listen_host', 'N/A')}:{proxy_config.get('listen_port', 'N/A')}` |",
        f"| Target Address | `{proxy_config.get('target_host', 'N/A')}:{proxy_config.get('target_port', 'N/A')}` |",
        f"| Mode | {proxy_config.get('mode', 'N/A')} |",
        f"| TLS Enabled | {'Yes' if proxy_config.get('tls_enabled') else 'No'} |",
        "",
    ])
    
    # AI Analysis (if available)
    if analysis.get("ai_analysis"):
        lines.extend([
            "---",
            "",
            "## 🤖 AI Security Analysis",
            "",
            analysis["ai_analysis"],
            "",
        ])
    
    # Security Findings
    findings = analysis.get("findings", [])
    if findings:
        lines.extend([
            "---",
            "",
            "## 🚨 Security Findings",
            "",
        ])
        
        severity_order = ["critical", "high", "medium", "low", "info"]
        findings_by_severity = {s: [] for s in severity_order}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in findings_by_severity:
                findings_by_severity[sev].append(f)
        
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵"
        }
        
        for severity in severity_order:
            sev_findings = findings_by_severity[severity]
            if sev_findings:
                emoji = severity_emoji.get(severity, "⚪")
                lines.extend([
                    f"### {emoji} {severity.upper()} ({len(sev_findings)})",
                    "",
                ])
                
                for i, f in enumerate(sev_findings, 1):
                    lines.extend([
                        f"#### {i}. {f.get('title', 'Unknown')}",
                        "",
                        f"**Category:** {f.get('category', 'N/A')}",
                        "",
                        f"**Description:** {f.get('description', 'N/A')}",
                        "",
                        f"**Evidence:** `{f.get('evidence', 'N/A')}`",
                        "",
                        f"**Recommendation:** {f.get('recommendation', 'N/A')}",
                        "",
                        "---",
                        "",
                    ])
    
    # Active Rules
    if rules:
        lines.extend([
            "## 📝 Active Interception Rules",
            "",
            "| Rule Name | Direction | Action | Enabled |",
            "|-----------|-----------|--------|---------|",
        ])
        
        for rule in rules:
            enabled = "✅" if rule.get("enabled") else "❌"
            lines.append(f"| {rule.get('name', 'N/A')} | {rule.get('match_direction', 'N/A')} | {rule.get('action', 'N/A')} | {enabled} |")
        
        lines.append("")
    
    # Traffic Sample
    if traffic_log:
        lines.extend([
            "---",
            "",
            "## 📊 Traffic Sample",
            "",
            "| Time | Method | Path | Status | Modified |",
            "|------|--------|------|--------|----------|",
        ])
        
        for entry in traffic_log[:20]:
            req = entry.get("request", {})
            resp = entry.get("response", {})
            timestamp = entry.get("timestamp", "N/A")
            if isinstance(timestamp, str) and "T" in timestamp:
                timestamp = timestamp.split("T")[1].split(".")[0]
            
            method = req.get("method", "?")
            path = req.get("path", "/")[:40]
            status = resp.get("status_code", "-") if resp else "-"
            modified = "✏️" if entry.get("modified") else ""
            
            lines.append(f"| {timestamp} | {method} | `{path}` | {status} | {modified} |")
        
        if len(traffic_log) > 20:
            lines.append(f"| ... | *{len(traffic_log) - 20} more entries* | ... | ... | |")
        
        lines.append("")
    
    # Recommendations
    recommendations = analysis.get("recommendations", [])
    if recommendations:
        lines.extend([
            "---",
            "",
            "## ✅ Recommendations",
            "",
        ])
        
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"{i}. {rec}")
        
        lines.append("")
    
    # Footer
    lines.extend([
        "---",
        "",
        "*Report generated by VRAgent MITM Workbench*",
        "",
    ])
    
    return "\n".join(lines)


def generate_mitm_pdf_report(
    proxy_config: Dict,
    traffic_log: List[Dict],
    rules: List[Dict],
    analysis: Dict
) -> bytes:
    """Generate PDF report for MITM analysis."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from io import BytesIO
    except ImportError:
        logger.error("reportlab not installed")
        return b"%PDF-1.4 placeholder"
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title_style = ParagraphStyle(
        'Title', parent=styles['Heading1'], fontSize=24, spaceAfter=20, alignment=1
    )
    story.append(Paragraph("🔐 MITM Traffic Analysis Report", title_style))
    story.append(Spacer(1, 20))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", styles['Heading2']))
    
    summary_data = [
        ["Risk Level", analysis.get('risk_level', 'unknown').upper()],
        ["Risk Score", f"{analysis.get('risk_score', 0)}/100"],
        ["Traffic Analyzed", str(analysis.get('traffic_analyzed', 0))],
        ["Issues Found", str(len(analysis.get('findings', [])))],
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # AI Analysis
    if analysis.get("ai_analysis"):
        story.append(Paragraph("AI Security Analysis", styles['Heading2']))
        # Clean text for PDF
        ai_text = analysis["ai_analysis"].replace("**", "").replace("*", "")
        story.append(Paragraph(ai_text, styles['Normal']))
        story.append(Spacer(1, 20))
    
    # Findings
    findings = analysis.get("findings", [])
    if findings:
        story.append(Paragraph("Security Findings", styles['Heading2']))
        
        for i, f in enumerate(findings[:15], 1):
            story.append(Paragraph(f"{i}. {f.get('title', 'Unknown')}", styles['Heading3']))
            story.append(Paragraph(f"Severity: {f.get('severity', 'N/A').upper()} | Category: {f.get('category', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"Description: {f.get('description', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"Recommendation: {f.get('recommendation', 'N/A')}", styles['Normal']))
            story.append(Spacer(1, 10))
    
    # Recommendations
    recommendations = analysis.get("recommendations", [])
    if recommendations:
        story.append(Paragraph("Recommendations", styles['Heading2']))
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
        story.append(Spacer(1, 10))
    
    story.append(Spacer(1, 20))
    story.append(Paragraph("Report generated by VRAgent MITM Workbench", 
        ParagraphStyle('footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey, alignment=1)))
    
    doc.build(story)
    return buffer.getvalue()


def generate_mitm_docx_report(
    proxy_config: Dict,
    traffic_log: List[Dict],
    rules: List[Dict],
    analysis: Dict
) -> bytes:
    """Generate DOCX report for MITM analysis."""
    try:
        from docx import Document
        from docx.shared import Inches, Pt
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from io import BytesIO
    except ImportError:
        logger.error("python-docx not installed")
        return b"PK placeholder"
    
    doc = Document()
    
    # Title
    title = doc.add_heading("🔐 MITM Traffic Analysis Report", 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    # Executive Summary
    doc.add_heading("Executive Summary", level=1)
    
    summary_table = doc.add_table(rows=4, cols=2)
    summary_table.style = 'Table Grid'
    
    summary_data = [
        ("Risk Level", analysis.get('risk_level', 'unknown').upper()),
        ("Risk Score", f"{analysis.get('risk_score', 0)}/100"),
        ("Traffic Analyzed", str(analysis.get('traffic_analyzed', 0))),
        ("Issues Found", str(len(analysis.get('findings', [])))),
    ]
    
    for i, (label, value) in enumerate(summary_data):
        summary_table.rows[i].cells[0].text = label
        summary_table.rows[i].cells[1].text = value
        summary_table.rows[i].cells[0].paragraphs[0].runs[0].bold = True
    
    doc.add_paragraph()
    
    # AI Analysis
    if analysis.get("ai_analysis"):
        doc.add_heading("AI Security Analysis", level=1)
        doc.add_paragraph(analysis["ai_analysis"])
    
    # Findings
    findings = analysis.get("findings", [])
    if findings:
        doc.add_heading("Security Findings", level=1)
        
        for i, f in enumerate(findings[:15], 1):
            doc.add_heading(f"{i}. {f.get('title', 'Unknown')}", level=2)
            
            p = doc.add_paragraph()
            p.add_run("Severity: ").bold = True
            p.add_run(f"{f.get('severity', 'N/A').upper()} | ")
            p.add_run("Category: ").bold = True
            p.add_run(f.get('category', 'N/A'))
            
            p = doc.add_paragraph()
            p.add_run("Description: ").bold = True
            p.add_run(f.get('description', 'N/A'))
            
            p = doc.add_paragraph()
            p.add_run("Recommendation: ").bold = True
            p.add_run(f.get('recommendation', 'N/A'))
            
            doc.add_paragraph()
    
    # Recommendations
    recommendations = analysis.get("recommendations", [])
    if recommendations:
        doc.add_heading("Recommendations", level=1)
        for i, rec in enumerate(recommendations, 1):
            doc.add_paragraph(f"{i}. {rec}")
    
    # Footer
    doc.add_paragraph()
    footer = doc.add_paragraph()
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.add_run("Report generated by VRAgent MITM Workbench").italic = True
    
    buffer = BytesIO()
    doc.save(buffer)
    return buffer.getvalue()


# ============================================================================
# AI-Powered Natural Language Rule Creation
# ============================================================================

async def create_rule_from_natural_language(description: str) -> Dict:
    """
    Convert natural language description to a MITM interception rule.
    
    Examples:
    - "Block all requests to analytics domains"
    - "Add a 2 second delay to all API responses"
    - "Remove authentication headers from requests"
    - "Replace all error responses with success"
    """
    from ..core.config import settings
    
    if not settings.gemini_api_key:
        # Fallback to pattern matching for common requests
        return _parse_rule_with_patterns(description)
    
    try:
        from google import genai
        from google.genai import types
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        prompt = f"""You are a MITM (Man-in-the-Middle) proxy rule generator. Convert the user's natural language request into a JSON rule configuration.

USER REQUEST: "{description}"

Generate a JSON object with these fields (include only relevant fields):
{{
    "name": "Rule name (descriptive)",
    "enabled": true,
    "match_direction": "request" | "response" | "both",
    "match_host": "regex pattern or null",
    "match_path": "regex pattern or null",
    "match_method": "GET|POST|PUT|DELETE or null",
    "match_content_type": "content type pattern or null",
    "match_status_code": number or null,
    "action": "modify" | "drop" | "delay",
    "modify_headers": {{"Header-Name": "value"}} or null,
    "remove_headers": ["header1", "header2"] or null,
    "body_find_replace": {{"find": "replace"}} or null,
    "delay_ms": number (only if action is delay)
}}

Common patterns:
- For blocking: action="drop"
- For adding headers: action="modify", modify_headers={{...}}
- For removing headers: action="modify", remove_headers=[...]
- For modifying body: action="modify", body_find_replace={{...}}
- For delays: action="delay", delay_ms=number

Return ONLY valid JSON, no explanation."""

        response = client.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
                max_output_tokens=500,
            )
        )
        
        if response and response.text:
            # Parse the JSON response
            import json
            text = response.text.strip()
            # Remove markdown code blocks if present
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            text = text.strip()
            
            rule = json.loads(text)
            rule["ai_generated"] = True
            rule["original_description"] = description
            
            return {
                "success": True,
                "rule": rule,
                "message": f"Created rule: {rule.get('name', 'Unnamed Rule')}"
            }
            
    except Exception as e:
        logger.warning(f"AI rule generation failed: {e}, falling back to pattern matching")
    
    # Fallback to pattern matching
    return _parse_rule_with_patterns(description)


def _parse_rule_with_patterns(description: str) -> Dict:
    """Fallback pattern-based rule parsing when AI is unavailable."""
    desc_lower = description.lower()
    rule = {
        "name": description[:50],
        "enabled": True,
        "match_direction": "both",
        "action": "modify"
    }
    
    # Detect blocking/dropping
    if any(word in desc_lower for word in ["block", "drop", "reject", "stop", "prevent"]):
        rule["action"] = "drop"
        
        # Common block targets
        if "analytics" in desc_lower:
            rule["match_host"] = "(google-analytics|googletagmanager|facebook|analytics|mixpanel|segment)"
            rule["name"] = "Block Analytics"
        elif "tracking" in desc_lower or "tracker" in desc_lower:
            rule["match_host"] = "(tracking|tracker|pixel|beacon)"
            rule["name"] = "Block Trackers"
        elif "ads" in desc_lower or "advert" in desc_lower:
            rule["match_host"] = "(doubleclick|adsense|adserver|ad\\.|ads\\.)"
            rule["name"] = "Block Ads"
    
    # Detect delays
    elif any(word in desc_lower for word in ["delay", "slow", "latency", "wait"]):
        rule["action"] = "delay"
        # Extract delay time
        import re
        time_match = re.search(r'(\d+)\s*(second|sec|s|ms|millisecond)', desc_lower)
        if time_match:
            value = int(time_match.group(1))
            unit = time_match.group(2)
            if unit.startswith("s") and not unit.startswith("ms"):
                value *= 1000  # Convert to ms
            rule["delay_ms"] = value
        else:
            rule["delay_ms"] = 2000
        rule["name"] = f"Add {rule['delay_ms']}ms Delay"
        rule["match_direction"] = "response"
    
    # Detect header removal
    elif "remove" in desc_lower and "header" in desc_lower:
        headers_to_remove = []
        if "auth" in desc_lower:
            headers_to_remove.extend(["Authorization", "X-Auth-Token", "X-API-Key"])
        if "security" in desc_lower:
            headers_to_remove.extend(["Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection"])
        if "cors" in desc_lower:
            headers_to_remove.extend(["Access-Control-Allow-Origin", "Access-Control-Allow-Methods"])
        if "cookie" in desc_lower:
            headers_to_remove.extend(["Set-Cookie", "Cookie"])
        if "csrf" in desc_lower:
            headers_to_remove.extend(["X-CSRF-Token", "X-XSRF-Token"])
        
        if headers_to_remove:
            rule["remove_headers"] = headers_to_remove
            rule["name"] = f"Remove {', '.join(headers_to_remove[:2])}..."
            rule["match_direction"] = "request" if "request" in desc_lower else "response" if "response" in desc_lower else "both"
    
    # Detect header addition
    elif "add" in desc_lower and "header" in desc_lower:
        rule["modify_headers"] = {}
        if "debug" in desc_lower:
            rule["modify_headers"]["X-Debug"] = "true"
        if "admin" in desc_lower:
            rule["modify_headers"]["X-Admin"] = "true"
            rule["modify_headers"]["X-User-Role"] = "admin"
        if "cors" in desc_lower or "cross-origin" in desc_lower:
            rule["modify_headers"]["Access-Control-Allow-Origin"] = "*"
            rule["modify_headers"]["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        rule["name"] = "Add Custom Headers"
        rule["match_direction"] = "request" if "request" in desc_lower else "response"
    
    # Detect body modification
    elif any(word in desc_lower for word in ["replace", "change", "modify body", "swap"]):
        rule["body_find_replace"] = {}
        if "error" in desc_lower and "success" in desc_lower:
            rule["body_find_replace"]["\"success\":false"] = "\"success\":true"
            rule["body_find_replace"]["\"error\":"] = "\"_hidden_error\":"
        elif "false" in desc_lower and "true" in desc_lower:
            rule["body_find_replace"]["false"] = "true"
        rule["name"] = "Modify Response Body"
        rule["match_direction"] = "response"
    
    return {
        "success": True,
        "rule": rule,
        "message": f"Created rule using pattern matching: {rule.get('name')}",
        "ai_generated": False
    }


# ============================================================================
# Real-time AI Traffic Suggestions
# ============================================================================

async def get_ai_traffic_suggestions(
    traffic_log: List[Dict],
    existing_rules: List[Dict],
    proxy_config: Dict
) -> Dict:
    """
    Analyze current traffic and suggest security tests or rules.
    
    Returns suggestions based on observed traffic patterns.
    """
    from ..core.config import settings
    
    if len(traffic_log) == 0:
        return {
            "suggestions": [{
                "type": "info",
                "title": "No Traffic Yet",
                "description": "Start sending traffic through the proxy to get AI-powered suggestions.",
                "priority": "low"
            }],
            "summary": "Waiting for traffic data"
        }
    
    # Analyze traffic patterns
    suggestions = []
    
    # Gather statistics
    methods = {}
    paths = []
    status_codes = {}
    content_types = {}
    has_auth = False
    has_json = False
    has_cors = False
    has_cookies = False
    error_count = 0
    
    for entry in traffic_log[:100]:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        
        # Count methods
        method = req.get("method", "GET")
        methods[method] = methods.get(method, 0) + 1
        
        # Collect paths
        path = req.get("path", "/")
        paths.append(path)
        
        # Count status codes
        if resp:
            status = resp.get("status_code", 0)
            status_codes[status] = status_codes.get(status, 0) + 1
            if status >= 400:
                error_count += 1
        
        # Check headers
        req_headers = {k.lower(): v for k, v in req.get("headers", {}).items()}
        resp_headers = {k.lower(): v for k, v in resp.get("headers", {}).items()} if resp else {}
        
        if "authorization" in req_headers or "x-api-key" in req_headers:
            has_auth = True
        if "application/json" in str(req_headers.get("content-type", "")) or \
           "application/json" in str(resp_headers.get("content-type", "")):
            has_json = True
        if "access-control-allow-origin" in resp_headers:
            has_cors = True
        if "cookie" in req_headers or "set-cookie" in resp_headers:
            has_cookies = True
    
    # Generate pattern-based suggestions
    existing_rule_names = [r.get("name", "").lower() for r in existing_rules]
    
    # Auth-related suggestions
    if has_auth and "auth" not in str(existing_rule_names):
        suggestions.append({
            "type": "security_test",
            "title": "Test Authentication Bypass",
            "description": "Detected authorization headers. Try removing auth headers to test for bypass vulnerabilities.",
            "priority": "high",
            "suggested_rule": {
                "name": "Remove Auth Headers",
                "match_direction": "request",
                "action": "modify",
                "remove_headers": ["Authorization", "X-API-Key", "X-Auth-Token"]
            },
            "quick_apply": True
        })
    
    # JSON API suggestions
    if has_json:
        suggestions.append({
            "type": "security_test",
            "title": "Test Response Tampering",
            "description": "JSON API detected. Try modifying response values to test client-side validation.",
            "priority": "medium",
            "suggested_rule": {
                "name": "Modify JSON Response",
                "match_direction": "response",
                "match_content_type": "application/json",
                "action": "modify",
                "body_find_replace": {
                    "\"success\":false": "\"success\":true",
                    "\"authorized\":false": "\"authorized\":true"
                }
            },
            "quick_apply": True
        })
    
    # CORS suggestions
    if has_cors:
        suggestions.append({
            "type": "security_test",
            "title": "Test CORS Policy",
            "description": "CORS headers detected. Test if permissive CORS could expose data.",
            "priority": "medium",
            "suggested_rule": {
                "name": "Modify CORS Headers",
                "match_direction": "response",
                "action": "modify",
                "modify_headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true"
                }
            },
            "quick_apply": True
        })
    
    # Cookie suggestions
    if has_cookies:
        suggestions.append({
            "type": "security_test",
            "title": "Test Cookie Security",
            "description": "Cookies detected. Check for missing HttpOnly, Secure, or SameSite flags.",
            "priority": "high",
            "suggested_rule": {
                "name": "Expose Cookie Values",
                "match_direction": "response",
                "action": "modify",
                "remove_headers": ["Set-Cookie"]
            },
            "quick_apply": True
        })
    
    # Error handling suggestions
    if error_count > 0:
        suggestions.append({
            "type": "observation",
            "title": "Error Responses Detected",
            "description": f"Found {error_count} error responses (4xx/5xx). Check for information disclosure in error messages.",
            "priority": "medium",
            "suggested_rule": None,
            "quick_apply": False
        })
    
    # Path pattern suggestions
    api_paths = [p for p in paths if "/api/" in p or "/v1/" in p or "/v2/" in p]
    if len(api_paths) > 5:
        suggestions.append({
            "type": "observation",
            "title": "API Endpoints Discovered",
            "description": f"Found {len(set(api_paths))} unique API paths. Consider fuzzing for undocumented endpoints.",
            "priority": "low",
            "suggested_rule": None,
            "quick_apply": False
        })
    
    # Admin path detection
    admin_paths = [p for p in paths if any(x in p.lower() for x in ["admin", "manage", "dashboard", "internal"])]
    if admin_paths:
        suggestions.append({
            "type": "security_test",
            "title": "Administrative Endpoints Found",
            "description": f"Detected potential admin paths: {', '.join(set(admin_paths)[:3])}. Test for access control.",
            "priority": "high",
            "suggested_rule": {
                "name": "Add Admin Headers",
                "match_direction": "request",
                "action": "modify",
                "modify_headers": {
                    "X-Admin": "true",
                    "X-User-Role": "administrator"
                }
            },
            "quick_apply": True
        })
    
    # Performance testing
    if "delay" not in str(existing_rule_names):
        suggestions.append({
            "type": "performance_test",
            "title": "Test Timeout Handling",
            "description": "Add artificial latency to test how the application handles slow responses.",
            "priority": "low",
            "suggested_rule": {
                "name": "Add 3s Delay",
                "match_direction": "response",
                "action": "delay",
                "delay_ms": 3000
            },
            "quick_apply": True
        })
    
    # AI-enhanced suggestions if available
    if settings.gemini_api_key and len(traffic_log) >= 5:
        try:
            from google import genai
            from google.genai import types
            
            client = genai.Client(api_key=settings.gemini_api_key)
            
            # Prepare traffic summary
            traffic_summary = []
            for entry in traffic_log[:15]:
                req = entry.get("request", {})
                resp = entry.get("response", {})
                traffic_summary.append({
                    "method": req.get("method"),
                    "path": req.get("path"),
                    "status": resp.get("status_code") if resp else None,
                })
            
            prompt = f"""As a security expert, analyze this HTTP traffic and suggest 2-3 specific security tests.

TRAFFIC SAMPLE:
{json.dumps(traffic_summary, indent=2)}

EXISTING RULES: {len(existing_rules)} rules already configured

Provide suggestions in JSON format:
{{
    "ai_suggestions": [
        {{
            "title": "Test name",
            "description": "What to test and why",
            "test_type": "auth|injection|access_control|information_disclosure|other",
            "risk_level": "high|medium|low"
        }}
    ],
    "traffic_insight": "Brief observation about the traffic patterns (1 sentence)"
}}

Return ONLY JSON."""

            response = client.models.generate_content(
                model=settings.gemini_model_id,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3,
                    max_output_tokens=500,
                )
            )
            
            if response and response.text:
                text = response.text.strip()
                if text.startswith("```"):
                    text = text.split("```")[1]
                    if text.startswith("json"):
                        text = text[4:]
                text = text.strip()
                
                ai_data = json.loads(text)
                
                # Add AI suggestions
                for ai_sug in ai_data.get("ai_suggestions", []):
                    suggestions.insert(0, {
                        "type": "ai_recommendation",
                        "title": f"🤖 {ai_sug.get('title', 'AI Suggestion')}",
                        "description": ai_sug.get("description", ""),
                        "priority": ai_sug.get("risk_level", "medium"),
                        "ai_generated": True,
                        "quick_apply": False
                    })
                
                # Add traffic insight
                if ai_data.get("traffic_insight"):
                    return {
                        "suggestions": suggestions[:8],
                        "summary": ai_data["traffic_insight"],
                        "traffic_stats": {
                            "total_requests": len(traffic_log),
                            "methods": methods,
                            "error_rate": f"{(error_count/len(traffic_log)*100):.1f}%" if traffic_log else "0%"
                        }
                    }
                    
        except Exception as e:
            logger.warning(f"AI suggestions failed: {e}")
    
    return {
        "suggestions": suggestions[:8],
        "summary": f"Analyzed {len(traffic_log)} requests. Found {len(suggestions)} potential tests.",
        "traffic_stats": {
            "total_requests": len(traffic_log),
            "methods": methods,
            "error_rate": f"{(error_count/len(traffic_log)*100):.1f}%" if traffic_log else "0%"
        }
    }
