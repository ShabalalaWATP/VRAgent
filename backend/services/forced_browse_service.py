"""
Local Forced Browse / Directory Discovery Service

Performs directory brute-forcing using local wordlists without requiring
external ZAP API or internet connection. Works entirely within the local
Docker environment.
"""

import asyncio
import aiohttp
import logging
import os
import time
from typing import Dict, List, Optional, AsyncGenerator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ForcedBrowseStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class ForcedBrowseResult:
    """Result of a forced browse discovery."""
    url: str
    status_code: int
    content_length: int
    content_type: str
    redirect_url: Optional[str] = None
    interesting: bool = False
    reason: str = ""


@dataclass
class ForcedBrowseSession:
    """Active forced browse session state."""
    session_id: str
    target_url: str
    wordlist: str
    status: ForcedBrowseStatus = ForcedBrowseStatus.IDLE
    progress: float = 0.0
    total_paths: int = 0
    checked_paths: int = 0
    found_paths: List[ForcedBrowseResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    recursive: bool = False
    threads: int = 10
    _stop_flag: bool = False
    _pause_flag: bool = False


class ForcedBrowseService:
    """
    Local directory brute-forcing service.
    
    Uses local wordlists to discover hidden directories and files
    on target web applications. Works entirely offline.
    """
    
    def __init__(self):
        self.sessions: Dict[str, ForcedBrowseSession] = {}
        self.wordlists_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 
            "wordlists"
        )
        
        # Status codes that indicate found resources
        self.success_codes = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403}
        
        # Extensions to try for file discovery
        self.common_extensions = [
            "", ".html", ".php", ".asp", ".aspx", ".jsp", 
            ".txt", ".xml", ".json", ".js", ".css",
            ".bak", ".old", ".orig", ".backup", ".sql",
            ".zip", ".tar", ".gz", ".rar"
        ]
    
    def get_available_wordlists(self) -> List[Dict[str, str]]:
        """Get list of available local wordlists."""
        wordlists = []
        
        if os.path.exists(self.wordlists_dir):
            for filename in os.listdir(self.wordlists_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(self.wordlists_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            line_count = sum(1 for _ in f)
                        
                        wordlists.append({
                            "name": filename,
                            "path": filepath,
                            "entries": line_count,
                            "description": self._get_wordlist_description(filename)
                        })
                    except Exception as e:
                        logger.warning(f"Could not read wordlist {filename}: {e}")
        
        return sorted(wordlists, key=lambda x: x["name"])
    
    def _get_wordlist_description(self, filename: str) -> str:
        """Get description for a wordlist based on filename."""
        descriptions = {
            "directories_comprehensive.txt": "Common directories and paths for web applications",
            "sqli_comprehensive.txt": "SQL injection payloads and test strings",
            "xss_comprehensive.txt": "XSS payloads and test vectors",
            "ssrf_comprehensive.txt": "SSRF payloads and internal URLs",
            "ssti_comprehensive.txt": "Server-side template injection payloads",
            "xxe_comprehensive.txt": "XXE payloads and XML attack vectors",
            "passwords_top10k.txt": "Common passwords for brute-force testing",
            "usernames_common.txt": "Common usernames for enumeration",
            "graphql_comprehensive.txt": "GraphQL introspection and attack queries",
        }
        return descriptions.get(filename, "Custom wordlist")
    
    def _load_wordlist(self, wordlist_name: str) -> List[str]:
        """Load wordlist from local storage."""
        filepath = os.path.join(self.wordlists_dir, wordlist_name)
        
        if not os.path.exists(filepath):
            # Try full path
            if os.path.exists(wordlist_name):
                filepath = wordlist_name
            else:
                raise FileNotFoundError(f"Wordlist not found: {wordlist_name}")
        
        paths = []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Normalize path
                    if not line.startswith('/'):
                        line = '/' + line
                    paths.append(line)
        
        return paths
    
    async def start_scan(
        self,
        target_url: str,
        wordlist: str = "directories_comprehensive.txt",
        recursive: bool = False,
        threads: int = 10,
        extensions: Optional[List[str]] = None
    ) -> str:
        """
        Start a forced browse scan.
        
        Args:
            target_url: Base URL to scan
            wordlist: Name of wordlist file to use
            recursive: Whether to recursively scan discovered directories
            threads: Number of concurrent requests
            extensions: File extensions to try (None for directories only)
        
        Returns:
            Session ID for tracking progress
        """
        import uuid
        
        session_id = str(uuid.uuid4())[:8]
        
        # Normalize target URL
        target_url = target_url.rstrip('/')
        
        # Load wordlist
        try:
            paths = self._load_wordlist(wordlist)
        except FileNotFoundError as e:
            raise ValueError(str(e))
        
        # Create session
        session = ForcedBrowseSession(
            session_id=session_id,
            target_url=target_url,
            wordlist=wordlist,
            total_paths=len(paths),
            recursive=recursive,
            threads=threads
        )
        
        self.sessions[session_id] = session
        
        # Start scan in background
        asyncio.create_task(self._run_scan(session, paths, extensions))
        
        return session_id
    
    async def _run_scan(
        self,
        session: ForcedBrowseSession,
        paths: List[str],
        extensions: Optional[List[str]]
    ):
        """Run the forced browse scan."""
        session.status = ForcedBrowseStatus.RUNNING
        session.start_time = time.time()
        
        # Use extensions if provided
        if extensions is None:
            extensions = [""]  # Just directories
        
        # Build full path list with extensions
        full_paths = []
        for path in paths:
            for ext in extensions:
                if ext and not path.endswith(ext):
                    full_paths.append(path + ext)
                elif not ext:
                    full_paths.append(path)
        
        session.total_paths = len(full_paths)
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(session.threads)
        
        # HTTP client settings
        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        connector = aiohttp.TCPConnector(
            limit=session.threads,
            ssl=False,  # Allow self-signed certs
            force_close=True
        )
        
        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={
                    "User-Agent": "VRAgent-ForcedBrowse/1.0",
                    "Accept": "*/*"
                }
            ) as http_client:
                
                # Process paths in batches
                tasks = []
                for path in full_paths:
                    if session._stop_flag:
                        break
                    
                    # Wait while paused
                    while session._pause_flag and not session._stop_flag:
                        await asyncio.sleep(0.5)
                    
                    task = asyncio.create_task(
                        self._check_path(http_client, semaphore, session, path)
                    )
                    tasks.append(task)
                
                # Wait for all tasks
                await asyncio.gather(*tasks, return_exceptions=True)
        
        except Exception as e:
            session.errors.append(f"Scan error: {str(e)}")
            logger.error(f"Forced browse scan error: {e}")
        
        finally:
            session.end_time = time.time()
            if session._stop_flag:
                session.status = ForcedBrowseStatus.STOPPED
            else:
                session.status = ForcedBrowseStatus.COMPLETED
    
    async def _check_path(
        self,
        client: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        session: ForcedBrowseSession,
        path: str
    ):
        """Check a single path."""
        async with semaphore:
            if session._stop_flag:
                return
            
            url = f"{session.target_url}{path}"
            
            try:
                async with client.get(url, allow_redirects=False) as response:
                    status = response.status
                    content_length = int(response.headers.get('Content-Length', 0))
                    content_type = response.headers.get('Content-Type', '')
                    redirect_url = response.headers.get('Location')
                    
                    # Check if this is an interesting result
                    interesting = False
                    reason = ""
                    
                    if status in self.success_codes:
                        interesting = True
                        
                        if status == 200:
                            reason = "Found (200 OK)"
                        elif status in (301, 302, 307, 308):
                            reason = f"Redirect to {redirect_url}"
                        elif status == 401:
                            reason = "Authentication required"
                        elif status == 403:
                            reason = "Forbidden (exists but restricted)"
                    
                    if interesting:
                        result = ForcedBrowseResult(
                            url=url,
                            status_code=status,
                            content_length=content_length,
                            content_type=content_type,
                            redirect_url=redirect_url,
                            interesting=True,
                            reason=reason
                        )
                        session.found_paths.append(result)
                        logger.info(f"Found: {url} ({status})")
            
            except asyncio.TimeoutError:
                pass  # Timeout is normal for non-existent paths
            except aiohttp.ClientError as e:
                # Only log unexpected errors
                if "Cannot connect" not in str(e):
                    logger.debug(f"Error checking {url}: {e}")
            except Exception as e:
                logger.debug(f"Unexpected error checking {url}: {e}")
            
            finally:
                session.checked_paths += 1
                session.progress = (session.checked_paths / session.total_paths) * 100
    
    def get_session(self, session_id: str) -> Optional[ForcedBrowseSession]:
        """Get session by ID."""
        return self.sessions.get(session_id)
    
    def get_status(self, session_id: str) -> Dict:
        """Get current status of a scan."""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
        
        duration = 0
        if session.start_time:
            end = session.end_time or time.time()
            duration = end - session.start_time
        
        return {
            "session_id": session.session_id,
            "status": session.status.value,
            "progress": round(session.progress, 2),
            "total_paths": session.total_paths,
            "checked_paths": session.checked_paths,
            "found_count": len(session.found_paths),
            "duration_seconds": round(duration, 2),
            "target_url": session.target_url,
            "wordlist": session.wordlist,
        }
    
    def get_results(self, session_id: str) -> List[Dict]:
        """Get discovered paths for a session."""
        session = self.sessions.get(session_id)
        if not session:
            return []
        
        return [
            {
                "url": r.url,
                "status_code": r.status_code,
                "content_length": r.content_length,
                "content_type": r.content_type,
                "redirect_url": r.redirect_url,
                "reason": r.reason
            }
            for r in session.found_paths
        ]
    
    def stop_scan(self, session_id: str) -> bool:
        """Stop a running scan."""
        session = self.sessions.get(session_id)
        if session and session.status == ForcedBrowseStatus.RUNNING:
            session._stop_flag = True
            return True
        return False
    
    def pause_scan(self, session_id: str) -> bool:
        """Pause a running scan."""
        session = self.sessions.get(session_id)
        if session and session.status == ForcedBrowseStatus.RUNNING:
            session._pause_flag = True
            session.status = ForcedBrowseStatus.PAUSED
            return True
        return False
    
    def resume_scan(self, session_id: str) -> bool:
        """Resume a paused scan."""
        session = self.sessions.get(session_id)
        if session and session.status == ForcedBrowseStatus.PAUSED:
            session._pause_flag = False
            session.status = ForcedBrowseStatus.RUNNING
            return True
        return False


# Singleton instance
_forced_browse_service: Optional[ForcedBrowseService] = None


def get_forced_browse_service() -> ForcedBrowseService:
    """Get the forced browse service singleton."""
    global _forced_browse_service
    if _forced_browse_service is None:
        _forced_browse_service = ForcedBrowseService()
    return _forced_browse_service
