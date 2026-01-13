"""
Wordlist Service

Manages loading and serving comprehensive wordlists for security testing.
Supports both built-in wordlists and external wordlist loading.

Features:
- Built-in comprehensive wordlists for all attack types
- External wordlist support (mount /wordlists volume)
- Memory-efficient streaming for large files
- Wordlist merging and deduplication
- Custom wordlist upload support
"""

import os
import logging
from pathlib import Path
from typing import List, Dict, Optional, Generator, Set
from functools import lru_cache
from enum import Enum

logger = logging.getLogger(__name__)


class WordlistCategory(str, Enum):
    """Categories of wordlists available."""
    PASSWORDS = "passwords"
    SQLI = "sqli"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SSTI = "ssti"
    NOSQLI = "nosqli"
    SSRF = "ssrf"
    XXE = "xxe"
    DIRECTORIES = "directories"
    USERNAMES = "usernames"
    GRAPHQL = "graphql"
    CUSTOM = "custom"


# Built-in wordlist file mappings
BUILTIN_WORDLISTS = {
    WordlistCategory.PASSWORDS: "passwords_top10k.txt",
    WordlistCategory.SQLI: "sqli_comprehensive.txt",
    WordlistCategory.XSS: "xss_comprehensive.txt",
    WordlistCategory.PATH_TRAVERSAL: "path_traversal_comprehensive.txt",
    WordlistCategory.COMMAND_INJECTION: "command_injection_comprehensive.txt",
    WordlistCategory.SSTI: "ssti_comprehensive.txt",
    WordlistCategory.NOSQLI: "nosqli_comprehensive.txt",
    WordlistCategory.SSRF: "ssrf_comprehensive.txt",
    WordlistCategory.XXE: "xxe_comprehensive.txt",
    WordlistCategory.DIRECTORIES: "directories_comprehensive.txt",
    WordlistCategory.USERNAMES: "usernames_common.txt",
    WordlistCategory.GRAPHQL: "graphql_comprehensive.txt",
}

# External wordlist search paths
EXTERNAL_WORDLIST_PATHS = [
    "/wordlists",           # Docker volume mount
    "/usr/share/wordlists", # Kali Linux default
    "/usr/share/seclists",  # SecLists
    "./wordlists",          # Local development
    "../wordlists",         # Relative path
]

# Known external wordlist files
KNOWN_EXTERNAL_WORDLISTS = {
    "rockyou": ["rockyou.txt", "rockyou.txt.gz"],
    "seclists_passwords": [
        "SecLists/Passwords/Common-Credentials/10k-most-common.txt",
        "SecLists/Passwords/Common-Credentials/100k-most-common.txt",
        "SecLists/Passwords/Leaked-Databases/rockyou.txt",
    ],
    "seclists_sqli": [
        "SecLists/Fuzzing/SQLi/Generic-SQLi.txt",
        "SecLists/Fuzzing/SQLi/quick-SQLi.txt",
    ],
    "seclists_xss": [
        "SecLists/Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt",
        "SecLists/Fuzzing/XSS/XSS-Jhaddix.txt",
    ],
    "seclists_lfi": [
        "SecLists/Fuzzing/LFI/LFI-Jhaddix.txt",
        "SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
        "SecLists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt",
    ],
    "seclists_directories": [
        "SecLists/Discovery/Web-Content/common.txt",
        "SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "SecLists/Discovery/Web-Content/raft-large-directories.txt",
    ],
    "dirbuster": [
        "dirbuster/directory-list-2.3-medium.txt",
        "dirbuster/directory-list-2.3-small.txt",
    ],
}


class WordlistService:
    """
    Service for managing and loading security testing wordlists.
    
    Provides access to comprehensive built-in wordlists and supports
    loading external wordlists from mounted volumes.
    """
    
    def __init__(self, builtin_path: Optional[str] = None):
        """
        Initialize the wordlist service.
        
        Args:
            builtin_path: Path to built-in wordlists directory.
                         Defaults to backend/wordlists.
        """
        self._builtin_path = builtin_path or self._find_builtin_path()
        self._external_paths = self._discover_external_paths()
        self._cache: Dict[str, List[str]] = {}
        self._custom_wordlists: Dict[str, List[str]] = {}
        
        logger.info(f"WordlistService initialized with builtin path: {self._builtin_path}")
        logger.info(f"External wordlist paths: {self._external_paths}")
    
    def _find_builtin_path(self) -> str:
        """Find the built-in wordlists directory."""
        possible_paths = [
            Path(__file__).parent.parent / "wordlists",  # backend/wordlists
            Path("/app/backend/wordlists"),              # Docker container
            Path("./backend/wordlists"),                  # Relative
            Path("./wordlists"),                          # Current dir
        ]
        
        for path in possible_paths:
            if path.exists():
                return str(path)
        
        # Create default path if not exists
        default_path = Path(__file__).parent.parent / "wordlists"
        default_path.mkdir(parents=True, exist_ok=True)
        return str(default_path)
    
    def _discover_external_paths(self) -> List[str]:
        """Discover available external wordlist paths."""
        available = []
        for path in EXTERNAL_WORDLIST_PATHS:
            if os.path.exists(path):
                available.append(path)
        return available
    
    @lru_cache(maxsize=20)
    def get_wordlist(
        self,
        category: WordlistCategory,
        limit: Optional[int] = None,
        include_external: bool = False
    ) -> List[str]:
        """
        Get wordlist for a specific category.
        
        Args:
            category: The wordlist category to load
            limit: Maximum number of entries to return
            include_external: Whether to include external wordlists
        
        Returns:
            List of wordlist entries
        """
        words: Set[str] = set()
        
        # Load built-in wordlist
        if category in BUILTIN_WORDLISTS:
            builtin_file = os.path.join(self._builtin_path, BUILTIN_WORDLISTS[category])
            if os.path.exists(builtin_file):
                words.update(self._load_file(builtin_file))
                logger.debug(f"Loaded {len(words)} entries from builtin {category}")
        
        # Optionally include external wordlists
        if include_external:
            external_words = self._load_external_for_category(category)
            words.update(external_words)
            logger.debug(f"Added {len(external_words)} entries from external sources")
        
        # Convert to list and apply limit
        result = list(words)
        if limit:
            result = result[:limit]
        
        return result
    
    def _load_file(self, filepath: str) -> List[str]:
        """Load wordlist from file, handling comments and empty lines."""
        words = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        words.append(line)
        except Exception as e:
            logger.error(f"Error loading wordlist {filepath}: {e}")
        return words
    
    def _load_external_for_category(self, category: WordlistCategory) -> List[str]:
        """Load external wordlists for a category."""
        words = []
        
        # Map categories to external wordlist keys
        category_mapping = {
            WordlistCategory.PASSWORDS: ["rockyou", "seclists_passwords"],
            WordlistCategory.SQLI: ["seclists_sqli"],
            WordlistCategory.XSS: ["seclists_xss"],
            WordlistCategory.PATH_TRAVERSAL: ["seclists_lfi"],
            WordlistCategory.DIRECTORIES: ["seclists_directories", "dirbuster"],
        }
        
        if category in category_mapping:
            for key in category_mapping[category]:
                if key in KNOWN_EXTERNAL_WORDLISTS:
                    for filename in KNOWN_EXTERNAL_WORDLISTS[key]:
                        for base_path in self._external_paths:
                            filepath = os.path.join(base_path, filename)
                            if os.path.exists(filepath):
                                words.extend(self._load_file(filepath))
                                break
        
        return words
    
    def stream_wordlist(
        self,
        category: WordlistCategory,
        chunk_size: int = 1000
    ) -> Generator[List[str], None, None]:
        """
        Stream wordlist in chunks for memory efficiency.
        
        Args:
            category: The wordlist category to stream
            chunk_size: Number of entries per chunk
        
        Yields:
            Chunks of wordlist entries
        """
        if category in BUILTIN_WORDLISTS:
            builtin_file = os.path.join(self._builtin_path, BUILTIN_WORDLISTS[category])
            if os.path.exists(builtin_file):
                chunk = []
                with open(builtin_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            chunk.append(line)
                            if len(chunk) >= chunk_size:
                                yield chunk
                                chunk = []
                if chunk:
                    yield chunk
    
    def add_custom_wordlist(self, name: str, words: List[str]) -> None:
        """
        Add a custom wordlist.
        
        Args:
            name: Name for the custom wordlist
            words: List of words to add
        """
        self._custom_wordlists[name] = words
        logger.info(f"Added custom wordlist '{name}' with {len(words)} entries")
    
    def get_custom_wordlist(self, name: str) -> List[str]:
        """Get a custom wordlist by name."""
        return self._custom_wordlists.get(name, [])
    
    def list_custom_wordlists(self) -> List[str]:
        """List all custom wordlist names."""
        return list(self._custom_wordlists.keys())
    
    def get_available_wordlists(self) -> Dict[str, Dict]:
        """
        Get information about all available wordlists.
        
        Returns:
            Dictionary with wordlist information
        """
        available = {}
        
        # Check built-in wordlists
        for category, filename in BUILTIN_WORDLISTS.items():
            filepath = os.path.join(self._builtin_path, filename)
            if os.path.exists(filepath):
                try:
                    count = sum(1 for line in open(filepath, 'r', encoding='utf-8', errors='ignore') 
                               if line.strip() and not line.startswith('#'))
                except Exception:
                    count = 0
                
                available[category.value] = {
                    "type": "builtin",
                    "filename": filename,
                    "filepath": filepath,
                    "count": count,
                    "available": True,
                }
            else:
                available[category.value] = {
                    "type": "builtin",
                    "filename": filename,
                    "available": False,
                }
        
        # Check external wordlists
        external_found = []
        for base_path in self._external_paths:
            if os.path.exists(base_path):
                for key, filenames in KNOWN_EXTERNAL_WORDLISTS.items():
                    for filename in filenames:
                        filepath = os.path.join(base_path, filename)
                        if os.path.exists(filepath):
                            external_found.append({
                                "key": key,
                                "filename": filename,
                                "path": filepath,
                            })
        
        available["external"] = {
            "paths": self._external_paths,
            "found": external_found,
        }
        
        # Add custom wordlists
        available["custom"] = {
            name: {"count": len(words)} 
            for name, words in self._custom_wordlists.items()
        }
        
        return available
    
    def search_external_file(self, filename: str) -> Optional[str]:
        """
        Search for an external wordlist file.
        
        Args:
            filename: Name of the file to search for
        
        Returns:
            Full path if found, None otherwise
        """
        for base_path in self._external_paths:
            filepath = os.path.join(base_path, filename)
            if os.path.exists(filepath):
                return filepath
            # Also check subdirectories
            for root, dirs, files in os.walk(base_path):
                if filename in files:
                    return os.path.join(root, filename)
        return None
    
    def load_external_file(self, filename: str, limit: Optional[int] = None) -> List[str]:
        """
        Load an external wordlist file by name.
        
        Args:
            filename: Name of the file to load
            limit: Maximum entries to return
        
        Returns:
            List of wordlist entries
        """
        filepath = self.search_external_file(filename)
        if filepath:
            words = self._load_file(filepath)
            if limit:
                words = words[:limit]
            return words
        return []
    
    def get_combined_wordlist(
        self,
        categories: List[WordlistCategory],
        limit: Optional[int] = None,
        deduplicate: bool = True
    ) -> List[str]:
        """
        Get combined wordlist from multiple categories.
        
        Args:
            categories: List of categories to combine
            limit: Maximum total entries
            deduplicate: Whether to remove duplicates
        
        Returns:
            Combined wordlist
        """
        if deduplicate:
            combined: Set[str] = set()
            for category in categories:
                combined.update(self.get_wordlist(category))
            result = list(combined)
        else:
            result = []
            for category in categories:
                result.extend(self.get_wordlist(category))
        
        if limit:
            result = result[:limit]
        
        return result
    
    def get_technique_payloads(self, technique: str, limit: int = 100) -> List[str]:
        """
        Get payloads for a specific attack technique.
        
        Args:
            technique: Attack technique name (sqli, xss, etc.)
            limit: Maximum payloads to return
        
        Returns:
            List of payloads for the technique
        """
        # Map technique names to categories
        technique_map = {
            "sqli": WordlistCategory.SQLI,
            "sql_injection": WordlistCategory.SQLI,
            "xss": WordlistCategory.XSS,
            "cross_site_scripting": WordlistCategory.XSS,
            "path_traversal": WordlistCategory.PATH_TRAVERSAL,
            "lfi": WordlistCategory.PATH_TRAVERSAL,
            "rfi": WordlistCategory.PATH_TRAVERSAL,
            "directory_traversal": WordlistCategory.PATH_TRAVERSAL,
            "command_injection": WordlistCategory.COMMAND_INJECTION,
            "cmdi": WordlistCategory.COMMAND_INJECTION,
            "os_injection": WordlistCategory.COMMAND_INJECTION,
            "rce": WordlistCategory.COMMAND_INJECTION,
            "ssti": WordlistCategory.SSTI,
            "template_injection": WordlistCategory.SSTI,
            "nosqli": WordlistCategory.NOSQLI,
            "nosql_injection": WordlistCategory.NOSQLI,
            "mongodb_injection": WordlistCategory.NOSQLI,
            "ssrf": WordlistCategory.SSRF,
            "server_side_request_forgery": WordlistCategory.SSRF,
            "xxe": WordlistCategory.XXE,
            "xml_external_entity": WordlistCategory.XXE,
            "password": WordlistCategory.PASSWORDS,
            "passwords": WordlistCategory.PASSWORDS,
            "auth_bypass": WordlistCategory.PASSWORDS,
            "brute_force": WordlistCategory.PASSWORDS,
            "directory_discovery": WordlistCategory.DIRECTORIES,
            "directories": WordlistCategory.DIRECTORIES,
            "content_discovery": WordlistCategory.DIRECTORIES,
        }
        
        technique_lower = technique.lower().replace("-", "_").replace(" ", "_")
        if technique_lower in technique_map:
            return self.get_wordlist(technique_map[technique_lower], limit=limit)
        
        return []
    
    def get_stats(self) -> Dict[str, int]:
        """Get wordlist statistics."""
        stats = {}
        for category, filename in BUILTIN_WORDLISTS.items():
            filepath = os.path.join(self._builtin_path, filename)
            if os.path.exists(filepath):
                try:
                    count = sum(1 for line in open(filepath, 'r', encoding='utf-8', errors='ignore') 
                               if line.strip() and not line.startswith('#'))
                    stats[category.value] = count
                except Exception:
                    stats[category.value] = 0
            else:
                stats[category.value] = 0
        
        stats["custom_lists"] = len(self._custom_wordlists)
        stats["custom_entries"] = sum(len(w) for w in self._custom_wordlists.values())
        stats["external_paths"] = len(self._external_paths)
        
        return stats


# Global service instance
_wordlist_service: Optional[WordlistService] = None


def get_wordlist_service() -> WordlistService:
    """Get the global wordlist service instance."""
    global _wordlist_service
    if _wordlist_service is None:
        _wordlist_service = WordlistService()
    return _wordlist_service


# Convenience functions
def get_payloads(technique: str, limit: int = 100) -> List[str]:
    """Get payloads for a technique."""
    return get_wordlist_service().get_technique_payloads(technique, limit)


def get_passwords(limit: int = 10000) -> List[str]:
    """Get common passwords."""
    return get_wordlist_service().get_wordlist(WordlistCategory.PASSWORDS, limit)


def get_directories(limit: int = 5000) -> List[str]:
    """Get common directories."""
    return get_wordlist_service().get_wordlist(WordlistCategory.DIRECTORIES, limit)


def get_usernames(limit: int = 1000) -> List[str]:
    """Get common usernames."""
    return get_wordlist_service().get_wordlist(WordlistCategory.USERNAMES, limit)
