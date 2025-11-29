"""
Git Service

Handles cloning GitHub/GitLab repositories for scanning.
"""

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse

from backend.core.exceptions import VRAgentError
from backend.core.logging import get_logger

logger = get_logger(__name__)


class GitCloneError(VRAgentError):
    """Raised when git clone operation fails."""
    pass


class InvalidRepoURLError(VRAgentError):
    """Raised when repository URL is invalid."""
    pass


@dataclass
class CloneResult:
    """Result of a git clone operation."""
    success: bool
    path: str
    repo_name: str
    branch: str
    error: Optional[str] = None


# Allowed Git hosting providers
ALLOWED_HOSTS = [
    'github.com',
    'gitlab.com',
    'bitbucket.org',
    'dev.azure.com',
    'ssh.dev.azure.com',
]

# Regex pattern for valid repository URLs
GIT_URL_PATTERNS = [
    # HTTPS URLs
    r'^https?://(?P<host>[^/]+)/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$',
    # SSH URLs
    r'^git@(?P<host>[^:]+):(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$',
    # Azure DevOps HTTPS
    r'^https://(?P<host>dev\.azure\.com)/(?P<owner>[^/]+)/(?P<project>[^/]+)/_git/(?P<repo>[^/]+?)(?:\.git)?/?$',
]


def validate_repo_url(url: str) -> Tuple[str, str, str]:
    """
    Validate and parse a git repository URL.
    
    Args:
        url: The repository URL to validate
        
    Returns:
        Tuple of (host, owner, repo_name)
        
    Raises:
        InvalidRepoURLError: If URL is invalid or from disallowed host
    """
    url = url.strip()
    
    for pattern in GIT_URL_PATTERNS:
        match = re.match(pattern, url)
        if match:
            groups = match.groupdict()
            host = groups['host']
            owner = groups['owner']
            repo = groups.get('repo') or groups.get('project', '')
            
            # Check if host is allowed
            if host not in ALLOWED_HOSTS:
                raise InvalidRepoURLError(
                    f"Repository host '{host}' is not in the allowed list. "
                    f"Allowed hosts: {', '.join(ALLOWED_HOSTS)}"
                )
            
            return host, owner, repo
    
    raise InvalidRepoURLError(
        f"Invalid repository URL format: {url}. "
        "Expected format: https://github.com/owner/repo or git@github.com:owner/repo"
    )


def sanitize_repo_name(name: str) -> str:
    """Sanitize repository name for use in file paths."""
    # Remove .git suffix
    if name.endswith('.git'):
        name = name[:-4]
    # Replace any non-alphanumeric chars except dash/underscore
    name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
    return name


def clone_repository(
    repo_url: str,
    target_dir: Optional[str] = None,
    branch: Optional[str] = None,
    depth: int = 1,
    timeout: int = 300,
) -> CloneResult:
    """
    Clone a git repository to a local directory.
    
    Args:
        repo_url: URL of the repository to clone
        target_dir: Directory to clone into (created if None)
        branch: Specific branch to clone (default branch if None)
        depth: Clone depth (1 for shallow clone)
        timeout: Timeout in seconds for the clone operation
        
    Returns:
        CloneResult object with clone details
        
    Raises:
        InvalidRepoURLError: If repository URL is invalid
        GitCloneError: If clone operation fails
    """
    # Validate URL
    host, owner, repo_name = validate_repo_url(repo_url)
    safe_repo_name = sanitize_repo_name(repo_name)
    
    logger.info(f"Cloning repository: {owner}/{repo_name} from {host}")
    
    # Create target directory
    if target_dir is None:
        target_dir = tempfile.mkdtemp(prefix=f"vragent_{safe_repo_name}_")
    else:
        os.makedirs(target_dir, exist_ok=True)
    
    clone_path = os.path.join(target_dir, safe_repo_name)
    
    # Build git command
    cmd = ['git', 'clone']
    
    if depth > 0:
        cmd.extend(['--depth', str(depth)])
    
    if branch:
        cmd.extend(['--branch', branch])
    
    cmd.extend([repo_url, clone_path])
    
    try:
        # Check if git is available
        subprocess.run(
            ['git', '--version'],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        raise GitCloneError("Git is not installed or not available in PATH")
    
    try:
        # Run git clone
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},  # Disable interactive prompts
        )
        
        # Get the actual branch name
        actual_branch = branch or get_default_branch(clone_path)
        
        logger.info(f"Successfully cloned {owner}/{repo_name} to {clone_path}")
        
        return CloneResult(
            success=True,
            path=clone_path,
            repo_name=repo_name,
            branch=actual_branch,
        )
        
    except subprocess.TimeoutExpired:
        # Clean up partial clone
        if os.path.exists(clone_path):
            shutil.rmtree(clone_path, ignore_errors=True)
        raise GitCloneError(f"Clone operation timed out after {timeout} seconds")
        
    except subprocess.CalledProcessError as e:
        # Clean up partial clone
        if os.path.exists(clone_path):
            shutil.rmtree(clone_path, ignore_errors=True)
        
        error_msg = e.stderr or e.stdout or str(e)
        
        # Parse common error messages
        if 'Repository not found' in error_msg or 'not found' in error_msg.lower():
            raise GitCloneError(f"Repository not found: {repo_url}")
        elif 'Authentication failed' in error_msg:
            raise GitCloneError("Authentication failed. Repository may be private.")
        elif 'Permission denied' in error_msg:
            raise GitCloneError("Permission denied. Repository may be private or require authentication.")
        else:
            raise GitCloneError(f"Git clone failed: {error_msg}")


def get_default_branch(repo_path: str) -> str:
    """Get the default branch name of a cloned repository."""
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except Exception:
        return 'main'


def get_repo_info(repo_path: str) -> dict:
    """
    Get information about a cloned repository.
    
    Args:
        repo_path: Path to the cloned repository
        
    Returns:
        Dictionary with repository information
    """
    info = {
        'path': repo_path,
        'branch': 'unknown',
        'commit': 'unknown',
        'remote_url': 'unknown',
    }
    
    try:
        # Get current branch
        result = subprocess.run(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        info['branch'] = result.stdout.strip()
        
        # Get current commit
        result = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        info['commit'] = result.stdout.strip()[:8]
        
        # Get remote URL
        result = subprocess.run(
            ['git', 'remote', 'get-url', 'origin'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        info['remote_url'] = result.stdout.strip()
        
    except Exception as e:
        logger.warning(f"Could not get full repo info: {e}")
    
    return info


def cleanup_clone(path: str) -> bool:
    """
    Remove a cloned repository directory.
    
    Args:
        path: Path to the cloned repository
        
    Returns:
        True if cleanup was successful
    """
    try:
        if os.path.exists(path):
            shutil.rmtree(path)
            logger.info(f"Cleaned up cloned repository: {path}")
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to cleanup clone at {path}: {e}")
        return False


def is_git_repo(path: str) -> bool:
    """Check if a path is a git repository."""
    git_dir = os.path.join(path, '.git')
    return os.path.isdir(git_dir)
