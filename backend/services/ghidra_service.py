import glob as _glob
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)

# Cached resolution result: (path_or_none, search_details)
_cached_resolution: Optional[Tuple[Optional[Path], Dict[str, Any]]] = None


def _get_candidate_paths() -> List[Path]:
    """Build a list of candidate Ghidra installation directories to search."""
    candidates: List[Path] = []

    # 1. Explicit GHIDRA_HEADLESS_PATH takes absolute priority (handled in _resolve)
    # 2. Explicit GHIDRA_HOME
    ghidra_home = settings.ghidra_home.strip() if settings.ghidra_home else ""
    if ghidra_home:
        candidates.append(Path(ghidra_home))

    # 3. Platform-specific common installation paths with version wildcards
    if os.name == "nt":
        # Windows: check common install locations with version wildcards
        for drive in ("C:", "D:", "E:"):
            # Glob for any Ghidra version: ghidra_*_PUBLIC, ghidra_*_DEV, etc.
            pattern = os.path.join(drive, os.sep, "ghidra_*")
            for match in sorted(_glob.glob(pattern), reverse=True):
                candidates.append(Path(match))
            # Also check Program Files
            for pf in ("Program Files", "Program Files (x86)"):
                pf_pattern = os.path.join(drive, os.sep, pf, "ghidra*")
                for match in sorted(_glob.glob(pf_pattern), reverse=True):
                    candidates.append(Path(match))
                # Check inside a "Ghidra" folder
                ghidra_dir = Path(drive + os.sep) / pf / "Ghidra"
                if ghidra_dir.is_dir():
                    candidates.append(ghidra_dir)
        # User home tools directory
        home = Path.home()
        for match in sorted(_glob.glob(str(home / "ghidra_*")), reverse=True):
            candidates.append(Path(match))
        tools_dir = home / "tools"
        if tools_dir.is_dir():
            for match in sorted(_glob.glob(str(tools_dir / "ghidra*")), reverse=True):
                candidates.append(Path(match))
    else:
        # Linux / macOS
        search_dirs = [
            "/opt",
            "/usr/local",
            "/usr/share",
            str(Path.home()),
            str(Path.home() / "tools"),
            str(Path.home() / ".local" / "share"),
        ]
        for search_dir in search_dirs:
            for match in sorted(_glob.glob(os.path.join(search_dir, "ghidra*")), reverse=True):
                candidates.append(Path(match))
        # Homebrew on macOS
        brew_prefix = Path("/opt/homebrew/Cellar/ghidra")
        if brew_prefix.is_dir():
            for version_dir in sorted(brew_prefix.iterdir(), reverse=True):
                if version_dir.is_dir():
                    candidates.append(version_dir / "libexec")
        # Docker default
        docker_path = Path("/opt/ghidra")
        if docker_path.is_dir():
            candidates.append(docker_path)

    # Deduplicate while preserving order
    seen = set()
    unique: List[Path] = []
    for c in candidates:
        key = str(c).lower() if os.name == "nt" else str(c)
        if key not in seen:
            seen.add(key)
            unique.append(c)

    return unique


def _resolve_headless_path() -> Tuple[Optional[Path], Dict[str, Any]]:
    """
    Resolve the Ghidra analyzeHeadless executable path.

    Returns a tuple of (resolved_path, details) where details contains
    diagnostic information about the search for troubleshooting.
    """
    global _cached_resolution
    if _cached_resolution is not None:
        return _cached_resolution

    details: Dict[str, Any] = {
        "ghidra_home_env": settings.ghidra_home or "(not set)",
        "ghidra_headless_path_env": settings.ghidra_headless_path or "(not set)",
        "searched_paths": [],
        "found_path": None,
        "resolution_method": None,
    }

    # Priority 1: Explicit GHIDRA_HEADLESS_PATH
    if settings.ghidra_headless_path:
        path = Path(settings.ghidra_headless_path)
        details["resolution_method"] = "GHIDRA_HEADLESS_PATH env var"
        if path.exists():
            details["found_path"] = str(path)
            _cached_resolution = (path, details)
            return _cached_resolution
        else:
            details["searched_paths"].append(f"{path} (GHIDRA_HEADLESS_PATH - NOT FOUND)")
            logger.warning(f"GHIDRA_HEADLESS_PATH set to '{path}' but file does not exist")

    # Priority 2: Search candidate directories
    candidates = _get_candidate_paths()
    details["resolution_method"] = "directory search"

    for base in candidates:
        if os.name == "nt":
            win_path = base / "support" / "analyzeHeadless.bat"
            details["searched_paths"].append(str(win_path))
            if win_path.exists():
                details["found_path"] = str(win_path)
                logger.info(f"Found Ghidra at: {win_path}")
                _cached_resolution = (win_path, details)
                return _cached_resolution
        nix_path = base / "support" / "analyzeHeadless"
        details["searched_paths"].append(str(nix_path))
        if nix_path.exists():
            details["found_path"] = str(nix_path)
            logger.info(f"Found Ghidra at: {nix_path}")
            _cached_resolution = (nix_path, details)
            return _cached_resolution

    logger.warning(
        f"Ghidra not found. Searched {len(details['searched_paths'])} paths. "
        f"Set GHIDRA_HOME or GHIDRA_HEADLESS_PATH environment variable."
    )
    _cached_resolution = (None, details)
    return _cached_resolution


def ghidra_available() -> bool:
    """Return True if Ghidra headless is available."""
    path, _ = _resolve_headless_path()
    return path is not None


def ghidra_status() -> Dict[str, Any]:
    """
    Return detailed Ghidra availability status for diagnostics.

    Includes the resolved path (if found) and all paths that were searched,
    which helps users troubleshoot configuration issues.
    """
    path, details = _resolve_headless_path()
    return {
        "available": path is not None,
        "path": str(path) if path else None,
        "ghidra_home": details["ghidra_home_env"],
        "ghidra_headless_path": details["ghidra_headless_path_env"],
        "searched_paths": details["searched_paths"][:20],  # Cap for response size
        "resolution_method": details["resolution_method"],
        "setup_instructions": _get_setup_instructions() if path is None else None,
    }


def _get_setup_instructions() -> str:
    """Return platform-specific Ghidra setup instructions."""
    if os.name == "nt":
        return (
            "To enable Ghidra decompilation:\n"
            "1. Download Ghidra from https://ghidra-sre.org/\n"
            "2. Extract to a directory (e.g., C:\\ghidra_11.3_PUBLIC)\n"
            "3. Set the GHIDRA_HOME environment variable to the extracted directory\n"
            "   Or set GHIDRA_HEADLESS_PATH to the full path of support\\analyzeHeadless.bat\n"
            "4. Ensure Java 17+ (JDK) is installed and JAVA_HOME is set\n"
            "5. Restart the VRAgent backend"
        )
    return (
        "To enable Ghidra decompilation:\n"
        "1. Download Ghidra from https://ghidra-sre.org/\n"
        "2. Extract to /opt/ghidra or ~/ghidra_*\n"
        "3. Set the GHIDRA_HOME environment variable to the extracted directory\n"
        "   Or set GHIDRA_HEADLESS_PATH to the full path of support/analyzeHeadless\n"
        "4. Ensure Java 17+ (JDK) is installed and JAVA_HOME is set\n"
        "5. Restart the VRAgent backend"
    )


def invalidate_cache() -> None:
    """Clear the cached Ghidra resolution. Call after config changes."""
    global _cached_resolution
    _cached_resolution = None


def run_ghidra_decompilation(
    file_path: Path,
    max_functions: int = 300,
    decomp_limit: int = 8000,
    timeout_seconds: int = 1200,
    selection_mode: str = "security",
) -> Dict[str, Any]:
    """
    Run Ghidra headless analysis and export decompilation JSON.
    """
    headless_path, details = _resolve_headless_path()
    if not headless_path:
        searched = details.get("searched_paths", [])
        hint = f" Searched {len(searched)} locations." if searched else ""
        return {
            "error": (
                "Ghidra headless not configured. Set GHIDRA_HOME or GHIDRA_HEADLESS_PATH "
                "environment variable to your Ghidra installation directory." + hint
            ),
            "setup_instructions": _get_setup_instructions(),
        }

    scripts_dir = Path(__file__).resolve().parent.parent / "ghidra_scripts"
    script_name = "export_decompilation.py"
    if not (scripts_dir / script_name).exists():
        return {"error": f"Ghidra export script not found: {scripts_dir / script_name}"}

    project_dir = Path(tempfile.mkdtemp(prefix="vragent_ghidra_"))
    project_name = "analysis"
    output_path = project_dir / "decompilation.json"

    cmd = [
        str(headless_path),
        str(project_dir),
        project_name,
        "-import",
        str(file_path),
        "-deleteProject",
        "-scriptPath",
        str(scripts_dir),
        "-postScript",
        script_name,
        str(output_path),
        str(max_functions),
        str(decomp_limit),
        selection_mode,  # Pass selection mode to script
    ]
    if headless_path.suffix.lower() == ".bat" and os.name == "nt":
        cmd = ["cmd", "/c"] + cmd

    # Set up environment for headless Java
    env = os.environ.copy()
    env["JAVA_TOOL_OPTIONS"] = "-Djava.awt.headless=true"

    try:
        logger.info(f"Running Ghidra headless analysis (max_functions={max_functions}, decomp_limit={decomp_limit}, mode={selection_mode})")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=env,
        )
        if result.returncode != 0:
            stderr_text = (result.stderr or "")
            stdout_text = (result.stdout or "")
            # Log full output for debugging, return truncated for API
            if len(stderr_text) > 10000:
                logger.error(f"Ghidra stderr (full, {len(stderr_text)} chars): {stderr_text}")
            # Save full logs to a file for user inspection
            log_path = project_dir / "ghidra_error.log"
            try:
                log_path.write_text(
                    f"=== STDOUT ===\n{stdout_text}\n\n=== STDERR ===\n{stderr_text}",
                    encoding="utf-8",
                )
                logger.info(f"Full Ghidra error log saved to: {log_path}")
            except Exception:
                pass
            # Detect common failure causes
            error_hint = ""
            if "java" in stderr_text.lower() and ("not found" in stderr_text.lower() or "no such file" in stderr_text.lower()):
                error_hint = " Hint: Java (JDK 17+) may not be installed or JAVA_HOME is not set."
            elif "out of memory" in stderr_text.lower() or "heap space" in stderr_text.lower():
                error_hint = " Hint: Ghidra ran out of memory. Try reducing max_functions or analyzing a smaller binary."
            elif "unsupported" in stderr_text.lower():
                error_hint = " Hint: The binary format may not be supported by this Ghidra version."
            return {
                "error": f"Ghidra analysis failed (exit code {result.returncode}).{error_hint}",
                "stderr": stderr_text[:10000],
                "stdout": stdout_text[:10000],
            }

        if not output_path.exists():
            return {
                "error": "Ghidra analysis completed but no decompilation output was produced. "
                         "The binary may use an unsupported format or have no analyzable functions.",
                "stdout": (result.stdout or "")[:5000],
            }

        data = output_path.read_text(encoding="utf-8", errors="ignore")
        return {"data": data}
    except subprocess.TimeoutExpired:
        return {
            "error": f"Ghidra analysis timed out after {timeout_seconds}s. "
                     f"Try reducing ghidra_max_functions or ghidra_decomp_limit for faster analysis.",
        }
    except Exception as exc:
        logger.error(f"Ghidra analysis failed: {exc}")
        return {"error": f"Ghidra analysis failed: {exc}"}
    finally:
        try:
            import shutil
            if project_dir.exists():
                shutil.rmtree(project_dir, ignore_errors=True)
        except Exception:
            pass
