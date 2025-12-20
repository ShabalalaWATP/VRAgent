import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)


def _resolve_headless_path() -> Optional[Path]:
    """Resolve the Ghidra analyzeHeadless executable path."""
    if settings.ghidra_headless_path:
        path = Path(settings.ghidra_headless_path)
        return path if path.exists() else None

    ghidra_home = settings.ghidra_home.strip() if settings.ghidra_home else ""
    candidates = []

    if ghidra_home:
        candidates.append(Path(ghidra_home))
    elif os.name == "nt":
        candidates.append(Path(r"C:\ghidra_12.0_PUBLIC"))

    for base in candidates:
        # Prefer the correct executable for the current OS
        if os.name == "nt":
            win_path = base / "support" / "analyzeHeadless.bat"
            if win_path.exists():
                return win_path
        nix_path = base / "support" / "analyzeHeadless"
        if nix_path.exists():
            return nix_path
        # Fallback to .bat on Windows if shell script not found
        if os.name == "nt":
            win_path = base / "support" / "analyzeHeadless.bat"
            if win_path.exists():
                return win_path

    return None


def ghidra_available() -> bool:
    """Return True if Ghidra headless is available."""
    return _resolve_headless_path() is not None


def run_ghidra_decompilation(
    file_path: Path,
    max_functions: int = 200,
    decomp_limit: int = 4000,
    timeout_seconds: int = 900,
) -> Dict[str, Any]:
    """
    Run Ghidra headless analysis and export decompilation JSON.
    """
    headless_path = _resolve_headless_path()
    if not headless_path:
        return {"error": "Ghidra headless not configured. Set GHIDRA_HOME or GHIDRA_HEADLESS_PATH."}

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
    ]
    if headless_path.suffix.lower() == ".bat" and os.name == "nt":
        cmd = ["cmd", "/c"] + cmd

    # Set up environment for headless Java
    env = os.environ.copy()
    env["JAVA_TOOL_OPTIONS"] = "-Djava.awt.headless=true"

    try:
        logger.info("Running Ghidra headless analysis")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=env,
        )
        if result.returncode != 0:
            return {
                "error": "Ghidra analysis failed",
                "stderr": (result.stderr or "")[:4000],
                "stdout": (result.stdout or "")[:4000],
            }

        if not output_path.exists():
            return {"error": "Ghidra analysis completed but no output was produced"}

        data = output_path.read_text(encoding="utf-8", errors="ignore")
        return {"data": data}
    except subprocess.TimeoutExpired:
        return {"error": f"Ghidra analysis timed out after {timeout_seconds} seconds"}
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
