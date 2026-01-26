import asyncio
import hashlib
import os
import shlex
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.services.binary_fuzzer_service import find_afl_tool


def parse_afl_filename(name: str) -> Dict[str, str]:
    parts = name.split(",")
    meta: Dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        if not key:
            continue
        meta[key] = value
    return meta


def compute_sha256(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def build_afl_input_record(path: str, include_hash: bool = False) -> Dict[str, Any]:
    name = os.path.basename(path)
    meta = parse_afl_filename(name)
    try:
        stat = os.stat(path)
        size = stat.st_size
        timestamp = stat.st_mtime
    except FileNotFoundError:
        size = 0
        timestamp = None
    record: Dict[str, Any] = {
        "id": name,
        "path": path,
        "size": size,
        "timestamp": timestamp,
        "meta": meta,
    }
    if include_hash and os.path.isfile(path):
        try:
            record["sha256"] = compute_sha256(path)
        except Exception:
            record["sha256"] = None
    return record


def list_afl_inputs_with_metadata(
    dir_path: str,
    limit: int = 200,
    include_hash: bool = False,
    skip_names: Optional[set] = None,
) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    if not os.path.isdir(dir_path):
        return entries

    skip = skip_names or set()
    try:
        for entry in os.scandir(dir_path):
            if not entry.is_file():
                continue
            if entry.name in skip:
                continue
            record = build_afl_input_record(entry.path, include_hash=include_hash)
            entries.append(record)
            if limit and len(entries) >= limit:
                break
    except FileNotFoundError:
        return entries

    return entries


def resolve_afl_session_dirs(output_dir: str, session_id: str) -> Dict[str, str]:
    session_dir = os.path.join(output_dir, session_id)
    default_dir = os.path.join(session_dir, "default")
    return {
        "session_dir": session_dir,
        "queue_dir": os.path.join(default_dir, "queue"),
        "crashes_dir": os.path.join(default_dir, "crashes"),
        "hangs_dir": os.path.join(default_dir, "hangs"),
        "default_dir": default_dir,
    }


async def reproduce_afl_input(
    target_path: str,
    target_args: str,
    input_path: str,
    timeout_ms: int = 5000,
    env_vars: Optional[Dict[str, str]] = None,
    working_dir: Optional[str] = None,
) -> Dict[str, Any]:
    args_template = target_args or ""
    stdin_payload = None
    if "@@" in args_template:
        args_template = args_template.replace("@@", input_path)
    else:
        try:
            stdin_payload = Path(input_path).read_bytes()
        except Exception:
            stdin_payload = b""

    args = shlex.split(args_template, posix=os.name != "nt") if args_template else []
    cmd = [target_path] + args

    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)

    start_time = time.time()
    result: Dict[str, Any] = {
        "command": " ".join(cmd),
        "exit_code": None,
        "signal": None,
        "timed_out": False,
        "crashed": False,
        "duration_ms": 0,
        "stdout": None,
        "stderr": None,
    }

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_payload is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=working_dir,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(stdin_payload),
                timeout=max(0.1, timeout_ms / 1000.0),
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            stdout, stderr = b"", b"timeout"
            result["timed_out"] = True
        result["exit_code"] = proc.returncode
        if proc.returncode is not None and proc.returncode != 0:
            result["crashed"] = True
            if proc.returncode < 0:
                result["signal"] = -proc.returncode
        result["stdout"] = stdout.decode("utf-8", errors="replace")
        result["stderr"] = stderr.decode("utf-8", errors="replace")
    except FileNotFoundError:
        result["stderr"] = f"Target not found: {target_path}"
    except Exception as exc:
        result["stderr"] = str(exc)
    finally:
        result["duration_ms"] = round((time.time() - start_time) * 1000, 3)

    return result


async def run_afl_tmin(
    target_path: str,
    target_args: str,
    input_path: str,
    output_path: Optional[str] = None,
    timeout_ms: int = 5000,
    memory_limit_mb: int = 256,
    use_qemu: bool = True,
    env_vars: Optional[Dict[str, str]] = None,
    extra_afl_flags: Optional[List[str]] = None,
    max_total_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    tool = find_afl_tool("afl-tmin")
    if not tool:
        return {"success": False, "error": "afl-tmin not found in PATH"}
    if not os.path.isfile(input_path):
        return {"success": False, "error": f"Input not found: {input_path}"}

    if not output_path:
        minimized_dir = os.path.join(os.path.dirname(input_path), "minimized")
        os.makedirs(minimized_dir, exist_ok=True)
        output_path = os.path.join(minimized_dir, os.path.basename(input_path))
    else:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    args_template = target_args or ""
    args = shlex.split(args_template, posix=os.name != "nt") if args_template else []
    cmd = [
        tool,
        "-i",
        input_path,
        "-o",
        output_path,
        "-t",
        str(timeout_ms),
        "-m",
        str(memory_limit_mb),
    ]
    if use_qemu:
        cmd.append("-Q")
    if extra_afl_flags:
        cmd.extend(extra_afl_flags)
    cmd.append("--")
    cmd.extend([target_path] + args)

    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)

    start_time = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=max_total_seconds if max_total_seconds else None,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {
                "success": False,
                "error": "afl-tmin timed out",
                "output_path": output_path,
            }
    except Exception as exc:
        return {"success": False, "error": str(exc)}

    return {
        "success": proc.returncode == 0,
        "returncode": proc.returncode,
        "duration_sec": round(time.time() - start_time, 3),
        "output_path": output_path,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
    }


async def run_afl_cmin(
    target_path: str,
    target_args: str,
    input_dir: str,
    output_dir: str,
    timeout_ms: int = 5000,
    memory_limit_mb: int = 256,
    use_qemu: bool = True,
    env_vars: Optional[Dict[str, str]] = None,
    extra_afl_flags: Optional[List[str]] = None,
    max_total_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    tool = find_afl_tool("afl-cmin")
    if not tool:
        return {"success": False, "error": "afl-cmin not found in PATH"}
    if not os.path.isdir(input_dir):
        return {"success": False, "error": f"Input directory not found: {input_dir}"}

    os.makedirs(output_dir, exist_ok=True)

    args_template = target_args or ""
    args = shlex.split(args_template, posix=os.name != "nt") if args_template else []
    cmd = [
        tool,
        "-i",
        input_dir,
        "-o",
        output_dir,
        "-t",
        str(timeout_ms),
        "-m",
        str(memory_limit_mb),
    ]
    if use_qemu:
        cmd.append("-Q")
    if extra_afl_flags:
        cmd.extend(extra_afl_flags)
    cmd.append("--")
    cmd.extend([target_path] + args)

    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)

    start_time = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=max_total_seconds if max_total_seconds else None,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {
                "success": False,
                "error": "afl-cmin timed out",
                "output_dir": output_dir,
            }
    except Exception as exc:
        return {"success": False, "error": str(exc)}

    return {
        "success": proc.returncode == 0,
        "returncode": proc.returncode,
        "duration_sec": round(time.time() - start_time, 3),
        "output_dir": output_dir,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
    }
