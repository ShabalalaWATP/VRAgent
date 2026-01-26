"""
Android Device Service

ADB communication layer for Android device management, FRIDA server control,
and file operations. Provides async interface for all ADB operations.
"""

import asyncio
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums and Constants
# =============================================================================

class DeviceState(str, Enum):
    """Android device connection states."""
    DEVICE = "device"
    OFFLINE = "offline"
    UNAUTHORIZED = "unauthorized"
    BOOTLOADER = "bootloader"
    RECOVERY = "recovery"
    SIDELOAD = "sideload"
    UNKNOWN = "unknown"


class DeviceABI(str, Enum):
    """Android device ABIs (architectures)."""
    ARM64_V8A = "arm64-v8a"
    ARMEABI_V7A = "armeabi-v7a"
    X86_64 = "x86_64"
    X86 = "x86"
    UNKNOWN = "unknown"


# FRIDA server download URLs by architecture
FRIDA_SERVER_URLS = {
    "arm64": "https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-arm64.xz",
    "arm": "https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-arm.xz",
    "x86_64": "https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-x86_64.xz",
    "x86": "https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-x86.xz",
}

# Map ABI to FRIDA architecture
ABI_TO_FRIDA_ARCH = {
    DeviceABI.ARM64_V8A: "arm64",
    DeviceABI.ARMEABI_V7A: "arm",
    DeviceABI.X86_64: "x86_64",
    DeviceABI.X86: "x86",
}


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class AndroidDevice:
    """Information about a connected Android device."""
    serial: str
    state: DeviceState
    model: str = ""
    manufacturer: str = ""
    android_version: str = ""
    sdk_version: int = 0
    abi: DeviceABI = DeviceABI.UNKNOWN
    supported_abis: List[str] = field(default_factory=list)
    is_emulator: bool = False
    is_rooted: bool = False
    frida_server_running: bool = False
    screen_resolution: str = ""
    battery_level: int = -1
    device_name: str = ""
    build_id: str = ""


@dataclass
class ADBConfig:
    """Configuration for ADB operations."""
    adb_path: str = "adb"
    timeout_ms: int = 30000
    auto_root: bool = False
    install_frida: bool = True
    frida_server_path: Optional[str] = None
    frida_server_port: int = 27042
    max_retries: int = 3
    retry_delay_ms: int = 1000


@dataclass
class ShellResult:
    """Result of a shell command execution."""
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    command: str = ""


@dataclass
class PackageInfo:
    """Information about an installed Android package."""
    package_name: str
    version_name: str = ""
    version_code: int = 0
    target_sdk: int = 0
    min_sdk: int = 0
    install_path: str = ""
    data_dir: str = ""
    native_libraries: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    is_system: bool = False
    is_debuggable: bool = False


@dataclass
class ProcessInfo:
    """Information about a running Android process."""
    pid: int
    user: str
    package: str
    process_name: str
    ppid: int = 0
    state: str = ""
    memory_kb: int = 0


# =============================================================================
# Android Device Service
# =============================================================================

class AndroidDeviceService:
    """ADB communication and device management service."""

    def __init__(self, config: Optional[ADBConfig] = None):
        self.config = config or ADBConfig()
        self._adb_path = self._find_adb()
        self._device_cache: Dict[str, AndroidDevice] = {}

    def _find_adb(self) -> str:
        """Find ADB executable path."""
        # Check configured path first
        if self.config.adb_path and shutil.which(self.config.adb_path):
            return self.config.adb_path

        # Check common locations
        common_paths = [
            "adb",
            os.path.expanduser("~/Android/Sdk/platform-tools/adb"),
            os.path.expandvars("%LOCALAPPDATA%/Android/Sdk/platform-tools/adb.exe"),
            "/usr/local/bin/adb",
            "/usr/bin/adb",
        ]

        for path in common_paths:
            resolved = shutil.which(path)
            if resolved:
                return resolved

        logger.warning("ADB not found in PATH or common locations")
        return "adb"  # Default, will fail if not available

    async def _run_adb(
        self,
        args: List[str],
        serial: Optional[str] = None,
        timeout_ms: Optional[int] = None
    ) -> ShellResult:
        """Run an ADB command."""
        cmd = [self._adb_path]

        if serial:
            cmd.extend(["-s", serial])

        cmd.extend(args)

        timeout = (timeout_ms or self.config.timeout_ms) / 1000.0
        start_time = time.time()

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return ShellResult(
                    stdout="",
                    stderr="Command timed out",
                    exit_code=-1,
                    duration_ms=(time.time() - start_time) * 1000,
                    command=" ".join(cmd),
                )

            duration_ms = (time.time() - start_time) * 1000

            return ShellResult(
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                exit_code=process.returncode or 0,
                duration_ms=duration_ms,
                command=" ".join(cmd),
            )

        except FileNotFoundError:
            return ShellResult(
                stdout="",
                stderr=f"ADB not found at {self._adb_path}",
                exit_code=-1,
                duration_ms=0,
                command=" ".join(cmd),
            )
        except Exception as e:
            return ShellResult(
                stdout="",
                stderr=str(e),
                exit_code=-1,
                duration_ms=(time.time() - start_time) * 1000,
                command=" ".join(cmd),
            )

    # =========================================================================
    # Device Management
    # =========================================================================

    async def list_devices(self) -> List[AndroidDevice]:
        """List all connected Android devices."""
        result = await self._run_adb(["devices", "-l"])

        if result.exit_code != 0:
            logger.error(f"Failed to list devices: {result.stderr}")
            return []

        devices = []
        lines = result.stdout.strip().split("\n")[1:]  # Skip header

        for line in lines:
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            serial = parts[0]
            state_str = parts[1]

            try:
                state = DeviceState(state_str)
            except ValueError:
                state = DeviceState.UNKNOWN

            device = AndroidDevice(serial=serial, state=state)

            # Parse additional info from -l output
            for part in parts[2:]:
                if ":" in part:
                    key, value = part.split(":", 1)
                    if key == "model":
                        device.model = value
                    elif key == "device":
                        device.device_name = value

            # Get full device info if connected
            if state == DeviceState.DEVICE:
                device = await self.get_device(serial)

            devices.append(device)

        return devices

    async def get_device(self, serial: str) -> AndroidDevice:
        """Get detailed information about a device."""
        # Check cache
        if serial in self._device_cache:
            cached = self._device_cache[serial]
            # Refresh if stale (older than 60 seconds)
            # For now, always refresh
            pass

        device = AndroidDevice(serial=serial, state=DeviceState.DEVICE)

        # Get device properties in parallel
        props_to_fetch = [
            ("ro.product.model", "model"),
            ("ro.product.manufacturer", "manufacturer"),
            ("ro.build.version.release", "android_version"),
            ("ro.build.version.sdk", "sdk_version"),
            ("ro.product.cpu.abi", "abi"),
            ("ro.product.cpu.abilist", "supported_abis"),
            ("ro.build.id", "build_id"),
            ("ro.hardware", "hardware"),
        ]

        tasks = [self.get_prop(serial, prop) for prop, _ in props_to_fetch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for (prop, attr), result in zip(props_to_fetch, results):
            if isinstance(result, Exception) or not result:
                continue

            if attr == "sdk_version":
                try:
                    device.sdk_version = int(result)
                except ValueError:
                    pass
            elif attr == "abi":
                try:
                    device.abi = DeviceABI(result)
                except ValueError:
                    device.abi = DeviceABI.UNKNOWN
            elif attr == "supported_abis":
                device.supported_abis = result.split(",")
            else:
                setattr(device, attr, result)

        # Check if emulator
        device.is_emulator = (
            serial.startswith("emulator-") or
            "goldfish" in (await self.get_prop(serial, "ro.hardware") or "") or
            "ranchu" in (await self.get_prop(serial, "ro.hardware") or "")
        )

        # Check if rooted
        device.is_rooted = await self._check_root(serial)

        # Check FRIDA server
        device.frida_server_running = await self.check_frida_server(serial)

        # Get screen resolution
        wm_result = await self.shell(serial, "wm size")
        if wm_result.exit_code == 0:
            match = re.search(r"(\d+x\d+)", wm_result.stdout)
            if match:
                device.screen_resolution = match.group(1)

        # Get battery level
        battery_result = await self.shell(serial, "dumpsys battery | grep level")
        if battery_result.exit_code == 0:
            match = re.search(r"level:\s*(\d+)", battery_result.stdout)
            if match:
                device.battery_level = int(match.group(1))

        self._device_cache[serial] = device
        return device

    async def wait_for_device(
        self,
        serial: str,
        timeout_ms: int = 60000,
        state: DeviceState = DeviceState.DEVICE
    ) -> bool:
        """Wait for a device to reach a specific state."""
        start_time = time.time()
        timeout_sec = timeout_ms / 1000.0

        while (time.time() - start_time) < timeout_sec:
            devices = await self.list_devices()
            for device in devices:
                if device.serial == serial and device.state == state:
                    return True
            await asyncio.sleep(1)

        return False

    async def _check_root(self, serial: str) -> bool:
        """Check if device is rooted."""
        # Try su
        result = await self.shell(serial, "su -c 'id'")
        if result.exit_code == 0 and "uid=0" in result.stdout:
            return True

        # Check for common root indicators
        for path in ["/system/xbin/su", "/system/bin/su", "/sbin/su", "/data/local/xbin/su"]:
            result = await self.shell(serial, f"ls {path}")
            if result.exit_code == 0:
                return True

        # Check Magisk
        result = await self.shell(serial, "magisk -v")
        if result.exit_code == 0:
            return True

        return False

    # =========================================================================
    # Shell Commands
    # =========================================================================

    async def shell(self, serial: str, command: str) -> ShellResult:
        """Execute a shell command on the device."""
        return await self._run_adb(["shell", command], serial=serial)

    async def shell_root(self, serial: str, command: str) -> ShellResult:
        """Execute a shell command as root."""
        # Try su first
        result = await self.shell(serial, f"su -c '{command}'")
        if result.exit_code == 0:
            return result

        # Try with Magisk su
        result = await self.shell(serial, f"su 0 {command}")
        if result.exit_code == 0:
            return result

        # Fall back to regular shell
        logger.warning(f"Root execution failed, falling back to regular shell")
        return await self.shell(serial, command)

    # =========================================================================
    # File Transfer
    # =========================================================================

    async def push(self, serial: str, local_path: str, remote_path: str) -> bool:
        """Push a file to the device."""
        result = await self._run_adb(["push", local_path, remote_path], serial=serial)
        if result.exit_code != 0:
            logger.error(f"Push failed: {result.stderr}")
            return False
        return True

    async def pull(self, serial: str, remote_path: str, local_path: str) -> bool:
        """Pull a file from the device."""
        result = await self._run_adb(["pull", remote_path, local_path], serial=serial)
        if result.exit_code != 0:
            logger.error(f"Pull failed: {result.stderr}")
            return False
        return True

    async def file_exists(self, serial: str, remote_path: str) -> bool:
        """Check if a file exists on the device."""
        result = await self.shell(serial, f"[ -f '{remote_path}' ] && echo 'exists'")
        return "exists" in result.stdout

    async def mkdir(self, serial: str, remote_path: str) -> bool:
        """Create a directory on the device."""
        result = await self.shell(serial, f"mkdir -p '{remote_path}'")
        return result.exit_code == 0

    async def rm(self, serial: str, remote_path: str, recursive: bool = False) -> bool:
        """Remove a file or directory."""
        cmd = f"rm {'-rf' if recursive else '-f'} '{remote_path}'"
        result = await self.shell(serial, cmd)
        return result.exit_code == 0

    async def chmod(self, serial: str, remote_path: str, mode: str) -> bool:
        """Change file permissions."""
        result = await self.shell(serial, f"chmod {mode} '{remote_path}'")
        return result.exit_code == 0

    # =========================================================================
    # App Management
    # =========================================================================

    async def install_apk(
        self,
        serial: str,
        apk_path: str,
        reinstall: bool = False,
        grant_permissions: bool = True
    ) -> bool:
        """Install an APK on the device."""
        args = ["install"]
        if reinstall:
            args.append("-r")
        if grant_permissions:
            args.append("-g")
        args.append(apk_path)

        result = await self._run_adb(args, serial=serial, timeout_ms=120000)
        if result.exit_code != 0 or "Failure" in result.stdout:
            logger.error(f"Install failed: {result.stdout} {result.stderr}")
            return False
        return True

    async def uninstall_package(self, serial: str, package: str, keep_data: bool = False) -> bool:
        """Uninstall a package."""
        args = ["uninstall"]
        if keep_data:
            args.append("-k")
        args.append(package)

        result = await self._run_adb(args, serial=serial)
        return result.exit_code == 0

    async def list_packages(
        self,
        serial: str,
        include_system: bool = False,
        include_disabled: bool = False
    ) -> List[str]:
        """List installed packages."""
        cmd = "pm list packages"
        if not include_system:
            cmd += " -3"  # Third-party only
        if include_disabled:
            cmd += " -d"

        result = await self.shell(serial, cmd)
        if result.exit_code != 0:
            return []

        packages = []
        for line in result.stdout.strip().split("\n"):
            if line.startswith("package:"):
                packages.append(line[8:])

        return packages

    async def get_package_info(self, serial: str, package: str) -> Optional[PackageInfo]:
        """Get detailed package information."""
        result = await self.shell(serial, f"dumpsys package {package}")
        if result.exit_code != 0 or "Unable to find package" in result.stdout:
            return None

        info = PackageInfo(package_name=package)

        # Parse version info
        version_match = re.search(r"versionName=(\S+)", result.stdout)
        if version_match:
            info.version_name = version_match.group(1)

        version_code_match = re.search(r"versionCode=(\d+)", result.stdout)
        if version_code_match:
            info.version_code = int(version_code_match.group(1))

        # Parse SDK info
        target_sdk_match = re.search(r"targetSdk=(\d+)", result.stdout)
        if target_sdk_match:
            info.target_sdk = int(target_sdk_match.group(1))

        min_sdk_match = re.search(r"minSdk=(\d+)", result.stdout)
        if min_sdk_match:
            info.min_sdk = int(min_sdk_match.group(1))

        # Get APK path
        path_match = re.search(r"codePath=(\S+)", result.stdout)
        if path_match:
            info.install_path = path_match.group(1)

        # Get data dir
        data_match = re.search(r"dataDir=(\S+)", result.stdout)
        if data_match:
            info.data_dir = data_match.group(1)

        # Check if debuggable
        info.is_debuggable = "FLAG_DEBUGGABLE" in result.stdout

        # Check if system app
        info.is_system = "/system/" in info.install_path

        # Get native libraries
        info.native_libraries = await self._get_native_libraries(serial, package)

        return info

    async def _get_native_libraries(self, serial: str, package: str) -> List[str]:
        """Get list of native libraries for a package."""
        # Get the app's lib directory
        result = await self.shell(serial, f"pm path {package}")
        if result.exit_code != 0:
            return []

        apk_path = ""
        for line in result.stdout.strip().split("\n"):
            if line.startswith("package:"):
                apk_path = line[8:]
                break

        if not apk_path:
            return []

        # Check lib directories
        lib_paths = [
            f"/data/app/{package}*/lib/*",
            f"/data/data/{package}/lib",
        ]

        libraries = []
        for lib_path in lib_paths:
            result = await self.shell(serial, f"find {lib_path} -name '*.so' 2>/dev/null")
            if result.exit_code == 0:
                for line in result.stdout.strip().split("\n"):
                    if line.endswith(".so"):
                        libraries.append(line)

        return libraries

    async def start_app(self, serial: str, package: str, activity: Optional[str] = None) -> bool:
        """Start an application."""
        if activity:
            cmd = f"am start -n {package}/{activity}"
        else:
            cmd = f"monkey -p {package} -c android.intent.category.LAUNCHER 1"

        result = await self.shell(serial, cmd)
        return result.exit_code == 0

    async def stop_app(self, serial: str, package: str) -> bool:
        """Force stop an application."""
        result = await self.shell(serial, f"am force-stop {package}")
        return result.exit_code == 0

    async def clear_app_data(self, serial: str, package: str) -> bool:
        """Clear application data."""
        result = await self.shell(serial, f"pm clear {package}")
        return "Success" in result.stdout

    # =========================================================================
    # Process Management
    # =========================================================================

    async def list_processes(self, serial: str, package_filter: Optional[str] = None) -> List[ProcessInfo]:
        """List running processes."""
        result = await self.shell(serial, "ps -A -o PID,USER,PPID,NAME")
        if result.exit_code != 0:
            # Try older ps format
            result = await self.shell(serial, "ps")

        if result.exit_code != 0:
            return []

        processes = []
        lines = result.stdout.strip().split("\n")[1:]  # Skip header

        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue

            try:
                proc = ProcessInfo(
                    pid=int(parts[0]),
                    user=parts[1],
                    ppid=int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                    process_name=parts[-1],
                    package=parts[-1].split(":")[0],
                )

                if package_filter and package_filter not in proc.package:
                    continue

                processes.append(proc)
            except (ValueError, IndexError):
                continue

        return processes

    async def get_pid(self, serial: str, package: str) -> Optional[int]:
        """Get PID of a running package."""
        result = await self.shell(serial, f"pidof {package}")
        if result.exit_code == 0 and result.stdout.strip():
            try:
                return int(result.stdout.strip().split()[0])
            except ValueError:
                pass
        return None

    async def kill_process(self, serial: str, pid: int) -> bool:
        """Kill a process by PID."""
        result = await self.shell(serial, f"kill -9 {pid}")
        return result.exit_code == 0

    # =========================================================================
    # FRIDA Server Management
    # =========================================================================

    async def check_frida_server(self, serial: str) -> bool:
        """Check if FRIDA server is running."""
        result = await self.shell(serial, "ps -A | grep frida-server")
        return "frida-server" in result.stdout

    async def start_frida_server(self, serial: str, port: int = 27042) -> bool:
        """Start FRIDA server on the device."""
        # Check if already running
        if await self.check_frida_server(serial):
            logger.info("FRIDA server already running")
            return True

        # Check if frida-server exists on device
        frida_path = "/data/local/tmp/frida-server"
        if not await self.file_exists(serial, frida_path):
            logger.warning("FRIDA server not found on device, attempting to push")
            if not await self.push_frida_server(serial):
                return False

        # Start frida-server
        result = await self.shell_root(
            serial,
            f"nohup {frida_path} -l 0.0.0.0:{port} > /dev/null 2>&1 &"
        )

        # Wait a moment and verify
        await asyncio.sleep(1)
        return await self.check_frida_server(serial)

    async def stop_frida_server(self, serial: str) -> bool:
        """Stop FRIDA server."""
        result = await self.shell_root(serial, "pkill -9 frida-server")
        await asyncio.sleep(0.5)
        return not await self.check_frida_server(serial)

    async def push_frida_server(self, serial: str) -> bool:
        """Push FRIDA server to device."""
        device = await self.get_device(serial)

        if device.abi == DeviceABI.UNKNOWN:
            logger.error("Unknown device architecture")
            return False

        frida_arch = ABI_TO_FRIDA_ARCH.get(device.abi)
        if not frida_arch:
            logger.error(f"No FRIDA server for architecture: {device.abi}")
            return False

        # Check if we have a local frida-server binary
        local_frida = self.config.frida_server_path
        if not local_frida or not os.path.exists(local_frida):
            logger.error("FRIDA server binary not found. Please download from GitHub releases.")
            return False

        # Push to device
        remote_path = "/data/local/tmp/frida-server"
        if not await self.push(serial, local_frida, remote_path):
            return False

        # Make executable
        if not await self.chmod(serial, remote_path, "755"):
            return False

        logger.info(f"FRIDA server pushed to {remote_path}")
        return True

    # =========================================================================
    # Logcat
    # =========================================================================

    async def logcat(
        self,
        serial: str,
        filter_spec: str = "",
        clear_first: bool = False
    ) -> AsyncGenerator[str, None]:
        """Stream logcat output."""
        if clear_first:
            await self.clear_logcat(serial)

        cmd = [self._adb_path, "-s", serial, "logcat"]
        if filter_spec:
            cmd.extend(filter_spec.split())

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                yield line.decode("utf-8", errors="replace").rstrip()
        finally:
            process.kill()
            await process.wait()

    async def clear_logcat(self, serial: str) -> bool:
        """Clear logcat buffer."""
        result = await self._run_adb(["logcat", "-c"], serial=serial)
        return result.exit_code == 0

    async def get_logcat_dump(
        self,
        serial: str,
        filter_spec: str = "",
        max_lines: int = 1000
    ) -> str:
        """Get logcat dump (non-streaming)."""
        cmd = f"logcat -d {filter_spec}"
        result = await self.shell(serial, cmd)
        if result.exit_code != 0:
            return ""

        lines = result.stdout.strip().split("\n")
        if len(lines) > max_lines:
            lines = lines[-max_lines:]

        return "\n".join(lines)

    # =========================================================================
    # Device Properties
    # =========================================================================

    async def get_prop(self, serial: str, prop: str) -> Optional[str]:
        """Get a device property."""
        result = await self.shell(serial, f"getprop {prop}")
        if result.exit_code == 0:
            return result.stdout.strip()
        return None

    async def set_prop(self, serial: str, prop: str, value: str) -> bool:
        """Set a device property (requires root for some props)."""
        result = await self.shell_root(serial, f"setprop {prop} {value}")
        return result.exit_code == 0

    # =========================================================================
    # Screen & Input
    # =========================================================================

    async def screenshot(self, serial: str, local_path: str) -> bool:
        """Take a screenshot."""
        remote_path = "/data/local/tmp/screenshot.png"
        result = await self.shell(serial, f"screencap -p {remote_path}")
        if result.exit_code != 0:
            return False

        if not await self.pull(serial, remote_path, local_path):
            return False

        await self.rm(serial, remote_path)
        return True

    async def tap(self, serial: str, x: int, y: int) -> bool:
        """Tap at coordinates."""
        result = await self.shell(serial, f"input tap {x} {y}")
        return result.exit_code == 0

    async def swipe(
        self,
        serial: str,
        x1: int, y1: int,
        x2: int, y2: int,
        duration_ms: int = 300
    ) -> bool:
        """Swipe from one point to another."""
        result = await self.shell(serial, f"input swipe {x1} {y1} {x2} {y2} {duration_ms}")
        return result.exit_code == 0

    async def input_text(self, serial: str, text: str) -> bool:
        """Input text."""
        # Escape special characters
        escaped = text.replace(" ", "%s").replace("'", "\\'").replace('"', '\\"')
        result = await self.shell(serial, f"input text '{escaped}'")
        return result.exit_code == 0

    async def key_event(self, serial: str, keycode: int) -> bool:
        """Send a key event."""
        result = await self.shell(serial, f"input keyevent {keycode}")
        return result.exit_code == 0

    # =========================================================================
    # Port Forwarding
    # =========================================================================

    async def forward(self, serial: str, local_port: int, remote_port: int) -> bool:
        """Set up port forwarding."""
        result = await self._run_adb(
            ["forward", f"tcp:{local_port}", f"tcp:{remote_port}"],
            serial=serial
        )
        return result.exit_code == 0

    async def reverse(self, serial: str, remote_port: int, local_port: int) -> bool:
        """Set up reverse port forwarding."""
        result = await self._run_adb(
            ["reverse", f"tcp:{remote_port}", f"tcp:{local_port}"],
            serial=serial
        )
        return result.exit_code == 0

    async def forward_remove(self, serial: str, local_port: int) -> bool:
        """Remove port forwarding."""
        result = await self._run_adb(
            ["forward", "--remove", f"tcp:{local_port}"],
            serial=serial
        )
        return result.exit_code == 0

    async def forward_list(self, serial: str) -> List[Tuple[int, int]]:
        """List port forwardings."""
        result = await self._run_adb(["forward", "--list"], serial=serial)
        if result.exit_code != 0:
            return []

        forwards = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                try:
                    local = int(parts[1].replace("tcp:", ""))
                    remote = int(parts[2].replace("tcp:", ""))
                    forwards.append((local, remote))
                except ValueError:
                    continue

        return forwards


# =============================================================================
# Singleton Instance
# =============================================================================

_device_service: Optional[AndroidDeviceService] = None


def get_android_device_service(config: Optional[ADBConfig] = None) -> AndroidDeviceService:
    """Get or create the Android device service singleton."""
    global _device_service
    if _device_service is None:
        _device_service = AndroidDeviceService(config)
    return _device_service
