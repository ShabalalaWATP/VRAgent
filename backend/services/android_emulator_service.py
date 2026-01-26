"""
Android Emulator Service

Manages Android emulators (AVDs) for fuzzing:
1. AVD creation and configuration
2. Emulator lifecycle management (start/stop/restart)
3. Snapshot management for fast state restore
4. Parallel emulator pools for distributed fuzzing
5. System modifications (root, SELinux, FRIDA)
"""

import asyncio
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class EmulatorState(Enum):
    """Emulator state."""
    STOPPED = "stopped"
    BOOTING = "booting"
    RUNNING = "running"
    ERROR = "error"


class GPUMode(Enum):
    """GPU acceleration mode."""
    AUTO = "auto"
    HOST = "host"
    GUEST = "guest"
    SWIFTSHADER = "swiftshader_indirect"
    OFF = "off"


class SystemImageType(Enum):
    """Type of Android system image."""
    DEFAULT = "default"
    GOOGLE_APIS = "google_apis"
    GOOGLE_APIS_PLAYSTORE = "google_apis_playstore"
    ANDROID_TV = "android-tv"
    ANDROID_WEAR = "android-wear"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class AVDConfig:
    """Configuration for creating an AVD."""
    name: str
    api_level: int = 33                     # Android 13
    target: str = "google_apis"             # google_apis, default, etc.
    abi: str = "x86_64"                     # x86_64, x86, arm64-v8a
    device: str = "pixel_6"                 # Device profile

    # Hardware
    ram_mb: int = 4096
    heap_mb: int = 512
    disk_mb: int = 8192
    cores: int = 4

    # Display
    skin: str = "pixel_6"
    screen_width: int = 1080
    screen_height: int = 2400
    screen_density: int = 440

    # GPU
    gpu_mode: GPUMode = GPUMode.AUTO

    # Networking
    network_speed: str = "full"             # full, lte, hsdpa, etc.
    network_delay: str = "none"             # none, gprs, edge, etc.

    # Options
    no_window: bool = True                  # Headless mode
    no_audio: bool = True
    no_boot_anim: bool = True
    writable_system: bool = True            # For rooting

    # Extra properties
    extra_properties: Dict[str, str] = field(default_factory=dict)


@dataclass
class EmulatorInstance:
    """Represents a running emulator instance."""
    name: str                               # AVD name
    serial: str                             # e.g., emulator-5554
    pid: int
    state: EmulatorState
    port: int                               # Console port (5554)
    adb_port: int                           # ADB port (5555)
    grpc_port: int = 0                      # gRPC port for advanced control
    snapshot: Optional[str] = None          # Current snapshot name
    started_at: Optional[datetime] = None
    boot_completed: bool = False
    is_rooted: bool = False
    has_frida: bool = False


@dataclass
class SnapshotInfo:
    """Information about an emulator snapshot."""
    name: str
    avd_name: str
    created_at: Optional[datetime] = None
    size_mb: int = 0
    description: str = ""
    is_valid: bool = True


@dataclass
class SystemImageInfo:
    """Information about an installed system image."""
    api_level: int
    target: str                             # google_apis, default
    abi: str                                # x86_64, arm64-v8a
    revision: int
    path: str
    display_name: str = ""


# ============================================================================
# Android Emulator Service
# ============================================================================

class AndroidEmulatorService:
    """
    Android emulator (AVD) management service.

    Provides:
    - AVD creation and configuration
    - Emulator lifecycle management
    - Snapshot management for fast fuzzing resets
    - System modifications for security testing
    - Parallel emulator pools
    """

    def __init__(self):
        self.device_service = None  # Injected
        self._running_emulators: Dict[str, EmulatorInstance] = {}
        self._emulator_processes: Dict[str, asyncio.subprocess.Process] = {}

        # Detect SDK paths
        self.android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT", "")
        self.avd_home = os.environ.get("ANDROID_AVD_HOME") or os.path.expanduser("~/.android/avd")

        # Tool paths
        self.emulator_path = self._find_tool("emulator")
        self.avdmanager_path = self._find_tool("avdmanager")
        self.sdkmanager_path = self._find_tool("sdkmanager")
        self.adb_path = self._find_tool("adb")

    def _find_tool(self, tool_name: str) -> str:
        """Find an Android SDK tool."""
        if not self.android_home:
            # Try common locations
            possible_homes = [
                os.path.expanduser("~/Android/Sdk"),
                os.path.expanduser("~/Library/Android/sdk"),
                "C:\\Users\\%USERNAME%\\AppData\\Local\\Android\\Sdk",
                "/opt/android-sdk",
            ]
            for home in possible_homes:
                expanded = os.path.expandvars(home)
                if os.path.exists(expanded):
                    self.android_home = expanded
                    break

        if not self.android_home:
            return tool_name  # Hope it's in PATH

        # Check various locations
        tool_locations = [
            f"emulator/{tool_name}",
            f"cmdline-tools/latest/bin/{tool_name}",
            f"tools/{tool_name}",
            f"tools/bin/{tool_name}",
            f"platform-tools/{tool_name}",
        ]

        for loc in tool_locations:
            full_path = os.path.join(self.android_home, loc)
            if os.path.exists(full_path):
                return full_path
            # Windows .exe
            if os.path.exists(full_path + ".exe"):
                return full_path + ".exe"
            # Windows .bat
            if os.path.exists(full_path + ".bat"):
                return full_path + ".bat"

        return tool_name  # Fallback to PATH

    def set_device_service(self, device_service):
        """Inject the device service dependency."""
        self.device_service = device_service

    # ========================================================================
    # System Image Management
    # ========================================================================

    async def list_system_images(self) -> List[SystemImageInfo]:
        """List installed system images."""
        images = []

        # Run sdkmanager to list installed packages
        proc = await asyncio.create_subprocess_exec(
            self.sdkmanager_path, "--list",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()

        output = stdout.decode('utf-8', errors='ignore')

        # Parse system-images entries
        # Format: system-images;android-33;google_apis;x86_64
        pattern = r'system-images;android-(\d+);([^;]+);([^\s|]+)'

        for match in re.finditer(pattern, output):
            api_level = int(match.group(1))
            target = match.group(2)
            abi = match.group(3)

            images.append(SystemImageInfo(
                api_level=api_level,
                target=target,
                abi=abi,
                revision=0,
                path=f"system-images/android-{api_level}/{target}/{abi}",
                display_name=f"Android {api_level} ({target}, {abi})"
            ))

        return images

    async def install_system_image(
        self,
        api_level: int,
        target: str = "google_apis",
        abi: str = "x86_64"
    ) -> bool:
        """Install a system image."""
        package = f"system-images;android-{api_level};{target};{abi}"

        logger.info(f"Installing system image: {package}")

        proc = await asyncio.create_subprocess_exec(
            self.sdkmanager_path, "--install", package,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Accept license if prompted
        stdout, stderr = await proc.communicate(input=b"y\n")

        if proc.returncode != 0:
            logger.error(f"Failed to install system image: {stderr.decode()}")
            return False

        logger.info(f"System image installed: {package}")
        return True

    # ========================================================================
    # AVD Management
    # ========================================================================

    async def list_avds(self) -> List[str]:
        """List available AVDs."""
        proc = await asyncio.create_subprocess_exec(
            self.emulator_path, "-list-avds",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()

        avds = []
        for line in stdout.decode('utf-8', errors='ignore').strip().split('\n'):
            line = line.strip()
            if line and not line.startswith("INFO"):
                avds.append(line)

        return avds

    async def get_avd_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about an AVD."""
        avd_path = os.path.join(self.avd_home, f"{name}.avd")
        ini_path = os.path.join(self.avd_home, f"{name}.ini")
        config_path = os.path.join(avd_path, "config.ini")

        if not os.path.exists(ini_path):
            return None

        info = {"name": name, "path": avd_path}

        # Parse main .ini file
        if os.path.exists(ini_path):
            with open(ini_path, 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        info[key.strip()] = value.strip()

        # Parse config.ini for hardware details
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        info[key.strip()] = value.strip()

        return info

    async def create_avd(self, config: AVDConfig) -> bool:
        """Create a new AVD with the specified configuration."""
        # Build system image path
        system_image = f"system-images;android-{config.api_level};{config.target};{config.abi}"

        # Check if system image exists
        images = await self.list_system_images()
        image_exists = any(
            img.api_level == config.api_level and
            img.target == config.target and
            img.abi == config.abi
            for img in images
        )

        if not image_exists:
            logger.info(f"System image not found, installing: {system_image}")
            success = await self.install_system_image(
                config.api_level,
                config.target,
                config.abi
            )
            if not success:
                return False

        # Delete existing AVD if present
        existing_avds = await self.list_avds()
        if config.name in existing_avds:
            logger.info(f"Deleting existing AVD: {config.name}")
            await self.delete_avd(config.name)

        # Create AVD using avdmanager
        cmd = [
            self.avdmanager_path, "create", "avd",
            "--name", config.name,
            "--package", system_image,
            "--device", config.device,
            "--force"
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Provide 'no' for custom hardware profile
        stdout, stderr = await proc.communicate(input=b"no\n")

        if proc.returncode != 0:
            logger.error(f"Failed to create AVD: {stderr.decode()}")
            return False

        # Configure hardware properties
        config_path = os.path.join(self.avd_home, f"{config.name}.avd", "config.ini")

        if os.path.exists(config_path):
            # Read existing config
            with open(config_path, 'r') as f:
                config_content = f.read()

            # Add/update properties
            properties = {
                "hw.ramSize": str(config.ram_mb),
                "vm.heapSize": str(config.heap_mb),
                "disk.dataPartition.size": f"{config.disk_mb}M",
                "hw.cpu.ncore": str(config.cores),
                "hw.lcd.width": str(config.screen_width),
                "hw.lcd.height": str(config.screen_height),
                "hw.lcd.density": str(config.screen_density),
                "hw.gpu.enabled": "yes",
                "hw.gpu.mode": config.gpu_mode.value,
                "hw.keyboard": "yes",
                "hw.mainKeys": "no",
                "fastboot.forceColdBoot": "no",
                "showDeviceFrame": "no" if config.no_window else "yes",
            }

            # Add extra properties
            properties.update(config.extra_properties)

            # Update config file
            lines = config_content.split('\n')
            existing_keys = set()
            new_lines = []

            for line in lines:
                if '=' in line:
                    key = line.split('=')[0].strip()
                    existing_keys.add(key)
                    if key in properties:
                        new_lines.append(f"{key}={properties[key]}")
                        continue
                new_lines.append(line)

            # Add new properties
            for key, value in properties.items():
                if key not in existing_keys:
                    new_lines.append(f"{key}={value}")

            with open(config_path, 'w') as f:
                f.write('\n'.join(new_lines))

        logger.info(f"AVD created: {config.name}")
        return True

    async def delete_avd(self, name: str) -> bool:
        """Delete an AVD."""
        proc = await asyncio.create_subprocess_exec(
            self.avdmanager_path, "delete", "avd", "--name", name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()

        return proc.returncode == 0

    # ========================================================================
    # Emulator Lifecycle
    # ========================================================================

    async def start_emulator(
        self,
        avd_name: str,
        headless: bool = True,
        port: Optional[int] = None,
        snapshot: Optional[str] = None,
        writable_system: bool = True,
        extra_args: Optional[List[str]] = None
    ) -> EmulatorInstance:
        """Start an emulator instance."""
        # Find available port if not specified
        if port is None:
            port = await self._find_available_port()

        adb_port = port + 1
        serial = f"emulator-{port}"

        # Build command
        cmd = [
            self.emulator_path,
            "-avd", avd_name,
            "-port", str(port),
        ]

        if headless:
            cmd.extend(["-no-window", "-no-audio"])

        cmd.append("-no-boot-anim")

        if writable_system:
            cmd.append("-writable-system")

        if snapshot:
            cmd.extend(["-snapshot", snapshot])

        # GPU acceleration
        cmd.extend(["-gpu", "swiftshader_indirect"])  # Safe default

        # Extra args
        if extra_args:
            cmd.extend(extra_args)

        logger.info(f"Starting emulator: {' '.join(cmd)}")

        # Start process
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        instance = EmulatorInstance(
            name=avd_name,
            serial=serial,
            pid=proc.pid,
            state=EmulatorState.BOOTING,
            port=port,
            adb_port=adb_port,
            snapshot=snapshot,
            started_at=datetime.now()
        )

        self._running_emulators[serial] = instance
        self._emulator_processes[serial] = proc

        return instance

    async def wait_for_boot(
        self,
        serial: str,
        timeout_sec: int = 180
    ) -> bool:
        """Wait for emulator to finish booting."""
        if not self.device_service:
            # Use direct ADB
            return await self._wait_for_boot_direct(serial, timeout_sec)

        start_time = time.time()

        while time.time() - start_time < timeout_sec:
            try:
                # Check if device is online
                result = await self.device_service.shell(serial, "getprop sys.boot_completed")

                if result.exit_code == 0 and "1" in result.stdout:
                    # Also check that package manager is ready
                    pm_result = await self.device_service.shell(serial, "pm path android")
                    if pm_result.exit_code == 0 and "package:" in pm_result.stdout:
                        if serial in self._running_emulators:
                            self._running_emulators[serial].state = EmulatorState.RUNNING
                            self._running_emulators[serial].boot_completed = True
                        logger.info(f"Emulator {serial} boot completed")
                        return True

            except Exception as e:
                logger.debug(f"Boot check error (expected during boot): {e}")

            await asyncio.sleep(2)

        logger.warning(f"Emulator {serial} boot timeout after {timeout_sec}s")
        return False

    async def _wait_for_boot_direct(
        self,
        serial: str,
        timeout_sec: int
    ) -> bool:
        """Wait for boot using direct ADB commands."""
        start_time = time.time()

        while time.time() - start_time < timeout_sec:
            proc = await asyncio.create_subprocess_exec(
                self.adb_path, "-s", serial, "shell", "getprop", "sys.boot_completed",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0 and "1" in stdout.decode():
                return True

            await asyncio.sleep(2)

        return False

    async def stop_emulator(self, serial: str) -> bool:
        """Stop an emulator instance."""
        instance = self._running_emulators.get(serial)

        if not instance:
            logger.warning(f"Emulator not found: {serial}")
            return False

        try:
            # Try graceful shutdown via ADB
            if self.device_service:
                await self.device_service.shell(serial, "reboot -p")
            else:
                proc = await asyncio.create_subprocess_exec(
                    self.adb_path, "-s", serial, "emu", "kill"
                )
                await proc.wait()

            # Wait for process to end
            process = self._emulator_processes.get(serial)
            if process:
                try:
                    await asyncio.wait_for(process.wait(), timeout=10)
                except asyncio.TimeoutError:
                    process.terminate()
                    await asyncio.sleep(1)
                    if process.returncode is None:
                        process.kill()

            instance.state = EmulatorState.STOPPED
            del self._running_emulators[serial]

            if serial in self._emulator_processes:
                del self._emulator_processes[serial]

            logger.info(f"Emulator stopped: {serial}")
            return True

        except Exception as e:
            logger.error(f"Error stopping emulator {serial}: {e}")
            return False

    async def restart_emulator(self, serial: str) -> bool:
        """Restart an emulator."""
        instance = self._running_emulators.get(serial)
        if not instance:
            return False

        avd_name = instance.name
        snapshot = instance.snapshot

        await self.stop_emulator(serial)
        await asyncio.sleep(2)

        new_instance = await self.start_emulator(
            avd_name,
            headless=True,
            snapshot=snapshot
        )

        return await self.wait_for_boot(new_instance.serial, timeout_sec=120)

    async def list_running_emulators(self) -> List[EmulatorInstance]:
        """List currently running emulators."""
        # Also check actual running state
        running = []

        for serial, instance in list(self._running_emulators.items()):
            process = self._emulator_processes.get(serial)

            if process and process.returncode is None:
                running.append(instance)
            else:
                # Process ended, update state
                instance.state = EmulatorState.STOPPED
                del self._running_emulators[serial]

        return running

    async def _find_available_port(self) -> int:
        """Find an available port for emulator."""
        # Emulators use even ports starting from 5554
        used_ports = {inst.port for inst in self._running_emulators.values()}

        for port in range(5554, 5600, 2):  # Step by 2
            if port not in used_ports:
                return port

        raise RuntimeError("No available emulator ports")

    # ========================================================================
    # Snapshot Management
    # ========================================================================

    async def save_snapshot(
        self,
        serial: str,
        name: str,
        description: str = ""
    ) -> bool:
        """Save emulator snapshot."""
        logger.info(f"Saving snapshot '{name}' for {serial}")

        # Use console command
        proc = await asyncio.create_subprocess_exec(
            self.adb_path, "-s", serial, "emu", "avd", "snapshot", "save", name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()

        if proc.returncode != 0:
            logger.error(f"Failed to save snapshot: {stderr.decode()}")
            return False

        logger.info(f"Snapshot saved: {name}")
        return True

    async def load_snapshot(
        self,
        serial: str,
        name: str
    ) -> bool:
        """Load emulator snapshot."""
        logger.info(f"Loading snapshot '{name}' for {serial}")

        proc = await asyncio.create_subprocess_exec(
            self.adb_path, "-s", serial, "emu", "avd", "snapshot", "load", name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()

        if proc.returncode != 0:
            logger.error(f"Failed to load snapshot: {stderr.decode()}")
            return False

        # Update instance
        if serial in self._running_emulators:
            self._running_emulators[serial].snapshot = name

        logger.info(f"Snapshot loaded: {name}")
        return True

    async def delete_snapshot(
        self,
        serial: str,
        name: str
    ) -> bool:
        """Delete a snapshot."""
        proc = await asyncio.create_subprocess_exec(
            self.adb_path, "-s", serial, "emu", "avd", "snapshot", "delete", name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()

        return proc.returncode == 0

    async def list_snapshots(self, avd_name: str) -> List[SnapshotInfo]:
        """List snapshots for an AVD."""
        snapshots = []

        # Snapshots are stored in AVD directory
        avd_path = os.path.join(self.avd_home, f"{avd_name}.avd")
        snapshots_path = os.path.join(avd_path, "snapshots")

        if not os.path.exists(snapshots_path):
            return []

        for entry in os.listdir(snapshots_path):
            snapshot_dir = os.path.join(snapshots_path, entry)
            if os.path.isdir(snapshot_dir):
                # Get snapshot metadata
                snapshot_pb = os.path.join(snapshot_dir, "snapshot.pb")
                size_mb = 0

                # Calculate total size
                for root, dirs, files in os.walk(snapshot_dir):
                    for file in files:
                        size_mb += os.path.getsize(os.path.join(root, file))
                size_mb = size_mb // (1024 * 1024)

                snapshots.append(SnapshotInfo(
                    name=entry,
                    avd_name=avd_name,
                    size_mb=size_mb,
                    is_valid=os.path.exists(snapshot_pb)
                ))

        return snapshots

    # ========================================================================
    # System Modifications
    # ========================================================================

    async def root_emulator(self, serial: str) -> bool:
        """Enable root access on emulator."""
        logger.info(f"Rooting emulator: {serial}")

        # Restart ADB as root
        proc = await asyncio.create_subprocess_exec(
            self.adb_path, "-s", serial, "root",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        output = stdout.decode() + stderr.decode()

        if "cannot run as root" in output.lower():
            logger.warning(f"Emulator {serial} doesn't support root (use userdebug image)")
            return False

        # Wait for device to reconnect
        await asyncio.sleep(2)

        # Verify root
        if self.device_service:
            result = await self.device_service.shell(serial, "whoami")
            is_root = result.exit_code == 0 and "root" in result.stdout
        else:
            proc = await asyncio.create_subprocess_exec(
                self.adb_path, "-s", serial, "shell", "whoami",
                stdout=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            is_root = "root" in stdout.decode()

        if serial in self._running_emulators:
            self._running_emulators[serial].is_rooted = is_root

        return is_root

    async def remount_system(self, serial: str) -> bool:
        """Remount /system as writable."""
        # Need root first
        await self.root_emulator(serial)

        proc = await asyncio.create_subprocess_exec(
            self.adb_path, "-s", serial, "remount",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        output = stdout.decode() + stderr.decode()
        success = "remount succeeded" in output.lower() or proc.returncode == 0

        logger.info(f"Remount system on {serial}: {'success' if success else 'failed'}")
        return success

    async def disable_selinux(self, serial: str) -> bool:
        """Disable SELinux (set to permissive)."""
        if self.device_service:
            result = await self.device_service.shell_root(serial, "setenforce 0")
            return result.exit_code == 0
        else:
            proc = await asyncio.create_subprocess_exec(
                self.adb_path, "-s", serial, "shell", "su", "-c", "setenforce 0",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            return proc.returncode == 0

    async def install_frida_server(self, serial: str) -> bool:
        """Install FRIDA server on emulator."""
        if self.device_service:
            # Use device service's method
            return await self.device_service.start_frida_server(serial)

        logger.warning("FRIDA server installation requires device_service")
        return False

    async def setup_fuzzing_environment(self, serial: str) -> Dict[str, bool]:
        """Set up emulator for fuzzing (root, FRIDA, SELinux)."""
        results = {}

        # Root the emulator
        results['root'] = await self.root_emulator(serial)

        if results['root']:
            # Remount system
            results['remount'] = await self.remount_system(serial)

            # Disable SELinux
            results['selinux_disabled'] = await self.disable_selinux(serial)

            # Install FRIDA
            results['frida'] = await self.install_frida_server(serial)

            if serial in self._running_emulators:
                self._running_emulators[serial].has_frida = results.get('frida', False)

        logger.info(f"Fuzzing environment setup for {serial}: {results}")
        return results

    # ========================================================================
    # Parallel Emulator Pool
    # ========================================================================

    async def start_emulator_pool(
        self,
        avd_name: str,
        count: int,
        setup_fuzzing: bool = True
    ) -> List[EmulatorInstance]:
        """Start multiple emulators in parallel."""
        logger.info(f"Starting emulator pool: {count} instances of {avd_name}")

        instances = []
        tasks = []

        for i in range(count):
            task = asyncio.create_task(
                self.start_emulator(
                    avd_name,
                    headless=True,
                    writable_system=True
                )
            )
            tasks.append(task)

        # Wait for all to start
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, EmulatorInstance):
                instances.append(result)
            else:
                logger.error(f"Failed to start emulator: {result}")

        # Wait for boot in parallel
        boot_tasks = []
        for instance in instances:
            task = asyncio.create_task(
                self.wait_for_boot(instance.serial, timeout_sec=180)
            )
            boot_tasks.append((instance, task))

        for instance, task in boot_tasks:
            try:
                booted = await task
                if not booted:
                    logger.warning(f"Emulator {instance.serial} failed to boot")
            except Exception as e:
                logger.error(f"Boot error for {instance.serial}: {e}")

        # Setup fuzzing environment if requested
        if setup_fuzzing:
            setup_tasks = []
            for instance in instances:
                if instance.boot_completed:
                    task = asyncio.create_task(
                        self.setup_fuzzing_environment(instance.serial)
                    )
                    setup_tasks.append(task)

            await asyncio.gather(*setup_tasks, return_exceptions=True)

        logger.info(f"Emulator pool ready: {len(instances)} instances")
        return instances

    async def stop_emulator_pool(
        self,
        instances: Optional[List[EmulatorInstance]] = None
    ) -> int:
        """Stop all or specified emulators."""
        if instances is None:
            instances = list(self._running_emulators.values())

        tasks = []
        for instance in instances:
            task = asyncio.create_task(self.stop_emulator(instance.serial))
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        stopped = sum(1 for r in results if r is True)

        logger.info(f"Stopped {stopped}/{len(instances)} emulators")
        return stopped

    async def restart_pool_with_snapshot(
        self,
        instances: List[EmulatorInstance],
        snapshot_name: str
    ) -> int:
        """Quickly restart all emulators to a snapshot."""
        tasks = []
        for instance in instances:
            task = asyncio.create_task(
                self.load_snapshot(instance.serial, snapshot_name)
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        restored = sum(1 for r in results if r is True)

        return restored


# ============================================================================
# Module-level instance
# ============================================================================

_emulator_service: Optional[AndroidEmulatorService] = None


def get_emulator_service() -> AndroidEmulatorService:
    """Get or create the emulator service singleton."""
    global _emulator_service
    if _emulator_service is None:
        _emulator_service = AndroidEmulatorService()
    return _emulator_service
