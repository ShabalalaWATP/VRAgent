"""
Android Fuzzer API Router

Provides REST and WebSocket endpoints for Android fuzzing:
- Device management
- Emulator management
- Native library fuzzing
- Intent/IPC fuzzing
- Campaign management
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect

from backend.core.auth import get_current_active_user
from backend.core.file_validator import sanitize_filename
from backend.models.models import User
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/android", tags=["Android Fuzzer"])


# ============================================================================
# Pydantic Models
# ============================================================================

# Device Models
class DeviceInfo(BaseModel):
    serial: str
    state: str
    model: str = ""
    manufacturer: str = ""
    android_version: str = ""
    sdk_version: int = 0
    abi: str = ""
    is_emulator: bool = False
    is_rooted: bool = False
    frida_server_running: bool = False


class ShellCommandRequest(BaseModel):
    command: str
    timeout_ms: int = 30000
    as_root: bool = False


class ShellCommandResponse(BaseModel):
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float


# Emulator Models
class AVDCreateRequest(BaseModel):
    name: str
    api_level: int = 33
    target: str = "google_apis"
    abi: str = "x86_64"
    device: str = "pixel_6"
    ram_mb: int = 4096
    disk_mb: int = 8192


class EmulatorStartRequest(BaseModel):
    avd_name: str
    headless: bool = True
    port: Optional[int] = None
    snapshot: Optional[str] = None
    writable_system: bool = True


class EmulatorInfo(BaseModel):
    name: str
    serial: str
    pid: int
    state: str
    port: int
    adb_port: int
    boot_completed: bool = False
    is_rooted: bool = False
    has_frida: bool = False


class SnapshotRequest(BaseModel):
    name: str
    description: str = ""


# Native Fuzzing Models
class NativeLibraryInfo(BaseModel):
    name: str
    path: str
    architecture: str
    size: int
    is_stripped: bool = True
    exports_count: int = 0
    dangerous_functions: List[str] = []
    jni_functions: List[str] = []


class NativeFuzzRequest(BaseModel):
    device_serial: str
    library_path: str
    target_function: Optional[str] = None
    fuzz_mode: str = "frida"  # frida, qemu
    input_size_max: int = 4096
    max_iterations: int = 10000
    max_crashes: int = 100
    timeout_ms: int = 5000
    track_coverage: bool = True


class NativeFuzzStatus(BaseModel):
    session_id: str
    library_name: str
    target_function: str
    status: str
    executions: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    coverage_edges: int = 0
    exec_per_sec: float = 0.0


# Intent Fuzzing Models
class ExportedComponentInfo(BaseModel):
    name: str
    component_type: str
    package_name: str
    exported: bool = True
    permissions: List[str] = []


class IntentFuzzRequest(BaseModel):
    device_serial: str
    package_name: str
    target_component: Optional[str] = None
    fuzz_activities: bool = True
    fuzz_services: bool = True
    fuzz_receivers: bool = True
    fuzz_providers: bool = True
    mutation_rate: float = 0.3
    max_iterations: int = 1000
    max_crashes: int = 50


class IntentFuzzStatus(BaseModel):
    session_id: str
    package_name: str
    status: str
    intents_sent: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    anrs: int = 0
    components_tested: int = 0


# Campaign Models
class CampaignCreateRequest(BaseModel):
    name: str
    target_type: str = "apk"  # apk, package, native_library
    target_path: str
    device_serial: Optional[str] = None
    use_emulator: bool = True
    emulator_avd: str = "fuzz_avd"
    fuzz_native_libraries: bool = True
    fuzz_activities: bool = True
    fuzz_services: bool = True
    fuzz_receivers: bool = True
    fuzz_providers: bool = True
    max_iterations: int = 10000
    max_crashes: int = 100
    timeout_hours: float = 24.0


class CampaignInfo(BaseModel):
    campaign_id: str
    name: str
    target_type: str
    target_path: str
    status: str
    current_phase: str = ""
    device_serial: Optional[str] = None
    error_message: Optional[str] = None


class CampaignStatsResponse(BaseModel):
    campaign_id: str
    name: str
    status: str
    current_phase: str
    device_serial: Optional[str]
    stats: Dict[str, Any]
    crashes_count: int
    error: Optional[str]


class CrashInfo(BaseModel):
    crash_id: str
    crash_type: str
    severity: str
    component: str
    source: str
    exception_or_signal: str
    is_exploitable: bool
    input_hash: str


# ============================================================================
# Device Endpoints
# ============================================================================

@router.get("/devices", response_model=List[DeviceInfo])
async def list_devices(current_user: User = Depends(get_current_active_user)):
    """List all connected Android devices."""
    from backend.services.android_device_service import get_device_service

    device_service = get_device_service()
    devices = await device_service.list_devices()

    return [
        DeviceInfo(
            serial=d.serial,
            state=d.state.value,
            model=d.model,
            manufacturer=d.manufacturer,
            android_version=d.android_version,
            sdk_version=d.sdk_version,
            abi=d.abi.value if hasattr(d.abi, 'value') else str(d.abi),
            is_emulator=d.is_emulator,
            is_rooted=d.is_rooted,
            frida_server_running=d.frida_server_running
        )
        for d in devices
    ]


@router.get("/devices/{serial}", response_model=DeviceInfo)
async def get_device(serial: str, current_user: User = Depends(get_current_active_user)):
    """Get information about a specific device."""
    from backend.services.android_device_service import get_device_service

    device_service = get_device_service()
    device = await device_service.get_device(serial)

    if not device:
        raise HTTPException(status_code=404, detail=f"Device not found: {serial}")

    return DeviceInfo(
        serial=device.serial,
        state=device.state.value,
        model=device.model,
        manufacturer=device.manufacturer,
        android_version=device.android_version,
        sdk_version=device.sdk_version,
        abi=device.abi.value if hasattr(device.abi, 'value') else str(device.abi),
        is_emulator=device.is_emulator,
        is_rooted=device.is_rooted,
        frida_server_running=device.frida_server_running
    )


@router.post("/devices/{serial}/shell", response_model=ShellCommandResponse)
async def execute_shell(serial: str, request: ShellCommandRequest, current_user: User = Depends(get_current_active_user)):
    """Execute a shell command on the device."""
    from backend.services.android_device_service import get_device_service

    device_service = get_device_service()

    if request.as_root:
        result = await device_service.shell_root(serial, request.command)
    else:
        result = await device_service.shell(serial, request.command)

    return ShellCommandResponse(
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms
    )


@router.post("/devices/{serial}/frida/start")
async def start_frida_server(serial: str, current_user: User = Depends(get_current_active_user)):
    """Start FRIDA server on the device."""
    from backend.services.android_device_service import get_device_service

    device_service = get_device_service()
    success = await device_service.start_frida_server(serial)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to start FRIDA server")

    return {"status": "started", "serial": serial}


@router.post("/devices/{serial}/frida/stop")
async def stop_frida_server(serial: str, current_user: User = Depends(get_current_active_user)):
    """Stop FRIDA server on the device."""
    from backend.services.android_device_service import get_device_service

    device_service = get_device_service()
    success = await device_service.stop_frida_server(serial)

    return {"status": "stopped" if success else "not_running", "serial": serial}


@router.get("/devices/{serial}/frida/status")
async def get_frida_status(serial: str, current_user: User = Depends(get_current_active_user)):
    """Check FRIDA server status on the device."""
    from backend.services.android_device_service import get_device_service

    device_service = get_device_service()
    running = await device_service.check_frida_server(serial)

    return {"running": running, "serial": serial}


# ============================================================================
# Emulator Endpoints
# ============================================================================

@router.get("/emulators", response_model=List[EmulatorInfo])
async def list_running_emulators(current_user: User = Depends(get_current_active_user)):
    """List running emulator instances."""
    from backend.services.android_emulator_service import get_emulator_service

    emulator_service = get_emulator_service()
    instances = await emulator_service.list_running_emulators()

    return [
        EmulatorInfo(
            name=i.name,
            serial=i.serial,
            pid=i.pid,
            state=i.state.value,
            port=i.port,
            adb_port=i.adb_port,
            boot_completed=i.boot_completed,
            is_rooted=i.is_rooted,
            has_frida=i.has_frida
        )
        for i in instances
    ]


@router.get("/avds", response_model=List[str])
async def list_avds(current_user: User = Depends(get_current_active_user)):
    """List available AVDs."""
    from backend.services.android_emulator_service import get_emulator_service

    emulator_service = get_emulator_service()
    return await emulator_service.list_avds()


@router.post("/avds", response_model=Dict[str, Any])
async def create_avd(request: AVDCreateRequest, current_user: User = Depends(get_current_active_user)):
    """Create a new AVD."""
    from backend.services.android_emulator_service import get_emulator_service, AVDConfig

    emulator_service = get_emulator_service()

    config = AVDConfig(
        name=request.name,
        api_level=request.api_level,
        target=request.target,
        abi=request.abi,
        device=request.device,
        ram_mb=request.ram_mb,
        disk_mb=request.disk_mb
    )

    success = await emulator_service.create_avd(config)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to create AVD")

    return {"status": "created", "name": request.name}


@router.delete("/avds/{name}")
async def delete_avd(name: str, current_user: User = Depends(get_current_active_user)):
    """Delete an AVD."""
    from backend.services.android_emulator_service import get_emulator_service

    emulator_service = get_emulator_service()
    success = await emulator_service.delete_avd(name)

    if not success:
        raise HTTPException(status_code=404, detail=f"AVD not found or delete failed: {name}")

    return {"status": "deleted", "name": name}


@router.post("/emulators/start", response_model=EmulatorInfo)
async def start_emulator(request: EmulatorStartRequest, current_user: User = Depends(get_current_active_user)):
    """Start an emulator instance."""
    from backend.services.android_emulator_service import get_emulator_service

    emulator_service = get_emulator_service()

    instance = await emulator_service.start_emulator(
        avd_name=request.avd_name,
        headless=request.headless,
        port=request.port,
        snapshot=request.snapshot,
        writable_system=request.writable_system
    )

    return EmulatorInfo(
        name=instance.name,
        serial=instance.serial,
        pid=instance.pid,
        state=instance.state.value,
        port=instance.port,
        adb_port=instance.adb_port,
        boot_completed=instance.boot_completed,
        is_rooted=instance.is_rooted,
        has_frida=instance.has_frida
    )


@router.post("/emulators/{serial}/stop")
async def stop_emulator(serial: str, current_user: User = Depends(get_current_active_user)):
    """Stop an emulator instance."""
    from backend.services.android_emulator_service import get_emulator_service

    emulator_service = get_emulator_service()
    success = await emulator_service.stop_emulator(serial)

    if not success:
        raise HTTPException(status_code=404, detail=f"Emulator not found: {serial}")

    return {"status": "stopped", "serial": serial}


@router.post("/emulators/{serial}/wait-for-boot")
async def wait_for_boot(serial: str, timeout_sec: int = 180, current_user: User = Depends(get_current_active_user)):
    """Wait for emulator to finish booting."""
    from backend.services.android_emulator_service import get_emulator_service

    emulator_service = get_emulator_service()
    booted = await emulator_service.wait_for_boot(serial, timeout_sec)

    return {"booted": booted, "serial": serial}


@router.post("/emulators/{serial}/snapshot/save")
async def save_snapshot(serial: str, request: SnapshotRequest, current_user: User = Depends(get_current_active_user)):
    """Save emulator snapshot."""
    from backend.services.android_emulator_service import get_emulator_service

    emulator_service = get_emulator_service()
    success = await emulator_service.save_snapshot(
        serial,
        request.name,
        request.description
    )

    if not success:
        raise HTTPException(status_code=500, detail="Failed to save snapshot")

    return {"status": "saved", "name": request.name}


@router.post("/emulators/{serial}/snapshot/load")
async def load_snapshot(serial: str, name: str, current_user: User = Depends(get_current_active_user)):
    """Load emulator snapshot."""
    from backend.services.android_emulator_service import get_emulator_service

    emulator_service = get_emulator_service()
    success = await emulator_service.load_snapshot(serial, name)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to load snapshot")

    return {"status": "loaded", "name": name}


@router.post("/emulators/{serial}/setup-fuzzing")
async def setup_fuzzing_environment(serial: str, current_user: User = Depends(get_current_active_user)):
    """Setup emulator for fuzzing (root, FRIDA, SELinux)."""
    from backend.services.android_emulator_service import get_emulator_service

    emulator_service = get_emulator_service()
    results = await emulator_service.setup_fuzzing_environment(serial)

    return {"serial": serial, "setup": results}


# ============================================================================
# Native Library Fuzzing Endpoints
# ============================================================================

@router.get("/packages/{package}/native-libraries", response_model=List[NativeLibraryInfo])
async def list_native_libraries(package: str, serial: str, current_user: User = Depends(get_current_active_user)):
    """List native libraries in a package."""
    from backend.services.android_native_fuzzer import get_native_fuzzer
    from backend.services.android_device_service import get_device_service

    fuzzer = get_native_fuzzer()
    fuzzer.set_device_service(get_device_service())

    libraries = await fuzzer.list_native_libraries(serial, package)

    return [
        NativeLibraryInfo(
            name=lib.name,
            path=lib.path,
            architecture=lib.architecture,
            size=lib.size,
            is_stripped=lib.is_stripped,
            exports_count=len(lib.exports),
            dangerous_functions=lib.dangerous_functions[:10],
            jni_functions=lib.jni_functions[:10]
        )
        for lib in libraries
    ]


@router.post("/fuzz/native/analyze")
async def analyze_native_library(
    serial: str,
    library_path: str,
    current_user: User = Depends(get_current_active_user),
):
    """Pull and analyze a native library."""
    from backend.services.android_native_fuzzer import get_native_fuzzer
    from backend.services.android_device_service import get_device_service

    fuzzer = get_native_fuzzer()
    fuzzer.set_device_service(get_device_service())

    local_path = await fuzzer.pull_library(serial, library_path)
    analysis = await fuzzer.analyze_library(local_path)

    return {
        "name": analysis.name,
        "architecture": analysis.architecture,
        "size": analysis.size,
        "is_stripped": analysis.is_stripped,
        "is_pie": analysis.is_pie,
        "has_stack_canary": analysis.has_stack_canary,
        "has_nx": analysis.has_nx,
        "has_relro": analysis.has_relro,
        "exports_count": len(analysis.exports),
        "imports_count": len(analysis.imports),
        "exports_sample": analysis.exports[:20],
        "dangerous_functions": analysis.dangerous_functions,
        "jni_functions": analysis.jni_functions,
        "interesting_strings": analysis.interesting_strings[:20]
    }


@router.post("/fuzz/native/start", response_model=NativeFuzzStatus)
async def start_native_fuzzing(request: NativeFuzzRequest, current_user: User = Depends(get_current_active_user)):
    """Start native library fuzzing session."""
    from backend.services.android_native_fuzzer import (
        get_native_fuzzer,
        NativeFuzzConfig,
        FuzzMode
    )
    from backend.services.android_device_service import get_device_service

    fuzzer = get_native_fuzzer()
    fuzzer.set_device_service(get_device_service())

    config = NativeFuzzConfig(
        device_serial=request.device_serial,
        library_path=request.library_path,
        target_function=request.target_function,
        fuzz_mode=FuzzMode(request.fuzz_mode),
        input_size_max=request.input_size_max,
        max_iterations=request.max_iterations,
        max_crashes=request.max_crashes,
        timeout_ms=request.timeout_ms,
        track_coverage=request.track_coverage
    )

    # Start fuzzing and get first event (session_start)
    session_id = None
    async for event in fuzzer.fuzz_with_frida(config):
        if event.get("type") == "session_start":
            session_id = event.get("session_id")
            break

    if not session_id:
        raise HTTPException(status_code=500, detail="Failed to start fuzzing")

    session = fuzzer.get_session(session_id)

    return NativeFuzzStatus(
        session_id=session_id,
        library_name=session.library_name if session else "",
        target_function=session.target_function if session else "",
        status=session.status if session else "unknown",
        executions=session.stats.executions if session else 0,
        crashes=session.stats.crashes if session else 0,
        unique_crashes=session.stats.unique_crashes if session else 0,
        coverage_edges=session.stats.coverage_edges if session else 0
    )


@router.get("/fuzz/native/{session_id}", response_model=NativeFuzzStatus)
async def get_native_fuzz_status(session_id: str, current_user: User = Depends(get_current_active_user)):
    """Get status of native fuzzing session."""
    from backend.services.android_native_fuzzer import get_native_fuzzer

    fuzzer = get_native_fuzzer()
    session = fuzzer.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")

    return NativeFuzzStatus(
        session_id=session_id,
        library_name=session.library_name,
        target_function=session.target_function,
        status=session.status,
        executions=session.stats.executions,
        crashes=session.stats.crashes,
        unique_crashes=session.stats.unique_crashes,
        coverage_edges=session.stats.coverage_edges,
        exec_per_sec=session.stats.exec_per_sec
    )


@router.post("/fuzz/native/{session_id}/stop")
async def stop_native_fuzzing(session_id: str, current_user: User = Depends(get_current_active_user)):
    """Stop native fuzzing session."""
    from backend.services.android_native_fuzzer import get_native_fuzzer

    fuzzer = get_native_fuzzer()
    success = await fuzzer.stop_session(session_id)

    if not success:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")

    return {"status": "stopped", "session_id": session_id}


@router.websocket("/fuzz/native/ws/{session_id}")
async def native_fuzz_websocket(websocket: WebSocket, session_id: str):
    """WebSocket for real-time native fuzzing progress."""
    await websocket.accept()

    from backend.services.android_native_fuzzer import get_native_fuzzer

    fuzzer = get_native_fuzzer()

    try:
        while True:
            session = fuzzer.get_session(session_id)
            if not session:
                await websocket.send_json({"type": "error", "message": "Session not found"})
                break

            await websocket.send_json({
                "type": "stats",
                "session_id": session_id,
                "status": session.status,
                "executions": session.stats.executions,
                "crashes": session.stats.crashes,
                "unique_crashes": session.stats.unique_crashes,
                "coverage_edges": session.stats.coverage_edges,
                "exec_per_sec": session.stats.exec_per_sec
            })

            if session.status in ["completed", "error", "stopped"]:
                await websocket.send_json({"type": "done", "status": session.status})
                break

            await asyncio.sleep(1)

    except WebSocketDisconnect:
        pass


# ============================================================================
# Intent Fuzzing Endpoints
# ============================================================================

@router.get("/packages/{package}/components", response_model=List[ExportedComponentInfo])
async def list_exported_components(package: str, serial: str, current_user: User = Depends(get_current_active_user)):
    """List exported components in a package."""
    from backend.services.android_intent_fuzzer import get_intent_fuzzer
    from backend.services.android_device_service import get_device_service

    fuzzer = get_intent_fuzzer()
    fuzzer.set_device_service(get_device_service())

    components = await fuzzer.get_exported_components(serial, package)

    return [
        ExportedComponentInfo(
            name=c.name,
            component_type=c.component_type.value,
            package_name=c.package_name,
            exported=c.exported,
            permissions=c.permissions
        )
        for c in components
    ]


@router.post("/fuzz/intent/start", response_model=IntentFuzzStatus)
async def start_intent_fuzzing(request: IntentFuzzRequest, current_user: User = Depends(get_current_active_user)):
    """Start intent fuzzing session."""
    from backend.services.android_intent_fuzzer import get_intent_fuzzer, IntentFuzzConfig
    from backend.services.android_device_service import get_device_service

    fuzzer = get_intent_fuzzer()
    fuzzer.set_device_service(get_device_service())

    config = IntentFuzzConfig(
        device_serial=request.device_serial,
        package_name=request.package_name,
        target_component=request.target_component,
        fuzz_activities=request.fuzz_activities,
        fuzz_services=request.fuzz_services,
        fuzz_receivers=request.fuzz_receivers,
        fuzz_providers=request.fuzz_providers,
        mutation_rate=request.mutation_rate,
        max_iterations=request.max_iterations,
        max_crashes=request.max_crashes
    )

    # Start fuzzing and get first event
    session_id = None
    async for event in fuzzer.fuzz_package(config):
        if event.get("type") == "session_start":
            session_id = event.get("session_id")
            break

    if not session_id:
        raise HTTPException(status_code=500, detail="Failed to start fuzzing")

    session = fuzzer.get_session(session_id)

    return IntentFuzzStatus(
        session_id=session_id,
        package_name=session.package_name if session else "",
        status=session.status if session else "unknown",
        intents_sent=session.stats.intents_sent if session else 0,
        crashes=session.stats.crashes if session else 0,
        unique_crashes=session.stats.unique_crashes if session else 0,
        anrs=session.stats.anrs if session else 0
    )


@router.get("/fuzz/intent/{session_id}", response_model=IntentFuzzStatus)
async def get_intent_fuzz_status(session_id: str, current_user: User = Depends(get_current_active_user)):
    """Get status of intent fuzzing session."""
    from backend.services.android_intent_fuzzer import get_intent_fuzzer

    fuzzer = get_intent_fuzzer()
    session = fuzzer.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")

    return IntentFuzzStatus(
        session_id=session_id,
        package_name=session.package_name,
        status=session.status,
        intents_sent=session.stats.intents_sent,
        crashes=session.stats.crashes,
        unique_crashes=session.stats.unique_crashes,
        anrs=session.stats.anrs,
        components_tested=session.stats.components_tested
    )


@router.post("/fuzz/intent/{session_id}/stop")
async def stop_intent_fuzzing(session_id: str, current_user: User = Depends(get_current_active_user)):
    """Stop intent fuzzing session."""
    from backend.services.android_intent_fuzzer import get_intent_fuzzer

    fuzzer = get_intent_fuzzer()
    success = await fuzzer.stop_session(session_id)

    if not success:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")

    return {"status": "stopped", "session_id": session_id}


@router.websocket("/fuzz/intent/ws/{session_id}")
async def intent_fuzz_websocket(websocket: WebSocket, session_id: str):
    """WebSocket for real-time intent fuzzing progress."""
    await websocket.accept()

    from backend.services.android_intent_fuzzer import get_intent_fuzzer

    fuzzer = get_intent_fuzzer()

    try:
        while True:
            session = fuzzer.get_session(session_id)
            if not session:
                await websocket.send_json({"type": "error", "message": "Session not found"})
                break

            await websocket.send_json({
                "type": "stats",
                "session_id": session_id,
                "status": session.status,
                "intents_sent": session.stats.intents_sent,
                "crashes": session.stats.crashes,
                "unique_crashes": session.stats.unique_crashes,
                "anrs": session.stats.anrs
            })

            if session.status in ["completed", "error", "stopped"]:
                await websocket.send_json({"type": "done", "status": session.status})
                break

            await asyncio.sleep(1)

    except WebSocketDisconnect:
        pass


# ============================================================================
# Campaign Endpoints
# ============================================================================

@router.post("/campaign/create", response_model=CampaignInfo)
async def create_campaign(request: CampaignCreateRequest, current_user: User = Depends(get_current_active_user)):
    """Create a new fuzzing campaign."""
    from backend.services.android_fuzzer_service import (
        get_android_fuzzer,
        AndroidFuzzCampaignConfig,
        TargetType
    )

    fuzzer = get_android_fuzzer()

    config = AndroidFuzzCampaignConfig(
        name=request.name,
        target_type=TargetType(request.target_type),
        target_path=request.target_path,
        device_serial=request.device_serial,
        use_emulator=request.use_emulator,
        emulator_avd=request.emulator_avd,
        fuzz_native_libraries=request.fuzz_native_libraries,
        fuzz_activities=request.fuzz_activities,
        fuzz_services=request.fuzz_services,
        fuzz_receivers=request.fuzz_receivers,
        fuzz_providers=request.fuzz_providers,
        max_iterations=request.max_iterations,
        max_crashes=request.max_crashes,
        timeout_hours=request.timeout_hours
    )

    campaign = await fuzzer.create_campaign(config)

    return CampaignInfo(
        campaign_id=campaign.campaign_id,
        name=campaign.config.name,
        target_type=campaign.config.target_type.value,
        target_path=campaign.config.target_path,
        status=campaign.status.value,
        current_phase=campaign.current_phase.value,
        device_serial=campaign.device_serial
    )


@router.post("/campaign/{campaign_id}/start")
async def start_campaign(campaign_id: str, current_user: User = Depends(get_current_active_user)):
    """Start a fuzzing campaign (returns immediately, use WebSocket for progress)."""
    from backend.services.android_fuzzer_service import get_android_fuzzer

    fuzzer = get_android_fuzzer()
    campaign = fuzzer.get_campaign(campaign_id)

    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign not found: {campaign_id}")

    # Start campaign in background
    async def run_campaign():
        async for _ in fuzzer.start_campaign(campaign_id):
            pass

    asyncio.create_task(run_campaign())

    return {"status": "started", "campaign_id": campaign_id}


@router.post("/campaign/{campaign_id}/stop")
async def stop_campaign(campaign_id: str, current_user: User = Depends(get_current_active_user)):
    """Stop a running campaign."""
    from backend.services.android_fuzzer_service import get_android_fuzzer

    fuzzer = get_android_fuzzer()
    success = await fuzzer.stop_campaign(campaign_id)

    if not success:
        raise HTTPException(status_code=404, detail=f"Campaign not found: {campaign_id}")

    return {"status": "stopped", "campaign_id": campaign_id}


@router.get("/campaign/{campaign_id}", response_model=CampaignStatsResponse)
async def get_campaign_status(campaign_id: str, current_user: User = Depends(get_current_active_user)):
    """Get campaign status and statistics."""
    from backend.services.android_fuzzer_service import get_android_fuzzer

    fuzzer = get_android_fuzzer()
    status = fuzzer.get_campaign_status(campaign_id)

    if not status:
        raise HTTPException(status_code=404, detail=f"Campaign not found: {campaign_id}")

    return CampaignStatsResponse(**status)


@router.get("/campaign/{campaign_id}/crashes", response_model=List[CrashInfo])
async def get_campaign_crashes(campaign_id: str, current_user: User = Depends(get_current_active_user)):
    """Get all crashes from a campaign."""
    from backend.services.android_fuzzer_service import get_android_fuzzer

    fuzzer = get_android_fuzzer()
    campaign = fuzzer.get_campaign(campaign_id)

    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign not found: {campaign_id}")

    return [
        CrashInfo(
            crash_id=c.crash_id,
            crash_type=c.crash_type,
            severity=c.severity,
            component=c.component,
            source=c.source,
            exception_or_signal=c.exception_or_signal,
            is_exploitable=c.is_exploitable,
            input_hash=c.input_hash
        )
        for c in campaign.crashes
    ]


@router.get("/campaigns", response_model=List[CampaignInfo])
async def list_campaigns(current_user: User = Depends(get_current_active_user)):
    """List all campaigns."""
    from backend.services.android_fuzzer_service import get_android_fuzzer

    fuzzer = get_android_fuzzer()
    campaigns = fuzzer.get_all_campaigns()

    return [
        CampaignInfo(
            campaign_id=c.campaign_id,
            name=c.config.name,
            target_type=c.config.target_type.value,
            target_path=c.config.target_path,
            status=c.status.value,
            current_phase=c.current_phase.value,
            device_serial=c.device_serial,
            error_message=c.error_message
        )
        for c in campaigns
    ]


@router.websocket("/campaign/ws/{campaign_id}")
async def campaign_websocket(websocket: WebSocket, campaign_id: str):
    """WebSocket for real-time campaign progress."""
    await websocket.accept()

    from backend.services.android_fuzzer_service import get_android_fuzzer

    fuzzer = get_android_fuzzer()

    try:
        async for event in fuzzer.start_campaign(campaign_id):
            await websocket.send_json(event)

            if event.get("type") in ["campaign_completed", "error"]:
                break

    except WebSocketDisconnect:
        # Stop campaign if client disconnects
        await fuzzer.stop_campaign(campaign_id)


# ============================================================================
# Quick Scan Endpoints
# ============================================================================

@router.post("/quick-scan/native")
async def quick_native_scan(
    serial: str,
    package: str,
    max_seconds: int = 60,
    current_user: User = Depends(get_current_active_user),
):
    """Quick native library security scan."""
    from backend.services.android_fuzzer_service import get_android_fuzzer

    fuzzer = get_android_fuzzer()
    results = await fuzzer.quick_native_fuzz(serial, package, max_seconds)

    return results


@router.post("/quick-scan/intent")
async def quick_intent_scan(
    serial: str,
    package: str,
    max_intents: int = 100,
    current_user: User = Depends(get_current_active_user),
):
    """Quick intent fuzzing scan."""
    from backend.services.android_fuzzer_service import get_android_fuzzer

    fuzzer = get_android_fuzzer()
    results = await fuzzer.quick_intent_fuzz(serial, package, max_intents)

    return results


# ============================================================================
# APK Upload Endpoint
# ============================================================================

@router.post("/apk/upload")
async def upload_apk(file: UploadFile = File(...), current_user: User = Depends(get_current_active_user)):
    """Upload an APK for analysis and fuzzing."""
    import tempfile
    import os

    if not file.filename or not file.filename.endswith('.apk'):
        raise HTTPException(status_code=400, detail="File must be an APK")

    # Save to temp directory with sanitized filename to prevent path traversal
    temp_dir = tempfile.mkdtemp(prefix="android_fuzzer_")
    safe_filename = sanitize_filename(file.filename, preserve_extension=True)
    apk_path = os.path.join(temp_dir, safe_filename)

    with open(apk_path, 'wb') as f:
        content = await file.read()
        f.write(content)

    return {
        "path": apk_path,
        "filename": safe_filename,
        "original_filename": file.filename,
        "size": len(content)
    }
