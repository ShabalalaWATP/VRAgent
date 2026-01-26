"""
Android Fuzzer Service - Main Orchestrator

Coordinates all Android fuzzing components:
1. Device management via AndroidDeviceService
2. Native library fuzzing via AndroidNativeFuzzer
3. Intent/IPC fuzzing via AndroidIntentFuzzer
4. Emulator management via AndroidEmulatorService
5. Full campaign management with AI-guided target selection
"""

import asyncio
import hashlib
import json
import logging
import os
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class CampaignStatus(Enum):
    """Fuzzing campaign status."""
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TargetType(Enum):
    """Target type for fuzzing."""
    APK = "apk"
    PACKAGE = "package"
    NATIVE_LIBRARY = "native_library"
    COMPONENT = "component"


class FuzzingPhase(Enum):
    """Current phase of the fuzzing campaign."""
    INITIALIZATION = "initialization"
    DEVICE_SETUP = "device_setup"
    APK_ANALYSIS = "apk_analysis"
    NATIVE_FUZZING = "native_fuzzing"
    INTENT_FUZZING = "intent_fuzzing"
    PROVIDER_FUZZING = "provider_fuzzing"
    CLEANUP = "cleanup"
    REPORT_GENERATION = "report_generation"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class AndroidFuzzCampaignConfig:
    """Configuration for an Android fuzzing campaign."""
    name: str
    target_type: TargetType
    target_path: str                        # APK path, package name, or library path

    # Device configuration
    device_serial: Optional[str] = None     # None = use emulator
    use_emulator: bool = True
    emulator_avd: str = "fuzz_avd"
    emulator_api_level: int = 33
    emulator_abi: str = "x86_64"
    emulator_count: int = 1                 # For parallel fuzzing

    # Fuzzing targets
    fuzz_native_libraries: bool = True
    fuzz_activities: bool = True
    fuzz_services: bool = True
    fuzz_receivers: bool = True
    fuzz_providers: bool = True

    # Native fuzzing options
    native_libraries: Optional[List[str]] = None    # Specific libs or auto-detect
    native_functions: Optional[List[str]] = None    # Specific functions or auto-detect
    native_use_frida: bool = True
    native_use_qemu: bool = False

    # Intent fuzzing options
    intent_mutation_rate: float = 0.3
    intent_max_per_component: int = 500

    # AI-guided options
    use_ai_target_selection: bool = True
    ai_model: str = "gpt-4"                 # For target prioritization

    # Limits
    max_iterations: int = 10000
    max_crashes: int = 100
    timeout_hours: float = 24.0

    # Output
    output_dir: Optional[str] = None
    save_crashes: bool = True
    save_coverage: bool = True
    generate_report: bool = True


@dataclass
class CampaignStats:
    """Statistics for a fuzzing campaign."""
    # Overall
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_sec: float = 0.0

    # APK Analysis
    apk_analyzed: bool = False
    native_libraries_found: int = 0
    exported_components_found: int = 0
    dangerous_functions_found: int = 0

    # Native Fuzzing
    native_executions: int = 0
    native_crashes: int = 0
    native_unique_crashes: int = 0
    native_coverage_edges: int = 0

    # Intent Fuzzing
    intents_sent: int = 0
    intent_crashes: int = 0
    intent_unique_crashes: int = 0
    anrs_detected: int = 0

    # Total
    total_crashes: int = 0
    total_unique_crashes: int = 0
    exploitable_crashes: int = 0


@dataclass
class CrashSummary:
    """Summary of a crash for reporting."""
    crash_id: str
    crash_type: str
    severity: str
    component: str
    source: str                             # native or intent
    exception_or_signal: str
    is_exploitable: bool
    input_hash: str
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AndroidFuzzCampaign:
    """Represents an Android fuzzing campaign."""
    campaign_id: str
    config: AndroidFuzzCampaignConfig
    status: CampaignStatus = CampaignStatus.CREATED
    current_phase: FuzzingPhase = FuzzingPhase.INITIALIZATION
    stats: CampaignStats = field(default_factory=CampaignStats)
    crashes: List[CrashSummary] = field(default_factory=list)
    device_serial: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)


# ============================================================================
# Android Fuzzer Service
# ============================================================================

class AndroidFuzzerService:
    """
    Main Android fuzzing orchestrator.

    Coordinates:
    - Device/emulator management
    - APK analysis
    - Native library fuzzing
    - Intent/IPC fuzzing
    - Campaign management
    - Report generation
    """

    def __init__(self):
        # Import services lazily to avoid circular imports
        self._device_service = None
        self._native_fuzzer = None
        self._intent_fuzzer = None
        self._emulator_service = None

        # Campaign storage
        self.campaigns: Dict[str, AndroidFuzzCampaign] = {}
        self._active_tasks: Dict[str, asyncio.Task] = {}

    @property
    def device_service(self):
        """Lazy-load device service."""
        if self._device_service is None:
            from backend.services.android_device_service import get_device_service
            self._device_service = get_device_service()
        return self._device_service

    @property
    def native_fuzzer(self):
        """Lazy-load native fuzzer."""
        if self._native_fuzzer is None:
            from backend.services.android_native_fuzzer import get_native_fuzzer
            self._native_fuzzer = get_native_fuzzer()
            self._native_fuzzer.set_device_service(self.device_service)
        return self._native_fuzzer

    @property
    def intent_fuzzer(self):
        """Lazy-load intent fuzzer."""
        if self._intent_fuzzer is None:
            from backend.services.android_intent_fuzzer import get_intent_fuzzer
            self._intent_fuzzer = get_intent_fuzzer()
            self._intent_fuzzer.set_device_service(self.device_service)
        return self._intent_fuzzer

    @property
    def emulator_service(self):
        """Lazy-load emulator service."""
        if self._emulator_service is None:
            from backend.services.android_emulator_service import get_emulator_service
            self._emulator_service = get_emulator_service()
            self._emulator_service.set_device_service(self.device_service)
        return self._emulator_service

    # ========================================================================
    # Campaign Management
    # ========================================================================

    async def create_campaign(
        self,
        config: AndroidFuzzCampaignConfig
    ) -> AndroidFuzzCampaign:
        """Create a new fuzzing campaign."""
        campaign_id = str(uuid.uuid4())[:12]

        campaign = AndroidFuzzCampaign(
            campaign_id=campaign_id,
            config=config
        )

        self.campaigns[campaign_id] = campaign
        logger.info(f"Created Android fuzzing campaign: {campaign_id}")

        return campaign

    async def start_campaign(
        self,
        campaign_id: str
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Start a fuzzing campaign."""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            yield {"type": "error", "message": f"Campaign not found: {campaign_id}"}
            return

        if campaign.status == CampaignStatus.RUNNING:
            yield {"type": "error", "message": "Campaign already running"}
            return

        campaign.status = CampaignStatus.RUNNING
        campaign.stats.start_time = datetime.now()

        yield {
            "type": "campaign_started",
            "campaign_id": campaign_id,
            "name": campaign.config.name,
            "target": campaign.config.target_path
        }

        try:
            # Phase 1: Device Setup
            campaign.current_phase = FuzzingPhase.DEVICE_SETUP
            yield {"type": "phase", "phase": "device_setup"}

            async for event in self._setup_device(campaign):
                yield event

            if not campaign.device_serial:
                raise RuntimeError("Failed to setup device/emulator")

            # Phase 2: APK Analysis (if target is APK)
            if campaign.config.target_type == TargetType.APK:
                campaign.current_phase = FuzzingPhase.APK_ANALYSIS
                yield {"type": "phase", "phase": "apk_analysis"}

                async for event in self._analyze_apk(campaign):
                    yield event

            # Phase 3: Native Library Fuzzing
            if campaign.config.fuzz_native_libraries:
                campaign.current_phase = FuzzingPhase.NATIVE_FUZZING
                yield {"type": "phase", "phase": "native_fuzzing"}

                async for event in self._run_native_fuzzing(campaign):
                    yield event

                    # Check limits
                    if campaign.stats.total_unique_crashes >= campaign.config.max_crashes:
                        yield {"type": "info", "message": "Max crashes reached, stopping native fuzzing"}
                        break

            # Phase 4: Intent Fuzzing
            if any([
                campaign.config.fuzz_activities,
                campaign.config.fuzz_services,
                campaign.config.fuzz_receivers
            ]):
                campaign.current_phase = FuzzingPhase.INTENT_FUZZING
                yield {"type": "phase", "phase": "intent_fuzzing"}

                async for event in self._run_intent_fuzzing(campaign):
                    yield event

                    if campaign.stats.total_unique_crashes >= campaign.config.max_crashes:
                        yield {"type": "info", "message": "Max crashes reached, stopping intent fuzzing"}
                        break

            # Phase 5: Content Provider Fuzzing
            if campaign.config.fuzz_providers:
                campaign.current_phase = FuzzingPhase.PROVIDER_FUZZING
                yield {"type": "phase", "phase": "provider_fuzzing"}

                async for event in self._run_provider_fuzzing(campaign):
                    yield event

            # Phase 6: Cleanup
            campaign.current_phase = FuzzingPhase.CLEANUP
            yield {"type": "phase", "phase": "cleanup"}

            await self._cleanup(campaign)

            # Phase 7: Report Generation
            if campaign.config.generate_report:
                campaign.current_phase = FuzzingPhase.REPORT_GENERATION
                yield {"type": "phase", "phase": "report_generation"}

                report = await self._generate_report(campaign)
                yield {"type": "report", "report": report}

            # Complete
            campaign.status = CampaignStatus.COMPLETED
            campaign.stats.end_time = datetime.now()
            campaign.stats.duration_sec = (
                campaign.stats.end_time - campaign.stats.start_time
            ).total_seconds()

            yield {
                "type": "campaign_completed",
                "campaign_id": campaign_id,
                "stats": self._stats_to_dict(campaign.stats)
            }

        except Exception as e:
            campaign.status = CampaignStatus.FAILED
            campaign.error_message = str(e)
            logger.exception(f"Campaign {campaign_id} failed: {e}")

            yield {
                "type": "error",
                "campaign_id": campaign_id,
                "message": str(e)
            }

    async def stop_campaign(self, campaign_id: str) -> bool:
        """Stop a running campaign."""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return False

        campaign.status = CampaignStatus.CANCELLED

        # Cancel any active tasks
        if campaign_id in self._active_tasks:
            self._active_tasks[campaign_id].cancel()
            del self._active_tasks[campaign_id]

        # Cleanup resources
        await self._cleanup(campaign)

        return True

    def get_campaign(self, campaign_id: str) -> Optional[AndroidFuzzCampaign]:
        """Get a campaign by ID."""
        return self.campaigns.get(campaign_id)

    def get_all_campaigns(self) -> List[AndroidFuzzCampaign]:
        """Get all campaigns."""
        return list(self.campaigns.values())

    def get_campaign_status(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a campaign."""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return None

        return {
            "campaign_id": campaign_id,
            "name": campaign.config.name,
            "status": campaign.status.value,
            "current_phase": campaign.current_phase.value,
            "device_serial": campaign.device_serial,
            "stats": self._stats_to_dict(campaign.stats),
            "crashes_count": len(campaign.crashes),
            "error": campaign.error_message
        }

    # ========================================================================
    # Campaign Phases
    # ========================================================================

    async def _setup_device(
        self,
        campaign: AndroidFuzzCampaign
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Setup device or emulator for fuzzing."""
        config = campaign.config

        if config.device_serial:
            # Use specified device
            yield {"type": "info", "message": f"Using device: {config.device_serial}"}

            # Verify device is connected
            devices = await self.device_service.list_devices()
            device = next((d for d in devices if d.serial == config.device_serial), None)

            if not device:
                raise RuntimeError(f"Device not found: {config.device_serial}")

            campaign.device_serial = config.device_serial
            yield {"type": "device_ready", "serial": config.device_serial}

        elif config.use_emulator:
            # Start emulator
            yield {"type": "info", "message": "Starting emulator..."}

            # Check if AVD exists, create if not
            avds = await self.emulator_service.list_avds()

            if config.emulator_avd not in avds:
                yield {"type": "info", "message": f"Creating AVD: {config.emulator_avd}"}

                from backend.services.android_emulator_service import AVDConfig

                avd_config = AVDConfig(
                    name=config.emulator_avd,
                    api_level=config.emulator_api_level,
                    abi=config.emulator_abi,
                    no_window=True,
                    writable_system=True
                )

                success = await self.emulator_service.create_avd(avd_config)
                if not success:
                    raise RuntimeError(f"Failed to create AVD: {config.emulator_avd}")

            # Start emulator
            instance = await self.emulator_service.start_emulator(
                config.emulator_avd,
                headless=True,
                writable_system=True
            )

            yield {"type": "info", "message": f"Emulator started: {instance.serial}"}

            # Wait for boot
            yield {"type": "info", "message": "Waiting for emulator to boot..."}
            booted = await self.emulator_service.wait_for_boot(instance.serial, timeout_sec=180)

            if not booted:
                raise RuntimeError("Emulator failed to boot")

            # Setup fuzzing environment
            yield {"type": "info", "message": "Setting up fuzzing environment..."}
            setup_results = await self.emulator_service.setup_fuzzing_environment(instance.serial)
            yield {"type": "info", "message": f"Environment setup: {setup_results}"}

            campaign.device_serial = instance.serial
            yield {"type": "device_ready", "serial": instance.serial, "is_emulator": True}

        else:
            # Auto-detect device
            yield {"type": "info", "message": "Auto-detecting devices..."}
            devices = await self.device_service.list_devices()

            if not devices:
                raise RuntimeError("No devices connected and emulator disabled")

            campaign.device_serial = devices[0].serial
            yield {"type": "device_ready", "serial": devices[0].serial}

    async def _analyze_apk(
        self,
        campaign: AndroidFuzzCampaign
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Analyze APK for fuzzing targets."""
        config = campaign.config
        apk_path = config.target_path

        yield {"type": "info", "message": f"Analyzing APK: {apk_path}"}

        # Install APK on device
        yield {"type": "info", "message": "Installing APK..."}
        success = await self.device_service.install_apk(
            campaign.device_serial,
            apk_path
        )

        if not success:
            raise RuntimeError(f"Failed to install APK: {apk_path}")

        # Get package name from APK
        # In real implementation, would use androguard
        package_name = await self._get_package_from_apk(apk_path)
        yield {"type": "info", "message": f"Package: {package_name}"}

        # Find native libraries
        libraries = await self.native_fuzzer.list_native_libraries(
            campaign.device_serial,
            package_name
        )
        campaign.stats.native_libraries_found = len(libraries)
        yield {
            "type": "native_libraries_found",
            "count": len(libraries),
            "libraries": [lib.name for lib in libraries]
        }

        # Find exported components
        components = await self.intent_fuzzer.get_exported_components(
            campaign.device_serial,
            package_name
        )
        campaign.stats.exported_components_found = len(components)
        yield {
            "type": "components_found",
            "count": len(components),
            "activities": len([c for c in components if c.component_type.value == "activity"]),
            "services": len([c for c in components if c.component_type.value == "service"]),
            "receivers": len([c for c in components if c.component_type.value == "receiver"]),
            "providers": len([c for c in components if c.component_type.value == "provider"])
        }

        # Analyze native libraries for dangerous functions
        dangerous_total = 0
        for lib in libraries:
            pulled_path = await self.native_fuzzer.pull_library(
                campaign.device_serial,
                lib.path
            )
            analyzed = await self.native_fuzzer.analyze_library(pulled_path)
            dangerous_total += len(analyzed.dangerous_functions)

            if analyzed.dangerous_functions:
                yield {
                    "type": "dangerous_functions",
                    "library": lib.name,
                    "functions": analyzed.dangerous_functions[:10]
                }

        campaign.stats.dangerous_functions_found = dangerous_total
        campaign.stats.apk_analyzed = True

        yield {"type": "apk_analysis_complete", "package": package_name}

    async def _run_native_fuzzing(
        self,
        campaign: AndroidFuzzCampaign
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Run native library fuzzing."""
        config = campaign.config

        # Get package name
        if config.target_type == TargetType.APK:
            package_name = await self._get_package_from_apk(config.target_path)
        else:
            package_name = config.target_path

        # Get native libraries
        libraries = await self.native_fuzzer.list_native_libraries(
            campaign.device_serial,
            package_name
        )

        if config.native_libraries:
            # Filter to specified libraries
            libraries = [l for l in libraries if l.name in config.native_libraries]

        if not libraries:
            yield {"type": "info", "message": "No native libraries to fuzz"}
            return

        yield {"type": "info", "message": f"Fuzzing {len(libraries)} native libraries"}

        for lib in libraries:
            yield {"type": "library_start", "library": lib.name}

            # Pull and analyze library
            local_path = await self.native_fuzzer.pull_library(
                campaign.device_serial,
                lib.path
            )
            analyzed = await self.native_fuzzer.analyze_library(local_path)

            # Find fuzzing targets
            targets = await self.native_fuzzer.find_fuzz_targets(analyzed)

            if config.native_functions:
                targets = [t for t in targets if t in config.native_functions]

            if not targets:
                yield {"type": "info", "message": f"No fuzz targets in {lib.name}"}
                continue

            yield {
                "type": "fuzz_targets",
                "library": lib.name,
                "targets": targets[:5]
            }

            # Fuzz each target
            for target_func in targets[:5]:  # Limit targets per library
                from backend.services.android_native_fuzzer import NativeFuzzConfig, FuzzMode

                fuzz_config = NativeFuzzConfig(
                    device_serial=campaign.device_serial,
                    library_path=lib.path,
                    target_function=target_func,
                    fuzz_mode=FuzzMode.FRIDA if config.native_use_frida else FuzzMode.QEMU,
                    max_iterations=config.max_iterations // (len(libraries) * len(targets)),
                    max_crashes=config.max_crashes - campaign.stats.total_unique_crashes
                )

                async for event in self.native_fuzzer.fuzz_with_frida(fuzz_config):
                    # Update campaign stats
                    if event.get("type") == "stats":
                        campaign.stats.native_executions += event.get("executions", 0)
                        campaign.stats.native_coverage_edges = max(
                            campaign.stats.native_coverage_edges,
                            event.get("coverage_edges", 0)
                        )

                    elif event.get("type") == "crash":
                        campaign.stats.native_crashes += 1
                        if event.get("is_unique", True):
                            campaign.stats.native_unique_crashes += 1
                            campaign.stats.total_unique_crashes += 1

                            # Add to campaign crashes
                            crash = CrashSummary(
                                crash_id=event.get("crash_id", ""),
                                crash_type=event.get("crash_type", "unknown"),
                                severity=event.get("severity", "medium"),
                                component=lib.name,
                                source="native",
                                exception_or_signal=event.get("crash_type", ""),
                                is_exploitable=event.get("is_exploitable", False),
                                input_hash=event.get("input_hash", ""),
                                details=event
                            )
                            campaign.crashes.append(crash)

                            if crash.is_exploitable:
                                campaign.stats.exploitable_crashes += 1

                    yield event

            yield {"type": "library_complete", "library": lib.name}

    async def _run_intent_fuzzing(
        self,
        campaign: AndroidFuzzCampaign
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Run intent/IPC fuzzing."""
        config = campaign.config

        # Get package name
        if config.target_type == TargetType.APK:
            package_name = await self._get_package_from_apk(config.target_path)
        else:
            package_name = config.target_path

        from backend.services.android_intent_fuzzer import IntentFuzzConfig

        intent_config = IntentFuzzConfig(
            device_serial=campaign.device_serial,
            package_name=package_name,
            fuzz_activities=config.fuzz_activities,
            fuzz_services=config.fuzz_services,
            fuzz_receivers=config.fuzz_receivers,
            fuzz_providers=False,  # Handled separately
            mutation_rate=config.intent_mutation_rate,
            max_iterations=config.max_iterations,
            max_crashes=config.max_crashes - campaign.stats.total_unique_crashes
        )

        async for event in self.intent_fuzzer.fuzz_package(intent_config):
            # Update campaign stats
            if event.get("type") == "stats":
                campaign.stats.intents_sent = event.get("intents_sent", 0)
                campaign.stats.anrs_detected = event.get("anrs", 0)

            elif event.get("type") == "crash":
                campaign.stats.intent_crashes += 1
                campaign.stats.intent_unique_crashes += 1
                campaign.stats.total_unique_crashes += 1

                crash = CrashSummary(
                    crash_id=event.get("crash_id", ""),
                    crash_type=event.get("crash_type", "unknown"),
                    severity=event.get("severity", "medium"),
                    component=event.get("component", "unknown"),
                    source="intent",
                    exception_or_signal=event.get("exception", ""),
                    is_exploitable=False,  # Intent crashes rarely exploitable
                    input_hash="",
                    details=event
                )
                campaign.crashes.append(crash)

            yield event

    async def _run_provider_fuzzing(
        self,
        campaign: AndroidFuzzCampaign
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Run content provider fuzzing."""
        config = campaign.config

        if config.target_type == TargetType.APK:
            package_name = await self._get_package_from_apk(config.target_path)
        else:
            package_name = config.target_path

        yield {"type": "info", "message": "Content provider fuzzing"}

        # Get exported providers
        components = await self.intent_fuzzer.get_exported_components(
            campaign.device_serial,
            package_name
        )

        from backend.services.android_intent_fuzzer import ComponentType

        providers = [c for c in components if c.component_type == ComponentType.PROVIDER]

        if not providers:
            yield {"type": "info", "message": "No exported content providers"}
            return

        yield {"type": "providers_found", "count": len(providers)}

        # Fuzz each provider with malicious URIs
        from backend.services.android_intent_fuzzer import MaliciousPayloads

        for provider in providers:
            yield {"type": "provider_start", "provider": provider.name}

            # Try various malicious queries
            for uri in MaliciousPayloads.URIS[:20]:
                try:
                    # Construct provider URI
                    authority = provider.name.split("/")[-1] if "/" in provider.name else provider.name
                    test_uri = f"content://{authority}/{uri}"

                    result = await self.intent_fuzzer.query_provider(
                        campaign.device_serial,
                        test_uri,
                        selection=MaliciousPayloads.generate_malicious_string()
                    )

                    if not result.get("success"):
                        error = result.get("error", "")
                        if "SecurityException" in error:
                            yield {
                                "type": "security_exception",
                                "provider": provider.name,
                                "uri": test_uri
                            }

                except Exception as e:
                    logger.debug(f"Provider query error: {e}")

            yield {"type": "provider_complete", "provider": provider.name}

    async def _cleanup(self, campaign: AndroidFuzzCampaign) -> None:
        """Cleanup campaign resources."""
        # Stop emulator if we started one
        if campaign.config.use_emulator and campaign.device_serial:
            try:
                running = await self.emulator_service.list_running_emulators()
                for emu in running:
                    if emu.serial == campaign.device_serial:
                        await self.emulator_service.stop_emulator(emu.serial)
                        break
            except Exception as e:
                logger.warning(f"Cleanup error: {e}")

    async def _generate_report(
        self,
        campaign: AndroidFuzzCampaign
    ) -> Dict[str, Any]:
        """Generate campaign report."""
        report = {
            "campaign_id": campaign.campaign_id,
            "name": campaign.config.name,
            "target": campaign.config.target_path,
            "target_type": campaign.config.target_type.value,
            "status": campaign.status.value,
            "duration_sec": campaign.stats.duration_sec,

            "summary": {
                "total_crashes": campaign.stats.total_crashes,
                "unique_crashes": campaign.stats.total_unique_crashes,
                "exploitable_crashes": campaign.stats.exploitable_crashes,
                "native_executions": campaign.stats.native_executions,
                "intents_sent": campaign.stats.intents_sent,
                "anrs_detected": campaign.stats.anrs_detected,
                "coverage_edges": campaign.stats.native_coverage_edges
            },

            "analysis": {
                "native_libraries": campaign.stats.native_libraries_found,
                "exported_components": campaign.stats.exported_components_found,
                "dangerous_functions": campaign.stats.dangerous_functions_found
            },

            "crashes": [
                {
                    "crash_id": c.crash_id,
                    "type": c.crash_type,
                    "severity": c.severity,
                    "component": c.component,
                    "source": c.source,
                    "is_exploitable": c.is_exploitable,
                    "exception": c.exception_or_signal
                }
                for c in campaign.crashes
            ],

            "recommendations": self._generate_recommendations(campaign)
        }

        # Save report if output dir specified
        if campaign.config.output_dir:
            report_path = os.path.join(
                campaign.config.output_dir,
                f"report_{campaign.campaign_id}.json"
            )
            os.makedirs(campaign.config.output_dir, exist_ok=True)
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)

        return report

    def _generate_recommendations(
        self,
        campaign: AndroidFuzzCampaign
    ) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []

        if campaign.stats.exploitable_crashes > 0:
            recommendations.append(
                f"CRITICAL: {campaign.stats.exploitable_crashes} potentially exploitable "
                "crashes found. Investigate immediately."
            )

        if campaign.stats.dangerous_functions_found > 0:
            recommendations.append(
                f"Found {campaign.stats.dangerous_functions_found} dangerous function calls. "
                "Review for buffer overflows and memory corruption."
            )

        if campaign.stats.anrs_detected > 0:
            recommendations.append(
                f"Detected {campaign.stats.anrs_detected} ANRs (Application Not Responding). "
                "Check for DoS vulnerabilities in IPC handlers."
            )

        # Check crash types
        intent_crashes = [c for c in campaign.crashes if c.source == "intent"]
        if intent_crashes:
            sec_exceptions = [c for c in intent_crashes if "security" in c.crash_type.lower()]
            if sec_exceptions:
                recommendations.append(
                    "Security exceptions found in IPC handling. "
                    "Review permission enforcement in exported components."
                )

            null_pointers = [c for c in intent_crashes if "null" in c.crash_type.lower()]
            if null_pointers:
                recommendations.append(
                    "NULL pointer exceptions in IPC handlers. "
                    "Add input validation for all Intent extras."
                )

        return recommendations

    def _stats_to_dict(self, stats: CampaignStats) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "start_time": stats.start_time.isoformat() if stats.start_time else None,
            "end_time": stats.end_time.isoformat() if stats.end_time else None,
            "duration_sec": stats.duration_sec,
            "native_libraries_found": stats.native_libraries_found,
            "exported_components_found": stats.exported_components_found,
            "native_executions": stats.native_executions,
            "native_crashes": stats.native_crashes,
            "native_unique_crashes": stats.native_unique_crashes,
            "intents_sent": stats.intents_sent,
            "intent_crashes": stats.intent_crashes,
            "anrs_detected": stats.anrs_detected,
            "total_unique_crashes": stats.total_unique_crashes,
            "exploitable_crashes": stats.exploitable_crashes
        }

    async def _get_package_from_apk(self, apk_path: str) -> str:
        """Extract package name from APK."""
        # Use aapt to get package name
        proc = await asyncio.create_subprocess_exec(
            "aapt", "dump", "badging", apk_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()

        output = stdout.decode('utf-8', errors='ignore')
        match = re.search(r"package: name='([^']+)'", output)

        if match:
            return match.group(1)

        # Fallback: extract from filename
        basename = os.path.basename(apk_path)
        return basename.replace(".apk", "")

    # ========================================================================
    # Quick Scan Methods
    # ========================================================================

    async def quick_native_fuzz(
        self,
        device_serial: str,
        package_name: str,
        max_seconds: int = 60
    ) -> Dict[str, Any]:
        """Quick native library fuzzing scan."""
        libraries = await self.native_fuzzer.list_native_libraries(
            device_serial,
            package_name
        )

        results = {
            "package": package_name,
            "libraries_found": len(libraries),
            "crashes": [],
            "dangerous_functions": []
        }

        for lib in libraries[:3]:  # Limit for quick scan
            local_path = await self.native_fuzzer.pull_library(
                device_serial,
                lib.path
            )
            analyzed = await self.native_fuzzer.analyze_library(local_path)

            if analyzed.dangerous_functions:
                results["dangerous_functions"].extend([
                    {"library": lib.name, "function": f}
                    for f in analyzed.dangerous_functions
                ])

        return results

    async def quick_intent_fuzz(
        self,
        device_serial: str,
        package_name: str,
        max_intents: int = 100
    ) -> Dict[str, Any]:
        """Quick intent fuzzing scan."""
        from backend.services.android_intent_fuzzer import IntentFuzzConfig

        config = IntentFuzzConfig(
            device_serial=device_serial,
            package_name=package_name,
            max_iterations=max_intents,
            max_crashes=10
        )

        crashes = []
        intents_sent = 0

        async for event in self.intent_fuzzer.fuzz_package(config):
            if event.get("type") == "stats":
                intents_sent = event.get("intents_sent", 0)
            elif event.get("type") == "crash":
                crashes.append(event)

        return {
            "package": package_name,
            "intents_sent": intents_sent,
            "crashes_found": len(crashes),
            "crashes": crashes
        }


# ============================================================================
# Module-level instance
# ============================================================================

_android_fuzzer: Optional[AndroidFuzzerService] = None


def get_android_fuzzer() -> AndroidFuzzerService:
    """Get or create the Android fuzzer service singleton."""
    global _android_fuzzer
    if _android_fuzzer is None:
        _android_fuzzer = AndroidFuzzerService()
    return _android_fuzzer
