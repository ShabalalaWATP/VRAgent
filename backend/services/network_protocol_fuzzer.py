"""
Network Protocol Fuzzer Service

TCP/UDP socket-level fuzzing with protocol state machine support.
Enables fuzzing of network services with stateful protocol awareness.
"""

import asyncio
import hashlib
import random
import re
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple, Union
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# Data Classes
# =============================================================================

class Transport(str, Enum):
    """Network transport protocol."""
    TCP = "tcp"
    UDP = "udp"


class MessageFormat(str, Enum):
    """Protocol message format type."""
    BINARY = "binary"
    TEXT = "text"
    MIXED = "mixed"


@dataclass
class ProtocolState:
    """Represents a state in a protocol state machine."""
    name: str
    transitions: Dict[str, str] = field(default_factory=dict)  # pattern -> next_state
    actions: List[str] = field(default_factory=list)  # actions to perform
    timeout_ms: int = 5000
    expected_response: Optional[str] = None  # regex pattern
    on_timeout: str = "error"  # error, retry, next


@dataclass
class ProtocolDefinition:
    """Defines a complete protocol for stateful fuzzing."""
    name: str
    transport: Transport
    port: int
    states: Dict[str, ProtocolState]
    initial_state: str
    message_format: MessageFormat = MessageFormat.TEXT
    line_ending: bytes = b"\r\n"
    max_message_size: int = 65536
    description: str = ""


@dataclass
class NetworkFuzzConfig:
    """Configuration for network fuzzing session."""
    target_host: str
    target_port: int
    transport: Transport = Transport.TCP
    protocol: Optional[ProtocolDefinition] = None
    timeout_ms: int = 5000
    max_message_size: int = 65536
    reconnect_on_error: bool = True
    ssl_enabled: bool = False
    ssl_verify: bool = False
    max_retries: int = 3
    delay_between_messages_ms: int = 100
    save_interesting_responses: bool = True


@dataclass
class NetworkMessage:
    """A single network message (sent or received)."""
    direction: str  # "sent" or "received"
    data: bytes
    timestamp: float
    size: int
    elapsed_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class FuzzingEvent:
    """Event during fuzzing session."""
    event_type: str  # "send", "receive", "crash", "timeout", "error", "interesting"
    timestamp: float
    data: Optional[bytes] = None
    response: Optional[bytes] = None
    error: Optional[str] = None
    state: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkFuzzResult:
    """Results from a network fuzzing session."""
    session_id: str
    target_host: str
    target_port: int
    transport: str
    protocol_name: Optional[str]
    messages_sent: int
    responses_received: int
    errors: List[Dict[str, Any]]
    crashes_detected: int
    timeouts: int
    interesting_responses: List[Dict[str, Any]]
    duration_sec: float
    events: List[FuzzingEvent] = field(default_factory=list)
    coverage_data: Optional[bytes] = None


@dataclass
class CrashIndicator:
    """Indicators that suggest a crash or interesting behavior."""
    pattern: bytes
    name: str
    severity: str = "medium"  # low, medium, high, critical
    description: str = ""


# =============================================================================
# Built-in Protocol Templates
# =============================================================================

PROTOCOL_TEMPLATES: Dict[str, ProtocolDefinition] = {
    "http": ProtocolDefinition(
        name="HTTP/1.1",
        transport=Transport.TCP,
        port=80,
        message_format=MessageFormat.TEXT,
        line_ending=b"\r\n",
        initial_state="request",
        states={
            "request": ProtocolState(
                name="request",
                transitions={".*": "response"},
                actions=["send_request"],
                expected_response=r"HTTP/\d\.\d \d{3}",
            ),
            "response": ProtocolState(
                name="response",
                transitions={".*": "request"},
                actions=["parse_response"],
            ),
        },
        description="HTTP/1.1 protocol for web server fuzzing",
    ),
    "ftp": ProtocolDefinition(
        name="FTP",
        transport=Transport.TCP,
        port=21,
        message_format=MessageFormat.TEXT,
        line_ending=b"\r\n",
        initial_state="connect",
        states={
            "connect": ProtocolState(
                name="connect",
                transitions={r"220.*": "auth"},
                expected_response=r"220.*",
            ),
            "auth": ProtocolState(
                name="auth",
                transitions={r"331.*": "password", r"230.*": "ready"},
                actions=["send_user"],
                expected_response=r"331.*|230.*",
            ),
            "password": ProtocolState(
                name="password",
                transitions={r"230.*": "ready", r"530.*": "auth"},
                actions=["send_pass"],
                expected_response=r"230.*|530.*",
            ),
            "ready": ProtocolState(
                name="ready",
                transitions={".*": "ready"},
                actions=["send_command"],
            ),
        },
        description="FTP protocol for file server fuzzing",
    ),
    "smtp": ProtocolDefinition(
        name="SMTP",
        transport=Transport.TCP,
        port=25,
        message_format=MessageFormat.TEXT,
        line_ending=b"\r\n",
        initial_state="connect",
        states={
            "connect": ProtocolState(
                name="connect",
                transitions={r"220.*": "helo"},
                expected_response=r"220.*",
            ),
            "helo": ProtocolState(
                name="helo",
                transitions={r"250.*": "mail"},
                actions=["send_helo"],
                expected_response=r"250.*",
            ),
            "mail": ProtocolState(
                name="mail",
                transitions={r"250.*": "rcpt"},
                actions=["send_mail_from"],
                expected_response=r"250.*",
            ),
            "rcpt": ProtocolState(
                name="rcpt",
                transitions={r"250.*": "data"},
                actions=["send_rcpt_to"],
                expected_response=r"250.*",
            ),
            "data": ProtocolState(
                name="data",
                transitions={r"354.*": "content", r"250.*": "mail"},
                actions=["send_data"],
            ),
            "content": ProtocolState(
                name="content",
                transitions={r"250.*": "mail"},
                actions=["send_content"],
            ),
        },
        description="SMTP protocol for mail server fuzzing",
    ),
    "dns": ProtocolDefinition(
        name="DNS",
        transport=Transport.UDP,
        port=53,
        message_format=MessageFormat.BINARY,
        initial_state="query",
        states={
            "query": ProtocolState(
                name="query",
                transitions={".*": "response"},
                actions=["send_query"],
            ),
            "response": ProtocolState(
                name="response",
                transitions={".*": "query"},
                actions=["parse_response"],
            ),
        },
        description="DNS protocol for resolver fuzzing",
    ),
    "modbus": ProtocolDefinition(
        name="Modbus/TCP",
        transport=Transport.TCP,
        port=502,
        message_format=MessageFormat.BINARY,
        initial_state="request",
        states={
            "request": ProtocolState(
                name="request",
                transitions={".*": "response"},
                actions=["send_request"],
                timeout_ms=3000,
            ),
            "response": ProtocolState(
                name="response",
                transitions={".*": "request"},
                actions=["parse_response"],
            ),
        },
        description="Modbus/TCP protocol for industrial control system fuzzing",
    ),
    "mqtt": ProtocolDefinition(
        name="MQTT",
        transport=Transport.TCP,
        port=1883,
        message_format=MessageFormat.BINARY,
        initial_state="connect",
        states={
            "connect": ProtocolState(
                name="connect",
                transitions={".*": "connected"},
                actions=["send_connect"],
            ),
            "connected": ProtocolState(
                name="connected",
                transitions={".*": "connected"},
                actions=["send_publish", "send_subscribe"],
            ),
        },
        description="MQTT protocol for IoT broker fuzzing",
    ),
}


# Default crash indicators
DEFAULT_CRASH_INDICATORS: List[CrashIndicator] = [
    CrashIndicator(b"Segmentation fault", "segfault", "critical", "Memory access violation"),
    CrashIndicator(b"SIGSEGV", "sigsegv", "critical", "Segmentation fault signal"),
    CrashIndicator(b"SIGABRT", "sigabrt", "high", "Abort signal"),
    CrashIndicator(b"stack smashing", "stack_smash", "critical", "Stack buffer overflow detected"),
    CrashIndicator(b"heap corruption", "heap_corrupt", "critical", "Heap memory corruption"),
    CrashIndicator(b"double free", "double_free", "critical", "Double free vulnerability"),
    CrashIndicator(b"use after free", "uaf", "critical", "Use after free vulnerability"),
    CrashIndicator(b"buffer overflow", "buffer_overflow", "critical", "Buffer overflow detected"),
    CrashIndicator(b"assertion failed", "assertion", "medium", "Assertion failure"),
    CrashIndicator(b"panic", "panic", "high", "Application panic"),
    CrashIndicator(b"ERROR", "error", "low", "Generic error"),
    CrashIndicator(b"Exception", "exception", "medium", "Unhandled exception"),
    CrashIndicator(b"Access violation", "access_violation", "critical", "Memory access violation (Windows)"),
]


# =============================================================================
# Network Protocol Fuzzer
# =============================================================================

class NetworkProtocolFuzzer:
    """TCP/UDP socket-level fuzzer with protocol state machine support."""

    def __init__(self, config: NetworkFuzzConfig):
        self.config = config
        self.socket: Optional[Union[socket.socket, ssl.SSLSocket]] = None
        self.connected = False
        self.current_state: Optional[str] = None
        self.session_id = hashlib.md5(
            f"{config.target_host}:{config.target_port}:{time.time()}".encode()
        ).hexdigest()[:16]
        self.crash_indicators = DEFAULT_CRASH_INDICATORS.copy()
        self.messages_sent = 0
        self.responses_received = 0
        self.crashes_detected = 0
        self.timeouts = 0
        self.errors: List[Dict[str, Any]] = []
        self.interesting_responses: List[Dict[str, Any]] = []
        self.events: List[FuzzingEvent] = []
        self._start_time = time.time()

    async def connect(self) -> bool:
        """Establish connection to target."""
        try:
            if self.config.transport == Transport.TCP:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(self.config.timeout_ms / 1000)

                if self.config.ssl_enabled:
                    context = ssl.create_default_context()
                    if not self.config.ssl_verify:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    self.socket = context.wrap_socket(
                        self.socket, server_hostname=self.config.target_host
                    )

                await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.socket.connect,
                    (self.config.target_host, self.config.target_port)
                )
            else:  # UDP
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.settimeout(self.config.timeout_ms / 1000)

            self.connected = True
            if self.config.protocol:
                self.current_state = self.config.protocol.initial_state

            logger.info(f"Connected to {self.config.target_host}:{self.config.target_port}")
            self._record_event("connect", details={"success": True})
            return True

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self.errors.append({
                "type": "connection_error",
                "message": str(e),
                "timestamp": time.time(),
            })
            self._record_event("error", error=str(e))
            return False

    async def disconnect(self):
        """Close connection."""
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                logger.warning(f"Error closing socket: {e}")
            self.socket = None
        self.connected = False
        self._record_event("disconnect")

    async def send_message(self, data: bytes) -> Tuple[Optional[bytes], Optional[str]]:
        """Send a message and optionally receive response."""
        if not self.socket:
            return None, "Not connected"

        start_time = time.time()
        response = None
        error = None

        try:
            # Send data
            if self.config.transport == Transport.TCP:
                await asyncio.get_event_loop().run_in_executor(
                    None, self.socket.sendall, data
                )
            else:  # UDP
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.socket.sendto,
                    data,
                    (self.config.target_host, self.config.target_port)
                )

            self.messages_sent += 1
            self._record_event("send", data=data)

            # Receive response
            try:
                if self.config.transport == Transport.TCP:
                    response = await asyncio.get_event_loop().run_in_executor(
                        None, self.socket.recv, self.config.max_message_size
                    )
                else:  # UDP
                    response, _ = await asyncio.get_event_loop().run_in_executor(
                        None, self.socket.recvfrom, self.config.max_message_size
                    )

                if response:
                    self.responses_received += 1
                    self._record_event("receive", response=response)

            except socket.timeout:
                self.timeouts += 1
                self._record_event("timeout", data=data)

        except ConnectionResetError:
            error = "Connection reset by peer"
            self.crashes_detected += 1
            self._record_event("crash", data=data, error=error)
        except BrokenPipeError:
            error = "Broken pipe"
            self.crashes_detected += 1
            self._record_event("crash", data=data, error=error)
        except Exception as e:
            error = str(e)
            self.errors.append({
                "type": "send_error",
                "message": error,
                "timestamp": time.time(),
            })
            self._record_event("error", data=data, error=error)

        # Check for crash indicators in response
        if response:
            crash = self._detect_crash(response)
            if crash:
                self.crashes_detected += 1
                self.interesting_responses.append({
                    "type": "crash_indicator",
                    "indicator": crash.name,
                    "severity": crash.severity,
                    "payload": data.hex()[:200],
                    "response": response[:500].hex(),
                    "timestamp": time.time(),
                })
                self._record_event("crash", data=data, response=response,
                                  details={"indicator": crash.name})

            # Check for interesting responses
            if self._is_interesting_response(response, data):
                self.interesting_responses.append({
                    "type": "interesting",
                    "payload": data.hex()[:200],
                    "response": response[:500].hex() if len(response) > 500 else response.hex(),
                    "timestamp": time.time(),
                })
                self._record_event("interesting", data=data, response=response)

        return response, error

    def _detect_crash(self, response: bytes) -> Optional[CrashIndicator]:
        """Check if response indicates a crash."""
        for indicator in self.crash_indicators:
            if indicator.pattern in response:
                return indicator
        return None

    def _is_interesting_response(self, response: bytes, payload: bytes) -> bool:
        """Determine if a response is interesting for further analysis."""
        # Very long responses
        if len(response) > 10000:
            return True

        # Response contains parts of our payload (potential reflection)
        if len(payload) > 10 and payload[:10] in response:
            return True

        # Response contains memory-like patterns (potential leak)
        if b"\x00\x00\x00\x00" in response or b"\xff\xff\xff\xff" in response:
            if len(response) > 100:
                return True

        # Error messages
        error_patterns = [b"error", b"fail", b"invalid", b"denied", b"overflow"]
        for pattern in error_patterns:
            if pattern.lower() in response.lower():
                return True

        return False

    def _record_event(self, event_type: str, data: Optional[bytes] = None,
                     response: Optional[bytes] = None, error: Optional[str] = None,
                     details: Optional[Dict[str, Any]] = None):
        """Record a fuzzing event."""
        self.events.append(FuzzingEvent(
            event_type=event_type,
            timestamp=time.time(),
            data=data,
            response=response,
            error=error,
            state=self.current_state,
            details=details or {},
        ))

    # =========================================================================
    # Mutation Strategies
    # =========================================================================

    def generate_mutations(self, seed: bytes, count: int = 100) -> List[bytes]:
        """Generate mutated payloads from a seed."""
        mutations = [seed]  # Include original

        for _ in range(count - 1):
            strategy = random.choice([
                self._mutate_bit_flip,
                self._mutate_byte_flip,
                self._mutate_insert,
                self._mutate_delete,
                self._mutate_replace,
                self._mutate_havoc,
                self._mutate_arithmetic,
                self._mutate_interesting_values,
            ])
            mutated = strategy(seed)
            if mutated not in mutations:
                mutations.append(mutated)

        return mutations

    def _mutate_bit_flip(self, data: bytes) -> bytes:
        """Flip random bits."""
        if not data:
            return data
        data = bytearray(data)
        for _ in range(random.randint(1, 5)):
            pos = random.randint(0, len(data) - 1)
            bit = random.randint(0, 7)
            data[pos] ^= (1 << bit)
        return bytes(data)

    def _mutate_byte_flip(self, data: bytes) -> bytes:
        """Flip random bytes."""
        if not data:
            return data
        data = bytearray(data)
        for _ in range(random.randint(1, 3)):
            pos = random.randint(0, len(data) - 1)
            data[pos] ^= 0xFF
        return bytes(data)

    def _mutate_insert(self, data: bytes) -> bytes:
        """Insert random bytes."""
        data = bytearray(data)
        pos = random.randint(0, len(data))
        insert_data = bytes([random.randint(0, 255) for _ in range(random.randint(1, 16))])
        return bytes(data[:pos] + insert_data + data[pos:])

    def _mutate_delete(self, data: bytes) -> bytes:
        """Delete random bytes."""
        if len(data) < 2:
            return data
        data = bytearray(data)
        start = random.randint(0, len(data) - 1)
        length = random.randint(1, min(16, len(data) - start))
        return bytes(data[:start] + data[start + length:])

    def _mutate_replace(self, data: bytes) -> bytes:
        """Replace random section with random bytes."""
        if not data:
            return data
        data = bytearray(data)
        start = random.randint(0, len(data) - 1)
        length = random.randint(1, min(16, len(data) - start))
        for i in range(length):
            data[start + i] = random.randint(0, 255)
        return bytes(data)

    def _mutate_havoc(self, data: bytes) -> bytes:
        """Apply multiple random mutations (havoc mode)."""
        result = data
        for _ in range(random.randint(2, 8)):
            strategy = random.choice([
                self._mutate_bit_flip,
                self._mutate_byte_flip,
                self._mutate_insert,
                self._mutate_delete,
                self._mutate_replace,
            ])
            result = strategy(result)
        return result

    def _mutate_arithmetic(self, data: bytes) -> bytes:
        """Apply arithmetic mutations to integer-like values."""
        if len(data) < 4:
            return self._mutate_byte_flip(data)

        data = bytearray(data)
        pos = random.randint(0, len(data) - 4)
        width = random.choice([1, 2, 4])

        if width == 1:
            value = data[pos]
            value = (value + random.randint(-35, 35)) & 0xFF
            data[pos] = value
        elif width == 2:
            value = struct.unpack("<H", bytes(data[pos:pos+2]))[0]
            value = (value + random.randint(-1000, 1000)) & 0xFFFF
            data[pos:pos+2] = struct.pack("<H", value)
        else:  # 4 bytes
            value = struct.unpack("<I", bytes(data[pos:pos+4]))[0]
            value = (value + random.randint(-10000, 10000)) & 0xFFFFFFFF
            data[pos:pos+4] = struct.pack("<I", value)

        return bytes(data)

    def _mutate_interesting_values(self, data: bytes) -> bytes:
        """Replace values with interesting edge cases."""
        if len(data) < 4:
            return data

        interesting_8 = [0, 1, 0x7F, 0x80, 0xFF]
        interesting_16 = [0, 1, 0x7FFF, 0x8000, 0xFFFF]
        interesting_32 = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]

        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        width = random.choice([1, 2, 4])

        if width == 1:
            data[pos] = random.choice(interesting_8)
        elif width == 2 and pos + 1 < len(data):
            struct.pack_into("<H", data, pos, random.choice(interesting_16))
        elif width == 4 and pos + 3 < len(data):
            struct.pack_into("<I", data, pos, random.choice(interesting_32))

        return bytes(data)

    # =========================================================================
    # Fuzzing Modes
    # =========================================================================

    async def fuzz_stateless(
        self,
        payloads: List[bytes],
        reconnect_between: bool = False
    ) -> AsyncGenerator[FuzzingEvent, None]:
        """Stateless fuzzing - send payloads without protocol awareness."""
        logger.info(f"Starting stateless fuzzing with {len(payloads)} payloads")

        if not self.connected:
            if not await self.connect():
                yield FuzzingEvent(
                    event_type="error",
                    timestamp=time.time(),
                    error="Failed to connect",
                )
                return

        for i, payload in enumerate(payloads):
            if reconnect_between and i > 0:
                await self.disconnect()
                if not await self.connect():
                    continue

            response, error = await self.send_message(payload)

            yield FuzzingEvent(
                event_type="fuzz_iteration",
                timestamp=time.time(),
                data=payload,
                response=response,
                error=error,
                details={
                    "iteration": i + 1,
                    "total": len(payloads),
                    "messages_sent": self.messages_sent,
                    "crashes": self.crashes_detected,
                },
            )

            if self.config.delay_between_messages_ms > 0:
                await asyncio.sleep(self.config.delay_between_messages_ms / 1000)

            # Reconnect on error if configured
            if error and self.config.reconnect_on_error:
                await self.disconnect()
                await self.connect()

        await self.disconnect()

    async def fuzz_stateful(
        self,
        protocol: ProtocolDefinition,
        max_iterations: int = 1000,
        mutate_probability: float = 0.3
    ) -> AsyncGenerator[FuzzingEvent, None]:
        """Stateful fuzzing following protocol state machine."""
        logger.info(f"Starting stateful fuzzing for {protocol.name}")

        self.config.protocol = protocol

        if not await self.connect():
            yield FuzzingEvent(
                event_type="error",
                timestamp=time.time(),
                error="Failed to connect",
            )
            return

        self.current_state = protocol.initial_state
        iteration = 0

        while iteration < max_iterations and self.connected:
            state = protocol.states.get(self.current_state)
            if not state:
                logger.error(f"Unknown state: {self.current_state}")
                break

            # Generate payload for current state
            payload = self._generate_state_payload(state, protocol, mutate_probability)

            # Send and receive
            response, error = await self.send_message(payload)

            # Determine next state based on response
            next_state = self._determine_next_state(state, response)

            yield FuzzingEvent(
                event_type="state_transition",
                timestamp=time.time(),
                data=payload,
                response=response,
                error=error,
                state=self.current_state,
                details={
                    "next_state": next_state,
                    "iteration": iteration + 1,
                    "messages_sent": self.messages_sent,
                    "crashes": self.crashes_detected,
                },
            )

            if next_state:
                self.current_state = next_state

            iteration += 1

            if error and self.config.reconnect_on_error:
                await self.disconnect()
                if await self.connect():
                    self.current_state = protocol.initial_state

            if self.config.delay_between_messages_ms > 0:
                await asyncio.sleep(self.config.delay_between_messages_ms / 1000)

        await self.disconnect()

    def _generate_state_payload(
        self,
        state: ProtocolState,
        protocol: ProtocolDefinition,
        mutate_probability: float
    ) -> bytes:
        """Generate a payload appropriate for the current protocol state."""
        # Generate base payload based on protocol and state
        base_payload = self._get_base_payload_for_state(state, protocol)

        # Optionally mutate
        if random.random() < mutate_probability:
            return self.generate_mutations(base_payload, count=1)[0]

        return base_payload

    def _get_base_payload_for_state(
        self,
        state: ProtocolState,
        protocol: ProtocolDefinition
    ) -> bytes:
        """Get a base payload for a given state."""
        line_ending = protocol.line_ending

        # Protocol-specific payload generation
        if protocol.name == "HTTP/1.1":
            return self._generate_http_payload(state)
        elif protocol.name == "FTP":
            return self._generate_ftp_payload(state)
        elif protocol.name == "SMTP":
            return self._generate_smtp_payload(state)
        elif protocol.name == "DNS":
            return self._generate_dns_payload()
        elif protocol.name == "Modbus/TCP":
            return self._generate_modbus_payload()
        else:
            # Generic payload
            return b"TEST" + line_ending

    def _generate_http_payload(self, state: ProtocolState) -> bytes:
        """Generate HTTP request payload."""
        methods = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"]
        paths = [b"/", b"/index.html", b"/api/test", b"/" + b"A" * 1000]

        method = random.choice(methods)
        path = random.choice(paths)

        headers = [
            b"Host: " + self.config.target_host.encode(),
            b"User-Agent: NetworkFuzzer/1.0",
            b"Accept: */*",
        ]

        # Sometimes add malicious headers
        if random.random() < 0.3:
            headers.extend([
                b"X-Forwarded-For: " + b"A" * random.randint(100, 1000),
                b"Content-Length: " + str(random.randint(-1, 999999999)).encode(),
            ])

        request = method + b" " + path + b" HTTP/1.1\r\n"
        request += b"\r\n".join(headers) + b"\r\n\r\n"

        return request

    def _generate_ftp_payload(self, state: ProtocolState) -> bytes:
        """Generate FTP command payload."""
        commands = {
            "auth": b"USER anonymous\r\n",
            "password": b"PASS test@test.com\r\n",
            "ready": random.choice([
                b"LIST\r\n",
                b"PWD\r\n",
                b"CWD /\r\n",
                b"PASV\r\n",
                b"TYPE I\r\n",
                b"RETR " + b"A" * random.randint(10, 500) + b"\r\n",
            ]),
        }
        return commands.get(state.name, b"NOOP\r\n")

    def _generate_smtp_payload(self, state: ProtocolState) -> bytes:
        """Generate SMTP command payload."""
        commands = {
            "helo": b"EHLO test.local\r\n",
            "mail": b"MAIL FROM:<test@test.local>\r\n",
            "rcpt": b"RCPT TO:<" + b"A" * random.randint(10, 200) + b"@test.local>\r\n",
            "data": b"DATA\r\n",
            "content": b"Subject: Test\r\n\r\nTest message\r\n.\r\n",
        }
        return commands.get(state.name, b"NOOP\r\n")

    def _generate_dns_payload(self) -> bytes:
        """Generate DNS query payload."""
        # DNS header
        transaction_id = struct.pack(">H", random.randint(0, 65535))
        flags = struct.pack(">H", 0x0100)  # Standard query
        questions = struct.pack(">H", 1)
        answer_rrs = struct.pack(">H", 0)
        authority_rrs = struct.pack(">H", 0)
        additional_rrs = struct.pack(">H", 0)

        header = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs

        # Query name (random domain)
        domain = b"".join([
            bytes([len(label)]) + label
            for label in [
                b"test" + str(random.randint(0, 9999)).encode(),
                b"example",
                b"com"
            ]
        ]) + b"\x00"

        # Query type (A) and class (IN)
        query_type = struct.pack(">H", 1)  # A record
        query_class = struct.pack(">H", 1)  # IN class

        return header + domain + query_type + query_class

    def _generate_modbus_payload(self) -> bytes:
        """Generate Modbus/TCP request payload."""
        # MBAP Header
        transaction_id = struct.pack(">H", random.randint(0, 65535))
        protocol_id = struct.pack(">H", 0)  # Modbus protocol
        length = struct.pack(">H", 6)  # Length of remaining bytes
        unit_id = bytes([random.randint(0, 255)])

        # Function codes
        function_codes = [
            1,   # Read Coils
            2,   # Read Discrete Inputs
            3,   # Read Holding Registers
            4,   # Read Input Registers
            5,   # Write Single Coil
            6,   # Write Single Register
            15,  # Write Multiple Coils
            16,  # Write Multiple Registers
        ]
        function_code = bytes([random.choice(function_codes)])

        # Starting address and quantity
        start_addr = struct.pack(">H", random.randint(0, 65535))
        quantity = struct.pack(">H", random.randint(1, 125))

        return transaction_id + protocol_id + length + unit_id + function_code + start_addr + quantity

    def _determine_next_state(
        self,
        current_state: ProtocolState,
        response: Optional[bytes]
    ) -> Optional[str]:
        """Determine the next state based on response."""
        if not response:
            return None

        response_str = response.decode("utf-8", errors="ignore")

        for pattern, next_state in current_state.transitions.items():
            if re.match(pattern, response_str, re.DOTALL):
                return next_state

        return None

    # =========================================================================
    # Results
    # =========================================================================

    def get_results(self) -> NetworkFuzzResult:
        """Get fuzzing session results."""
        return NetworkFuzzResult(
            session_id=self.session_id,
            target_host=self.config.target_host,
            target_port=self.config.target_port,
            transport=self.config.transport.value,
            protocol_name=self.config.protocol.name if self.config.protocol else None,
            messages_sent=self.messages_sent,
            responses_received=self.responses_received,
            errors=self.errors,
            crashes_detected=self.crashes_detected,
            timeouts=self.timeouts,
            interesting_responses=self.interesting_responses,
            duration_sec=time.time() - self._start_time,
            events=self.events,
        )


# =============================================================================
# Helper Functions
# =============================================================================

def get_protocol_template(name: str) -> Optional[ProtocolDefinition]:
    """Get a built-in protocol template by name."""
    return PROTOCOL_TEMPLATES.get(name.lower())


def list_protocol_templates() -> Dict[str, Dict[str, Any]]:
    """List all available protocol templates."""
    return {
        name: {
            "name": proto.name,
            "transport": proto.transport.value,
            "port": proto.port,
            "description": proto.description,
            "states": list(proto.states.keys()),
        }
        for name, proto in PROTOCOL_TEMPLATES.items()
    }


async def quick_fuzz(
    host: str,
    port: int,
    transport: str = "tcp",
    payloads: Optional[List[bytes]] = None,
    timeout_ms: int = 5000,
    max_payloads: int = 100
) -> NetworkFuzzResult:
    """Quick stateless fuzzing of a network target."""
    config = NetworkFuzzConfig(
        target_host=host,
        target_port=port,
        transport=Transport(transport),
        timeout_ms=timeout_ms,
    )

    fuzzer = NetworkProtocolFuzzer(config)

    if not payloads:
        # Generate default test payloads
        seed = b"TEST\x00\x01\x02\x03"
        payloads = fuzzer.generate_mutations(seed, count=max_payloads)

    async for _ in fuzzer.fuzz_stateless(payloads):
        pass  # Process events

    return fuzzer.get_results()


async def protocol_fuzz(
    host: str,
    port: int,
    protocol_name: str,
    max_iterations: int = 1000,
    timeout_ms: int = 5000
) -> NetworkFuzzResult:
    """Fuzz a target using a known protocol template."""
    protocol = get_protocol_template(protocol_name)
    if not protocol:
        raise ValueError(f"Unknown protocol: {protocol_name}")

    config = NetworkFuzzConfig(
        target_host=host,
        target_port=port,
        transport=protocol.transport,
        protocol=protocol,
        timeout_ms=timeout_ms,
    )

    fuzzer = NetworkProtocolFuzzer(config)

    async for _ in fuzzer.fuzz_stateful(protocol, max_iterations=max_iterations):
        pass

    return fuzzer.get_results()
