"""
Protocol & Format Fuzzing API Router

Endpoints for:
- Network Protocol Fuzzing (TCP/UDP with state machines)
- Grammar-Based Fuzzing (DSL-defined grammars)
- Structured Format Fuzzing (PNG, PDF, ZIP, etc.)
"""

import asyncio
import base64
import hashlib
import time
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, Depends
from pydantic import BaseModel, Field
import logging

from backend.core.auth import get_current_active_user
from backend.models.models import User

from backend.services.network_protocol_fuzzer import (
    NetworkProtocolFuzzer,
    NetworkFuzzConfig,
    Transport,
    get_protocol_template,
    list_protocol_templates,
    quick_fuzz,
    protocol_fuzz,
)
from backend.services.grammar_fuzzer_service import (
    GrammarFuzzerService,
    get_builtin_grammar,
    list_builtin_grammars,
    create_grammar_from_builtin,
    generate_from_builtin,
)
from backend.services.structured_format_service import (
    StructuredFormatService,
    FormatType,
    FormatFuzzConfig,
    list_supported_formats,
    detect_format,
    generate_sample,
)
from backend.services.format_mutators import (
    get_mutator,
    list_mutators,
    auto_mutate,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/protocol-fuzzer", tags=["protocol-fuzzer"])


# =============================================================================
# Request/Response Models
# =============================================================================

# Network Protocol Models
class NetworkConnectRequest(BaseModel):
    target_host: str = Field(..., description="Target hostname or IP")
    target_port: int = Field(..., ge=1, le=65535, description="Target port")
    transport: str = Field("tcp", description="Transport protocol (tcp/udp)")
    timeout_ms: int = Field(5000, ge=100, le=60000, description="Connection timeout")
    ssl_enabled: bool = Field(False, description="Enable SSL/TLS")


class NetworkSendRequest(BaseModel):
    session_id: str = Field(..., description="Session ID from connect")
    data: str = Field(..., description="Base64-encoded data to send")
    expect_response: bool = Field(True, description="Wait for response")


class StatelessFuzzRequest(BaseModel):
    target_host: str
    target_port: int
    transport: str = "tcp"
    payloads: Optional[List[str]] = Field(None, description="Base64-encoded payloads (or generate)")
    seed: Optional[str] = Field(None, description="Base64-encoded seed for mutation")
    count: int = Field(100, ge=1, le=10000, description="Number of payloads to send")
    timeout_ms: int = Field(5000, ge=100, le=60000)
    reconnect_between: bool = Field(False, description="Reconnect between each payload")


class StatefulFuzzRequest(BaseModel):
    target_host: str
    target_port: int
    protocol_name: str = Field(..., description="Built-in protocol name (http, ftp, smtp, dns, modbus)")
    max_iterations: int = Field(1000, ge=1, le=100000)
    mutation_rate: float = Field(0.3, ge=0.0, le=1.0)
    timeout_ms: int = Field(5000, ge=100, le=60000)


class CustomProtocolRequest(BaseModel):
    name: str
    transport: str = "tcp"
    port: int = Field(..., ge=1, le=65535)
    states: Dict[str, Dict[str, Any]]
    initial_state: str
    message_format: str = "text"


# Grammar Fuzzing Models
class GrammarGenerateRequest(BaseModel):
    grammar_name: Optional[str] = Field(None, description="Built-in grammar name")
    grammar_json: Optional[Dict[str, Any]] = Field(None, description="Custom grammar definition")
    count: int = Field(10, ge=1, le=1000, description="Number of inputs to generate")


class GrammarMutateRequest(BaseModel):
    grammar_name: Optional[str] = None
    grammar_json: Optional[Dict[str, Any]] = None
    input_data: str = Field(..., description="Base64-encoded input to mutate")
    rule: Optional[str] = Field(None, description="Specific rule to mutate at")


class GrammarInferRequest(BaseModel):
    samples: List[str] = Field(..., description="Base64-encoded sample inputs")
    name: str = Field("inferred", description="Name for inferred grammar")


class GrammarFuzzRequest(BaseModel):
    grammar_name: Optional[str] = None
    grammar_json: Optional[Dict[str, Any]] = None
    count: int = Field(1000, ge=1, le=100000)
    mutation_rate: float = Field(0.3, ge=0.0, le=1.0)
    crossover_rate: float = Field(0.2, ge=0.0, le=1.0)


# Format Fuzzing Models
class FormatDetectRequest(BaseModel):
    data: str = Field(..., description="Base64-encoded file data")


class FormatParseRequest(BaseModel):
    data: str = Field(..., description="Base64-encoded file data")
    format_type: Optional[str] = Field(None, description="Force specific format type")


class FormatMutateRequest(BaseModel):
    data: str = Field(..., description="Base64-encoded file data")
    format_type: Optional[str] = None
    field_name: Optional[str] = Field(None, description="Specific field to mutate")
    fix_checksums: bool = Field(True, description="Fix checksums after mutation")


class FormatFuzzRequest(BaseModel):
    seed_data: str = Field(..., description="Base64-encoded seed file")
    format_type: Optional[str] = None
    count: int = Field(100, ge=1, le=10000)
    fix_checksums: bool = True
    fix_sizes: bool = True
    target_fields: Optional[List[str]] = None


class FormatGenerateRequest(BaseModel):
    format_type: str = Field(..., description="Format type to generate (png, zip, pdf, gif)")


class MutatorRequest(BaseModel):
    data: str = Field(..., description="Base64-encoded data")
    format_name: Optional[str] = Field(None, description="Format name (auto-detect if not specified)")
    mutation_type: Optional[str] = Field(None, description="Specific mutation type")
    count: int = Field(1, ge=1, le=100, description="Number of mutations")


# =============================================================================
# Active Sessions Storage
# =============================================================================

_active_sessions: Dict[str, NetworkProtocolFuzzer] = {}
_session_results: Dict[str, Dict[str, Any]] = {}


# =============================================================================
# Network Protocol Endpoints
# =============================================================================

@router.post("/network/connect")
async def network_connect(request: NetworkConnectRequest, current_user: User = Depends(get_current_active_user)):
    """Connect to a network target."""
    config = NetworkFuzzConfig(
        target_host=request.target_host,
        target_port=request.target_port,
        transport=Transport(request.transport),
        timeout_ms=request.timeout_ms,
        ssl_enabled=request.ssl_enabled,
    )

    fuzzer = NetworkProtocolFuzzer(config)
    success = await fuzzer.connect()

    if success:
        _active_sessions[fuzzer.session_id] = fuzzer
        return {
            "success": True,
            "session_id": fuzzer.session_id,
            "message": f"Connected to {request.target_host}:{request.target_port}",
        }
    else:
        raise HTTPException(status_code=500, detail="Failed to connect to target")


@router.post("/network/disconnect")
async def network_disconnect(session_id: str, current_user: User = Depends(get_current_active_user)):
    """Disconnect from a network target."""
    fuzzer = _active_sessions.get(session_id)
    if not fuzzer:
        raise HTTPException(status_code=404, detail="Session not found")

    await fuzzer.disconnect()
    del _active_sessions[session_id]

    return {"success": True, "message": "Disconnected"}


@router.post("/network/send")
async def network_send(request: NetworkSendRequest, current_user: User = Depends(get_current_active_user)):
    """Send a message to the connected target."""
    fuzzer = _active_sessions.get(request.session_id)
    if not fuzzer:
        raise HTTPException(status_code=404, detail="Session not found")

    try:
        data = base64.b64decode(request.data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 data")

    response, error = await fuzzer.send_message(data)

    return {
        "success": error is None,
        "response": base64.b64encode(response).decode() if response else None,
        "response_text": response.decode("utf-8", errors="replace") if response else None,
        "error": error,
        "messages_sent": fuzzer.messages_sent,
        "crashes_detected": fuzzer.crashes_detected,
    }


@router.post("/network/fuzz/stateless")
async def network_fuzz_stateless(request: StatelessFuzzRequest, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_active_user)):
    """Run stateless network fuzzing session."""
    config = NetworkFuzzConfig(
        target_host=request.target_host,
        target_port=request.target_port,
        transport=Transport(request.transport),
        timeout_ms=request.timeout_ms,
        reconnect_on_error=True,
    )

    fuzzer = NetworkProtocolFuzzer(config)

    # Prepare payloads
    if request.payloads:
        payloads = [base64.b64decode(p) for p in request.payloads]
    elif request.seed:
        seed = base64.b64decode(request.seed)
        payloads = fuzzer.generate_mutations(seed, count=request.count)
    else:
        # Generate default payloads
        seed = b"TEST\x00\x01\x02\x03\r\n"
        payloads = fuzzer.generate_mutations(seed, count=request.count)

    session_id = fuzzer.session_id
    _session_results[session_id] = {"status": "running", "progress": 0}

    async def run_fuzzing():
        try:
            events = []
            async for event in fuzzer.fuzz_stateless(payloads, request.reconnect_between):
                events.append({
                    "type": event.event_type,
                    "iteration": event.details.get("iteration", 0),
                    "crashes": event.details.get("crashes", 0),
                })
                _session_results[session_id]["progress"] = event.details.get("iteration", 0) / len(payloads)

            result = fuzzer.get_results()
            _session_results[session_id] = {
                "status": "completed",
                "progress": 1.0,
                "result": {
                    "session_id": result.session_id,
                    "messages_sent": result.messages_sent,
                    "responses_received": result.responses_received,
                    "crashes_detected": result.crashes_detected,
                    "timeouts": result.timeouts,
                    "errors": result.errors,
                    "interesting_responses": result.interesting_responses[:50],
                    "duration_sec": result.duration_sec,
                },
            }
        except Exception as e:
            _session_results[session_id] = {"status": "error", "error": str(e)}

    background_tasks.add_task(run_fuzzing)

    return {
        "session_id": session_id,
        "status": "started",
        "message": f"Fuzzing {len(payloads)} payloads against {request.target_host}:{request.target_port}",
    }


@router.post("/network/fuzz/stateful")
async def network_fuzz_stateful(request: StatefulFuzzRequest, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_active_user)):
    """Run stateful protocol fuzzing session."""
    protocol = get_protocol_template(request.protocol_name)
    if not protocol:
        raise HTTPException(status_code=400, detail=f"Unknown protocol: {request.protocol_name}")

    config = NetworkFuzzConfig(
        target_host=request.target_host,
        target_port=request.target_port,
        transport=protocol.transport,
        protocol=protocol,
        timeout_ms=request.timeout_ms,
    )

    fuzzer = NetworkProtocolFuzzer(config)
    session_id = fuzzer.session_id
    _session_results[session_id] = {"status": "running", "progress": 0}

    async def run_fuzzing():
        try:
            async for event in fuzzer.fuzz_stateful(protocol, request.max_iterations, request.mutation_rate):
                _session_results[session_id]["progress"] = event.details.get("iteration", 0) / request.max_iterations

            result = fuzzer.get_results()
            _session_results[session_id] = {
                "status": "completed",
                "progress": 1.0,
                "result": {
                    "session_id": result.session_id,
                    "protocol_name": result.protocol_name,
                    "messages_sent": result.messages_sent,
                    "responses_received": result.responses_received,
                    "crashes_detected": result.crashes_detected,
                    "timeouts": result.timeouts,
                    "errors": result.errors,
                    "interesting_responses": result.interesting_responses[:50],
                    "duration_sec": result.duration_sec,
                },
            }
        except Exception as e:
            _session_results[session_id] = {"status": "error", "error": str(e)}

    background_tasks.add_task(run_fuzzing)

    return {
        "session_id": session_id,
        "status": "started",
        "protocol": request.protocol_name,
        "message": f"Stateful fuzzing {request.protocol_name} against {request.target_host}:{request.target_port}",
    }


@router.get("/network/fuzz/status/{session_id}")
async def get_fuzz_status(session_id: str, current_user: User = Depends(get_current_active_user)):
    """Get status of a fuzzing session."""
    if session_id not in _session_results:
        raise HTTPException(status_code=404, detail="Session not found")

    return _session_results[session_id]


@router.get("/network/protocols")
async def list_protocols(current_user: User = Depends(get_current_active_user)):
    """List available built-in protocols."""
    return {
        "protocols": list_protocol_templates(),
    }


@router.post("/network/protocols/custom")
async def register_custom_protocol(request: CustomProtocolRequest, current_user: User = Depends(get_current_active_user)):
    """Register a custom protocol definition."""
    # For now, just validate and return - actual registration would need persistence
    return {
        "success": True,
        "message": f"Custom protocol '{request.name}' validated",
        "protocol": {
            "name": request.name,
            "transport": request.transport,
            "port": request.port,
            "states": list(request.states.keys()),
        },
    }


# =============================================================================
# Grammar Fuzzing Endpoints
# =============================================================================

@router.get("/grammar/grammars")
async def list_grammars(current_user: User = Depends(get_current_active_user)):
    """List available built-in grammars."""
    return {
        "grammars": list_builtin_grammars(),
    }


@router.get("/grammar/grammars/{grammar_name}")
async def get_grammar(grammar_name: str, current_user: User = Depends(get_current_active_user)):
    """Get a specific built-in grammar definition."""
    grammar = get_builtin_grammar(grammar_name)
    if not grammar:
        raise HTTPException(status_code=404, detail=f"Grammar not found: {grammar_name}")

    return {"grammar": grammar}


@router.post("/grammar/generate")
async def grammar_generate(request: GrammarGenerateRequest, current_user: User = Depends(get_current_active_user)):
    """Generate inputs from a grammar."""
    service = GrammarFuzzerService()

    if request.grammar_name:
        grammar_def = get_builtin_grammar(request.grammar_name)
        if not grammar_def:
            raise HTTPException(status_code=404, detail=f"Grammar not found: {request.grammar_name}")
        service.load_grammar(grammar_def)
    elif request.grammar_json:
        service.load_grammar(request.grammar_json)
    else:
        raise HTTPException(status_code=400, detail="Either grammar_name or grammar_json required")

    try:
        inputs = service.generate(count=request.count)
        return {
            "count": len(inputs),
            "inputs": [
                {
                    "data": base64.b64encode(inp.data).decode(),
                    "data_text": inp.data.decode("utf-8", errors="replace")[:1000],
                    "size": inp.size,
                    "depth": inp.depth,
                    "rules_used": inp.rules_used,
                    "generation_time_ms": inp.generation_time_ms,
                }
                for inp in inputs
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Generation failed: {e}")


@router.post("/grammar/mutate")
async def grammar_mutate(request: GrammarMutateRequest, current_user: User = Depends(get_current_active_user)):
    """Mutate an input using grammar rules."""
    service = GrammarFuzzerService()

    if request.grammar_name:
        grammar_def = get_builtin_grammar(request.grammar_name)
        if not grammar_def:
            raise HTTPException(status_code=404, detail=f"Grammar not found: {request.grammar_name}")
        service.load_grammar(grammar_def)
    elif request.grammar_json:
        service.load_grammar(request.grammar_json)
    else:
        raise HTTPException(status_code=400, detail="Either grammar_name or grammar_json required")

    try:
        input_data = base64.b64decode(request.input_data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 input data")

    # First generate to get a proper input with derivation tree
    inputs = service.generate(count=1)
    if not inputs:
        raise HTTPException(status_code=500, detail="Failed to generate base input")

    mutation = service.mutate_at_rule(inputs[0], request.rule)

    return {
        "original": base64.b64encode(mutation.original.data).decode(),
        "mutated": base64.b64encode(mutation.mutated.data).decode(),
        "mutated_text": mutation.mutated.data.decode("utf-8", errors="replace")[:1000],
        "mutation_type": mutation.mutation_type,
        "rule_mutated": mutation.rule_mutated,
    }


@router.post("/grammar/infer")
async def grammar_infer(request: GrammarInferRequest, current_user: User = Depends(get_current_active_user)):
    """Infer a grammar from sample inputs."""
    try:
        samples = [base64.b64decode(s) for s in request.samples]
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 samples")

    if len(samples) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 samples")

    service = GrammarFuzzerService()
    grammar = service.infer_grammar(samples, name=request.name)

    return {
        "grammar": {
            "name": grammar.name,
            "start_symbol": grammar.start_symbol,
            "rules": {name: {"type": rule.type.value, "productions": rule.productions} for name, rule in grammar.rules.items()},
            "terminals": {name: {"type": term.type.value, "value": term.value} for name, term in grammar.terminals.items()},
            "description": grammar.description,
        },
    }


@router.post("/grammar/fuzz")
async def grammar_fuzz(request: GrammarFuzzRequest, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_active_user)):
    """Run a grammar-based fuzzing session."""
    service = GrammarFuzzerService()

    if request.grammar_name:
        grammar_def = get_builtin_grammar(request.grammar_name)
        if not grammar_def:
            raise HTTPException(status_code=404, detail=f"Grammar not found: {request.grammar_name}")
        grammar = service.load_grammar(grammar_def)
    elif request.grammar_json:
        grammar = service.load_grammar(request.grammar_json)
    else:
        raise HTTPException(status_code=400, detail="Either grammar_name or grammar_json required")

    session_id = hashlib.md5(f"{grammar.name}:{time.time()}".encode()).hexdigest()[:16]
    _session_results[session_id] = {"status": "running", "progress": 0, "generated": []}

    async def dummy_callback(data: bytes) -> Dict[str, Any]:
        # Placeholder callback - in real use, this would send to a target
        return {"interesting": len(data) > 100}

    async def run_fuzzing():
        try:
            generated = []
            async for event in service.fuzz_with_grammar(
                dummy_callback,
                grammar,
                count=request.count,
                mutation_rate=request.mutation_rate,
                crossover_rate=request.crossover_rate,
            ):
                generated.append({
                    "operation": event["operation"],
                    "size": event["input_size"],
                })
                _session_results[session_id]["progress"] = event["iteration"] / event["total"]
                _session_results[session_id]["generated"] = generated[-100:]  # Keep last 100

            _session_results[session_id] = {
                "status": "completed",
                "progress": 1.0,
                "total_generated": len(generated),
                "sample_outputs": generated[-20:],
            }
        except Exception as e:
            _session_results[session_id] = {"status": "error", "error": str(e)}

    background_tasks.add_task(run_fuzzing)

    return {
        "session_id": session_id,
        "status": "started",
        "grammar_name": grammar.name,
    }


# =============================================================================
# Format Fuzzing Endpoints
# =============================================================================

@router.get("/format/formats")
async def list_formats(current_user: User = Depends(get_current_active_user)):
    """List supported file formats."""
    return {
        "formats": list_supported_formats(),
        "mutators": list_mutators(),
    }


@router.post("/format/detect")
async def format_detect(request: FormatDetectRequest, current_user: User = Depends(get_current_active_user)):
    """Detect file format from data."""
    try:
        data = base64.b64decode(request.data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 data")

    format_type = detect_format(data)

    return {
        "format": format_type.value,
        "size": len(data),
    }


@router.post("/format/parse")
async def format_parse(request: FormatParseRequest, current_user: User = Depends(get_current_active_user)):
    """Parse file structure."""
    try:
        data = base64.b64decode(request.data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 data")

    service = StructuredFormatService()
    format_type = FormatType(request.format_type) if request.format_type else None

    parsed = service.parse_structure(data, format_type)

    return {
        "format": parsed.structure.format_type.value,
        "valid": parsed.valid,
        "errors": parsed.errors,
        "total_size": parsed.total_size,
        "header_fields": [
            {
                "name": pf.field.name,
                "offset": pf.offset,
                "size": pf.field.size,
                "type": pf.field.field_type.value,
                "value": str(pf.value) if not isinstance(pf.value, bytes) else pf.value.hex()[:50],
            }
            for pf in parsed.header_fields
        ],
        "chunks": [
            {
                "name": pc.chunk.name,
                "offset": pc.offset,
                "size": pc.size,
                "fields": [
                    {"name": pf.field.name, "value": str(pf.value)[:50]}
                    for pf in pc.fields
                ],
            }
            for pc in parsed.chunks
        ],
    }


@router.post("/format/mutate")
async def format_mutate(request: FormatMutateRequest, current_user: User = Depends(get_current_active_user)):
    """Apply structure-aware mutation."""
    try:
        data = base64.b64decode(request.data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 data")

    service = StructuredFormatService()
    format_type = FormatType(request.format_type) if request.format_type else None

    parsed = service.parse_structure(data, format_type)

    if request.field_name:
        mutation = service.mutate_field(data, request.field_name, parsed, request.fix_checksums)
    else:
        # Random field mutation
        all_fields = [pf.field.name for pf in parsed.header_fields if not pf.field.is_checksum]
        if all_fields:
            field_name = all_fields[0]
            mutation = service.mutate_field(data, field_name, parsed, request.fix_checksums)
        else:
            raise HTTPException(status_code=400, detail="No mutable fields found")

    return {
        "original_size": len(mutation.original),
        "mutated_size": len(mutation.mutated),
        "mutation_type": mutation.mutation_type,
        "field_mutated": mutation.field_mutated,
        "checksum_fixed": mutation.checksum_fixed,
        "mutated_data": base64.b64encode(mutation.mutated).decode(),
    }


@router.post("/format/fix-checksums")
async def format_fix_checksums(request: FormatDetectRequest, current_user: User = Depends(get_current_active_user)):
    """Fix checksums in file data."""
    try:
        data = base64.b64decode(request.data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 data")

    service = StructuredFormatService()
    fixed = service.fix_checksums(data)

    return {
        "original_size": len(data),
        "fixed_size": len(fixed),
        "changed": data != fixed,
        "fixed_data": base64.b64encode(fixed).decode(),
    }


@router.post("/format/generate")
async def format_generate(request: FormatGenerateRequest, current_user: User = Depends(get_current_active_user)):
    """Generate a minimal valid sample of a format."""
    try:
        data = generate_sample(request.format_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not data:
        raise HTTPException(status_code=400, detail=f"Cannot generate sample for format: {request.format_type}")

    return {
        "format": request.format_type,
        "size": len(data),
        "data": base64.b64encode(data).decode(),
    }


@router.post("/format/fuzz")
async def format_fuzz(request: FormatFuzzRequest, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_active_user)):
    """Run structure-aware format fuzzing."""
    try:
        seed = base64.b64decode(request.seed_data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 seed data")

    service = StructuredFormatService()
    format_type = FormatType(request.format_type) if request.format_type else None

    config = FormatFuzzConfig(
        format_type=format_type or service.detect_format(seed),
        fix_checksums=request.fix_checksums,
        fix_sizes=request.fix_sizes,
        target_fields=request.target_fields,
    )

    session_id = hashlib.md5(f"format:{time.time()}".encode()).hexdigest()[:16]
    _session_results[session_id] = {"status": "running", "progress": 0, "mutations": []}

    async def run_fuzzing():
        try:
            mutations = []
            async for mutation in service.fuzz_format(seed, format_type, config, request.count):
                mutations.append({
                    "type": mutation.mutation_type,
                    "field": mutation.field_mutated,
                    "checksum_fixed": mutation.checksum_fixed,
                })
                _session_results[session_id]["progress"] = mutation.details.get("iteration", 0) / mutation.details.get("total", 1)
                _session_results[session_id]["mutations"] = mutations[-100:]

            _session_results[session_id] = {
                "status": "completed",
                "progress": 1.0,
                "total_mutations": len(mutations),
                "sample_mutations": mutations[-20:],
            }
        except Exception as e:
            _session_results[session_id] = {"status": "error", "error": str(e)}

    background_tasks.add_task(run_fuzzing)

    return {
        "session_id": session_id,
        "status": "started",
        "format": config.format_type.value,
    }


@router.get("/format/mutators")
async def get_mutators(current_user: User = Depends(get_current_active_user)):
    """List available format-specific mutators."""
    return {"mutators": list_mutators()}


@router.post("/format/mutators/apply")
async def apply_mutator(request: MutatorRequest, current_user: User = Depends(get_current_active_user)):
    """Apply format-specific mutations."""
    try:
        data = base64.b64decode(request.data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 data")

    if request.format_name:
        mutator = get_mutator(request.format_name)
        if not mutator:
            raise HTTPException(status_code=404, detail=f"Mutator not found: {request.format_name}")

        if not mutator.validate(data):
            raise HTTPException(status_code=400, detail=f"Data is not valid {mutator.format_name}")

        results = mutator.mutate_random(data, request.count)
    else:
        results = auto_mutate(data, request.count)

    return {
        "count": len(results),
        "mutations": [
            {
                "mutation_name": r.mutation_name,
                "description": r.description,
                "original_size": len(r.original),
                "mutated_size": len(r.mutated),
                "locations_modified": r.locations_modified[:10],
                "metadata": r.metadata,
                "mutated_data": base64.b64encode(r.mutated).decode(),
            }
            for r in results
        ],
    }


# =============================================================================
# WebSocket Endpoints
# =============================================================================

@router.websocket("/network/fuzz/ws/{session_id}")
async def network_fuzz_websocket(websocket: WebSocket, session_id: str):
    """WebSocket for real-time fuzzing progress."""
    await websocket.accept()

    try:
        while True:
            if session_id in _session_results:
                result = _session_results[session_id]
                await websocket.send_json(result)

                if result.get("status") in ["completed", "error"]:
                    break

            await asyncio.sleep(0.5)

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for session {session_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()


@router.websocket("/grammar/fuzz/ws/{session_id}")
async def grammar_fuzz_websocket(websocket: WebSocket, session_id: str):
    """WebSocket for grammar fuzzing progress."""
    await websocket.accept()

    try:
        while True:
            if session_id in _session_results:
                result = _session_results[session_id]
                await websocket.send_json(result)

                if result.get("status") in ["completed", "error"]:
                    break

            await asyncio.sleep(0.5)

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for session {session_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()
