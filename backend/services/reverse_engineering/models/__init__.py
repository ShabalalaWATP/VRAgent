"""
Reverse Engineering Service - Type Definitions and Models

This module contains all dataclasses and type definitions used by the reverse engineering service:
- Data Flow Analysis Types (TaintSource, TaintSink, DataFlowPath, etc.)
- Type Recovery Types (RecoveredField, RecoveredStruct, RecoveredFunctionSignature, etc.)
- Emulation Types (EmulationTrace, EmulationState, DecodedString, etc.)
- Symbolic Execution Types (SymbolicInput, SymbolicPath, CrashInput, etc.)
- Binary Diffing Types (FunctionDiff, BlockDiff, BinaryDiffResult, etc.)
- ROP Gadget Types (ROPGadget, ROPChainTemplate, ROPGadgetResult, etc.)
- JADX Types (JadxDecompiledClass, JadxDecompilationResult, etc.)
- Manifest Visualization Types (ManifestNode, ManifestEdge, ManifestVisualization, etc.)
- Attack Surface Types (AttackVector, ExposedDataPath, AttackSurfaceMap, etc.)
- Secret Patterns and Legitimacy Indicators
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
import re


# ============================================================================
# Data Flow Analysis Types
# ============================================================================

@dataclass
class TaintSource:
    """A source of tainted (untrusted) data."""
    address: int
    source_type: str  # "user_input", "network", "file", "environment", "argv"
    register_or_memory: str  # Which register or memory location is tainted
    function_name: Optional[str] = None
    description: str = ""


@dataclass
class TaintSink:
    """A dangerous sink where tainted data should not reach."""
    address: int
    sink_type: str  # "exec", "sql", "file_write", "format_string", "memcpy"
    function_name: str
    cwe_id: str = ""
    description: str = ""


@dataclass
class TaintedValue:
    """A value that is tainted (derived from untrusted input)."""
    location: str  # Register name or memory address
    source: TaintSource
    transformations: List[str] = field(default_factory=list)  # Operations applied
    confidence: float = 1.0  # How confident we are it's still tainted


@dataclass
class DataFlowPath:
    """A path from a taint source to a sink."""
    source: TaintSource
    sink: TaintSink
    path: List[int]  # Addresses along the path
    instructions: List[str]  # Instruction summaries along path
    is_exploitable: bool = False
    sanitizers_found: List[str] = field(default_factory=list)
    confidence: float = 0.0
    vulnerability_type: Optional[str] = None
    cwe_id: Optional[str] = None


@dataclass
class DataFlowAnalysisResult:
    """Complete data flow analysis result."""
    taint_sources: List[TaintSource]
    taint_sinks: List[TaintSink]
    data_flow_paths: List[DataFlowPath]
    vulnerable_paths: List[DataFlowPath]
    total_paths_analyzed: int = 0
    analysis_coverage: float = 0.0


# ============================================================================
# Type Recovery Types
# ============================================================================

@dataclass
class RecoveredField:
    """A recovered struct/class field."""
    offset: int
    size: int
    inferred_type: str  # "int", "ptr", "char[]", "float", "unknown"
    access_pattern: str  # "read", "write", "read_write"
    name: Optional[str] = None  # Recovered or generated name


@dataclass
class RecoveredStruct:
    """A recovered structure/class type."""
    address: int  # Where it's allocated or referenced
    total_size: int
    fields: List[RecoveredField]
    inferred_name: Optional[str] = None
    confidence: float = 0.0
    usage_count: int = 0  # How many times this struct pattern appears


@dataclass
class RecoveredArgument:
    """A recovered function argument."""
    index: int
    register_or_stack: str  # "rdi", "rsi", "[rbp+0x10]", etc.
    inferred_type: str
    inferred_name: Optional[str] = None
    is_pointer: bool = False
    points_to: Optional[str] = None  # What the pointer points to


@dataclass
class RecoveredLocalVar:
    """A recovered local variable."""
    stack_offset: int
    size: int
    inferred_type: str
    scope_start: int  # First instruction that uses it
    scope_end: int  # Last instruction that uses it
    inferred_name: Optional[str] = None


@dataclass
class RecoveredFunctionSignature:
    """Recovered function signature with types."""
    address: int
    name: str
    return_type: str
    arguments: List[RecoveredArgument]
    local_vars: List[RecoveredLocalVar]
    calling_convention: str
    is_variadic: bool = False
    confidence: float = 0.0


@dataclass
class TypeRecoveryResult:
    """Complete type recovery result."""
    functions: List[RecoveredFunctionSignature]
    structs: List[RecoveredStruct]
    global_vars: List[Dict[str, Any]]
    vtables: List[Dict[str, Any]]  # Virtual function tables (C++)
    total_types_recovered: int = 0


# ============================================================================
# Emulation Types
# ============================================================================

@dataclass
class EmulationMemoryAccess:
    """A memory access during emulation."""
    address: int
    access_type: str  # "read", "write", "execute"
    size: int
    value: Optional[int] = None
    instruction_address: int = 0


@dataclass
class EmulationSyscall:
    """A system call during emulation."""
    address: int
    syscall_number: int
    syscall_name: str
    arguments: List[int]
    return_value: Optional[int] = None


@dataclass
class EmulationApiCall:
    """An API/library call during emulation."""
    address: int
    function_name: str
    arguments: List[Any]
    return_value: Optional[Any] = None
    library: Optional[str] = None


@dataclass
class EmulationState:
    """CPU state at a point in emulation."""
    address: int
    registers: Dict[str, int]
    flags: Dict[str, bool]
    stack_top: List[int]  # Top N values on stack
    instruction_count: int = 0


@dataclass
class DecodedString:
    """A string decoded during emulation."""
    address: int
    decoded_value: str
    encoding: str  # "ascii", "utf-16", "xor", "base64"
    decoding_method: str  # How it was decoded
    original_bytes: bytes = b""


@dataclass
class EmulationTrace:
    """A trace of emulation execution."""
    start_address: int
    end_address: int
    instructions_executed: int
    states: List[EmulationState]
    memory_accesses: List[EmulationMemoryAccess]
    syscalls: List[EmulationSyscall]
    api_calls: List[EmulationApiCall]
    decoded_strings: List[DecodedString]
    loops_detected: List[Dict[str, Any]]
    suspicious_behaviors: List[str]
    error: Optional[str] = None


@dataclass
class EmulationResult:
    """Complete emulation analysis result."""
    traces: List[EmulationTrace]
    decoded_strings: List[DecodedString]
    api_calls: List[EmulationApiCall]
    syscalls: List[EmulationSyscall]
    self_modifying_code: List[Dict[str, Any]]
    unpacked_code: Optional[bytes] = None
    shellcode_detected: bool = False
    anti_analysis_detected: List[str] = field(default_factory=list)
    total_instructions_emulated: int = 0
    emulation_coverage: float = 0.0


# ============================================================================
# Symbolic Execution Types
# ============================================================================

@dataclass
class SymbolicInput:
    """A symbolic input discovered during exploration."""
    name: str
    type: str  # 'stdin', 'argv', 'file', 'network', 'memory'
    size_bits: int
    constraints: List[str]  # String representation of constraints
    concrete_examples: List[str]  # Concrete values that satisfy constraints


@dataclass
class SymbolicPath:
    """A path discovered during symbolic execution."""
    path_id: int
    depth: int  # Number of branches taken
    constraints_count: int
    is_feasible: bool
    termination_reason: str  # 'reached_target', 'deadended', 'errored', 'timeout'
    addresses_visited: List[int]
    branches_taken: List[Tuple[int, bool]]  # (address, taken/not-taken)


@dataclass
class CrashInput:
    """Input that causes a crash."""
    input_type: str  # 'stdin', 'argv', 'file'
    input_value: bytes
    crash_address: int
    crash_type: str  # 'segfault', 'abort', 'div_by_zero', 'stack_overflow'
    vulnerability_type: str  # 'buffer_overflow', 'use_after_free', 'format_string'
    cwe_id: Optional[str] = None
    exploitability: str = "unknown"  # 'exploitable', 'probably_exploitable', 'not_exploitable'


@dataclass
class TargetReach:
    """Result of trying to reach a specific target address."""
    target_address: int
    target_name: Optional[str]
    reached: bool
    input_to_reach: Optional[bytes]
    path_length: int
    constraints_solved: int


@dataclass
class SymbolicExecutionResult:
    """Complete symbolic execution analysis result."""
    paths_explored: int
    paths_deadended: int
    paths_errored: int
    max_depth_reached: int
    symbolic_inputs: List[SymbolicInput]
    crash_inputs: List[CrashInput]
    target_reaches: List[TargetReach]
    interesting_paths: List[SymbolicPath]
    vulnerabilities_found: List[Dict[str, Any]]
    execution_time_seconds: float
    memory_used_mb: float
    timeout_reached: bool = False
    error: Optional[str] = None


# ============================================================================
# Binary Diffing Types
# ============================================================================

@dataclass
class FunctionDiff:
    """Difference between two functions."""
    address_a: int
    address_b: Optional[int]  # None if function doesn't exist in B
    name: str
    match_type: str  # 'identical', 'modified', 'added', 'removed'
    similarity_score: float  # 0.0 - 1.0
    size_a: int
    size_b: Optional[int]
    instructions_changed: int
    blocks_changed: int
    calls_added: List[str]
    calls_removed: List[str]
    is_security_relevant: bool  # True if related to security functions
    diff_summary: Optional[str] = None


@dataclass
class BlockDiff:
    """Difference at basic block level."""
    address_a: int
    address_b: Optional[int]
    function_name: str
    match_type: str
    instructions_a: List[str]
    instructions_b: List[str]
    similarity: float


@dataclass
class StringDiff:
    """Difference in strings between binaries."""
    value: str
    status: str  # 'added', 'removed', 'unchanged'
    address_a: Optional[int]
    address_b: Optional[int]
    is_security_relevant: bool  # URLs, credentials, commands


@dataclass
class ImportDiff:
    """Difference in imports between binaries."""
    name: str
    library: str
    status: str  # 'added', 'removed', 'unchanged'
    is_security_relevant: bool


@dataclass
class BinaryDiffResult:
    """Complete binary diffing result."""
    file_a: str
    file_b: str
    architecture_a: str
    architecture_b: str
    functions_identical: int
    functions_modified: int
    functions_added: int
    functions_removed: int
    overall_similarity: float
    function_diffs: List[FunctionDiff]
    block_diffs: List[BlockDiff]  # Only for modified functions
    string_diffs: List[StringDiff]
    import_diffs: List[ImportDiff]
    security_relevant_changes: List[Dict[str, Any]]
    patch_analysis: Optional[str]  # AI-generated summary of patch
    is_same_binary: bool  # True if binaries are functionally identical
    error: Optional[str] = None


# ============================================================================
# ROP Gadget Types
# ============================================================================

@dataclass
class ROPGadget:
    """A single ROP gadget."""
    address: int
    instructions: List[str]  # e.g., ['pop rdi', 'ret']
    gadget_string: str  # Full string representation
    gadget_type: str  # 'pop', 'mov', 'xchg', 'syscall', 'jmp', 'call', 'arithmetic'
    size_bytes: int
    registers_controlled: List[str]
    is_useful: bool  # True if commonly useful in exploits
    quality_score: float  # 0.0-1.0, higher = cleaner gadget


@dataclass
class ROPChainTemplate:
    """A template for a common ROP chain."""
    name: str  # 'execve_shellcode', 'mprotect_rwx', 'write_primitive'
    description: str
    required_gadgets: List[str]
    available_gadgets: List[ROPGadget]
    is_buildable: bool  # True if all required gadgets are available
    chain_addresses: List[int]  # Addresses in order for the chain
    payload_template: Optional[str]  # Python code template to build payload


@dataclass
class ROPGadgetResult:
    """Complete ROP gadget analysis result."""
    total_gadgets: int
    unique_gadgets: int
    gadgets_by_type: Dict[str, int]
    gadgets: List[ROPGadget]
    useful_gadgets: List[ROPGadget]  # Filtered to most useful
    # Chain building support
    pop_gadgets: List[ROPGadget]  # For controlling registers
    syscall_gadgets: List[ROPGadget]  # syscall/int 0x80
    write_gadgets: List[ROPGadget]  # mov [reg], reg style
    pivot_gadgets: List[ROPGadget]  # Stack pivots
    chain_templates: List[ROPChainTemplate]
    # Security assessment
    nx_bypass_possible: bool
    execve_chain_buildable: bool
    mprotect_chain_buildable: bool
    rop_difficulty: str  # 'easy', 'medium', 'hard', 'very_hard'
    error: Optional[str] = None


@dataclass
class BinaryAnalysisResult:
    """Complete analysis result for a binary file."""
    filename: str
    metadata: Any  # BinaryMetadata
    strings: List[Any]  # List[ExtractedString]
    imports: List[Any]  # List[ImportedFunction]
    exports: List[str]
    secrets: List[Dict[str, Any]]
    suspicious_indicators: List[Dict[str, Any]]
    fuzzy_hashes: Dict[str, Optional[str]] = field(default_factory=dict)
    yara_matches: List[Dict[str, Any]] = field(default_factory=list)
    capa_summary: Optional[Dict[str, Any]] = None
    deobfuscated_strings: List[Dict[str, Any]] = field(default_factory=list)
    # Enhanced ELF fields
    symbols: List[Any] = field(default_factory=list)  # List[ELFSymbol]
    disassembly: Optional[Any] = None  # DisassemblyResult
    dwarf_info: Optional[Dict[str, Any]] = None
    ai_analysis: Optional[str] = None
    ghidra_analysis: Optional[Dict[str, Any]] = None
    ghidra_ai_summaries: Optional[List[Dict[str, Any]]] = None
    # New advanced analysis fields
    data_flow_analysis: Optional[DataFlowAnalysisResult] = None
    type_recovery: Optional[TypeRecoveryResult] = None
    emulation_analysis: Optional[EmulationResult] = None
    # Symbolic execution, diffing, ROP analysis
    symbolic_execution: Optional[SymbolicExecutionResult] = None
    rop_gadgets: Optional[ROPGadgetResult] = None
    error: Optional[str] = None


@dataclass
class ApkCertificate:
    """APK signing certificate information."""
    subject: str
    issuer: str
    serial_number: str
    fingerprint_sha256: str
    fingerprint_sha1: str
    fingerprint_md5: str
    valid_from: str
    valid_until: str
    is_debug_cert: bool = False
    is_expired: bool = False
    is_self_signed: bool = False
    signature_version: str = "v1"  # v1, v2, v3
    public_key_algorithm: Optional[str] = None
    public_key_bits: Optional[int] = None


@dataclass
class ApkPermission:
    """An Android permission."""
    name: str
    is_dangerous: bool
    description: Optional[str] = None


@dataclass
class ApkComponent:
    """An Android app component."""
    name: str
    component_type: str  # "activity", "service", "receiver", "provider"
    is_exported: bool
    intent_filters: List[str] = field(default_factory=list)


@dataclass
class ApkAnalysisResult:
    """Complete analysis result for an APK file."""
    filename: str
    package_name: str
    version_name: Optional[str]
    version_code: Optional[int]
    min_sdk: Optional[int]
    target_sdk: Optional[int]
    permissions: List[ApkPermission]
    components: List[ApkComponent]
    strings: List[Any]  # List[ExtractedString]
    secrets: List[Dict[str, Any]]
    urls: List[str]
    native_libraries: List[str]
    certificate: Optional[ApkCertificate] = None
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    uses_features: List[str] = field(default_factory=list)
    app_name: Optional[str] = None
    debuggable: bool = False
    allow_backup: bool = True
    network_security_config: Optional[str] = None
    # New analysis fields
    dex_analysis: Optional[Dict[str, Any]] = None
    resource_analysis: Optional[Dict[str, Any]] = None
    intent_filter_analysis: Optional[Dict[str, Any]] = None
    network_config_analysis: Optional[Dict[str, Any]] = None
    smali_analysis: Optional[Dict[str, Any]] = None  # Smali/bytecode decompilation
    dynamic_analysis: Optional[Dict[str, Any]] = None  # Frida scripts for dynamic testing
    native_analysis: Optional[Dict[str, Any]] = None  # Native library (.so) analysis
    hardening_score: Optional[Dict[str, Any]] = None  # Security hardening score
    data_flow_analysis: Optional[Dict[str, Any]] = None  # Data flow/taint analysis
    security_issues: List[Dict[str, Any]] = field(default_factory=list)
    ai_analysis: Optional[str] = None
    # New structured AI reports
    ai_report_functionality: Optional[str] = None  # "What does this APK do" report
    ai_report_security: Optional[str] = None  # "Security Findings" report
    ai_report_architecture: Optional[str] = None  # Code architecture Mermaid diagram
    ai_report_attack_surface: Optional[str] = None  # Attack surface map
    # AI-Generated Mermaid Diagrams (with icons)
    ai_architecture_diagram: Optional[str] = None  # App architecture flowchart
    ai_data_flow_diagram: Optional[str] = None  # Data flow and privacy diagram
    error: Optional[str] = None


@dataclass
class SmaliMethodCode:
    """Decompiled Smali bytecode for a method."""
    class_name: str
    method_name: str
    method_signature: str
    access_flags: str
    return_type: str
    parameters: List[str]
    registers_count: int
    instructions: List[str]  # Smali bytecode instructions
    instruction_count: int
    has_try_catch: bool = False
    is_native: bool = False
    is_abstract: bool = False


@dataclass
class DexClassInfo:
    """Information about a class in DEX."""
    name: str
    access_flags: str
    superclass: Optional[str]
    interfaces: List[str]
    methods_count: int
    fields_count: int
    is_suspicious: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)


@dataclass
class DexMethodInfo:
    """Information about a method in DEX."""
    class_name: str
    method_name: str
    access_flags: str
    return_type: str
    parameters: List[str]
    is_suspicious: bool = False
    suspicious_reason: Optional[str] = None


@dataclass
class ApkResourceInfo:
    """Information about APK resources."""
    string_resources: Dict[str, str]  # name -> value
    asset_files: List[str]
    raw_resources: List[str]
    drawable_count: int
    layout_count: int
    potential_secrets_in_resources: List[Dict[str, Any]]


@dataclass
class IntentFilterInfo:
    """Deep link and intent filter information."""
    component_name: str
    component_type: str
    actions: List[str]
    categories: List[str]
    data_schemes: List[str]
    data_hosts: List[str]
    data_paths: List[str]
    is_browsable: bool
    is_exported: bool
    deep_links: List[str]


@dataclass
class NetworkSecurityConfig:
    """Parsed network security configuration."""
    cleartext_permitted: bool
    cleartext_domains: List[str]
    trust_anchors: List[Dict[str, Any]]
    certificate_pins: List[Dict[str, Any]]
    domain_configs: List[Dict[str, Any]]
    security_issues: List[str]


@dataclass
class DockerLayerSecret:
    """A potential secret found in a Docker layer."""
    layer_id: str
    layer_command: str
    secret_type: str
    value: str
    masked_value: str
    context: str
    severity: str


@dataclass
class DockerLayerAnalysisResult:
    """Analysis result for Docker image layers."""
    image_name: str
    image_id: str
    total_layers: int
    total_size: int
    base_image: Optional[str]
    layers: List[Dict[str, Any]]
    secrets: List[DockerLayerSecret]
    deleted_files: List[Dict[str, Any]]
    security_issues: List[Dict[str, Any]]
    ai_analysis: Optional[str] = None
    error: Optional[str] = None


@dataclass
class FridaScript:
    """A generated Frida script for dynamic analysis."""
    name: str
    category: str  # ssl_bypass, root_bypass, crypto_hook, method_trace, etc.
    description: str
    script_code: str
    target_classes: List[str]
    target_methods: List[str]
    is_dangerous: bool = False  # Scripts that modify app behavior
    usage_instructions: str = ""


@dataclass
class DynamicAnalysisResult:
    """Dynamic analysis data including generated Frida scripts."""
    package_name: str
    frida_scripts: List[FridaScript]
    ssl_pinning_detected: bool
    root_detection_detected: bool
    crypto_methods: List[Dict[str, Any]]
    interesting_hooks: List[Dict[str, Any]]
    suggested_test_cases: List[str]
    frida_spawn_command: str
    frida_attach_command: str


@dataclass
class NativeFunction:
    """A function found in a native library."""
    name: str
    address: str
    size: int
    is_jni: bool = False
    is_exported: bool = False
    is_suspicious: bool = False
    suspicious_reason: Optional[str] = None


@dataclass
class NativeLibraryInfo:
    """Analysis of a single native library (.so file)."""
    name: str
    architecture: str
    size: int
    is_stripped: bool
    has_debug_info: bool
    exported_functions: List[NativeFunction]
    jni_functions: List[str]
    imported_libraries: List[str]
    strings: List[str]  # Interesting strings found
    hardcoded_secrets: List[Dict[str, Any]]
    anti_debug_detected: bool
    anti_debug_techniques: List[str]
    crypto_functions: List[str]
    suspicious_patterns: List[Dict[str, Any]]


@dataclass
class NativeAnalysisResult:
    """Complete native library analysis result."""
    total_libraries: int
    libraries: List[NativeLibraryInfo]
    total_jni_functions: int
    total_exported_functions: int
    architectures: List[str]
    security_findings: List[Dict[str, Any]]
    overall_native_risk: str  # low, medium, high, critical


@dataclass
class HardeningCategory:
    """A category in the hardening score."""
    name: str
    score: int  # 0-100
    max_score: int
    weight: float
    findings: List[Dict[str, Any]]
    recommendations: List[str]


@dataclass
class HardeningScore:
    """Overall APK hardening/security score."""
    overall_score: int  # 0-100
    grade: str  # A, B, C, D, F
    risk_level: str  # Low, Medium, High, Critical
    categories: List[HardeningCategory]
    attack_surface_score: int
    protection_score: int
    data_security_score: int
    summary: str
    top_risks: List[str]
    top_recommendations: List[str]


# ============================================================================
# JADX Decompilation Types
# ============================================================================

@dataclass
class JadxDecompiledClass:
    """A decompiled Java class from JADX."""
    class_name: str
    package_name: str
    file_path: str  # Relative path in decompiled output
    source_code: str
    line_count: int
    is_activity: bool = False
    is_service: bool = False
    is_receiver: bool = False
    is_provider: bool = False
    is_application: bool = False
    extends: Optional[str] = None
    implements: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    security_issues: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class JadxDecompilationResult:
    """Complete JADX decompilation result."""
    package_name: str
    total_classes: int
    total_files: int
    output_directory: str
    classes: List[JadxDecompiledClass]
    resources_dir: str
    manifest_path: str
    source_tree: Dict[str, Any]  # Directory structure
    decompilation_time: float
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# ============================================================================
# Manifest Visualization Types
# ============================================================================

@dataclass
class ManifestNode:
    """A node in the manifest visualization graph."""
    id: str
    name: str
    node_type: str  # activity, service, receiver, provider, permission, feature
    label: str
    is_exported: bool = False
    is_main: bool = False
    is_dangerous: bool = False
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ManifestEdge:
    """An edge in the manifest visualization graph."""
    source: str
    target: str
    edge_type: str  # uses_permission, intent_filter, data_scheme, category
    label: str


@dataclass
class ManifestVisualization:
    """Complete manifest visualization data."""
    package_name: str
    app_name: Optional[str]
    version_name: Optional[str]
    nodes: List[ManifestNode]
    edges: List[ManifestEdge]
    component_counts: Dict[str, int]
    permission_summary: Dict[str, int]  # dangerous, normal, signature, etc.
    exported_count: int
    main_activity: Optional[str]
    deep_link_schemes: List[str]
    mermaid_diagram: str  # Pre-rendered mermaid flowchart
    # AI-enhanced fields
    ai_analysis: Optional[str] = None  # AI interpretation of manifest structure
    component_purposes: Optional[Dict[str, str]] = None  # AI-inferred purpose of each component
    security_assessment: Optional[str] = None  # AI security analysis of manifest
    intent_filter_analysis: Optional[Dict[str, Any]] = None  # Detailed intent filter breakdown


# ============================================================================
# Attack Surface Map Types
# ============================================================================

@dataclass
class AttackVector:
    """A potential attack vector/entry point."""
    id: str
    name: str
    vector_type: str  # exported_activity, deep_link, content_provider, broadcast, etc.
    component: str
    severity: str  # low, medium, high, critical
    description: str
    exploitation_steps: List[str]
    required_permissions: List[str]
    adb_command: Optional[str] = None
    intent_example: Optional[str] = None
    mitigation: str = ""


@dataclass
class ExposedDataPath:
    """An exposed data path through content providers."""
    provider_name: str
    uri_pattern: str
    permissions_required: List[str]
    operations: List[str]  # read, write, delete
    is_exported: bool
    potential_data: str
    risk_level: str


@dataclass
class DeepLinkEntry:
    """A deep link entry point."""
    scheme: str
    host: str
    path: str
    full_url: str
    handling_activity: str
    parameters: List[str]
    is_verified: bool  # App Links verification
    security_notes: List[str]


@dataclass
class AttackSurfaceMap:
    """Complete attack surface analysis."""
    package_name: str
    total_attack_vectors: int
    attack_vectors: List[AttackVector]
    exposed_data_paths: List[ExposedDataPath]
    deep_links: List[DeepLinkEntry]
    ipc_endpoints: List[Dict[str, Any]]  # Inter-Process Communication endpoints
    overall_exposure_score: int  # 0-100
    risk_level: str  # low, medium, high, critical
    risk_breakdown: Dict[str, int]  # vectors by severity
    priority_targets: List[str]  # Top items to investigate
    automated_tests: List[Dict[str, Any]]  # adb commands to test each vector
    mermaid_attack_tree: str  # Visual attack tree diagram


# ============================================================================
# Secret Patterns
# ============================================================================

SECRET_PATTERNS = {
    "api_key": re.compile(r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', re.IGNORECASE),
    "aws_key": re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}'),
    "aws_secret": re.compile(r'(?:aws[_-]?secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', re.IGNORECASE),
    "password": re.compile(r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']{6,})["\']?', re.IGNORECASE),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    "github_token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
    "jwt": re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
    "connection_string": re.compile(r'(?:mongodb|mysql|postgres|redis|mssql)://[^\s"\']+', re.IGNORECASE),
    "bearer_token": re.compile(r'[Bb]earer\s+[a-zA-Z0-9_\-\.]+'),
    "base64_secret": re.compile(r'(?:secret|key|token|password)["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/]{40,}={0,2})["\']?', re.IGNORECASE),
}

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+')
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
PATH_PATTERN = re.compile(r'(?:/[a-zA-Z0-9_\-\.]+){2,}|(?:[A-Z]:\\[a-zA-Z0-9_\-\.\\ ]+)')

# Dangerous Android permissions
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS": "Access contacts",
    "android.permission.WRITE_CONTACTS": "Modify contacts",
    "android.permission.READ_CALL_LOG": "Access call logs",
    "android.permission.WRITE_CALL_LOG": "Modify call logs",
    "android.permission.READ_CALENDAR": "Access calendar",
    "android.permission.WRITE_CALENDAR": "Modify calendar",
    "android.permission.CAMERA": "Access camera",
    "android.permission.RECORD_AUDIO": "Record audio",
    "android.permission.READ_PHONE_STATE": "Access phone state",
    "android.permission.READ_PHONE_NUMBERS": "Access phone numbers",
    "android.permission.CALL_PHONE": "Make phone calls",
    "android.permission.READ_SMS": "Read SMS messages",
    "android.permission.SEND_SMS": "Send SMS messages",
    "android.permission.RECEIVE_SMS": "Receive SMS messages",
    "android.permission.READ_EXTERNAL_STORAGE": "Read external storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Write external storage",
    "android.permission.ACCESS_FINE_LOCATION": "Access precise location",
    "android.permission.ACCESS_COARSE_LOCATION": "Access approximate location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Access location in background",
    "android.permission.BODY_SENSORS": "Access body sensors",
    "android.permission.ACTIVITY_RECOGNITION": "Activity recognition",
    "android.permission.INTERNET": "Full network access",
    "android.permission.SYSTEM_ALERT_WINDOW": "Draw over other apps",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Install packages",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility service",
    "android.permission.BIND_DEVICE_ADMIN": "Device admin",
}

# ============================================================================
# LEGITIMACY INDICATORS - Used to reduce false positives on known-good software
# ============================================================================

# Known legitimate publishers/signers (case-insensitive matching)
LEGITIMATE_PUBLISHERS = {
    "microsoft", "google", "mozilla", "apple", "adobe", "oracle", "intel",
    "nvidia", "amd", "vmware", "cisco", "ibm", "hp", "dell", "lenovo",
    "amazon", "cloudflare", "github", "atlassian", "jetbrains", "slack",
    "spotify", "discord", "zoom", "dropbox", "1password", "lastpass",
    "symantec", "mcafee", "kaspersky", "norton", "avast", "avg",
    "chromium", "firefox", "electron", "node.js foundation",
}

# Known legitimate product name patterns
LEGITIMATE_PRODUCTS = {
    "chrome", "firefox", "edge", "safari", "opera", "brave",  # Browsers
    "visual studio", "vscode", "vs code", "intellij", "pycharm",  # IDEs
    "office", "word", "excel", "powerpoint", "outlook",  # Office
    "windows", "explorer", "notepad", "calc",  # Windows built-in
    "python", "node", "java", "dotnet", ".net",  # Runtimes
    "defender", "security", "antivirus",  # Security
}

# APIs that are NORMAL in legitimate software (only flag if other red flags present)
# These are marked as 'low' suspicion unless combined with other indicators
NORMAL_IN_LEGITIMATE_SOFTWARE = {
    "CreateProcess", "ShellExecute", "WinExec",  # Process creation is normal
    "InternetOpen", "URLDownloadToFile",  # Network is normal for most apps
    "CryptEncrypt", "CryptDecrypt",  # Crypto is normal for security
    "RegSetValue", "RegQueryValue",  # Registry access is normal
    "Sleep", "GetTickCount",  # Timing is normal
    "socket", "connect", "send", "recv",  # Network is normal
    "dlopen", "dlsym",  # Dynamic loading is normal
    "fork", "execve",  # Process management is normal on Linux
}

# APIs that are ALWAYS suspicious regardless of context
ALWAYS_SUSPICIOUS_APIS = {
    "NtUnmapViewOfSection",  # Process hollowing
    "ZwUnmapViewOfSection",  # Process hollowing variant
    "NtCreateThreadEx",  # Injection
    "RtlCreateUserThread",  # Injection
}

# Suspicious Windows API imports - NOW WITH CONTEXT AWARENESS
# severity: "high" = always flag, "medium" = flag unless legitimate, "low" = only flag with other indicators
SUSPICIOUS_IMPORTS = {
    "CreateRemoteThread": "Can inject code into other processes",
    "VirtualAllocEx": "Can allocate memory in other processes",
    "WriteProcessMemory": "Can write to other processes' memory",
    "ReadProcessMemory": "Can read other processes' memory",
    "NtUnmapViewOfSection": "Process hollowing technique",
    "SetWindowsHookEx": "Keylogger capability",
    "GetAsyncKeyState": "Keylogger capability",
    "InternetOpen": "Network communication",
    "URLDownloadToFile": "Can download files from internet",
    "WinExec": "Can execute commands",
    "ShellExecute": "Can execute programs",
    "CreateProcess": "Can spawn processes",
    "RegSetValue": "Can modify registry",
    "CryptEncrypt": "Encryption capability (ransomware indicator)",
    "CryptDecrypt": "Decryption capability",
    "IsDebuggerPresent": "Anti-debugging technique",
    "CheckRemoteDebuggerPresent": "Anti-debugging technique",
    "OutputDebugString": "Anti-debugging technique",
    "GetTickCount": "Anti-sandbox technique",
    "Sleep": "Anti-sandbox technique (long sleep)",
}

# Suspicion levels for imports (used for context-aware filtering)
IMPORT_SUSPICION_LEVEL = {
    # HIGH - Always suspicious
    "CreateRemoteThread": "high",
    "VirtualAllocEx": "high",
    "WriteProcessMemory": "high",
    "ReadProcessMemory": "medium",  # Debuggers use this legitimately
    "NtUnmapViewOfSection": "high",
    "SetWindowsHookEx": "medium",  # Some apps use for accessibility
    "GetAsyncKeyState": "medium",  # Games use this
    # MEDIUM - Suspicious but common in legitimate software
    "InternetOpen": "low",  # Almost all apps use networking
    "URLDownloadToFile": "low",  # Updaters use this
    "WinExec": "medium",
    "ShellExecute": "low",  # Very common
    "CreateProcess": "low",  # Very common
    "RegSetValue": "low",  # Most installers use this
    # LOW - Only suspicious in malware context
    "CryptEncrypt": "low",  # Normal for secure apps
    "CryptDecrypt": "low",
    "IsDebuggerPresent": "low",  # Even Chrome uses this
    "CheckRemoteDebuggerPresent": "low",
    "OutputDebugString": "info",  # Debug builds use this
    "GetTickCount": "info",  # Extremely common
    "Sleep": "info",  # Extremely common
}

# Suspicious Linux/ELF function imports
SUSPICIOUS_ELF_FUNCTIONS = {
    # Process manipulation
    "ptrace": "Can debug/trace processes (anti-debugging or injection)",
    "fork": "Creates child processes",
    "execve": "Executes programs",
    "execl": "Executes programs",
    "execlp": "Executes programs",
    "execv": "Executes programs",
    "execvp": "Executes programs",
    "system": "Executes shell commands",
    "popen": "Opens pipe to shell command",
    "dlopen": "Dynamic library loading",
    "dlsym": "Dynamic symbol resolution",
    # Network
    "socket": "Network communication",
    "connect": "Network connection",
    "bind": "Network binding (server)",
    "listen": "Network listening (server)",
    "accept": "Accepts network connections",
    "send": "Sends network data",
    "recv": "Receives network data",
    "sendto": "Sends UDP data",
    "recvfrom": "Receives UDP data",
    "gethostbyname": "DNS resolution",
    "getaddrinfo": "Address resolution",
    # File operations
    "unlink": "Deletes files",
    "rmdir": "Removes directories",
    "chmod": "Changes file permissions",
    "chown": "Changes file ownership",
    "mmap": "Memory mapping (code injection)",
    "mprotect": "Memory protection change (code injection)",
    # Privilege escalation
    "setuid": "Changes user ID",
    "setgid": "Changes group ID",
    "seteuid": "Changes effective user ID",
    "setegid": "Changes effective group ID",
    # Crypto (potential ransomware)
    "EVP_EncryptInit": "OpenSSL encryption",
    "EVP_DecryptInit": "OpenSSL decryption",
    "AES_encrypt": "AES encryption",
    "AES_decrypt": "AES decryption",
    "RSA_public_encrypt": "RSA encryption",
    # Anti-debugging/evasion
    "prctl": "Process control (can hide from ps)",
    "getenv": "Environment variable access",
    "uname": "System information gathering",
    "geteuid": "Check if running as root",
    "getpid": "Get process ID",
    "kill": "Send signals to processes",
}

# Suspicious x86/x64 instruction patterns - comprehensive list
SUSPICIOUS_INSTRUCTIONS = {
    # System calls
    "int 0x80": "Linux syscall (x86)",
    "syscall": "Linux syscall (x64)",
    "sysenter": "Fast syscall entry",
    "int 0x2e": "Windows syscall (legacy)",

    # Anti-debugging / Anti-VM
    "int3": "Debugger breakpoint (anti-debug)",
    "int 1": "Single-step trap (anti-debug)",
    "cpuid": "CPU identification (VM/sandbox detection)",
    "rdtsc": "Timestamp counter (timing attacks/anti-debug)",
    "rdtscp": "Timestamp counter with processor ID",
    "rdpmc": "Performance counter read (anti-debug)",
    "icebp": "ICE breakpoint (anti-debug)",
    "ud2": "Undefined instruction (anti-debug trigger)",

    # Privileged/Ring0 operations
    "in al": "I/O port read (rootkit/driver behavior)",
    "in ax": "I/O port read word (rootkit/driver behavior)",
    "in eax": "I/O port read dword (rootkit/driver behavior)",
    "out": "I/O port write (rootkit/driver behavior)",
    "cli": "Disable interrupts (kernel/rootkit)",
    "sti": "Enable interrupts (kernel/rootkit)",
    "hlt": "Halt processor (DoS/rootkit)",
    "lidt": "Load IDT (rootkit hooking)",
    "sidt": "Store IDT (VM detection)",
    "lgdt": "Load GDT (rootkit)",
    "sgdt": "Store GDT (VM detection)",
    "sldt": "Store LDT (VM detection)",
    "str": "Store task register (VM detection)",
    "ltr": "Load task register (rootkit)",
    "lldt": "Load LDT (rootkit)",
    "lmsw": "Load machine status word",
    "clts": "Clear task-switched flag (rootkit)",
    "invd": "Invalidate cache (DoS)",
    "wbinvd": "Write-back and invalidate cache",
    "invlpg": "Invalidate TLB entry",
    "wrmsr": "Write MSR (rootkit/hypervisor)",
    "rdmsr": "Read MSR (fingerprinting)",

    # Memory manipulation
    "swapgs": "Swap GS base (kernel exploit)",
    "xsave": "Save processor state",
    "xrstor": "Restore processor state",

    # Crypto operations (potential ransomware indicators)
    "aesenc": "AES encryption round (crypto/ransomware)",
    "aesenclast": "AES final encryption round",
    "aesdec": "AES decryption round",
    "aesdeclast": "AES final decryption round",
    "aesimc": "AES inverse mix columns",
    "aeskeygenassist": "AES key generation",
    "pclmulqdq": "Carryless multiplication (crypto)",
    "sha1": "SHA1 instruction (crypto)",
    "sha256": "SHA256 instruction (crypto)",

    # Self-modifying code indicators
    "stosb": "Store string byte (potential code modification)",
    "stosw": "Store string word",
    "stosd": "Store string dword",
    "stosq": "Store string qword",
    "rep stos": "Repeated store (memory fill/clear)",
    "rep movs": "Repeated move (memory copy)",

    # Indirect control flow (potential ROP/JOP)
    "jmp dword ptr": "Indirect jump (potential ROP gadget)",
    "jmp qword ptr": "Indirect jump 64-bit (potential ROP)",
    "call dword ptr": "Indirect call (potential shellcode)",
    "call qword ptr": "Indirect call 64-bit",
    "jmp rax": "Register indirect jump (ROP)",
    "jmp rbx": "Register indirect jump (ROP)",
    "jmp rcx": "Register indirect jump (ROP)",
    "jmp rdx": "Register indirect jump (ROP)",
    "jmp rsi": "Register indirect jump (ROP)",
    "jmp rdi": "Register indirect jump (ROP)",
    "call rax": "Register indirect call",
    "call rbx": "Register indirect call",
    "ret": "Return (ROP gadget terminator)",

    # Process/thread manipulation
    "vmptrld": "VMX load pointer (hypervisor)",
    "vmptrst": "VMX store pointer",
    "vmclear": "VMX clear VMCS",
    "vmread": "VMX read VMCS field",
    "vmwrite": "VMX write VMCS field",
    "vmlaunch": "VMX launch VM",
    "vmresume": "VMX resume VM",
    "vmxoff": "Exit VMX operation",
    "vmxon": "Enter VMX operation",
    "vmcall": "VMX call hypervisor",
    "vmfunc": "VMX function",

    # SGX instructions (enclave operations)
    "enclu": "SGX user-mode enclave operation",
    "encls": "SGX supervisor enclave operation",

    # Potential shellcode patterns
    "fstenv": "Store FPU environment (shellcode decoder)",
    "fnstenv": "Store FPU environment no-wait",
    "fldenv": "Load FPU environment",
    "fxsave": "Save FPU/MMX/SSE state",
    "fxrstor": "Restore FPU/MMX/SSE state",
}

# Anti-analysis function names
ANTI_ANALYSIS_FUNCTIONS = {
    "IsDebuggerPresent": "Windows debugger detection",
    "CheckRemoteDebuggerPresent": "Remote debugger check",
    "NtQueryInformationProcess": "Process info query (anti-debug)",
    "NtSetInformationThread": "Thread info manipulation",
    "OutputDebugStringA": "Debug output (anti-debug technique)",
    "OutputDebugStringW": "Debug output (anti-debug technique)",
    "QueryPerformanceCounter": "Timing check (anti-debug)",
    "GetTickCount": "Timing check (anti-debug)",
    "GetTickCount64": "Timing check (anti-debug)",
    "ptrace": "Linux debugger detection/manipulation",
    "getenv": "Environment check (sandbox detection)",
    "VirtualAlloc": "Memory allocation (shellcode loader)",
    "VirtualProtect": "Memory protection change (shellcode)",
    "NtAllocateVirtualMemory": "Low-level memory alloc",
    "NtProtectVirtualMemory": "Low-level memory protection",
    "CreateRemoteThread": "Remote code injection",
    "NtCreateThreadEx": "Thread creation (injection)",
    "WriteProcessMemory": "Process memory write (injection)",
    "ReadProcessMemory": "Process memory read",
    "LoadLibraryA": "DLL loading",
    "LoadLibraryW": "DLL loading",
    "GetProcAddress": "Function resolution (shellcode)",
    "LdrLoadDll": "Low-level DLL loading",
    "mmap": "Memory mapping (shellcode loader)",
    "mprotect": "Memory protection change (shellcode)",
    "dlopen": "Dynamic library loading",
    "dlsym": "Dynamic symbol resolution",
}


# Export all public types and constants
__all__ = [
    # Data Flow Analysis
    "TaintSource", "TaintSink", "TaintedValue", "DataFlowPath", "DataFlowAnalysisResult",
    # Type Recovery
    "RecoveredField", "RecoveredStruct", "RecoveredArgument", "RecoveredLocalVar",
    "RecoveredFunctionSignature", "TypeRecoveryResult",
    # Emulation
    "EmulationMemoryAccess", "EmulationSyscall", "EmulationApiCall", "EmulationState",
    "DecodedString", "EmulationTrace", "EmulationResult",
    # Symbolic Execution
    "SymbolicInput", "SymbolicPath", "CrashInput", "TargetReach", "SymbolicExecutionResult",
    # Binary Diffing
    "FunctionDiff", "BlockDiff", "StringDiff", "ImportDiff", "BinaryDiffResult",
    # ROP Gadgets
    "ROPGadget", "ROPChainTemplate", "ROPGadgetResult",
    # Binary Analysis
    "BinaryAnalysisResult",
    # APK Analysis
    "ApkCertificate", "ApkPermission", "ApkComponent", "ApkAnalysisResult",
    "SmaliMethodCode", "DexClassInfo", "DexMethodInfo", "ApkResourceInfo",
    "IntentFilterInfo", "NetworkSecurityConfig",
    # Docker Analysis
    "DockerLayerSecret", "DockerLayerAnalysisResult",
    # Dynamic Analysis
    "FridaScript", "DynamicAnalysisResult",
    # Native Analysis
    "NativeFunction", "NativeLibraryInfo", "NativeAnalysisResult",
    # Hardening
    "HardeningCategory", "HardeningScore",
    # JADX
    "JadxDecompiledClass", "JadxDecompilationResult",
    # Manifest Visualization
    "ManifestNode", "ManifestEdge", "ManifestVisualization",
    # Attack Surface
    "AttackVector", "ExposedDataPath", "DeepLinkEntry", "AttackSurfaceMap",
    # Patterns and Constants
    "SECRET_PATTERNS", "URL_PATTERN", "EMAIL_PATTERN", "IP_PATTERN", "PATH_PATTERN",
    "DANGEROUS_PERMISSIONS", "LEGITIMATE_PUBLISHERS", "LEGITIMATE_PRODUCTS",
    "NORMAL_IN_LEGITIMATE_SOFTWARE", "ALWAYS_SUSPICIOUS_APIS", "SUSPICIOUS_IMPORTS",
    "IMPORT_SUSPICION_LEVEL", "SUSPICIOUS_ELF_FUNCTIONS", "SUSPICIOUS_INSTRUCTIONS",
    "ANTI_ANALYSIS_FUNCTIONS",
]
