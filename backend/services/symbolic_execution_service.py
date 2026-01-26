"""
Symbolic Execution Service using angr

AI-guided symbolic execution for:
- Path exploration beyond fuzzing limits
- Generating inputs to reach specific code locations
- Finding constraint-solving opportunities for vulnerabilities
- Hybrid fuzzing (AFL++ coverage + angr constraint solving)
"""

import asyncio
import hashlib
import logging
import os
import struct
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# Check for angr availability
ANGR_AVAILABLE = False
try:
    import angr
    import claripy
    from angr.exploration_techniques import DFS, BFS, Explorer
    ANGR_AVAILABLE = True
    logger.info("angr symbolic execution engine available")
except (ImportError, AttributeError, Exception) as e:
    logger.warning(f"angr not available - symbolic execution disabled: {e}")
    angr = None
    claripy = None


# =============================================================================
# Data Classes
# =============================================================================

class ExplorationStrategy(str, Enum):
    """Strategy for symbolic exploration."""
    DFS = "dfs"  # Depth-first - good for finding deep bugs
    BFS = "bfs"  # Breadth-first - good for coverage
    DIRECTED = "directed"  # Target specific addresses
    COVERAGE = "coverage"  # Maximize code coverage
    VULN_HUNT = "vuln_hunt"  # Focus on dangerous functions


class VulnType(str, Enum):
    """Types of vulnerabilities symbolic execution can detect."""
    BUFFER_OVERFLOW = "buffer_overflow"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_DEREF = "null_dereference"
    USE_AFTER_FREE = "use_after_free"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"


@dataclass
class SymbolicInput:
    """Symbolic input definition."""
    name: str
    size: int  # in bytes
    input_type: str = "stdin"  # stdin, file, argv, network
    constraints: List[str] = field(default_factory=list)
    concrete_prefix: Optional[bytes] = None


@dataclass
class ExplorationConfig:
    """Configuration for symbolic exploration."""
    timeout_seconds: int = 300  # 5 minutes default
    max_states: int = 10000
    max_depth: int = 100
    strategy: ExplorationStrategy = ExplorationStrategy.COVERAGE
    target_addresses: List[int] = field(default_factory=list)
    avoid_addresses: List[int] = field(default_factory=list)
    symbolic_inputs: List[SymbolicInput] = field(default_factory=list)
    enable_veritesting: bool = True  # Merge similar states
    enable_simprocs: bool = True  # Use simplified function models
    track_memory_writes: bool = True
    concretize_symbolic_read_sizes: bool = True


@dataclass
class PathConstraint:
    """A path constraint from symbolic execution."""
    address: int
    constraint_str: str
    satisfiable: bool
    variables_involved: List[str]


@dataclass
class SymbolicState:
    """A symbolic execution state snapshot."""
    state_id: str
    address: int
    depth: int
    constraints: List[PathConstraint]
    symbolic_memory: Dict[int, str]  # addr -> variable name
    registers: Dict[str, str]  # reg -> symbolic expr


@dataclass
class VulnerabilityCandidate:
    """A potential vulnerability found via symbolic execution."""
    vuln_type: VulnType
    address: int
    description: str
    triggering_input: Optional[bytes]
    path_constraints: List[str]
    confidence: float  # 0-1
    exploitable: bool


@dataclass
class ExplorationResult:
    """Result of symbolic exploration."""
    binary_path: str
    exploration_id: str
    strategy: ExplorationStrategy

    # Statistics
    states_explored: int
    paths_completed: int
    deadends_reached: int
    errors_encountered: int
    execution_time_ms: int

    # Discoveries
    unique_blocks_reached: Set[int]
    target_states_found: int
    vulnerabilities: List[VulnerabilityCandidate]
    interesting_inputs: List[bytes]  # Inputs that reach new coverage

    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    angr_version: str = ""


# =============================================================================
# Symbolic Execution Service
# =============================================================================

class SymbolicExecutionService:
    """
    AI-guided symbolic execution using angr.

    Provides:
    - Path exploration beyond fuzzing limits
    - Input generation to reach specific code
    - Vulnerability detection via constraint analysis
    - Hybrid fuzzing integration
    """

    # Dangerous functions to monitor
    DANGEROUS_FUNCTIONS = {
        "strcpy": VulnType.BUFFER_OVERFLOW,
        "strcat": VulnType.BUFFER_OVERFLOW,
        "sprintf": VulnType.BUFFER_OVERFLOW,
        "gets": VulnType.BUFFER_OVERFLOW,
        "scanf": VulnType.BUFFER_OVERFLOW,
        "memcpy": VulnType.BUFFER_OVERFLOW,
        "memmove": VulnType.BUFFER_OVERFLOW,
        "printf": VulnType.FORMAT_STRING,
        "fprintf": VulnType.FORMAT_STRING,
        "snprintf": VulnType.FORMAT_STRING,
        "system": VulnType.COMMAND_INJECTION,
        "popen": VulnType.COMMAND_INJECTION,
        "execve": VulnType.COMMAND_INJECTION,
        "open": VulnType.PATH_TRAVERSAL,
        "fopen": VulnType.PATH_TRAVERSAL,
    }

    def __init__(self, max_workers: int = 2):
        """Initialize symbolic execution service."""
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._exploration_cache: Dict[str, ExplorationResult] = {}

        if ANGR_AVAILABLE:
            self._angr_version = angr.__version__
            logger.info(f"SymbolicExecutionService initialized with angr {self._angr_version}")
        else:
            self._angr_version = "N/A"
            logger.warning("SymbolicExecutionService running without angr (limited functionality)")

    @property
    def is_available(self) -> bool:
        """Check if symbolic execution is available."""
        return ANGR_AVAILABLE

    async def explore(
        self,
        binary_path: str,
        config: Optional[ExplorationConfig] = None,
    ) -> ExplorationResult:
        """
        Perform symbolic exploration of a binary.

        Args:
            binary_path: Path to the binary to analyze
            config: Exploration configuration

        Returns:
            ExplorationResult with discovered paths and vulnerabilities
        """
        if not ANGR_AVAILABLE:
            return self._create_empty_result(binary_path, "angr not available")

        if not os.path.exists(binary_path):
            return self._create_empty_result(binary_path, f"Binary not found: {binary_path}")

        config = config or ExplorationConfig()
        exploration_id = hashlib.md5(f"{binary_path}{time.time()}".encode()).hexdigest()[:12]

        # Run exploration in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                self._executor,
                self._do_exploration,
                binary_path,
                config,
                exploration_id,
            )
            return result
        except Exception as e:
            logger.error(f"Symbolic exploration failed: {e}")
            return self._create_empty_result(binary_path, str(e))

    def _do_exploration(
        self,
        binary_path: str,
        config: ExplorationConfig,
        exploration_id: str,
    ) -> ExplorationResult:
        """Perform the actual symbolic exploration (runs in thread)."""
        start_time = time.time()

        # Load the binary
        try:
            project = angr.Project(
                binary_path,
                auto_load_libs=config.enable_simprocs,
                load_options={
                    'auto_load_libs': False,  # Faster, but less accurate
                }
            )
        except Exception as e:
            logger.error(f"Failed to load binary: {e}")
            return self._create_empty_result(binary_path, f"Load failed: {e}")

        # Create initial state
        state = self._create_initial_state(project, config)

        # Create simulation manager
        simgr = project.factory.simulation_manager(state)

        # Configure exploration technique
        self._apply_exploration_technique(simgr, config, project)

        # Hook dangerous functions for vulnerability detection
        vulnerabilities = []
        if config.strategy == ExplorationStrategy.VULN_HUNT:
            vulnerabilities = self._hook_dangerous_functions(project, simgr)

        # Run exploration
        unique_blocks = set()
        states_explored = 0
        max_states = config.max_states

        try:
            while simgr.active and states_explored < max_states:
                # Check timeout
                elapsed = time.time() - start_time
                if elapsed > config.timeout_seconds:
                    logger.info(f"Exploration timeout after {elapsed:.1f}s")
                    break

                # Step simulation
                simgr.step()
                states_explored += len(simgr.active)

                # Track coverage
                for s in simgr.active:
                    if hasattr(s, 'addr') and s.addr:
                        unique_blocks.add(s.addr)

                # Avoid state explosion
                if len(simgr.active) > 100:
                    simgr.drop(stash='active', filter_func=lambda s: s.history.depth > config.max_depth)

        except Exception as e:
            logger.error(f"Exploration error: {e}")

        # Collect interesting inputs
        interesting_inputs = []
        for stash_name in ['found', 'deadended']:
            if hasattr(simgr, stash_name):
                for s in getattr(simgr, stash_name, []):
                    try:
                        concrete_input = self._concretize_input(s, config)
                        if concrete_input:
                            interesting_inputs.append(concrete_input)
                    except Exception:
                        pass

        execution_time = int((time.time() - start_time) * 1000)

        return ExplorationResult(
            binary_path=binary_path,
            exploration_id=exploration_id,
            strategy=config.strategy,
            states_explored=states_explored,
            paths_completed=len(getattr(simgr, 'deadended', [])),
            deadends_reached=len(getattr(simgr, 'deadended', [])),
            errors_encountered=len(getattr(simgr, 'errored', [])),
            execution_time_ms=execution_time,
            unique_blocks_reached=unique_blocks,
            target_states_found=len(getattr(simgr, 'found', [])),
            vulnerabilities=vulnerabilities,
            interesting_inputs=interesting_inputs[:50],  # Limit
            angr_version=self._angr_version,
        )

    def _create_initial_state(
        self,
        project,
        config: ExplorationConfig,
    ):
        """Create initial symbolic state."""
        # Entry state with symbolic input
        state = project.factory.entry_state(
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }
        )

        # Add symbolic inputs
        for sym_input in config.symbolic_inputs:
            if sym_input.input_type == "stdin":
                # Create symbolic stdin
                sym_data = claripy.BVS(sym_input.name, sym_input.size * 8)

                # Apply constraints
                for constraint in sym_input.constraints:
                    try:
                        # Parse simple constraints like "printable"
                        if constraint == "printable":
                            for i in range(sym_input.size):
                                byte = sym_data.get_byte(i)
                                state.solver.add(byte >= 0x20)
                                state.solver.add(byte <= 0x7e)
                        elif constraint == "alphanumeric":
                            for i in range(sym_input.size):
                                byte = sym_data.get_byte(i)
                                state.solver.add(claripy.Or(
                                    claripy.And(byte >= 0x30, byte <= 0x39),  # 0-9
                                    claripy.And(byte >= 0x41, byte <= 0x5a),  # A-Z
                                    claripy.And(byte >= 0x61, byte <= 0x7a),  # a-z
                                ))
                    except Exception as e:
                        logger.debug(f"Failed to apply constraint {constraint}: {e}")

                # Set up stdin
                state.posix.stdin.content = [(sym_data, sym_input.size)]
                state.posix.stdin.size = sym_input.size

        return state

    def _apply_exploration_technique(
        self,
        simgr,
        config: ExplorationConfig,
        project,
    ):
        """Apply exploration technique to simulation manager."""
        if config.strategy == ExplorationStrategy.DFS:
            simgr.use_technique(DFS())

        elif config.strategy == ExplorationStrategy.BFS:
            simgr.use_technique(BFS())

        elif config.strategy == ExplorationStrategy.DIRECTED:
            if config.target_addresses:
                simgr.use_technique(Explorer(
                    find=config.target_addresses,
                    avoid=config.avoid_addresses,
                ))

        elif config.strategy == ExplorationStrategy.VULN_HUNT:
            # Focus on dangerous function callsites
            dangerous_addrs = self._find_dangerous_function_calls(project)
            if dangerous_addrs:
                simgr.use_technique(Explorer(
                    find=dangerous_addrs,
                    avoid=config.avoid_addresses,
                ))

        # Enable veritesting for state merging
        if config.enable_veritesting:
            try:
                from angr.exploration_techniques import Veritesting
                simgr.use_technique(Veritesting())
            except ImportError:
                pass

    def _find_dangerous_function_calls(self, project) -> List[int]:
        """Find addresses where dangerous functions are called."""
        dangerous_addrs = []

        try:
            cfg = project.analyses.CFGFast()

            for func_name in self.DANGEROUS_FUNCTIONS.keys():
                # Find PLT entry for function
                try:
                    sym = project.loader.find_symbol(func_name)
                    if sym:
                        # Find all call sites to this function
                        for func in cfg.functions.values():
                            for block in func.blocks:
                                try:
                                    # Check if block calls the dangerous function
                                    if hasattr(block, 'vex') and block.vex:
                                        for stmt in block.vex.statements:
                                            if hasattr(stmt, 'data') and hasattr(stmt.data, 'addr'):
                                                if stmt.data.addr == sym.rebased_addr:
                                                    dangerous_addrs.append(block.addr)
                                except Exception:
                                    pass
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"CFG analysis failed: {e}")

        return dangerous_addrs

    def _hook_dangerous_functions(
        self,
        project,
        simgr,
    ) -> List[VulnerabilityCandidate]:
        """Hook dangerous functions to detect vulnerabilities."""
        vulnerabilities = []

        for func_name, vuln_type in self.DANGEROUS_FUNCTIONS.items():
            try:
                # Create hook that checks for symbolic arguments
                class VulnHook(angr.SimProcedure):
                    def __init__(self, vuln_name, vuln_t, vulns_list):
                        super().__init__()
                        self.vuln_name = vuln_name
                        self.vuln_type = vuln_t
                        self.vulns = vulns_list

                    def run(self, *args):
                        # Check if arguments are symbolic (attacker-controlled)
                        for i, arg in enumerate(args):
                            if self.state.solver.symbolic(arg):
                                self.vulns.append(VulnerabilityCandidate(
                                    vuln_type=self.vuln_type,
                                    address=self.state.addr,
                                    description=f"Symbolic input reaches {self.vuln_name} arg {i}",
                                    triggering_input=None,
                                    path_constraints=[],
                                    confidence=0.7,
                                    exploitable=True,
                                ))

                        # Continue normal execution (simplified)
                        return self.state.solver.BVV(0, self.state.arch.bits)

                # Hook the function
                project.hook_symbol(func_name, VulnHook(func_name, vuln_type, vulnerabilities))

            except Exception as e:
                logger.debug(f"Failed to hook {func_name}: {e}")

        return vulnerabilities

    def _concretize_input(
        self,
        state,
        config: ExplorationConfig,
    ) -> Optional[bytes]:
        """Generate concrete input from symbolic state."""
        try:
            # Find stdin content
            if hasattr(state, 'posix') and hasattr(state.posix, 'stdin'):
                stdin = state.posix.stdin
                if hasattr(stdin, 'content') and stdin.content:
                    sym_data, size = stdin.content[0]
                    if state.solver.satisfiable():
                        concrete = state.solver.eval(sym_data, cast_to=bytes)
                        return concrete
        except Exception as e:
            logger.debug(f"Concretization failed: {e}")

        return None

    def _create_empty_result(self, binary_path: str, error: str) -> ExplorationResult:
        """Create an empty result for error cases."""
        return ExplorationResult(
            binary_path=binary_path,
            exploration_id="error",
            strategy=ExplorationStrategy.COVERAGE,
            states_explored=0,
            paths_completed=0,
            deadends_reached=0,
            errors_encountered=1,
            execution_time_ms=0,
            unique_blocks_reached=set(),
            target_states_found=0,
            vulnerabilities=[],
            interesting_inputs=[],
            angr_version=self._angr_version,
        )

    async def generate_input_for_target(
        self,
        binary_path: str,
        target_address: int,
        input_size: int = 256,
        timeout: int = 60,
    ) -> Optional[bytes]:
        """
        Generate an input that reaches a specific address.

        Useful for:
        - Reaching unexplored code blocks
        - Targeting specific vulnerable functions
        - Generating test cases for specific paths
        """
        if not ANGR_AVAILABLE:
            return None

        config = ExplorationConfig(
            timeout_seconds=timeout,
            max_states=5000,
            strategy=ExplorationStrategy.DIRECTED,
            target_addresses=[target_address],
            symbolic_inputs=[
                SymbolicInput(
                    name="input",
                    size=input_size,
                    input_type="stdin",
                )
            ],
        )

        result = await self.explore(binary_path, config)

        if result.interesting_inputs:
            return result.interesting_inputs[0]

        return None

    async def find_vulnerability_paths(
        self,
        binary_path: str,
        timeout: int = 300,
    ) -> List[VulnerabilityCandidate]:
        """
        Find paths leading to potentially vulnerable code.

        Analyzes:
        - Dangerous function calls with symbolic input
        - Potential buffer overflows
        - Format string vulnerabilities
        - Command injection possibilities
        """
        if not ANGR_AVAILABLE:
            return []

        config = ExplorationConfig(
            timeout_seconds=timeout,
            max_states=10000,
            strategy=ExplorationStrategy.VULN_HUNT,
            symbolic_inputs=[
                SymbolicInput(
                    name="input",
                    size=512,
                    input_type="stdin",
                    constraints=["printable"],
                )
            ],
        )

        result = await self.explore(binary_path, config)
        return result.vulnerabilities

    async def hybrid_fuzz_integration(
        self,
        binary_path: str,
        coverage_bitmap: bytes,
        existing_corpus: List[bytes],
    ) -> List[bytes]:
        """
        Generate inputs to improve fuzzing coverage.

        Analyzes current coverage and uses symbolic execution to
        generate inputs that reach uncovered blocks.

        Args:
            binary_path: Path to target binary
            coverage_bitmap: AFL-style coverage bitmap
            existing_corpus: Current fuzzing corpus

        Returns:
            List of new inputs that may improve coverage
        """
        if not ANGR_AVAILABLE:
            return []

        new_inputs = []

        try:
            # Load binary and analyze
            project = angr.Project(binary_path, auto_load_libs=False)

            # Find uncovered blocks from coverage bitmap
            # (This is a simplified version - real implementation would
            # parse the actual AFL bitmap format)

            # Get all basic blocks
            cfg = project.analyses.CFGFast()
            all_blocks = set(node.addr for node in cfg.model.nodes())

            # Estimate covered blocks from bitmap
            covered = set()
            for i, byte in enumerate(coverage_bitmap[:len(all_blocks)]):
                if byte > 0:
                    if i < len(all_blocks):
                        covered.add(list(all_blocks)[i])

            # Find uncovered interesting blocks
            uncovered = all_blocks - covered

            # Target a few uncovered blocks
            targets = list(uncovered)[:5]

            for target in targets:
                inp = await self.generate_input_for_target(
                    binary_path,
                    target,
                    input_size=256,
                    timeout=30,
                )
                if inp:
                    new_inputs.append(inp)

        except Exception as e:
            logger.error(f"Hybrid fuzzing integration failed: {e}")

        return new_inputs


# =============================================================================
# Convenience Functions
# =============================================================================

# Global service instance
_symbolic_service: Optional[SymbolicExecutionService] = None


def get_symbolic_execution_service() -> SymbolicExecutionService:
    """Get global symbolic execution service instance."""
    global _symbolic_service
    if _symbolic_service is None:
        _symbolic_service = SymbolicExecutionService()
    return _symbolic_service


async def explore_binary(
    binary_path: str,
    timeout: int = 300,
    strategy: str = "coverage",
) -> ExplorationResult:
    """Convenience function to explore a binary."""
    service = get_symbolic_execution_service()
    config = ExplorationConfig(
        timeout_seconds=timeout,
        strategy=ExplorationStrategy(strategy) if strategy else ExplorationStrategy.COVERAGE,
    )
    return await service.explore(binary_path, config)


async def generate_reaching_input(
    binary_path: str,
    target_address: int,
    timeout: int = 60,
) -> Optional[bytes]:
    """Convenience function to generate input reaching an address."""
    service = get_symbolic_execution_service()
    return await service.generate_input_for_target(binary_path, target_address, timeout=timeout)


async def find_vulnerabilities(
    binary_path: str,
    timeout: int = 300,
) -> List[VulnerabilityCandidate]:
    """Convenience function to find vulnerabilities."""
    service = get_symbolic_execution_service()
    return await service.find_vulnerability_paths(binary_path, timeout)
