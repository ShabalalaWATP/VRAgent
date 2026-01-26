"""
Persistent Mode Service

Persistent mode is one of the most important optimizations in modern fuzzing.
Instead of fork+exec for each test case, the target runs in a loop and receives
inputs via shared memory - providing 10-100x speedup.

AFL++ Persistent Mode:
    while (__AFL_LOOP(10000)) {
        // Read input from stdin or shared memory
        // Process input
        // Reset state for next iteration
    }

This service provides:
1. Persistent mode harness generation (C, C++, Rust)
2. Deferred forkserver configuration
3. Shared memory input handling
4. In-process fuzzing support
"""

import logging
import os
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import hashlib
import struct

logger = logging.getLogger(__name__)


class PersistentModeType(str, Enum):
    """Types of persistent mode."""
    AFL_LOOP = "afl_loop"  # AFL++ __AFL_LOOP
    LIBFUZZER = "libfuzzer"  # LibFuzzer LLVMFuzzerTestOneInput
    HONGGFUZZ = "honggfuzz"  # Honggfuzz HF_ITER
    CUSTOM = "custom"  # Custom persistent loop


class HarnessLanguage(str, Enum):
    """Supported harness languages."""
    C = "c"
    CPP = "cpp"
    RUST = "rust"
    PYTHON = "python"


@dataclass
class PersistentConfig:
    """Configuration for persistent mode."""
    mode_type: PersistentModeType = PersistentModeType.AFL_LOOP
    iterations_per_loop: int = 10000  # Iterations before fork
    use_shared_memory: bool = True
    deferred_forkserver: bool = True
    max_input_size: int = 1024 * 1024  # 1MB default
    reset_state: bool = True  # Reset global state between iterations

    # Performance tuning
    disable_coverage_checks: bool = False
    use_cmplog: bool = True
    use_dictionary: bool = True

    # Memory options
    shared_memory_id: Optional[str] = None
    shared_memory_size: int = 1024 * 1024


@dataclass
class HarnessTemplate:
    """Generated harness template."""
    language: HarnessLanguage
    code: str
    compile_command: str
    dependencies: List[str]
    notes: str = ""


@dataclass
class PersistentModeStats:
    """Statistics for persistent mode execution."""
    iterations_total: int = 0
    loop_cycles: int = 0
    average_exec_time_us: float = 0.0
    peak_memory_mb: float = 0.0
    reset_overhead_pct: float = 0.0


class PersistentModeService:
    """
    Service for enabling persistent mode in fuzzing targets.

    Persistent mode provides massive speedups by:
    1. Avoiding fork+exec overhead for each test case
    2. Using shared memory for input delivery
    3. Deferring forkserver to after initialization

    Typical speedup: 10-100x compared to standard fork mode.
    """

    # AFL++ persistent mode macros
    AFL_LOOP_MACRO = "__AFL_LOOP"
    AFL_INIT_MACRO = "__AFL_INIT"
    AFL_FUZZ_INPUT = "__AFL_FUZZ_TESTCASE_BUF"
    AFL_FUZZ_LENGTH = "__AFL_FUZZ_TESTCASE_LEN"

    def __init__(self, config: Optional[PersistentConfig] = None):
        self.config = config or PersistentConfig()
        self._stats = PersistentModeStats()

        logger.info(f"PersistentModeService initialized: {self.config.mode_type.value}")

    def generate_harness(
        self,
        target_function: str,
        language: HarnessLanguage = HarnessLanguage.C,
        input_type: str = "buffer",  # buffer, file, stdin
        includes: Optional[List[str]] = None,
        custom_init: Optional[str] = None,
        custom_reset: Optional[str] = None,
    ) -> HarnessTemplate:
        """
        Generate a persistent mode harness for the given target.

        Args:
            target_function: Function to fuzz (e.g., "parse_input")
            language: Programming language
            input_type: How the target receives input
            includes: Additional includes/imports
            custom_init: Custom initialization code
            custom_reset: Custom state reset code

        Returns:
            HarnessTemplate with generated code
        """
        if language == HarnessLanguage.C:
            return self._generate_c_harness(
                target_function, input_type, includes, custom_init, custom_reset
            )
        elif language == HarnessLanguage.CPP:
            return self._generate_cpp_harness(
                target_function, input_type, includes, custom_init, custom_reset
            )
        elif language == HarnessLanguage.RUST:
            return self._generate_rust_harness(
                target_function, input_type, includes, custom_init, custom_reset
            )
        elif language == HarnessLanguage.PYTHON:
            return self._generate_python_harness(
                target_function, input_type, includes, custom_init, custom_reset
            )
        else:
            raise ValueError(f"Unsupported language: {language}")

    def _generate_c_harness(
        self,
        target_function: str,
        input_type: str,
        includes: Optional[List[str]],
        custom_init: Optional[str],
        custom_reset: Optional[str],
    ) -> HarnessTemplate:
        """Generate C persistent mode harness."""
        includes = includes or []
        custom_init = custom_init or "// No custom initialization"
        custom_reset = custom_reset or "// No custom state reset"

        include_lines = "\n".join(f'#include <{inc}>' for inc in includes)

        if self.config.mode_type == PersistentModeType.AFL_LOOP:
            code = f'''/*
 * AFL++ Persistent Mode Harness
 *
 * Compile with:
 *   afl-clang-fast -o harness harness.c -fsanitize=address,fuzzer-no-link
 *
 * Run with:
 *   afl-fuzz -i seeds -o output ./harness
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
{include_lines}

// AFL++ persistent mode macros
__AFL_FUZZ_INIT();

// Forward declaration of target function
extern int {target_function}(const uint8_t *data, size_t size);

// Global state that needs reset between iterations
static int initialized = 0;

void init_target(void) {{
    if (initialized) return;

    {custom_init}

    initialized = 1;
}}

void reset_state(void) {{
    {custom_reset}
}}

int main(int argc, char **argv) {{
    // Deferred forkserver initialization
    // This runs expensive init code ONCE, then forks
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    init_target();

    // Shared memory for input (faster than file I/O)
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    // Persistent loop - runs {self.config.iterations_per_loop} iterations before forking
    while (__AFL_LOOP({self.config.iterations_per_loop})) {{

        int len = __AFL_FUZZ_TESTCASE_LEN;

        if (len < 1) continue;
        if (len > {self.config.max_input_size}) len = {self.config.max_input_size};

        // Call the target function
        {target_function}(buf, len);

        // Reset state for next iteration
        reset_state();
    }}

    return 0;
}}
'''
            compile_cmd = "afl-clang-fast -O2 -g -o harness harness.c target.c -fsanitize=address"

        elif self.config.mode_type == PersistentModeType.LIBFUZZER:
            code = f'''/*
 * LibFuzzer Harness (in-process fuzzing)
 *
 * Compile with:
 *   clang -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address harness.c target.c
 *
 * Run with:
 *   ./harness corpus/ -max_len={self.config.max_input_size}
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
{include_lines}

// Forward declaration of target function
extern int {target_function}(const uint8_t *data, size_t size);

// Initialization (called once before fuzzing)
int LLVMFuzzerInitialize(int *argc, char ***argv) {{
    {custom_init}
    return 0;
}}

// LibFuzzer entry point - called for each test case
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < 1 || size > {self.config.max_input_size}) {{
        return 0;
    }}

    // Call target
    {target_function}(data, size);

    // Reset state
    {custom_reset}

    return 0;
}}
'''
            compile_cmd = "clang -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address -o harness harness.c target.c"

        else:
            # Custom/generic persistent mode
            code = f'''/*
 * Generic Persistent Mode Harness
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
{include_lines}

extern int {target_function}(const uint8_t *data, size_t size);

int main(int argc, char **argv) {{
    unsigned char buf[{self.config.max_input_size}];

    {custom_init}

    while (1) {{
        // Read input from stdin
        size_t len = fread(buf, 1, sizeof(buf), stdin);
        if (len == 0) break;

        {target_function}(buf, len);

        {custom_reset}
    }}

    return 0;
}}
'''
            compile_cmd = "gcc -O2 -g -o harness harness.c target.c"

        return HarnessTemplate(
            language=HarnessLanguage.C,
            code=code,
            compile_command=compile_cmd,
            dependencies=["afl++"] if self.config.mode_type == PersistentModeType.AFL_LOOP else [],
            notes="Persistent mode provides 10-100x speedup over fork mode"
        )

    def _generate_cpp_harness(
        self,
        target_function: str,
        input_type: str,
        includes: Optional[List[str]],
        custom_init: Optional[str],
        custom_reset: Optional[str],
    ) -> HarnessTemplate:
        """Generate C++ persistent mode harness."""
        includes = includes or []
        custom_init = custom_init or "// No custom initialization"
        custom_reset = custom_reset or "// No custom state reset"

        include_lines = "\n".join(f'#include <{inc}>' for inc in includes)

        code = f'''/*
 * AFL++ C++ Persistent Mode Harness
 *
 * Compile with:
 *   afl-clang-fast++ -O2 -g -o harness harness.cpp target.cpp -fsanitize=address
 */

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>
{include_lines}

__AFL_FUZZ_INIT();

extern "C" int {target_function}(const uint8_t *data, size_t size);

class FuzzTarget {{
public:
    FuzzTarget() {{
        {custom_init}
    }}

    void reset() {{
        {custom_reset}
    }}

    int fuzz(const uint8_t* data, size_t size) {{
        return {target_function}(data, size);
    }}
}};

static std::unique_ptr<FuzzTarget> target;

int main(int argc, char **argv) {{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    target = std::make_unique<FuzzTarget>();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP({self.config.iterations_per_loop})) {{
        int len = __AFL_FUZZ_TESTCASE_LEN;

        if (len < 1 || len > {self.config.max_input_size}) continue;

        target->fuzz(buf, len);
        target->reset();
    }}

    return 0;
}}
'''

        return HarnessTemplate(
            language=HarnessLanguage.CPP,
            code=code,
            compile_command="afl-clang-fast++ -O2 -g -o harness harness.cpp target.cpp -fsanitize=address",
            dependencies=["afl++"],
            notes="C++ harness with RAII resource management"
        )

    def _generate_rust_harness(
        self,
        target_function: str,
        input_type: str,
        includes: Optional[List[str]],
        custom_init: Optional[str],
        custom_reset: Optional[str],
    ) -> HarnessTemplate:
        """Generate Rust persistent mode harness."""
        custom_init = custom_init or "// No custom initialization"
        custom_reset = custom_reset or "// No custom state reset"

        code = f'''//! AFL++ Rust Persistent Mode Harness
//!
//! Add to Cargo.toml:
//!   [dependencies]
//!   afl = "0.13"
//!
//! Build with: cargo afl build
//! Run with: cargo afl fuzz -i seeds -o output target/debug/harness

#[macro_use] extern crate afl;

// Import your target module
// mod target;

fn init() {{
    {custom_init}
}}

fn reset() {{
    {custom_reset}
}}

fn {target_function}(data: &[u8]) {{
    // Your fuzzing target here
    // Example: target::parse(data);

    // Placeholder - replace with actual target
    if data.len() > 0 && data[0] == b'P' {{
        if data.len() > 1 && data[1] == b'W' {{
            if data.len() > 2 && data[2] == b'N' {{
                panic!("Found the bug!");
            }}
        }}
    }}
}}

fn main() {{
    init();

    // AFL persistent mode loop
    fuzz!(|data: &[u8]| {{
        if data.len() > {self.config.max_input_size} {{
            return;
        }}

        {target_function}(data);

        reset();
    }});
}}
'''

        return HarnessTemplate(
            language=HarnessLanguage.RUST,
            code=code,
            compile_command="cargo afl build --release",
            dependencies=["afl = \"0.13\""],
            notes="Rust harness using afl.rs crate"
        )

    def _generate_python_harness(
        self,
        target_function: str,
        input_type: str,
        includes: Optional[List[str]],
        custom_init: Optional[str],
        custom_reset: Optional[str],
    ) -> HarnessTemplate:
        """Generate Python persistent mode harness (for python-afl or Atheris)."""
        includes = includes or []
        custom_init = custom_init or "pass  # No custom initialization"
        custom_reset = custom_reset or "pass  # No custom state reset"

        import_lines = "\n".join(f"import {inc}" for inc in includes)

        code = f'''#!/usr/bin/env python3
"""
Python Fuzzing Harness (Atheris/python-afl compatible)

Install: pip install atheris
Run: python harness.py corpus/

For python-afl:
Install: pip install python-afl
Run: py-afl-fuzz -i seeds -o output -- python harness.py
"""

import sys
import atheris

{import_lines}

# Global state
_initialized = False

def init():
    global _initialized
    if _initialized:
        return

    {custom_init}

    _initialized = True

def reset():
    {custom_reset}

def {target_function}(data: bytes) -> None:
    """
    Target function to fuzz.
    Replace this with your actual target.
    """
    if len(data) < 1:
        return

    # Example target - replace with actual code
    try:
        # Your parsing/processing code here
        pass
    except Exception:
        pass  # Catch expected exceptions

def TestOneInput(data: bytes) -> int:
    """Atheris entry point."""
    if len(data) > {self.config.max_input_size}:
        return 0

    {target_function}(data)
    reset()

    return 0

def main():
    init()

    # For Atheris (libFuzzer-style)
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
'''

        return HarnessTemplate(
            language=HarnessLanguage.PYTHON,
            code=code,
            compile_command="pip install atheris && python harness.py",
            dependencies=["atheris"],
            notes="Python harness using Atheris (Google's Python fuzzer)"
        )

    def configure_engine_for_persistent(
        self,
        engine_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Configure a fuzzing engine for persistent mode.

        Args:
            engine_config: Engine configuration dictionary

        Returns:
            Updated configuration with persistent mode settings
        """
        config = engine_config.copy()

        # AFL++ specific settings
        if self.config.mode_type == PersistentModeType.AFL_LOOP:
            config["afl_persistent_mode"] = True
            config["afl_deferred_forkserver"] = self.config.deferred_forkserver
            config["afl_loop_count"] = self.config.iterations_per_loop

            # Performance flags
            config["afl_no_affinity"] = False  # Use CPU pinning
            config["afl_skip_crashes"] = False

            # CMPLOG for comparison tracking
            if self.config.use_cmplog:
                config["afl_cmplog"] = True

        # LibFuzzer settings
        elif self.config.mode_type == PersistentModeType.LIBFUZZER:
            config["libfuzzer_mode"] = True
            config["libfuzzer_runs"] = -1  # Infinite
            config["libfuzzer_max_len"] = self.config.max_input_size

        # Shared memory settings
        if self.config.use_shared_memory:
            config["use_shm"] = True
            config["shm_size"] = self.config.shared_memory_size
            if self.config.shared_memory_id:
                config["shm_id"] = self.config.shared_memory_id

        logger.info(f"Configured engine for persistent mode: {self.config.mode_type.value}")

        return config

    def estimate_speedup(
        self,
        fork_exec_time_us: int = 500,  # Typical fork+exec overhead
        target_exec_time_us: int = 100,  # Time to run target
    ) -> Tuple[float, str]:
        """
        Estimate speedup from persistent mode.

        Args:
            fork_exec_time_us: Fork+exec overhead in microseconds
            target_exec_time_us: Target execution time in microseconds

        Returns:
            (speedup_factor, explanation)
        """
        # Without persistent mode: each execution = fork + exec + target
        non_persistent_time = fork_exec_time_us + target_exec_time_us

        # With persistent mode: fork once per N iterations
        # Per iteration: target + small overhead
        persistent_overhead = 10  # Minimal loop overhead
        fork_amortized = fork_exec_time_us / self.config.iterations_per_loop
        persistent_time = target_exec_time_us + persistent_overhead + fork_amortized

        speedup = non_persistent_time / persistent_time

        explanation = (
            f"Non-persistent: {non_persistent_time}us per exec (fork:{fork_exec_time_us}us + target:{target_exec_time_us}us)\n"
            f"Persistent: {persistent_time:.1f}us per exec (target + {persistent_overhead}us overhead + "
            f"{fork_amortized:.1f}us amortized fork)\n"
            f"Speedup: {speedup:.1f}x"
        )

        return speedup, explanation

    def get_statistics(self) -> PersistentModeStats:
        """Get persistent mode statistics."""
        return self._stats

    def update_stats(
        self,
        iterations: int,
        exec_time_us: float,
        memory_mb: float,
    ):
        """Update statistics with new execution data."""
        self._stats.iterations_total += iterations
        self._stats.loop_cycles += 1

        # Running average
        n = self._stats.loop_cycles
        self._stats.average_exec_time_us = (
            (self._stats.average_exec_time_us * (n - 1) + exec_time_us) / n
        )

        self._stats.peak_memory_mb = max(self._stats.peak_memory_mb, memory_mb)


# =============================================================================
# Convenience Functions
# =============================================================================

_persistent_service: Optional[PersistentModeService] = None


def get_persistent_mode_service(
    config: Optional[PersistentConfig] = None,
) -> PersistentModeService:
    """Get global persistent mode service."""
    global _persistent_service
    if _persistent_service is None:
        _persistent_service = PersistentModeService(config)
    return _persistent_service


def generate_persistent_harness(
    target_function: str,
    language: HarnessLanguage = HarnessLanguage.C,
    mode: PersistentModeType = PersistentModeType.AFL_LOOP,
    iterations: int = 10000,
) -> HarnessTemplate:
    """Convenience function to generate a persistent mode harness."""
    service = get_persistent_mode_service(PersistentConfig(
        mode_type=mode,
        iterations_per_loop=iterations,
    ))
    return service.generate_harness(target_function, language)


def estimate_persistent_speedup(
    fork_time_us: int = 500,
    target_time_us: int = 100,
) -> float:
    """Estimate speedup from using persistent mode."""
    service = get_persistent_mode_service()
    speedup, _ = service.estimate_speedup(fork_time_us, target_time_us)
    return speedup
