"""
Export decompilation and function metadata to JSON.

Enhanced version with smarter function selection for security analysis.

Args:
  0: output_path
  1: max_functions (optional, default 200)
  2: decomp_limit (optional, max chars per function, default 8000)
  3: selection_mode (optional: "size", "security", "all" - default "security")
"""

import json
import re

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def _to_hex(addr):
    try:
        return "0x%X" % addr.getOffset()
    except Exception:
        return "0x0"


def _safe_int(value, fallback=0):
    try:
        return int(value)
    except Exception:
        return fallback


# Security-relevant function name patterns
SECURITY_INTERESTING_PATTERNS = [
    # Memory operations
    r'(?i)(alloc|malloc|free|realloc|calloc|memcpy|memmove|memset|strcpy|strncpy|strcat|strncat|sprintf|snprintf|vsprintf)',
    # String operations that can overflow
    r'(?i)(gets|scanf|sscanf|fscanf|fgets|read|recv|recvfrom)',
    # File operations
    r'(?i)(fopen|fread|fwrite|open|write|popen|system|exec|shell|cmd)',
    # Network operations
    r'(?i)(socket|connect|bind|listen|accept|send|sendto|inet|http|url|download)',
    # Crypto
    r'(?i)(crypt|encrypt|decrypt|hash|aes|rsa|sha|md5|hmac|key|password|auth|login|token)',
    # Registry/Config
    r'(?i)(reg|registry|config|setting|preference|ini)',
    # Process operations
    r'(?i)(process|thread|inject|hook|load|dll|module)',
    # Error/Exception handling
    r'(?i)(error|exception|fail|abort|exit|terminate)',
    # Parsing/Deserialization
    r'(?i)(parse|decode|deserialize|unmarshal|xml|json|yaml)',
    # User input
    r'(?i)(input|command|arg|param|buffer|data)',
]


def is_security_interesting(func_name, called_funcs):
    """Check if function is interesting for security analysis."""
    name_lower = func_name.lower()
    
    # Skip obvious library/thunk functions
    if name_lower.startswith(('__', '_rt', 'std::', '@')):
        return False
    if 'thunk' in name_lower or 'stub' in name_lower:
        return False
    
    # Check function name against patterns
    for pattern in SECURITY_INTERESTING_PATTERNS:
        if re.search(pattern, func_name):
            return True
    
    # Check called functions for interesting APIs
    for called in called_funcs:
        for pattern in SECURITY_INTERESTING_PATTERNS:
            if re.search(pattern, called):
                return True
    
    return False


def main():
    args = getScriptArgs()
    if not args or len(args) < 1:
        raise Exception("Missing output_path argument")

    output_path = args[0]
    max_functions = _safe_int(args[1], 200) if len(args) > 1 else 200
    decomp_limit = _safe_int(args[2], 8000) if len(args) > 2 else 8000
    selection_mode = args[3] if len(args) > 3 else "security"

    program = currentProgram
    monitor = ConsoleTaskMonitor()

    decomp = DecompInterface()
    decomp.openProgram(program)
    
    # Increase decompiler timeout for complex functions
    decomp.setSimplificationStyle("decompile")

    all_funcs = list(program.getFunctionManager().getFunctions(True))
    
    # Pre-compute called functions for all functions (for security scoring)
    func_called_map = {}
    for func in all_funcs:
        try:
            called = [cf.getName() for cf in func.getCalledFunctions(monitor)]
            func_called_map[func.getEntryPoint()] = called
        except:
            func_called_map[func.getEntryPoint()] = []
    
    # Select functions based on mode
    if selection_mode == "security":
        # Prioritize security-interesting functions
        security_funcs = []
        other_funcs = []
        
        for func in all_funcs:
            called = func_called_map.get(func.getEntryPoint(), [])
            if is_security_interesting(func.getName(), called):
                security_funcs.append(func)
            else:
                other_funcs.append(func)
        
        # Sort security functions by size (larger = more complex = more interesting)
        security_funcs.sort(key=lambda f: f.getBody().getNumAddresses(), reverse=True)
        # Sort other functions by size too
        other_funcs.sort(key=lambda f: f.getBody().getNumAddresses(), reverse=True)
        
        # Take security functions first, then fill with others
        selected_funcs = security_funcs[:max_functions]
        remaining = max_functions - len(selected_funcs)
        if remaining > 0:
            selected_funcs.extend(other_funcs[:remaining])
    
    elif selection_mode == "all":
        # Try to get more functions with smaller decompilation each
        selected_funcs = all_funcs[:max_functions * 2]  # Get more, truncate decomp
        decomp_limit = min(decomp_limit, 4000)  # Reduce per-function limit
    
    else:  # "size" mode - original behavior
        selected_funcs = sorted(all_funcs, key=lambda f: f.getBody().getNumAddresses(), reverse=True)[:max_functions]

    functions_out = []
    security_count = 0
    
    for func in selected_funcs:
        if monitor.isCancelled():
            break

        func_name = func.getName()
        called = func_called_map.get(func.getEntryPoint(), [])
        is_interesting = is_security_interesting(func_name, called)
        
        if is_interesting:
            security_count += 1

        decompiled = ""
        try:
            # Give more time to complex/interesting functions
            timeout = 60 if is_interesting else 30
            res = decomp.decompileFunction(func, timeout, monitor)
            if res and res.decompileCompleted():
                decompiled = res.getDecompiledFunction().getC()
        except Exception:
            decompiled = ""

        # For security-interesting functions, allow more decompilation
        limit = decomp_limit * 2 if is_interesting else decomp_limit

        functions_out.append({
            "name": func_name,
            "entry": _to_hex(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses(),
            "is_thunk": bool(func.isThunk()),
            "called_functions": list(set(called))[:50],  # Limit called functions list
            "decompiled": decompiled[:limit],
            "security_relevant": is_interesting,
        })

    payload = {
        "program": {
            "name": program.getName(),
            "language_id": str(program.getLanguageID()),
            "compiler_spec": str(program.getCompilerSpec().getCompilerSpecID()),
            "processor": str(program.getLanguage().getProcessor()),
            "image_base": _to_hex(program.getImageBase()),
        },
        "functions_total": len(all_funcs),
        "functions_exported": len(functions_out),
        "security_relevant_count": security_count,
        "selection_mode": selection_mode,
        "functions": functions_out,
    }

    with open(output_path, "w") as fh:
        json.dump(payload, fh)


main()
