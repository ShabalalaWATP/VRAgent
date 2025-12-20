"""
Export decompilation and function metadata to JSON.

Args:
  0: output_path
  1: max_functions (optional)
  2: decomp_limit (optional, max chars per function)
"""

import json

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


def main():
    args = getScriptArgs()
    if not args or len(args) < 1:
        raise Exception("Missing output_path argument")

    output_path = args[0]
    max_functions = _safe_int(args[1], 200) if len(args) > 1 else 200
    decomp_limit = _safe_int(args[2], 4000) if len(args) > 2 else 4000

    program = currentProgram
    monitor = ConsoleTaskMonitor()

    decomp = DecompInterface()
    decomp.openProgram(program)

    funcs = list(program.getFunctionManager().getFunctions(True))
    funcs.sort(key=lambda f: f.getBody().getNumAddresses(), reverse=True)

    functions_out = []
    for func in funcs[:max_functions]:
        if monitor.isCancelled():
            break

        decompiled = ""
        try:
            res = decomp.decompileFunction(func, 30, monitor)
            if res and res.decompileCompleted():
                decompiled = res.getDecompiledFunction().getC()
        except Exception:
            decompiled = ""

        called = []
        try:
            for called_func in func.getCalledFunctions(monitor):
                called.append(called_func.getName())
        except Exception:
            called = []

        functions_out.append({
            "name": func.getName(),
            "entry": _to_hex(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses(),
            "is_thunk": bool(func.isThunk()),
            "called_functions": list(set(called)),
            "decompiled": decompiled[:decomp_limit],
        })

    payload = {
        "program": {
            "name": program.getName(),
            "language_id": str(program.getLanguageID()),
            "compiler_spec": str(program.getCompilerSpec().getCompilerSpecID()),
            "processor": str(program.getLanguage().getProcessor()),
            "image_base": _to_hex(program.getImageBase()),
        },
        "functions_total": len(funcs),
        "functions": functions_out,
    }

    with open(output_path, "w") as fh:
        json.dump(payload, fh)


main()
