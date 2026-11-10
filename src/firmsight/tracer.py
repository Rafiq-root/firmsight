"""Generate bounded GDB scripts for QEMU's loopback GDB stub."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .core import FirmSightError, _tool


_FUNCTION = re.compile(r"(?:\*0x[0-9a-fA-F]+|[A-Za-z_.$][A-Za-z0-9_.$@]*)\Z")
CRASH_SYMBOLS = ("panic", "__stack_chk_fail", "__fortify_fail", "abort")


def create_gdb_trace(endpoint: str, functions: list[str], output: Path,
                     stack_depth: int = 8, symbols: Path | None = None,
                     crash_breakpoints: bool = True, script_path: Path | None = None,
                     gdb_binary: str | None = None, remote_output: str | None = None,
                     remote_symbols: str | None = None) -> tuple[list[str], Path, Path]:
    """Create a GDB command script that logs selected hits and crash paths."""
    host, separator, port = endpoint.rpartition(":")
    if not separator or host not in ("127.0.0.1", "localhost", "::1"):
        raise FirmSightError("Debugger endpoint must use loopback, for example 127.0.0.1:1234")
    try:
        if not 1 <= int(port) <= 65535:
            raise ValueError
    except ValueError as exc:
        raise FirmSightError("Debugger port must be between 1 and 65535") from exc
    if stack_depth < 0 or stack_depth > 64:
        raise FirmSightError("Stack depth must be between 0 and 64")
    for function in functions:
        if not _FUNCTION.fullmatch(function):
            raise FirmSightError(f"Invalid function name/address: {function}")
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    script_path = script_path.expanduser().resolve() if script_path else output.with_suffix(output.suffix + ".gdb")
    if "\n" in str(output) or '"' in str(output):
        raise FirmSightError("Trace output path cannot contain quotes or newlines")

    log_target = remote_output or str(output)
    if '"' in log_target or "\n" in log_target:
        raise FirmSightError("Trace output path cannot contain quotes or newlines")
    lines = ["set pagination off", "set confirm off", "set breakpoint pending on",
             f'set logging file "{log_target}"', "set logging overwrite on", "set logging on"]
    if symbols:
        symbols = symbols.expanduser().resolve()
        if not symbols.is_file():
            raise FirmSightError(f"Symbol file does not exist: {symbols}")
        if '"' in str(symbols) or "\n" in str(symbols):
            raise FirmSightError("Symbol path cannot contain quotes or newlines")
        symbol_target = remote_symbols or str(symbols)
        if '"' in symbol_target or "\n" in symbol_target:
            raise FirmSightError("Symbol path cannot contain quotes or newlines")
        lines.append(f'file "{symbol_target}"')
    lines.extend([f"target remote {host}:{port}", 'printf "[FIRMSIGHT] attached to QEMU\\n"'])
    for function in functions:
        lines.extend([f"break {function}", "commands", "silent",
                      f'printf "[HIT] {function}\\n"', f"bt {stack_depth}", "continue", "end"])
    if crash_breakpoints:
        for symbol in CRASH_SYMBOLS:
            lines.extend([f"break {symbol}", "commands", "silent",
                          f'printf "[CRASH PATH] {symbol}\\n"', "info registers", f"bt {stack_depth}", "quit", "end"])
    lines.extend(["continue", "set logging off", "quit"])
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    gdb = gdb_binary or _tool("gdb-multiarch")
    return [gdb, "-q", "-batch", "-x", str(script_path)], script_path, output


def run_timed(argv: list[str], duration: int) -> int:
    if duration < 1 or duration > 86400:
        raise FirmSightError("Trace duration must be between 1 and 86400 seconds")
    try:
        return subprocess.run(argv, check=False, timeout=duration).returncode
    except subprocess.TimeoutExpired:
        return 124
