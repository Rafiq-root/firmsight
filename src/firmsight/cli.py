"""Command line interface for FirmSight."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import (FirmSightError, capture_command, extract_firmware, inspect_firmware,
                   qemu_command, run_command, trace_command)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="firmsight", description="IoT firmware triage and emulation preparation")
    root.add_argument("--version", action="version", version=f"FirmSight {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="hash and scan a firmware image with Binwalk")
    inspect.add_argument("firmware", type=Path)
    inspect.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    extract = commands.add_parser("extract", help="extract recognized filesystems with Binwalk")
    extract.add_argument("firmware", type=Path)
    extract.add_argument("--output", type=Path, required=True)
    emulate = commands.add_parser("emulate", help="boot a prepared kernel and disk image in isolated QEMU")
    emulate.add_argument("--arch", required=True, choices=("arm", "aarch64", "mips", "mipsel"))
    emulate.add_argument("--kernel", type=Path, required=True)
    emulate.add_argument("--disk", type=Path, required=True, help="prepared raw disk image (not a raw vendor firmware blob)")
    emulate.add_argument("--memory", default="512M")
    emulate.add_argument("--gdb-port", type=int, help="enable QEMU's debugger stub on loopback at this port")
    emulate.add_argument("--print-command", action="store_true", help="show command without starting QEMU")
    capture = commands.add_parser("capture", help="capture packets from an isolated lab interface with tcpdump")
    capture.add_argument("--interface", required=True, help="researcher-created isolated TAP/bridge interface")
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--duration", type=int, default=60, help="capture window in seconds (default: 60)")
    trace = commands.add_parser("trace", help="attach radare2 to a loopback QEMU GDB stub")
    trace.add_argument("--endpoint", default="127.0.0.1:1234")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "inspect":
            report = inspect_firmware(args.firmware)
            print(report.to_json() if args.json else _pretty_report(report))
            return 0
        if args.command == "extract":
            destination = extract_firmware(args.firmware, args.output)
            print(f"Extraction complete: {destination}")
            return 0
        if args.command == "emulate":
            command = qemu_command(args.arch, args.kernel, args.disk, args.memory, args.gdb_port)
            if args.print_command:
                print(json.dumps(command, indent=2))
                return 0
            print("Starting isolated QEMU. Network adapter is disabled; Ctrl-C stops the VM.", file=sys.stderr)
            if args.gdb_port:
                print(f"GDB stub listening on 127.0.0.1:{args.gdb_port}; run firmsight trace --endpoint 127.0.0.1:{args.gdb_port} in another terminal.", file=sys.stderr)
            return run_command(command)
        if args.command == "capture":
            print("Capturing selected interface. Use only a dedicated, isolated lab interface.", file=sys.stderr)
            return run_command(capture_command(args.interface, args.output, args.duration))
        if args.command == "trace":
            print("Attaching radare2 to the loopback QEMU GDB stub.", file=sys.stderr)
            return run_command(trace_command(args.endpoint))
    except FirmSightError as exc:
        print(f"firmsight: error: {exc}", file=sys.stderr)
        return 2
    return 2


def _pretty_report(report: object) -> str:
    data = json.loads(report.to_json())
    lines = [f"Firmware: {data['file']}", f"Size: {data['size_bytes']} bytes", f"SHA-256: {data['sha256']}",
             f"Likely architectures: {', '.join(data['likely_architectures']) or 'unknown'}", "Signatures:"]
    lines.extend(f"  {item}" for item in data["signatures"] or ["(none detected)"])
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
