"""Command line interface for FirmSight."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import (FirmSightError, capture_command, extract_firmware, inspect_firmware,
                   qemu_command, run_command, trace_command)
from .firmware import initramfs_qemu_command, prepare_firmware
from .network import (init_lab, lab_capture_command, lab_command, lab_emulate_command,
                      lab_trace_command, qemu_lab_network_args)
from .profiles import list_profiles, load_profile
from .reports import analyze_rootfs, write_report
from .tracer import create_gdb_trace, run_timed
from .terminal import run_tui


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
    extract.add_argument("--extractor-mode", choices=("docker", "host"), default="docker",
                         help="run Binwalk in a constrained container (default) or directly on the host")
    prepare = commands.add_parser("prepare", help="extract firmware and prepare a kernel/rootfs initramfs")
    _add_firmware_args(prepare)
    emulate_fw = commands.add_parser("emulate-firmware", help="prepare a vendor firmware image and launch it in QEMU")
    _add_firmware_args(emulate_fw)
    emulate_fw.add_argument("--memory")
    emulate_fw.add_argument("--machine", help="override the generic QEMU machine profile")
    emulate_fw.add_argument("--cpu", help="override the generic QEMU CPU model")
    emulate_fw.add_argument("--kernel-args", help="replace generic console/init kernel arguments")
    emulate_fw.add_argument("--dtb", type=Path, help="optional device tree blob")
    emulate_fw.add_argument("--gdb-port", type=int, help="enable QEMU's debugger stub on loopback")
    emulate_fw.add_argument("--print-command", action="store_true", help="prepare assets and print command without launching QEMU")
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
    profiles = commands.add_parser("profiles", help="list built-in QEMU device profiles")
    profiles.add_argument("--json", action="store_true")
    report_cmd = commands.add_parser("report", help="inventory a rootfs and write JSON and HTML static-analysis reports")
    report_cmd.add_argument("--firmware", type=Path, required=True)
    report_cmd.add_argument("--rootfs", type=Path, required=True)
    report_cmd.add_argument("--output-dir", type=Path, required=True)
    report_cmd.add_argument("--max-file-size", type=int, default=16 * 1024 * 1024,
                            help="maximum bytes scanned per file for static strings (default: 16 MiB)")
    trace = commands.add_parser("trace", help="attach radare2 to a loopback QEMU GDB stub")
    trace.add_argument("--endpoint", default="127.0.0.1:1234")
    trace.add_argument("--gdb", action="store_true", help="generate a bounded GDB trace instead of opening radare2")
    trace.add_argument("--function", action="append", default=[], help="function name or *0xADDRESS to log; repeatable")
    trace.add_argument("--symbols", type=Path, help="ELF symbol file such as an unstripped vmlinux")
    trace.add_argument("--output", type=Path, default=Path("firmsight-trace.log"))
    trace.add_argument("--duration", type=int, default=300, help="maximum trace duration in seconds")
    trace.add_argument("--stack-depth", type=int, default=8)
    trace.add_argument("--crash-breakpoints", action=argparse.BooleanOptionalAction, default=True)
    lab = commands.add_parser("lab", help="manage the Docker network-isolated analysis lab")
    lab_commands = lab.add_subparsers(dest="lab_action", required=True)
    lab_init = lab_commands.add_parser("init", help="write Docker Compose lab files into an analysis directory")
    lab_init.add_argument("--workdir", type=Path, required=True)
    for action in ("up", "down", "status", "logs"):
        command = lab_commands.add_parser(action)
        command.add_argument("--workdir", type=Path, required=True)
        if action == "logs":
            command.add_argument("--follow", action="store_true")
    lab_emulate = lab_commands.add_parser("emulate", help="run the prepared firmware inside the isolated lab")
    lab_emulate.add_argument("--workdir", type=Path, required=True)
    lab_emulate.add_argument("--manifest", type=Path)
    lab_emulate.add_argument("--memory")
    lab_emulate.add_argument("--machine")
    lab_emulate.add_argument("--cpu")
    lab_emulate.add_argument("--kernel-args")
    lab_emulate.add_argument("--dtb", type=Path)
    lab_emulate.add_argument("--gdb-port", type=int)
    lab_emulate.add_argument("--profile")
    lab_trace = lab_commands.add_parser("trace", help="run GDB breakpoints against the QEMU stub inside the lab")
    lab_trace.add_argument("--workdir", type=Path, required=True)
    lab_trace.add_argument("--endpoint", default="127.0.0.1:1234")
    lab_trace.add_argument("--function", action="append", default=[])
    lab_trace.add_argument("--symbols", type=Path)
    lab_trace.add_argument("--output", default="trace.log")
    lab_trace.add_argument("--duration", type=int, default=300)
    lab_trace.add_argument("--stack-depth", type=int, default=8)
    lab_trace.add_argument("--crash-breakpoints", action=argparse.BooleanOptionalAction, default=True)
    lab_capture = lab_commands.add_parser("capture", help="capture traffic arriving at the DNS/HTTP sinkhole")
    lab_capture.add_argument("--workdir", type=Path, required=True)
    lab_capture.add_argument("--output", default="session.pcap")
    lab_capture.add_argument("--duration", type=int, default=90)
    tui = commands.add_parser("tui", help="open the interactive case dashboard")
    tui.add_argument("firmware", type=Path)
    tui.add_argument("--workdir", type=Path, required=True)
    tui.add_argument("--extractor-mode", choices=("docker", "host"), default="docker")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "tui":
            return run_tui(args.firmware, args.workdir, extractor_mode=args.extractor_mode)
        if args.command == "inspect":
            report = inspect_firmware(args.firmware)
            print(report.to_json() if args.json else _pretty_report(report))
            return 0
        if args.command == "extract":
            destination = extract_firmware(args.firmware, args.output, args.extractor_mode, _progress)
            print(f"Extraction complete: {destination}")
            return 0
        if args.command == "prepare":
            profile = load_profile(args.profile) if args.profile else None
            if profile and args.arch and profile["architecture"] != args.arch:
                raise FirmSightError("Selected architecture conflicts with the device profile")
            manifest = prepare_firmware(args.firmware, args.workdir, args.kernel, args.rootfs,
                                        args.arch or (profile["architecture"] if profile else None),
                                        args.extractor_mode, _progress)
            if profile:
                manifest["profile"] = profile["name"]
                Path(str(manifest["manifest"])).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(manifest, indent=2))
            return 0
        if args.command == "emulate-firmware":
            profile = load_profile(args.profile) if args.profile else None
            if profile and args.arch and profile["architecture"] != args.arch:
                raise FirmSightError("Selected architecture conflicts with the device profile")
            manifest = prepare_firmware(args.firmware, args.workdir, args.kernel, args.rootfs,
                                        args.arch or (profile["architecture"] if profile else None),
                                        args.extractor_mode, _progress)
            command = initramfs_qemu_command(
                str(manifest["architecture"]), Path(str(manifest["kernel"])),
                Path(str(manifest["initramfs"])), args.memory, args.machine, args.cpu,
                args.kernel_args, args.dtb, args.gdb_port, profile=profile,
            )
            if args.print_command:
                print(json.dumps({"manifest": manifest, "qemu_command": command}, indent=2))
                return 0
            print("Starting QEMU with the generated initramfs. The VM has no network adapter.", file=sys.stderr)
            if args.gdb_port:
                print(f"GDB stub listening on 127.0.0.1:{args.gdb_port}.", file=sys.stderr)
            return run_command(command)
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
            if args.gdb or args.function:
                command, script_path, output_path = create_gdb_trace(
                    args.endpoint, args.function, args.output, args.stack_depth,
                    args.symbols, args.crash_breakpoints,
                )
                print(f"Running GDB trace; script: {script_path}; output: {output_path}", file=sys.stderr)
                return run_timed(command, args.duration)
            print("Attaching radare2 to the loopback QEMU GDB stub.", file=sys.stderr)
            return run_command(trace_command(args.endpoint))
        if args.command == "profiles":
            items = list_profiles()
            print(json.dumps(items, indent=2) if args.json else "\n".join(f"{item['name']:<16} {item['architecture']:<8} {item['description']}" for item in items))
            return 0
        if args.command == "report":
            report = analyze_rootfs(args.firmware, args.rootfs, args.max_file_size)
            json_path, html_path = write_report(report, args.output_dir)
            print(json.dumps({"json": str(json_path), "html": str(html_path), "summary": report["summary"]}, indent=2))
            return 0
        if args.command == "lab":
            if args.lab_action == "init":
                print(f"Isolated lab files created at {init_lab(args.workdir)}")
                return 0
            if args.lab_action == "emulate":
                manifest_path = (args.manifest or (args.workdir / "manifest.json")).expanduser().resolve()
                if not manifest_path.is_file():
                    raise FirmSightError(f"Manifest does not exist: {manifest_path}. Run `firmsight prepare` first.")
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                architecture = str(manifest.get("architecture", ""))
                profile = load_profile(args.profile) if args.profile else None
                if profile and profile["architecture"] != architecture:
                    raise FirmSightError("Selected profile architecture conflicts with the prepared firmware")
                kernel = Path(str(manifest.get("kernel", "")))
                initramfs = Path(str(manifest.get("initramfs", "")))
                binaries = {"arm": "qemu-system-arm", "aarch64": "qemu-system-aarch64",
                            "mips": "qemu-system-mips", "mipsel": "qemu-system-mipsel"}
                if architecture not in binaries:
                    raise FirmSightError("Manifest has no supported architecture")
                command = initramfs_qemu_command(architecture, kernel, initramfs, args.memory,
                                                  args.machine, args.cpu, args.kernel_args, args.dtb,
                                                  args.gdb_port, binaries[architecture], profile)
                network_start = command.index("-nic")
                command[network_start:] = qemu_lab_network_args(architecture)
                print("Starting the guest on the internal Docker network. It can reach only lab containers such as the sinkhole.", file=sys.stderr)
                return run_command(lab_emulate_command(args.workdir, command))
            if args.lab_action == "capture":
                print("Capturing traffic arriving at the lab sinkhole.", file=sys.stderr)
                return run_command(lab_capture_command(args.workdir, args.output, args.duration))
            if args.lab_action == "trace":
                if Path(args.output).name != args.output or args.output in ("", ".", ".."):
                    raise FirmSightError("Trace output must be a filename, not a path")
                labdir = args.workdir.expanduser().resolve() / ".firmsight-lab" / "captures"
                output = labdir / args.output
                script_path = labdir / f"{args.output}.gdb"
                remote_symbols = None
                if args.symbols:
                    symbols = args.symbols.expanduser().resolve()
                    try:
                        remote_symbols = "/analysis/" + str(symbols.relative_to(args.workdir.expanduser().resolve()))
                    except ValueError as exc:
                        raise FirmSightError("Lab symbol file must live under the analysis work directory") from exc
                _, script_path, _ = create_gdb_trace(
                    args.endpoint, args.function, output, args.stack_depth, args.symbols,
                    args.crash_breakpoints, script_path, "gdb-multiarch", "/captures/" + args.output,
                    remote_symbols,
                )
                command = lab_trace_command(args.workdir, script_path)
                print(f"Running isolated GDB trace; output: {output}", file=sys.stderr)
                return run_timed(command, args.duration)
            extra = ["--follow"] if args.lab_action == "logs" and args.follow else []
            if args.lab_action == "up":
                print("Starting an internally isolated Docker network with local DNS/HTTP sinkhole.", file=sys.stderr)
            if args.lab_action == "down":
                print("Stopping FirmSight lab containers and removing their isolated network.", file=sys.stderr)
            return run_command(lab_command(args.workdir, args.lab_action, extra))
    except FirmSightError as exc:
        print(f"firmsight: error: {exc}", file=sys.stderr)
        return 2
    return 2


def _add_firmware_args(command: argparse.ArgumentParser) -> None:
    command.add_argument("firmware", type=Path)
    command.add_argument("--workdir", type=Path, required=True)
    command.add_argument("--kernel", type=Path, help="select a kernel when discovery is ambiguous or unsupported")
    command.add_argument("--rootfs", type=Path, help="select an extracted Linux root filesystem tree")
    command.add_argument("--arch", choices=("arm", "aarch64", "mips", "mipsel"), help="override or supply the kernel architecture")
    command.add_argument("--profile", help="built-in profile name or JSON profile path")
    command.add_argument("--extractor-mode", choices=("docker", "host"), default="docker",
                         help="run Binwalk in a constrained container (default) or directly on the host")


def _progress(message: str) -> None:
    print(f"[FirmSight] {message}", file=sys.stderr, flush=True)


def _pretty_report(report: object) -> str:
    data = json.loads(report.to_json())
    lines = [f"Firmware: {data['file']}", f"Size: {data['size_bytes']} bytes", f"SHA-256: {data['sha256']}",
             f"Likely architectures: {', '.join(data['likely_architectures']) or 'unknown'}", "Signatures:"]
    lines.extend(f"  {item}" for item in data["signatures"] or ["(none detected)"])
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
