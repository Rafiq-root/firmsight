"""Lightweight interactive terminal dashboard for FirmSight workflows."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from .core import FirmSightError
from .network import lab_command


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _snapshot(firmware: Path, workdir: Path) -> list[str]:
    rows = ["CURRENT CASE", f"Firmware: {firmware}", f"SHA-256: {_sha256(firmware)}"]
    manifest_path = workdir / "manifest.json"
    extraction_path = workdir / "extracted" / "firmsight-extraction.json"
    report_path = workdir / "reports" / "firmsight-report.json"
    if extraction_path.is_file():
        data = json.loads(extraction_path.read_text(encoding="utf-8"))
        rows.append(f"Extraction: {data.get('status')} ({data.get('extracted_entries', 0)} entries)")
    else:
        rows.append("Extraction: not prepared")
    if manifest_path.is_file():
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        rows.append(f"Boot assets: {data.get('architecture')} · {Path(str(data.get('kernel', ''))).name} · {Path(str(data.get('initramfs', ''))).name}")
    else:
        rows.append("Boot assets: no manifest")
    if report_path.is_file():
        data = json.loads(report_path.read_text(encoding="utf-8"))
        summary = data.get("summary", {})
        rows.append(f"Findings: {summary.get('network_indicators', 0)} network · {summary.get('credential_keys', 0)} credential keys · {summary.get('suspicious_command_strings', 0)} command strings")
    else:
        rows.append("Findings: no static report")
    capture_dir = workdir / ".firmsight-lab" / "captures"
    captures = sorted(capture_dir.glob("*.pcap"), key=lambda path: path.stat().st_mtime, reverse=True) if capture_dir.is_dir() else []
    if captures:
        latest = captures[0]
        rows.append(f"Packet capture: {latest.name} ({latest.stat().st_size} bytes)")
    else:
        rows.append("Packet capture: none")
    compose_file = workdir / ".firmsight-lab" / "compose.yaml"
    if compose_file.is_file():
        try:
            status = subprocess.run(lab_command(workdir, "status"), capture_output=True, text=True, timeout=5, check=False)
            status_lines = [line.strip() for line in status.stdout.splitlines() if line.strip()]
            rows.append("Lab status: " + (" · ".join(status_lines[-2:]) if status.returncode == 0 and status_lines else "unavailable"))
            logs = subprocess.run(lab_command(workdir, "logs"), capture_output=True, text=True, timeout=5, check=False)
            events = [line.strip() for line in logs.stdout.splitlines() if '"kind"' in line][-2:]
            rows.append("Latest sinkhole events:")
            rows.extend("  " + (line[:180] + ("…" if len(line) > 180 else "")) for line in events)
            if not events:
                rows.append("  none yet")
        except (FirmSightError, OSError, subprocess.TimeoutExpired):
            rows.append("Lab status: unavailable")
    else:
        rows.append("Lab status: not initialized")
    return rows


def _stream(command: list[str], output: TextIO) -> int:
    output.write("\n$ " + " ".join(command) + "\n")
    output.flush()
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, bufsize=1)
        assert process.stdout is not None
        for line in process.stdout:
            output.write(line)
            output.flush()
        return process.wait()
    except KeyboardInterrupt:
        if "process" in locals() and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        return 130
    except OSError as exc:
        output.write(f"FirmSight could not start the command: {exc}\n")
        return 127


def run_tui(firmware: Path, workdir: Path, input_fn: Callable[[str], str] | None = None,
            output: TextIO | None = None, runner: Callable[[list[str], TextIO], int] | None = None,
            extractor_mode: str = "docker") -> int:
    """Interactive line-oriented case dashboard; subprocess output streams into the session."""
    firmware = firmware.expanduser().resolve()
    workdir = workdir.expanduser().resolve()
    if not firmware.is_file():
        raise FirmSightError(f"Firmware file does not exist: {firmware}")
    workdir.mkdir(parents=True, exist_ok=True)
    input_fn = input_fn or input
    output = output or sys.stdout
    runner = runner or _stream
    python = sys.executable
    cli = [python, "-u", "-m", "firmsight.cli"]
    actions = {
        "i": ([*cli, "inspect", str(firmware), "--json"], "Inspect and fingerprint"),
        "x": ([*cli, "extract", str(firmware), "--output", str(workdir / "extraction-only"), "--extractor-mode", extractor_mode], "Sandboxed extraction"),
        "p": ([*cli, "prepare", str(firmware), "--workdir", str(workdir), "--extractor-mode", extractor_mode], "Prepare kernel/rootfs/initramfs"),
        "r": None,
        "e": ([*cli, "emulate-firmware", str(firmware), "--workdir", str(workdir), "--extractor-mode", extractor_mode], "Boot with networking disabled"),
        "u": ([*cli, "lab", "up", "--workdir", str(workdir)], "Start isolated Docker lab"),
        "l": ([*cli, "lab", "emulate", "--workdir", str(workdir), "--gdb-port", "1234"], "Boot in isolated Docker lab (GDB port 1234)"),
        "c": ([*cli, "lab", "capture", "--workdir", str(workdir)], "Capture sinkhole traffic (90 seconds)"),
        "t": ([*cli, "lab", "trace", "--workdir", str(workdir)], "Trace QEMU GDB stub"),
        "s": ([*cli, "lab", "status", "--workdir", str(workdir)], "Show lab status"),
        "g": ([*cli, "lab", "logs", "--workdir", str(workdir)], "Show latest DNS/HTTP sinkhole events"),
        "d": ([*cli, "lab", "down", "--workdir", str(workdir)], "Stop lab and remove isolated network"),
    }
    while True:
        output.write("\n" + "=" * 72 + "\nFirmSight · case dashboard\n" + "=" * 72 + "\n")
        output.write("\n".join(_snapshot(firmware, workdir)) + "\n\nACTIONS\n")
        for key, entry in actions.items():
            label = entry[1] if entry else "Generate static report"
            output.write(f"  {key}  {label}\n")
        output.write("  q  Quit\n")
        output.flush()
        choice = input_fn("firmsight> ").strip().lower()
        if choice in ("q", "quit", "exit"):
            return 0
        if choice not in actions:
            output.write("Choose one of the listed keys.\n")
            continue
        if choice == "r":
            try:
                manifest = json.loads((workdir / "manifest.json").read_text(encoding="utf-8"))
                rootfs = Path(str(manifest["rootfs_directory"]))
            except (OSError, json.JSONDecodeError, KeyError) as exc:
                output.write(f"Prepare the firmware first; no rootfs manifest is available ({exc}).\n")
                continue
            command = [*cli, "report", "--firmware", str(firmware), "--rootfs", str(rootfs),
                       "--output-dir", str(workdir / "reports")]
        else:
            command = actions[choice][0]
        code = runner(command, output)
        output.write(f"\nCommand finished with exit code {code}.\n")
        output.flush()
