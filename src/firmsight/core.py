"""Core firmware inspection helpers; all external commands use argv, never a shell."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence


class FirmSightError(RuntimeError):
    """A user-correctable FirmSight operation error."""


@dataclass
class FirmwareReport:
    file: str
    size_bytes: int
    sha256: str
    signatures: list[str]
    likely_architectures: list[str]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def _tool(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise FirmSightError(f"Required tool not found on PATH: {name}")
    return resolved


def inspect_firmware(path: Path) -> FirmwareReport:
    path = path.expanduser().resolve()
    if not path.is_file():
        raise FirmSightError(f"Firmware file does not exist: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)

    binwalk = _tool("binwalk")
    result = subprocess.run([binwalk, str(path)], capture_output=True, text=True, check=False)
    if result.returncode not in (0, 1):
        raise FirmSightError(f"binwalk failed ({result.returncode}): {result.stderr.strip()}")
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    signatures = [line for line in lines if "DECIMAL" not in line.upper() and "DESCRIPTION" not in line.upper()]
    combined = "\n".join(lines).lower()
    arch = []
    for label, terms in (("ARM", ("arm", "aarch64")), ("MIPS", ("mips",)), ("PowerPC", ("powerpc", "ppc")), ("x86", (" x86", "i386", "x86_64"))):
        if any(term in combined for term in terms):
            arch.append(label)
    return FirmwareReport(str(path), path.stat().st_size, digest.hexdigest(), signatures, arch)


def extract_firmware(firmware: Path, destination: Path) -> Path:
    firmware = firmware.expanduser().resolve()
    if not firmware.is_file():
        raise FirmSightError(f"Firmware file does not exist: {firmware}")
    destination = destination.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    binwalk = _tool("binwalk")
    result = subprocess.run(
        [binwalk, "-e", "-M", "-C", str(destination), str(firmware)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise FirmSightError(f"binwalk extraction failed ({result.returncode}): {detail}")
    return destination


def qemu_command(architecture: str, kernel: Path, disk: Path, memory: str = "512M", gdb_port: int | None = None) -> list[str]:
    """Build a network-disabled QEMU full-system command for a prepared disk image."""
    suffix = {"arm": "arm", "aarch64": "aarch64", "mips": "mips", "mipsel": "mipsel"}.get(architecture)
    if not suffix:
        raise FirmSightError("Architecture must be one of: arm, aarch64, mips, mipsel")
    kernel = kernel.expanduser().resolve()
    disk = disk.expanduser().resolve()
    if not kernel.is_file():
        raise FirmSightError(f"Kernel image does not exist: {kernel}")
    if not disk.is_file():
        raise FirmSightError(f"Disk image does not exist: {disk}")
    if not memory.strip() or any(c in memory for c in "\n\r\0"):
        raise FirmSightError("Invalid memory size")
    qemu = _tool(f"qemu-system-{suffix}")
    machine, cpu = {
        "arm": ("virt", "cortex-a15"),
        "aarch64": ("virt", "cortex-a57"),
        "mips": ("malta", "24Kf"),
        "mipsel": ("malta", "24Kf"),
    }[architecture]
    command = [qemu, "-M", machine, "-cpu", cpu, "-m", memory, "-nographic", "-snapshot",
               "-kernel", str(kernel), "-drive", f"file={disk},format=raw,if=virtio",
               "-append", "console=ttyAMA0,115200 root=/dev/vda rw", "-nic", "none"]
    if gdb_port is not None:
        if not 1 <= gdb_port <= 65535:
            raise FirmSightError("GDB port must be between 1 and 65535")
        command.extend(["-gdb", f"tcp:127.0.0.1:{gdb_port}"])
    return command


def capture_command(interface: str, output: Path, duration: int = 60) -> list[str]:
    """Capture packets from a researcher-selected interface using tcpdump."""
    if not interface or any(c.isspace() or c in "\n\r\0" for c in interface):
        raise FirmSightError("Invalid network interface name")
    if duration < 1 or duration > 86400:
        raise FirmSightError("Capture duration must be between 1 and 86400 seconds")
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    return [_tool("tcpdump"), "-i", interface, "-nn", "-U", "-w", str(output), "-G", str(duration), "-W", "1"]


def trace_command(endpoint: str) -> list[str]:
    """Connect radare2's debugger to a loopback QEMU GDB stub."""
    if not endpoint or any(c in endpoint for c in "\n\r\0"):
        raise FirmSightError("Invalid debugger endpoint")
    host, separator, port = endpoint.rpartition(":")
    if not separator or host not in ("127.0.0.1", "localhost", "::1"):
        raise FirmSightError("Debugger endpoint must use loopback, for example 127.0.0.1:1234")
    try:
        if not 1 <= int(port) <= 65535:
            raise ValueError
    except ValueError as exc:
        raise FirmSightError("Debugger port must be between 1 and 65535") from exc
    return [_tool("r2"), "-d", f"gdb://{host}:{port}"]


def run_command(argv: Sequence[str]) -> int:
    try:
        return subprocess.run(list(argv), check=False).returncode
    except KeyboardInterrupt:
        return 130
