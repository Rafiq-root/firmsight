"""Core firmware inspection helpers; all external commands use argv, never a shell."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


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


def extract_firmware(firmware: Path, destination: Path, mode: str = "docker",
                     progress: Callable[[str], None] | None = None) -> Path:
    firmware = firmware.expanduser().resolve()
    if not firmware.is_file():
        raise FirmSightError(f"Firmware file does not exist: {firmware}")
    if mode not in ("docker", "host"):
        raise FirmSightError("Extractor mode must be 'docker' or 'host'")
    destination = destination.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    existing = [item for item in destination.iterdir()]
    if existing:
        raise FirmSightError(f"Extraction output directory must be empty: {destination}")
    started = datetime.now(timezone.utc).isoformat()
    input_hash = hashlib.sha256()
    with firmware.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            input_hash.update(block)

    docker = shutil.which("docker") if mode == "docker" else None
    if mode == "docker":
        if not docker:
            raise FirmSightError("Docker executable not found. Install Docker or explicitly use --extractor-mode host.")
        image = "firmsight-extractor:0.1.0"
        if progress:
            progress("Checking the isolated Binwalk image")
        image_check = subprocess.run([docker, "image", "inspect", image], capture_output=True, text=True, check=False)
        if image_check.returncode:
            if progress:
                progress("Building the constrained extractor image (first run may take several minutes)")
            dockerfile = Path(__file__).parent / "sandbox" / "Dockerfile.extractor"
            build = subprocess.run([docker, "build", "--tag", image, "--file", str(dockerfile), str(dockerfile.parent)],
                                   capture_output=True, text=True, check=False)
            if build.returncode:
                raise FirmSightError(f"Could not build the isolated extractor image: {(build.stderr or build.stdout).strip()}")
        for path in (firmware, destination):
            if ":" in str(path) or "," in str(path):
                raise FirmSightError("Docker bind paths cannot contain ':' or ',' in this prototype")
        uid, gid = os.getuid(), os.getgid()
        command = [docker, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges:true", "--pids-limit", "128", "--memory", "1g",
                   "--cpus", "2", "--user", f"{uid}:{gid}", "--env", "HOME=/tmp",
                   "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m",
                   "--volume", f"{firmware}:/input/firmware:ro", "--volume", f"{destination}:/output:rw",
                   image, "-e", "-M", "-C", "/output", "/input/firmware"]
    else:
        binwalk = _tool("binwalk")
        command = [binwalk, "-e", "-M", "-C", str(destination), str(firmware)]
    version_specs = (("binwalk", ["--version"]), ("unsquashfs", ["-version"]),
                     ("7z", ["i"]), ("cpio", ["--version"]))
    tool_versions: dict[str, str] = {}
    if progress:
        progress("Recording unpacker versions")
    for tool_name, version_args in version_specs:
        if mode == "docker":
            version_cmd = [docker, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                           "--entrypoint", tool_name, image, *version_args]
        else:
            tool_path = shutil.which(tool_name)
            if not tool_path:
                tool_versions[tool_name] = "not installed"
                continue
            version_cmd = [tool_path, *version_args]
        try:
            version_result = subprocess.run(version_cmd, capture_output=True, text=True, check=False, timeout=30)
            tool_versions[tool_name] = ((version_result.stdout or version_result.stderr).strip()[:2000]
                                        or f"exit status {version_result.returncode}")
        except subprocess.TimeoutExpired:
            tool_versions[tool_name] = "version query timed out"
    try:
        if progress:
            progress("Running Binwalk extraction with a 10 minute limit")
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=600)
        return_code = result.returncode
        stdout, stderr = result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        return_code = 124
        stdout = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        stderr += "\nExtraction exceeded the 600 second limit."
    extracted_count = sum(1 for item in destination.rglob("*") if item.name not in ("firmsight-extraction.json", "firmsight-extraction.log"))
    log = {
        "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode, "firmware": str(firmware), "firmware_sha256": input_hash.hexdigest(),
        "tool_versions": tool_versions, "command": command,
        "return_code": return_code, "status": "success" if return_code == 0 else ("partial_failure" if extracted_count else "failure"),
        "extracted_entries": extracted_count, "stdout": stdout[-1_000_000:], "stderr": stderr[-1_000_000:],
    }
    (destination / "firmsight-extraction.json").write_text(json.dumps(log, indent=2) + "\n", encoding="utf-8")
    (destination / "firmsight-extraction.log").write_text(
        f"FirmSight extraction status: {log['status']}\nTools: {json.dumps(tool_versions, sort_keys=True)}\nReturn code: {return_code}\n\n{stdout}\n{stderr}\n",
        encoding="utf-8",
    )
    if progress:
        progress(f"Extraction ended with {log['status']} and {extracted_count} entries")
    if return_code:
        detail = stderr.strip() or stdout.strip() or f"exit status {return_code}"
        raise FirmSightError(f"Binwalk extraction {log['status']} ({return_code}); see {destination / 'firmsight-extraction.log'}: {detail[-1000:]}")
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
