"""Discovery and boot preparation for unpacked firmware images."""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
from collections.abc import Callable
from pathlib import Path

from .core import FirmSightError, _tool, extract_firmware
from .initramfs import create_initramfs

SUPPORTED_ARCHES = ("arm", "aarch64", "mips", "mipsel")


def _files_below(root: Path, limit: int = 100_000) -> list[Path]:
    found: list[Path] = []
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(name for name in directories if not (Path(current) / name).is_symlink())
        for name in filenames:
            path = Path(current) / name
            if path.is_file() and not path.is_symlink():
                found.append(path)
                if len(found) >= limit:
                    raise FirmSightError(f"Extraction contains more than {limit} regular files; narrow the input or select assets explicitly")
    return found


def _rootfs_candidates(root: Path) -> list[Path]:
    candidates: list[Path] = []
    for current, directories, _ in os.walk(root, followlinks=False):
        base = Path(current)
        directories[:] = sorted(name for name in directories if not (base / name).is_symlink())
        etc = base / "etc"
        executable_dirs = (base / "bin", base / "sbin", base / "usr" / "bin", base / "usr" / "sbin")
        if etc.is_dir() and sum(p.is_dir() or p.is_symlink() for p in executable_dirs) >= 2:
            candidates.append(base)
    return candidates


def _elf_arch(path: Path) -> str | None:
    try:
        with path.open("rb") as stream:
            header = stream.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    byte_order = "<" if header[5] == 1 else ">" if header[5] == 2 else None
    if byte_order is None:
        return None
    machine = struct.unpack(byte_order + "H", header[18:20])[0]
    if machine == 40:
        return "arm"
    if machine == 183:
        return "aarch64"
    if machine == 8:
        return "mipsel" if header[5] == 1 else "mips"
    return None


def _describe(path: Path) -> str:
    result = subprocess.run([_tool("file"), "-b", "--", str(path)], capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def _kernel_candidates(root: Path, files: list[Path]) -> list[dict[str, str]]:
    candidates = []
    name_hint = re.compile(r"(^|[/_.-])(kernel|zimage|uimage|vmlinuz|vmlinux|image)([/_.-]|$)", re.IGNORECASE)
    for path in files:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size < 64 or size > 128 * 1024 * 1024:
            continue
        if not name_hint.search(path.name) and not (128 * 1024 <= size <= 64 * 1024 * 1024):
            continue
        description = _describe(path)
        lowered = description.lower()
        arch = _elf_arch(path)
        if arch is None:
            if "aarch64" in lowered or "arm64" in lowered:
                arch = "aarch64"
            elif "mips" in lowered:
                arch = "mipsel" if "little-endian" in lowered or "le " in lowered else "mips"
            elif "arm" in lowered:
                arch = "arm"
        if arch or any(token in lowered for token in ("linux kernel", "boot executable", "u-boot legacy")):
            candidates.append({"path": str(path), "description": description, "architecture": arch or "unknown"})
    return candidates


def _select_kernel(candidates: list[dict[str, str]], requested: Path | None) -> Path:
    if requested:
        path = requested.expanduser().resolve()
        if not path.is_file():
            raise FirmSightError(f"Kernel image does not exist: {path}")
        return path
    if not candidates:
        raise FirmSightError("No recognizable kernel was found in extracted files. Supply --kernel with a compatible kernel image.")
    if len(candidates) > 1:
        paths = "\n".join(f"  {item['path']} ({item['architecture']}; {item['description']})" for item in candidates)
        raise FirmSightError(f"Multiple possible kernels found; select one with --kernel:\n{paths}")
    return Path(candidates[0]["path"])


def _select_rootfs(root: Path, requested: Path | None) -> Path:
    if requested:
        path = requested.expanduser().resolve()
        if not path.is_dir():
            raise FirmSightError(f"Root filesystem directory does not exist: {path}")
        return path
    candidates = _rootfs_candidates(root)
    if not candidates:
        raise FirmSightError("No root filesystem tree was recognized. Supply --rootfs pointing to an extracted Linux root directory.")
    candidates.sort(key=lambda p: (len(p.parts), str(p)), reverse=True)
    best_depth = len(candidates[0].parts)
    best = [path for path in candidates if len(path.parts) == best_depth]
    if len(best) != 1:
        choices = "\n".join(f"  {path}" for path in best)
        raise FirmSightError(f"Multiple root filesystem candidates found; select one with --rootfs:\n{choices}")
    return best[0]


def prepare_firmware(firmware: Path, workdir: Path, kernel: Path | None = None,
                     rootfs: Path | None = None, architecture: str | None = None,
                     extractor_mode: str = "docker",
                     progress: Callable[[str], None] | None = None) -> dict[str, object]:
    """Extract a vendor image, discover boot assets, and build a rootfs initramfs."""
    firmware = firmware.expanduser().resolve()
    if not firmware.is_file():
        raise FirmSightError(f"Firmware file does not exist: {firmware}")
    if architecture and architecture not in SUPPORTED_ARCHES:
        raise FirmSightError(f"Architecture must be one of: {', '.join(SUPPORTED_ARCHES)}")
    workdir = workdir.expanduser().resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with firmware.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    firmware_hash = digest.hexdigest()
    extracted = workdir / "extracted"
    if extracted.exists() and any(extracted.iterdir()):
        manifest_path = workdir / "manifest.json"
        try:
            existing_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing_manifest = {}
        if existing_manifest.get("firmware_sha256") != firmware_hash:
            raise FirmSightError(f"Extraction directory belongs to another sample or has no manifest: {extracted}. Use a fresh --workdir.")
    else:
        if progress:
            progress("Extracting firmware")
        extract_firmware(firmware, extracted, extractor_mode, progress)
    if progress:
        progress("Discovering kernel and root filesystem candidates")
    files = _files_below(extracted)
    rootfs_path = _select_rootfs(extracted, rootfs)
    kernel_candidates = _kernel_candidates(extracted, files)
    kernel_path = _select_kernel(kernel_candidates, kernel)
    detected_arch = _elf_arch(kernel_path)
    if detected_arch is None:
        description = _describe(kernel_path).lower()
        if "aarch64" in description or "arm64" in description:
            detected_arch = "aarch64"
        elif "mips" in description:
            detected_arch = "mipsel" if "little-endian" in description else "mips"
        elif "arm" in description:
            detected_arch = "arm"
    selected_arch = architecture or detected_arch
    if selected_arch is None:
        raise FirmSightError("Could not determine the kernel architecture. Specify --arch arm|aarch64|mips|mipsel.")
    if detected_arch and architecture and detected_arch != architecture:
        raise FirmSightError(f"Selected architecture {architecture} conflicts with kernel architecture {detected_arch}.")

    if progress:
        progress("Packing root filesystem into a gzip initramfs")
    initramfs = create_initramfs(rootfs_path, workdir / "rootfs.cpio.gz")
    manifest: dict[str, object] = {
        "firmware": str(firmware), "firmware_sha256": firmware_hash,
        "extractor_mode": extractor_mode,
        "extracted_directory": str(extracted), "kernel": str(kernel_path),
        "rootfs_directory": str(rootfs_path), "initramfs": str(initramfs),
        "initramfs_sha256": hashlib.sha256(initramfs.read_bytes()).hexdigest(),
        "architecture": selected_arch, "architecture_source": "user" if architecture else "kernel signature",
        "kernel_candidates": kernel_candidates,
        "notes": [
            "A vendor kernel may require its original board, DTB, peripherals, or boot arguments.",
            "QEMU machine profiles are generic; successful boot is device and kernel dependent.",
            "The VM network adapter is disabled by default.",
        ],
    }
    manifest_path = workdir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    manifest["manifest"] = str(manifest_path)
    return manifest


def initramfs_qemu_command(architecture: str, kernel: Path, initramfs: Path,
                           memory: str | None = "512M", machine: str | None = None,
                           cpu: str | None = None, kernel_args: str | None = None,
                           dtb: Path | None = None, gdb_port: int | None = None,
                           qemu_binary: str | None = None,
                           profile: dict[str, object] | None = None) -> list[str]:
    """Build a QEMU command booting a kernel directly with a generated initramfs."""
    profiles = {
        "arm": ("qemu-system-arm", "virt", "cortex-a15", "console=ttyAMA0,115200 rdinit=/sbin/init"),
        "aarch64": ("qemu-system-aarch64", "virt", "cortex-a57", "console=ttyAMA0,115200 rdinit=/sbin/init"),
        "mips": ("qemu-system-mips", "malta", "24Kf", "console=ttyS0,115200 rdinit=/sbin/init"),
        "mipsel": ("qemu-system-mipsel", "malta", "24Kf", "console=ttyS0,115200 rdinit=/sbin/init"),
    }
    if architecture not in profiles:
        raise FirmSightError(f"Architecture must be one of: {', '.join(SUPPORTED_ARCHES)}")
    if profile and profile.get("architecture") != architecture:
        raise FirmSightError(f"Profile architecture {profile.get('architecture')} does not match firmware architecture {architecture}")
    binary, default_machine, default_cpu, default_args = profiles[architecture]
    profile = profile or {}
    machine = machine or str(profile.get("machine") or default_machine)
    cpu = cpu or str(profile.get("cpu") or default_cpu)
    memory = memory or str(profile.get("memory") or "512M")
    if kernel_args is None:
        kernel_args = str(profile.get("kernel_args") or "") or None
        if kernel_args is None:
            console = str(profile.get("console") or ("ttyS0,115200" if architecture.startswith("mips") else "ttyAMA0,115200"))
            init = str(profile.get("init") or "/sbin/init")
            kernel_args = f"console={console} rdinit={init}"
    dtb = dtb or (Path(str(profile["dtb"])) if profile.get("dtb") else None)
    kernel = kernel.expanduser().resolve()
    initramfs = initramfs.expanduser().resolve()
    if not kernel.is_file():
        raise FirmSightError(f"Kernel image does not exist: {kernel}")
    if not initramfs.is_file():
        raise FirmSightError(f"Initramfs image does not exist: {initramfs}")
    if not memory or any(char in memory for char in "\r\n\0"):
        raise FirmSightError("Invalid memory size")
    command = [qemu_binary or _tool(binary), "-M", machine, "-cpu", cpu,
               "-m", memory, "-nographic", "-snapshot", "-kernel", str(kernel),
               "-initrd", str(initramfs), "-append", kernel_args or default_args, "-nic", "none"]
    for device in profile.get("devices", []):
        command.extend(["-device", str(device)])
    for drive in profile.get("drives", []):
        drive_path = Path(str(drive["file"])).expanduser().resolve()
        if not drive_path.is_file():
            raise FirmSightError(f"Profile drive image does not exist: {drive_path}")
        values = [f"file={drive_path}", f"format={drive.get('format', 'raw')}", f"if={drive.get('interface', 'virtio')}"]
        if drive.get("readonly", True):
            values.append("readonly=on")
        command.extend(["-drive", ",".join(values)])
    if dtb:
        dtb = dtb.expanduser().resolve()
        if not dtb.is_file():
            raise FirmSightError(f"Device tree blob does not exist: {dtb}")
        command.extend(["-dtb", str(dtb)])
    if gdb_port is not None:
        if not 1 <= gdb_port <= 65535:
            raise FirmSightError("GDB port must be between 1 and 65535")
        command.extend(["-gdb", f"tcp:127.0.0.1:{gdb_port}"])
    return command
