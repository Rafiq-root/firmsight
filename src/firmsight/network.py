"""Docker Compose isolated lab helpers and QEMU network device profiles."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .core import FirmSightError, _tool

LAB_SUBNET = "172.29.41.0/24"
SINKHOLE_IP = "172.29.41.2"


def qemu_lab_network_args(architecture: str) -> list[str]:
    """Connect a guest to the isolated lab, with DNS sent to the local sinkhole."""
    devices = {
        "arm": "virtio-net-device",
        "aarch64": "virtio-net-device",
        "mips": "e1000",
        "mipsel": "e1000",
    }
    if architecture not in devices:
        raise FirmSightError("Unsupported lab architecture")
    return ["-netdev", "user,id=firmsight-net",
            "-device", f"{devices[architecture]},netdev=firmsight-net"]


def _compose_prefix(workdir: Path) -> list[str]:
    compose_file = workdir / ".firmsight-lab" / "compose.yaml"
    if not compose_file.is_file():
        raise FirmSightError(f"Lab not initialized. Run `firmsight lab init --workdir {workdir}` first.")
    docker = _tool("docker")
    check = subprocess.run([docker, "compose", "version"], capture_output=True, text=True, check=False)
    if check.returncode:
        raise FirmSightError("Docker Compose v2 is required (check `docker compose version`).")
    return [docker, "compose", "--project-directory", str(compose_file.parent), "-f", str(compose_file)]


def init_lab(workdir: Path) -> Path:
    workdir = workdir.expanduser().resolve()
    if not workdir.is_dir():
        raise FirmSightError(f"Analysis work directory does not exist: {workdir}")
    labdir = workdir / ".firmsight-lab"
    if labdir.exists():
        raise FirmSightError(f"Lab directory already exists: {labdir}")
    source = Path(__file__).parent / "sandbox"
    if not source.is_dir():
        raise FirmSightError("Sandbox templates are missing from the FirmSight installation")
    shutil.copytree(source, labdir)
    (labdir / "captures").mkdir()
    compose = f'''services:
  emulator:
    build:
      context: .
      dockerfile: Dockerfile.emulator
    command: ["sleep", "infinity"]
    dns: [{SINKHOLE_IP}]
    volumes:
      - type: bind
        source: {json.dumps(str(workdir))}
        target: /analysis
        read_only: true
      - type: bind
        source: ./captures
        target: /captures
    networks: [lab]
  sinkhole:
    build:
      context: ./sinkhole
      dockerfile: Dockerfile
    cap_add: [NET_RAW]
    volumes:
      - type: bind
        source: ./captures
        target: /captures
    networks:
      lab:
        ipv4_address: {SINKHOLE_IP}
networks:
  lab:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: {LAB_SUBNET}
'''
    (labdir / "compose.yaml").write_text(compose, encoding="utf-8")
    return labdir


def lab_command(workdir: Path, action: str, extra: list[str] | None = None) -> list[str]:
    workdir = workdir.expanduser().resolve()
    prefix = _compose_prefix(workdir)
    actions = {"up": ["up", "-d", "--build", "emulator", "sinkhole"],
               "down": ["down", "--remove-orphans"],
               "status": ["ps"],
               "logs": ["logs", "--tail", "100", "sinkhole"]}
    if action not in actions:
        raise FirmSightError(f"Unknown lab action: {action}")
    return [*prefix, *actions[action], *(extra or [])]


def lab_emulate_command(workdir: Path, qemu_args: list[str]) -> list[str]:
    workdir = workdir.expanduser().resolve()
    prefix = _compose_prefix(workdir)
    docker = prefix[0]
    # QEMU binaries and assets are container-side; translate host asset paths to /analysis.
    translated = list(qemu_args)
    for flag in ("-kernel", "-initrd", "-dtb"):
        if flag in translated:
            index = translated.index(flag) + 1
            path = Path(translated[index]).expanduser().resolve()
            try:
                translated[index] = "/analysis/" + str(path.relative_to(workdir))
            except ValueError as exc:
                raise FirmSightError(f"Lab assets must live under the analysis work directory: {path}") from exc
    if "-drive" in translated:
        index = translated.index("-drive") + 1
        options = translated[index].split(",")
        for option_index, option in enumerate(options):
            if option.startswith("file="):
                path = Path(option[5:]).expanduser().resolve()
                try:
                    options[option_index] = "file=/analysis/" + str(path.relative_to(workdir))
                except ValueError as exc:
                    raise FirmSightError(f"Lab drive images must live under the analysis work directory: {path}") from exc
        translated[index] = ",".join(options)
    return [*prefix, "exec", "-T", "emulator", *translated]


def lab_capture_command(workdir: Path, output_name: str, duration: int = 90) -> list[str]:
    if Path(output_name).name != output_name or output_name in ("", ".", ".."):
        raise FirmSightError("Capture output must be a filename, not a path")
    if duration < 1 or duration > 86400:
        raise FirmSightError("Capture duration must be between 1 and 86400 seconds")
    workdir = workdir.expanduser().resolve()
    capture_path = workdir / ".firmsight-lab" / "captures" / output_name
    if capture_path.exists():
        raise FirmSightError(f"Capture output already exists: {capture_path}")
    prefix = _compose_prefix(workdir)
    # The sinkhole sees DNS and TCP sessions reaching its reserved internal address.
    return [*prefix, "exec", "-T", "sinkhole", "timeout", str(duration),
            "tcpdump", "-i", "eth0", "-nn", "-U", "-w", f"/captures/{output_name}"]


def lab_trace_command(workdir: Path, script_path: Path) -> list[str]:
    workdir = workdir.expanduser().resolve()
    script_path = script_path.expanduser().resolve()
    try:
        relative = script_path.relative_to(workdir / ".firmsight-lab" / "captures")
    except ValueError as exc:
        raise FirmSightError("Lab GDB script must be inside the shared lab captures directory") from exc
    prefix = _compose_prefix(workdir)
    return [*prefix, "exec", "-T", "emulator", "gdb-multiarch", "-q", "-batch", "-x", f"/captures/{relative}"]
