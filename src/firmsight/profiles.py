"""JSON device profile loading and validation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .core import FirmSightError
from .firmware import SUPPORTED_ARCHES


BUILTIN_PROFILE_DIR = Path(__file__).parent / "profiles"
NETWORK_DEVICES = {"e1000", "e1000-82540em", "e1000-82545em", "e1000-82544gc",
                   "rtl8139", "ne2k_pci", "virtio-net-device", "virtio-net-pci",
                   "pcnet", "smc91c111", "lan9118"}


def list_profiles() -> list[dict[str, str]]:
    profiles = []
    for path in sorted(BUILTIN_PROFILE_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        profiles.append({"name": data["name"], "architecture": data["architecture"],
                         "description": data.get("description", "")})
    return profiles


def load_profile(identifier: str | Path) -> dict[str, Any]:
    supplied = Path(identifier).expanduser()
    path = supplied if supplied.is_file() else BUILTIN_PROFILE_DIR / f"{identifier}.json"
    if not path.is_file():
        choices = ", ".join(item["name"] for item in list_profiles())
        raise FirmSightError(f"Device profile not found: {identifier}. Built-ins: {choices}; or pass a JSON file path.")
    try:
        profile = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FirmSightError(f"Cannot read device profile {path}: {exc}") from exc
    profile["_path"] = str(path.resolve())
    _validate_profile(profile)
    for drive in profile.get("drives", []):
        drive_file = Path(drive["file"]).expanduser()
        if not drive_file.is_absolute():
            drive["file"] = str((path.parent / drive_file).resolve())
        else:
            drive["file"] = str(drive_file.resolve())
    dtb = profile.get("dtb")
    if dtb and not Path(dtb).expanduser().is_absolute():
        profile["dtb"] = str((path.parent / dtb).resolve())
    return profile


def _validate_profile(profile: dict[str, Any]) -> None:
    required = ("name", "architecture", "machine", "cpu")
    missing = [field for field in required if not isinstance(profile.get(field), str) or not profile[field].strip()]
    if missing:
        raise FirmSightError(f"Profile is missing required string fields: {', '.join(missing)}")
    if profile["architecture"] not in SUPPORTED_ARCHES:
        raise FirmSightError(f"Unsupported profile architecture: {profile['architecture']}")
    for field in ("machine", "cpu", "memory", "console", "init", "kernel_args", "dtb"):
        value = profile.get(field)
        if value is not None and (not isinstance(value, str) or any(char in value for char in "\r\n\0")):
            raise FirmSightError(f"Profile field {field} must be a single-line string")
    devices = profile.get("devices", [])
    if not isinstance(devices, list) or any(not isinstance(value, str) or not value or any(c in value for c in "\r\n\0") for value in devices):
        raise FirmSightError("Profile devices must be a list of QEMU device option strings")
    for device in devices:
        model = device.split(",", 1)[0].strip()
        if model in NETWORK_DEVICES:
            raise FirmSightError("Network devices are managed by FirmSight's isolated lab and cannot be added through profiles")
    drives = profile.get("drives", [])
    if not isinstance(drives, list):
        raise FirmSightError("Profile drives must be a list")
    for drive in drives:
        if not isinstance(drive, dict) or not isinstance(drive.get("file"), str):
            raise FirmSightError("Each drive needs a file path")
        for field in ("format", "interface"):
            value = drive.get(field, "raw" if field == "format" else "virtio")
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
                raise FirmSightError(f"Invalid drive {field}")
        if not isinstance(drive.get("readonly", True), bool):
            raise FirmSightError("Drive readonly must be true or false")
