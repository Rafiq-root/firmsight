"""Static root-filesystem inventory and indicator report generation."""

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import stat
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .core import FirmSightError, inspect_firmware
from .firmware import _elf_arch

URL_RE = re.compile(rb"\b(?:https?|ftp)://[^\s\x00\"'<>]{1,512}", re.IGNORECASE)
IP_RE = re.compile(rb"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
DOMAIN_RE = re.compile(rb"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|cc|tk|xyz|top|local|lan)(?![A-Za-z0-9_-])", re.IGNORECASE)
CREDENTIAL_RE = re.compile(rb"(?im)^\s*(password|passwd|pwd|secret|token|private[_-]?key|auth[_-]?key)\s*[:=]")
SUSPICIOUS_RE = re.compile(rb"(?i)\b(telnetd|tftp|wget|curl|nc|netcat|busybox\s+telnetd|iptables\s+-F|/bin/sh)\b")
STARTUP_RE = re.compile(r"(^|/)(init\.d/|rc[0-9S]?\.d/|rc\.local$|inittab$|preinit$|rcS$|xinetd\.d/|inetd\.conf$)", re.IGNORECASE)
SERVICE_RE = re.compile(r"(^|/)(inetd\.conf$|xinetd\.d/|services$|init\.d/|rc[0-9S]?\.d/)", re.IGNORECASE)
MAX_REPORT_FINDINGS = 2000
MAX_INVENTORY_ENTRIES = 200_000
MAX_TOTAL_SCAN_BYTES = 256 * 1024 * 1024


def _file_kind(path: Path, mode: int) -> str:
    if stat.S_ISREG(mode):
        if path.is_symlink():
            return "symlink"
        if _elf_arch(path):
            return "ELF"
        try:
            with path.open("rb") as stream:
                if stream.read(4) == b"\x7fELF":
                    return "ELF (architecture unknown)"
        except OSError:
            pass
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISCHR(mode):
        return "character device"
    if stat.S_ISBLK(mode):
        return "block device"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    return "other"


def _iter_entries(rootfs: Path):
    for current, directories, filenames in os.walk(rootfs, followlinks=False):
        base = Path(current)
        symlink_directories = sorted(name for name in directories if (base / name).is_symlink())
        directories[:] = sorted(name for name in directories if name not in symlink_directories)
        yield base, "directory"
        for name in sorted(filenames):
            path = base / name
            yield path, "entry"
        for name in symlink_directories:
            yield base / name, "entry"


def _redact_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        if parts.port:
            host += f":{parts.port}"
        query = urlencode([(key, "[REDACTED]") for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
        return urlunsplit((parts.scheme, host, parts.path, query, parts.fragment))
    except ValueError:
        return value.split("?", 1)[0]


def _scan_content(path: Path, relative: str, data: bytes) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {"network": [], "credentials": [], "commands": []}
    expressions = (("url", URL_RE, "network"), ("ip", IP_RE, "network"),
                   ("domain", DOMAIN_RE, "network"))
    text_like = b"\0" not in data
    def location(offset: int) -> dict[str, int]:
        point = {"byte_offset": offset}
        if text_like:
            point["line"] = data.count(b"\n", 0, offset) + 1
        return point
    for kind, expression, group in expressions:
        for match in expression.finditer(data):
            value = match.group(0).decode("utf-8", "replace").rstrip(".,;)")
            if kind == "ip":
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
            elif kind == "url":
                value = _redact_url(value)
            result[group].append({"kind": kind, "value": value, "path": relative, **location(match.start())})
    for match in CREDENTIAL_RE.finditer(data):
        result["credentials"].append({"kind": "credential_key", "key": match.group(1).decode("ascii", "replace").lower(),
                                      "value_redacted": True, "path": relative, **location(match.start())})
    for match in SUSPICIOUS_RE.finditer(data):
        result["commands"].append({"kind": "command", "value": match.group(0).decode("utf-8", "replace"),
                                   "path": relative, **location(match.start())})
    for group in result.values():
        del group[MAX_REPORT_FINDINGS:]
    return result


def analyze_rootfs(firmware: Path, rootfs: Path, max_file_size: int = 16 * 1024 * 1024) -> dict[str, Any]:
    rootfs = rootfs.expanduser().resolve()
    if not rootfs.is_dir():
        raise FirmSightError(f"Root filesystem directory does not exist: {rootfs}")
    if max_file_size < 1 or max_file_size > 128 * 1024 * 1024:
        raise FirmSightError("Maximum scanned file size must be between 1 and 134217728 bytes")
    firmware_report = inspect_firmware(firmware)
    inventory: list[dict[str, Any]] = []
    network: list[dict[str, Any]] = []
    credentials: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = []
    startup: list[str] = []
    services: list[str] = []
    skipped_large = 0
    scanned_bytes = 0
    inventory_truncated = False

    for path, _ in _iter_entries(rootfs):
        if len(inventory) >= MAX_INVENTORY_ENTRIES:
            inventory_truncated = True
            break
        try:
            info = path.lstat()
        except OSError:
            continue
        relative = path.relative_to(rootfs).as_posix() or "."
        kind = _file_kind(path, info.st_mode)
        entry: dict[str, Any] = {"path": relative, "type": kind, "mode": oct(stat.S_IMODE(info.st_mode)),
                                 "size_bytes": info.st_size}
        if stat.S_ISLNK(info.st_mode):
            entry["target"] = os.readlink(path)
        arch = _elf_arch(path) if stat.S_ISREG(info.st_mode) else None
        if arch:
            entry["architecture"] = arch
        inventory.append(entry)
        if STARTUP_RE.search(relative):
            startup.append(relative)
        if SERVICE_RE.search(relative):
            services.append(relative)
        if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
            continue
        if info.st_size > max_file_size:
            skipped_large += 1
            continue
        if scanned_bytes + info.st_size > MAX_TOTAL_SCAN_BYTES:
            skipped_large += 1
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        found = _scan_content(path, relative, data)
        scanned_bytes += len(data)
        network.extend(found["network"])
        credentials.extend(found["credentials"])
        commands.extend(found["commands"])

    passwd_path = rootfs / "etc/passwd"
    users = []
    if passwd_path.is_file() and not passwd_path.is_symlink():
        try:
            for line_number, line in enumerate(passwd_path.read_text(errors="replace").splitlines(), 1):
                fields = line.split(":")
                if len(fields) >= 7:
                    users.append({"username": fields[0], "uid": fields[2], "gid": fields[3], "shell": fields[6],
                                  "path": "etc/passwd", "line": line_number})
        except OSError:
            pass

    report: dict[str, Any] = {
        "schema_version": 1,
        "sample": {"file": firmware_report.file, "size_bytes": firmware_report.size_bytes,
                   "sha256": firmware_report.sha256, "binwalk_signatures": firmware_report.signatures,
                   "likely_architectures": firmware_report.likely_architectures},
        "rootfs": str(rootfs),
        "summary": {"files_and_directories": len(inventory), "elf_binaries": sum(item["type"].startswith("ELF") for item in inventory),
                    "startup_files": len(startup), "service_configs": len(services),
                    "network_indicators": len(network), "credential_keys": len(credentials),
                    "suspicious_command_strings": len(commands), "large_files_skipped": skipped_large},
        "inventory": inventory,
        "startup_files": sorted(set(startup)),
        "service_configs": sorted(set(services)),
        "users": users,
        "indicators": {"network": network[:MAX_REPORT_FINDINGS], "credential_keys": credentials[:MAX_REPORT_FINDINGS],
                       "commands": commands[:MAX_REPORT_FINDINGS]},
        "limitations": [
            "Static strings and configuration matches are leads for review, not proof of behavior.",
            "Credential values are deliberately omitted from this report.",
            f"Regular files larger than {max_file_size} bytes were not scanned for strings.",
            f"At most {MAX_TOTAL_SCAN_BYTES} bytes across regular files were scanned; {MAX_INVENTORY_ENTRIES} inventory entries were recorded.",
        ],
    }
    report["summary"]["bytes_scanned"] = scanned_bytes
    report["summary"]["inventory_truncated"] = inventory_truncated
    return report


def write_report(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "firmsight-report.json"
    html_path = output_dir / "firmsight-report.html"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    html_path.write_text(_html_report(report), encoding="utf-8")
    return json_path, html_path


def _html_report(report: dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value), quote=True)
    rows = []
    for item in report["inventory"]:
        row_id = "file-" + re.sub(r"[^A-Za-z0-9_-]", "-", item["path"])
        rows.append(f'<tr id="{esc(row_id)}"><td>{esc(item["path"])}</td><td>{esc(item["type"])}</td>'
                    f'<td>{esc(item.get("architecture", ""))}</td><td>{esc(item["size_bytes"])}</td><td>{esc(item["mode"])}</td></tr>')
    finding_sections = []
    for group, label in (("network", "Network indicators"), ("credential_keys", "Credential keys"), ("commands", "Command indicators")):
        entries = report["indicators"][group]
        body = []
        for item in entries:
            row_id = "file-" + re.sub(r"[^A-Za-z0-9_-]", "-", item["path"])
            where = f"line {item['line']} · byte {item['byte_offset']}" if "line" in item else f"byte {item['byte_offset']}"
            value = item.get("value", item.get("key", item["kind"]))
            body.append(f'<li><a href="#{esc(row_id)}">{esc(item["path"])}</a> ({esc(where)}): <code>{esc(value)}</code></li>')
        finding_sections.append(f'<section><h2>{esc(label)} ({len(entries)})</h2><ul>{"".join(body) or "<li>None detected</li>"}</ul></section>')
    summary = report["summary"]
    summary_html = "".join(f"<li><strong>{esc(key.replace('_', ' ').title())}:</strong> {esc(value)}</li>" for key, value in summary.items())
    return """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FirmSight firmware report</title><style>body{font:15px/1.5 system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#182230}h1,h2{color:#164e63}code{overflow-wrap:anywhere}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #ccd4dc;padding:.4rem;text-align:left}th{background:#eef4f6;position:sticky;top:0}ul{padding-left:1.4rem}section{margin:2rem 0}.muted{color:#536373}</style>
<h1>FirmSight firmware report</h1><p>SHA-256: <code>""" + esc(report["sample"]["sha256"]) + "</code></p><p>Root filesystem: <code>" + esc(report["rootfs"]) + "</code></p><h2>Summary</h2><ul>" + summary_html + "</ul>" + "".join(finding_sections) + "<h2>File inventory</h2><div style='overflow:auto;max-height:70vh'><table><thead><tr><th>Path</th><th>Type</th><th>Architecture</th><th>Bytes</th><th>Mode</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div><p class='muted'>Static findings are leads for manual review, not proof of runtime behavior.</p></html>"
