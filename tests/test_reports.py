import json
import struct

from firmsight.core import FirmwareReport
from firmsight.reports import analyze_rootfs, write_report


def test_report_inventories_rootfs_and_redacts_secrets(tmp_path, monkeypatch):
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"sample")
    rootfs = tmp_path / "rootfs"
    init = rootfs / "etc" / "init.d" / "S20boot"
    init.parent.mkdir(parents=True)
    init.write_text("curl https://user:secret@example.org/c2?token=topsecret\npassword=supersecret\nconnect 203.0.113.4\n")
    (rootfs / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    (rootfs / "bin").mkdir()
    elf = bytearray(64)
    elf[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<H", elf, 18, 40)
    (rootfs / "bin" / "service").write_bytes(elf)
    monkeypatch.setattr("firmsight.reports.inspect_firmware", lambda _path: FirmwareReport(str(firmware), 6, "sha", [], []))

    report = analyze_rootfs(firmware, rootfs)
    serialized = json.dumps(report)
    assert report["summary"]["elf_binaries"] == 1
    assert next(item for item in report["inventory"] if item["path"] == "bin/service")["architecture"] == "arm"
    assert "etc/init.d/S20boot" in report["startup_files"]
    assert any(item["value"] == "203.0.113.4" and item["byte_offset"] > 0 for item in report["indicators"]["network"])
    assert "credential_key" in serialized and "value_redacted" in serialized
    assert "supersecret" not in serialized
    assert "topsecret" not in serialized
    assert "user:secret" not in serialized


def test_html_report_escapes_firmware_paths(tmp_path, monkeypatch):
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"sample")
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "<script>.txt").write_text("plain file")
    monkeypatch.setattr("firmsight.reports.inspect_firmware", lambda _path: FirmwareReport(str(firmware), 6, "sha", [], []))
    report = analyze_rootfs(firmware, rootfs)
    _, html_path = write_report(report, tmp_path / "out")
    content = html_path.read_text()
    assert "&lt;script&gt;.txt" in content
    assert "<script>.txt</td>" not in content
