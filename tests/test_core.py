from pathlib import Path

import pytest

from firmsight.core import FirmSightError, FirmwareReport, qemu_command, trace_command


def test_report_json_round_trip():
    report = FirmwareReport("sample.bin", 4, "abcd", ["Squashfs"], ["ARM"])
    assert '"sha256": "abcd"' in report.to_json()


def test_qemu_architecture_validation():
    with pytest.raises(FirmSightError, match="Architecture"):
        qemu_command("riscv", Path("kernel"), Path("disk"))


def test_qemu_requires_files(tmp_path):
    with pytest.raises(FirmSightError, match="Kernel"):
        qemu_command("arm", tmp_path / "missing-kernel", tmp_path / "missing-disk")


def test_qemu_command_is_snapshot_and_network_disabled(tmp_path, monkeypatch):
    kernel = tmp_path / "kernel"
    disk = tmp_path / "disk.img"
    kernel.touch()
    disk.touch()
    monkeypatch.setattr("firmsight.core._tool", lambda _: "/usr/bin/qemu-system-arm")
    command = qemu_command("arm", kernel, disk, gdb_port=1234)
    assert "-snapshot" in command
    assert command[command.index("-nic") + 1] == "none"
    assert command[command.index("-gdb") + 1] == "tcp:127.0.0.1:1234"


def test_trace_rejects_non_loopback_endpoint():
    with pytest.raises(FirmSightError, match="loopback"):
        trace_command("192.0.2.4:1234")
