from pathlib import Path

import pytest

from firmsight.core import FirmSightError, FirmwareReport, qemu_command, trace_command
from firmsight.firmware import initramfs_qemu_command
from firmsight.profiles import load_profile


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


def test_initramfs_qemu_profile_is_network_disabled(tmp_path, monkeypatch):
    kernel = tmp_path / "kernel"
    initramfs = tmp_path / "initramfs.gz"
    kernel.touch()
    initramfs.touch()
    monkeypatch.setattr("firmsight.firmware._tool", lambda _: "/usr/bin/qemu-system-mipsel")
    command = initramfs_qemu_command("mipsel", kernel, initramfs, gdb_port=2345)
    assert command[command.index("-M") + 1] == "malta"
    assert command[command.index("-initrd") + 1] == str(initramfs.resolve())
    assert command[command.index("-nic") + 1] == "none"
    assert command[command.index("-gdb") + 1] == "tcp:127.0.0.1:2345"


def test_device_profile_applies_board_devices_and_storage(tmp_path, monkeypatch):
    kernel, initramfs, disk = (tmp_path / name for name in ("kernel", "rootfs.gz", "flash.bin"))
    for path in (kernel, initramfs, disk):
        path.touch()
    profile_path = tmp_path / "device.json"
    profile_path.write_text('''{"name":"test-board","architecture":"arm","machine":"vexpress-a9","cpu":"cortex-a9","memory":"256M","console":"ttyAMA0,115200","init":"/etc/preinit","devices":["virtio-rng-device"],"drives":[{"file":"flash.bin","format":"raw","interface":"mtd","readonly":true}]}''')
    profile = load_profile(profile_path)
    monkeypatch.setattr("firmsight.firmware._tool", lambda _: "/usr/bin/qemu-system-arm")
    command = initramfs_qemu_command("arm", kernel, initramfs, memory=None, profile=profile)
    assert command[command.index("-M") + 1] == "vexpress-a9"
    assert command[command.index("-m") + 1] == "256M"
    assert command[command.index("-append") + 1] == "console=ttyAMA0,115200 rdinit=/etc/preinit"
    assert "virtio-rng-device" in command
    assert f"file={disk.resolve()}" in command[command.index("-drive") + 1]


def test_device_profiles_cannot_reenable_network_in_disconnected_mode(tmp_path):
    profile_path = tmp_path / "unsafe.json"
    profile_path.write_text('{"name":"unsafe","architecture":"arm","machine":"virt","cpu":"cortex-a15","devices":["virtio-net-device"]}')
    with pytest.raises(FirmSightError, match="Network devices"):
        load_profile(profile_path)
