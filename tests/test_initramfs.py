import gzip
import stat
import struct
from pathlib import Path

from firmsight.firmware import prepare_firmware
from firmsight.initramfs import create_initramfs


def _entries(payload: bytes) -> dict[str, tuple[int, bytes]]:
    result = {}
    offset = 0
    while True:
        header = payload[offset:offset + 110]
        assert header[:6] == b"070701"
        fields = [int(header[index:index + 8], 16) for index in range(6, 110, 8)]
        mode, size, name_size = fields[1], fields[6], fields[11]
        offset += 110
        name = payload[offset:offset + name_size - 1].decode()
        offset += name_size
        offset = (offset + 3) & ~3
        content = payload[offset:offset + size]
        offset += size
        offset = (offset + 3) & ~3
        if name == "TRAILER!!!":
            break
        result[name] = (mode, content)
    return result


def test_initramfs_preserves_regular_files_and_symlinks(tmp_path):
    rootfs = tmp_path / "rootfs"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "etc" / "motd").write_text("hello")
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "init").write_text("init")
    (rootfs / "bin").symlink_to("usr/bin")
    archive = create_initramfs(rootfs, tmp_path / "rootfs.cpio.gz")
    entries = _entries(gzip.decompress(archive.read_bytes()))
    assert entries["etc/motd"][1] == b"hello"
    assert stat.S_ISLNK(entries["bin"][0])
    assert entries["bin"][1] == b"usr/bin"
    assert stat.S_ISCHR(entries["dev/console"][0])
    assert stat.S_ISCHR(entries["dev/null"][0])


def test_prepare_discovers_kernel_rootfs_and_writes_manifest(tmp_path, monkeypatch):
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")

    calls = 0

    def fake_extract(_firmware, destination, _mode, _progress):
        nonlocal calls
        calls += 1
        rootfs = destination / "squashfs-root"
        for directory in ("etc", "bin", "sbin"):
            (rootfs / directory).mkdir(parents=True, exist_ok=True)
        (rootfs / "sbin" / "init").write_text("init")
        kernel = destination / "zImage"
        header = bytearray(4096)
        header[:4] = b"\x7fELF"
        header[4:7] = b"\x01\x01\x01"
        struct.pack_into("<H", header, 18, 40)  # ELF e_machine = ARM
        kernel.write_bytes(header)
        return destination

    monkeypatch.setattr("firmsight.firmware.extract_firmware", fake_extract)
    result = prepare_firmware(firmware, tmp_path / "run")
    again = prepare_firmware(firmware, tmp_path / "run")
    assert result["architecture"] == "arm"
    assert again["firmware_sha256"] == result["firmware_sha256"]
    assert calls == 1
    assert Path(str(result["initramfs"])).is_file()
    assert Path(str(result["manifest"])).is_file()
