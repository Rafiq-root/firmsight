"""Build a gzip-compressed newc initramfs without following filesystem symlinks."""

from __future__ import annotations

import gzip
import os
import shutil
import stat
from pathlib import Path

from .core import FirmSightError


def _header(ino: int, mode: int, uid: int, gid: int, nlink: int, mtime: int,
            size: int, devmajor: int, devminor: int, rdevmajor: int,
            rdevminor: int, name: bytes) -> bytes:
    fields = (ino, mode, uid, gid, nlink, mtime, size, devmajor, devminor,
              rdevmajor, rdevminor, len(name) + 1, 0)
    return b"070701" + b"".join(f"{value & 0xFFFFFFFF:08x}".encode("ascii") for value in fields)


def _pad(stream, position: int) -> int:
    count = (-position) % 4
    if count:
        stream.write(b"\0" * count)
    return position + count


def create_initramfs(rootfs: Path, output: Path) -> Path:
    """Serialize a Linux root tree as gzip/newc, preserving symlinks as symlinks."""
    rootfs = rootfs.expanduser().resolve()
    if not rootfs.is_dir():
        raise FirmSightError(f"Root filesystem directory does not exist: {rootfs}")
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    entries: list[tuple[str, Path | None, int | None, int | None]] = [(".", rootfs, None, None)]

    def visit(directory: Path, relative: str) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise FirmSightError(f"Cannot read root filesystem directory {directory}: {exc}") from exc
        for child in children:
            path = Path(child.path)
            child_relative = f"{relative}/{child.name}" if relative else child.name
            info = path.lstat()
            if stat.S_ISSOCK(info.st_mode):
                continue
            entries.append((child_relative, path, None, None))
            if stat.S_ISDIR(info.st_mode):
                visit(path, child_relative)
            if len(entries) > 200_000:
                raise FirmSightError("Root filesystem contains more than 200000 entries; refusing oversized initramfs build")

    visit(rootfs, "")
    names = {name for name, _, _, _ in entries}
    if "dev" not in names:
        entries.append(("dev", None, stat.S_IFDIR | 0o755, None))
    if "dev/console" not in names:
        entries.append(("dev/console", None, stat.S_IFCHR | 0o600, (5 << 8) | 1))
    if "dev/null" not in names:
        entries.append(("dev/null", None, stat.S_IFCHR | 0o666, (1 << 8) | 3))

    output_tmp = output.with_suffix(output.suffix + ".tmp")
    try:
        with output_tmp.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as stream:
            position = 0
            inode = 1
            for name, path, synthetic_mode, synthetic_rdev in entries:
                encoded_name = name.encode("utf-8", errors="surrogateescape")
                content_path: Path | None = None
                if path is None:
                    mode, uid, gid, nlink, mtime, content = synthetic_mode, 0, 0, 1, 0, b""
                    rdevmajor, rdevminor = ((synthetic_rdev >> 8) & 0xFFF, synthetic_rdev & 0xFF) if synthetic_rdev else (0, 0)
                else:
                    info = path.lstat()
                    mode, uid, gid, nlink, mtime = info.st_mode, info.st_uid, info.st_gid, max(info.st_nlink, 1), int(info.st_mtime)
                    rdevmajor, rdevminor = os.major(info.st_rdev), os.minor(info.st_rdev)
                    if stat.S_ISREG(mode):
                        content = b""
                        content_path = path
                        content_size = info.st_size
                    elif stat.S_ISLNK(mode):
                        content = os.readlink(path).encode("utf-8", errors="surrogateescape")
                    else:
                        content = b""
                if not (path is not None and stat.S_ISREG(mode)):
                    content_size = len(content)
                header = _header(inode, mode, uid, gid, nlink, mtime, content_size, 0, 0,
                                 rdevmajor, rdevminor, encoded_name)
                stream.write(header)
                stream.write(encoded_name + b"\0")
                position = _pad(stream, position + len(header) + len(encoded_name) + 1)
                if content_path is not None:
                    with content_path.open("rb") as content_stream:
                        shutil.copyfileobj(content_stream, stream, length=1024 * 1024)
                else:
                    stream.write(content)
                position = _pad(stream, position + content_size)
                inode += 1
            trailer = b"TRAILER!!!"
            header = _header(inode, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, trailer)
            stream.write(header + trailer + b"\0")
            _pad(stream, position + len(header) + len(trailer) + 1)
        output_tmp.replace(output)
    except OSError as exc:
        output_tmp.unlink(missing_ok=True)
        raise FirmSightError(f"Cannot create initramfs {output}: {exc}") from exc
    return output
