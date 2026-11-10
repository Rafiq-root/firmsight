import json
import subprocess

import pytest

from firmsight.core import FirmSightError, extract_firmware


def test_docker_extraction_uses_no_network_and_read_only_input(tmp_path, monkeypatch):
    firmware = tmp_path / "sample.bin"
    firmware.write_bytes(b"firmware")
    output = tmp_path / "extracted"
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        if command[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(command, 0, "image", "")
        if "--entrypoint" in command:
            return subprocess.CompletedProcess(command, 0, "Binwalk test", "")
        (output / "filesystem.bin").write_bytes(b"extract")
        return subprocess.CompletedProcess(command, 0, "scan output", "")

    monkeypatch.setattr("firmsight.core.shutil.which", lambda name: "/usr/bin/docker" if name == "docker" else None)
    monkeypatch.setattr("firmsight.core.subprocess.run", fake_run)
    extract_firmware(firmware, output)
    extraction = calls[-1]
    assert "--network" in extraction and extraction[extraction.index("--network") + 1] == "none"
    assert "--read-only" in extraction
    assert extraction[extraction.index("--cap-drop") + 1] == "ALL"
    assert f"{firmware.resolve()}:/input/firmware:ro" in extraction
    manifest = json.loads((output / "firmsight-extraction.json").read_text())
    assert manifest["status"] == "success"
    assert manifest["firmware_sha256"]


def test_host_extraction_records_partial_failure(tmp_path, monkeypatch):
    firmware = tmp_path / "sample.bin"
    firmware.write_bytes(b"firmware")
    output = tmp_path / "extracted"
    def fake_run(command, **_kwargs):
        if "-e" not in command:
            return subprocess.CompletedProcess(command, 0, "Tool version", "")
        (output / "partial.bin").write_bytes(b"partial")
        return subprocess.CompletedProcess(command, 1, "partial output", "failed unpacker")

    monkeypatch.setattr("firmsight.core._tool", lambda _: "/usr/bin/binwalk")
    monkeypatch.setattr("firmsight.core.shutil.which", lambda _: None)
    monkeypatch.setattr("firmsight.core.subprocess.run", fake_run)
    with pytest.raises(FirmSightError, match="partial_failure"):
        extract_firmware(firmware, output, mode="host")
    manifest = json.loads((output / "firmsight-extraction.json").read_text())
    assert manifest["status"] == "partial_failure"
    assert "failed unpacker" in (output / "firmsight-extraction.log").read_text()


def test_extraction_refuses_to_mix_existing_output(tmp_path):
    firmware = tmp_path / "sample.bin"
    firmware.write_bytes(b"firmware")
    output = tmp_path / "existing"
    output.mkdir()
    (output / "old").touch()
    with pytest.raises(FirmSightError, match="must be empty"):
        extract_firmware(firmware, output, mode="host")
