
import pytest

from firmsight.core import FirmSightError
from firmsight.network import init_lab, lab_emulate_command, lab_capture_command, qemu_lab_network_args
from firmsight.sandbox.sinkhole.sinkhole import DNSHandler


def test_lab_compose_uses_internal_network_and_sinkhole(tmp_path):
    labdir = tmp_path / "analysis"
    labdir.mkdir()
    config = init_lab(labdir)
    compose = (config / "compose.yaml").read_text()
    assert "internal: true" in compose
    assert "172.29.41.2" in compose
    assert "sinkhole" in compose
    assert (config / "sinkhole" / "sinkhole.py").is_file()


def test_qemu_lab_network_routes_dns_to_sinkhole():
    args = qemu_lab_network_args("arm")
    assert args[0] == "-netdev"
    assert args[1] == "user,id=firmsight-net"
    assert "virtio-net-device" in args[3]


def test_lab_capture_rejects_path_traversal(tmp_path):
    with pytest.raises(FirmSightError, match="filename"):
        lab_capture_command(tmp_path, "../unsafe.pcap")


def test_lab_emulate_requires_assets_inside_workdir(tmp_path, monkeypatch):
    workdir = tmp_path / "analysis"
    workdir.mkdir()
    init_lab(workdir)
    monkeypatch.setattr("firmsight.network._compose_prefix", lambda _: ["docker", "compose"])
    outside = tmp_path / "kernel"
    outside.touch()
    with pytest.raises(FirmSightError, match="under the analysis"):
        lab_emulate_command(workdir, ["qemu-system-arm", "-kernel", str(outside)])


def test_builtin_profiles_cover_supported_architectures():
    from firmsight.profiles import list_profiles

    assert {item["architecture"] for item in list_profiles()} == {"arm", "aarch64", "mips", "mipsel"}


def test_sinkhole_dns_maps_a_queries_to_lab_ip():
    qname = b"\x04evil\x04test\x00"
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"

    class FakeSocket:
        data = b""

        def sendto(self, data, _address):
            self.data = data

    fake = FakeSocket()
    DNSHandler((query, fake), ("192.0.2.10", 53000), object())
    assert fake.data[:2] == b"\x12\x34"
    assert int.from_bytes(fake.data[6:8], "big") == 1
    assert fake.data[-4:] == bytes((172, 29, 41, 2))
