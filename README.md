# FirmSight

FirmSight is a defensive IoT firmware triage prototype. It fingerprints a firmware image, delegates filesystem extraction to Binwalk, prepares isolated QEMU commands for researcher-provided boot assets, records traffic from a dedicated lab interface, and attaches radare2 to a local QEMU GDB stub.

> **Prototype boundary:** Firmware extraction and fingerprinting are automated. Emulating a real vendor image still requires a compatible kernel and a prepared disk image. FirmSight does not claim to turn every vendor `.bin` into a bootable VM automatically. Hardware setup, kernel selection, flash layout reconstruction, and init behavior remain device-specific research work.

## Features

- SHA-256 digest and Binwalk signature scan (`inspect`)
- Recursive Binwalk extraction (`extract`)
- ARM, AArch64, MIPS, and MIPS little-endian QEMU launch profiles (`emulate`)
- Network adapter disabled by default (`-nic none`); disk uses QEMU snapshot mode
- Optional QEMU GDB stub bound to loopback and radare2 debugger attachment (`--gdb-port`, `trace`)
- Bounded tcpdump capture on a researcher-selected isolated lab interface (`capture`)
- JSON inspection output for use in other analysis workflows

## Quick start

Requirements: Python 3.10+, Binwalk, QEMU system emulator for the target architecture. `tcpdump` is needed for packet capture; `radare2` is needed for debugger attachment. Install the package in a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
firmsight --help
```

Scan and extract a firmware image:

```sh
firmsight inspect router.bin --json
firmsight extract router.bin --output work/router-extracted
```

Boot a prepared image in an isolated VM:

```sh
firmsight emulate --arch arm --kernel work/zImage --disk work/rootfs.ext4
```

Enable loopback debugging (second terminal):

```sh
firmsight emulate --arch arm --kernel work/zImage --disk work/rootfs.ext4 --gdb-port 1234
firmsight trace --endpoint 127.0.0.1:1234
```

Capture lab traffic from a dedicated interface configured separately by the researcher:

```sh
firmsight capture --interface firmsight0 --output captures/session.pcap --duration 90
```

See [docs/BUILD_AND_OPERATION.md](docs/BUILD_AND_OPERATION.md) for architecture, setup, command details, lab networking guidance, troubleshooting, and limitations.

## Development

```sh
python -m pip install -e '.[test]'
pytest
```

## Responsible use

Use only firmware you are authorized to analyze. Extracted filesystems and emulated images are untrusted. Run analysis in a disposable VM with no host mounts or host network access. Do not connect a sample to the internet or a production network. The `capture` command records only the interface you select; FirmSight does not configure network namespaces, firewall rules, or virtual interfaces on your behalf.

## License

MIT; see [LICENSE](LICENSE).
