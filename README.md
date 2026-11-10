# FirmSight

FirmSight is a defensive IoT firmware triage prototype. It fingerprints firmware, delegates extraction to Binwalk, packages root filesystems for QEMU, records traffic from a dedicated lab interface, and attaches radare2 to a local QEMU GDB stub.

> **Prototype boundary:** Extraction and root filesystem packaging are automated. Emulating a real vendor image still requires a compatible kernel; FirmSight discovers likely kernels when possible and accepts an explicit path otherwise. Vendor board peripherals, DTBs, flash layouts, and boot arguments remain device-specific, so a successful boot cannot be guaranteed for every `.bin`.

## Features

- SHA-256 digest and Binwalk signature scan (`inspect`)
- Recursive Binwalk extraction (`extract`)
- Firmware-to-initramfs preparation with kernel/rootfs discovery (`prepare`)
- One-command launch from vendor firmware (`emulate-firmware`)
- Reusable QEMU device profiles for board, CPU, RAM, DTB, storage, and peripherals (`profiles`)
- File inventory, ELF hints, startup/service lists, and redacted static indicators (`report`)
- Interactive case dashboard with streamed action output and live lab/capture snapshots (`tui`)
- ARM, AArch64, MIPS, and MIPS little-endian QEMU launch profiles (`emulate`)
- Network adapter disabled by default (`-nic none`); disk uses QEMU snapshot mode
- Optional Docker lab with an internal-only network, local DNS/HTTP sinkhole, and pcap capture (`lab`)
- Optional QEMU GDB stub bound to loopback and radare2 debugger attachment (`--gdb-port`, `trace`)
- Bounded tcpdump capture on a researcher-selected isolated lab interface (`capture`)
- JSON inspection output for use in other analysis workflows

## Quick start

Requirements: Python 3.10+, Docker Engine for the default sandboxed extraction and network lab, and QEMU system emulator for direct host boot. `tcpdump` is needed for host-interface capture; `radare2` is needed for interactive debugger attachment. Install the package in a virtual environment:

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

Prepare and boot directly from a firmware image:

```sh
firmsight prepare router.bin --workdir work/router
firmsight profiles
firmsight emulate-firmware router.bin --workdir work/router --profile arm-virt
firmsight report --firmware router.bin --rootfs work/router/extracted/rootfs \
  --output-dir reports/router
```

Open the interactive workflow for a sample:

```sh
firmsight tui router.bin --workdir work/router
```

When discovery is ambiguous, pass explicit kernel, rootfs, architecture, and device settings with `--kernel`, `--rootfs`, `--arch`, `--dtb`, `--machine`, `--cpu`, and `--kernel-args`.

Custom device profiles are JSON files. Start from one of the built-ins under `src/firmsight/profiles/`; keep device-specific boot settings, extra QEMU `devices`, and `drives` together for repeatable analysis.

The report command writes a self-contained HTML view and machine-readable JSON. It deliberately omits credential values and records paths with byte offsets and text line numbers for review.

Without Docker, extraction can run directly on the host with `--extractor-mode host`; use that only in a disposable analysis VM.

Boot a previously prepared disk image in an isolated VM:

```sh
firmsight emulate --arch arm --kernel work/zImage --disk work/rootfs.ext4
```

Enable loopback debugging (second terminal):

```sh
firmsight emulate --arch arm --kernel work/zImage --disk work/rootfs.ext4 --gdb-port 1234
firmsight trace --endpoint 127.0.0.1:1234
```

Use bounded GDB tracing for function hits, backtraces, and common crash paths:

```sh
firmsight trace --endpoint 127.0.0.1:1234 --gdb --symbols work/vmlinux \
  --function handle_request --function '*0x81234000' --duration 120
```

For controlled outbound-behavior observation, initialize and start the isolated sinkhole lab:

```sh
firmsight lab init --workdir work/router
firmsight lab up --workdir work/router
```

Run capture and emulation in separate terminals so they overlap:

```sh
# Terminal A
firmsight lab capture --workdir work/router --output run.pcap --duration 90

# Terminal B
firmsight lab emulate --workdir work/router
```

For lab tracing, start `firmsight lab emulate --workdir work/router --gdb-port 1234` and run `firmsight lab trace --workdir work/router --symbols work/router/vmlinux --function handle_request` in another terminal.

After the run:

```sh
firmsight lab logs --workdir work/router
firmsight lab down --workdir work/router
```

The guest gets a QEMU user-mode NIC inside a Docker Compose network marked `internal`; only the local sinkhole container is reachable. This opt-in mode requires Docker Engine and Compose v2.

Capture lab traffic from a dedicated interface configured separately by the researcher:

```sh
firmsight capture --interface firmsight0 --output captures/session.pcap --duration 90
```

See [docs/BUILD_AND_OPERATION.md](docs/BUILD_AND_OPERATION.md) for architecture, setup, command details, lab networking guidance, troubleshooting, and limitations.

## Development

```sh
python -m pip install -e '.[test,dev]'
ruff check src tests
pytest
python -m build
```

GitHub Actions runs lint, tests, source/wheel builds, and installed-wheel smoke checks on Python 3.10–3.12 for `main` and `devlop`. Pushing a tag matching the package version (for example `v0.1.0`) creates a GitHub Release with generated notes and build artifacts.

## Responsible use

Use only firmware you are authorized to analyze. Extracted filesystems and emulated images are untrusted. Run analysis in a disposable VM with no host mounts or host network access. Do not connect a sample to the internet or a production network. The `capture` command records only the interface you select; FirmSight does not configure network namespaces, firewall rules, or virtual interfaces on your behalf.

## License

MIT; see [LICENSE](LICENSE).
