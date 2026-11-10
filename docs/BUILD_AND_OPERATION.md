# FirmSight build and operation guide

## 1. Purpose and scope

FirmSight is a command-line starter application for authorized defensive IoT firmware research. It organizes four tasks: firmware fingerprinting, filesystem extraction, isolated emulation preparation, and observation support. It aims to make repeatable triage easier; it is not an automatic universal firmware-to-VM converter.

The normal input is a vendor firmware update file. Such a file may contain a header, checksums/signatures, multiple partitions, a compressed filesystem, a kernel, or a vendor-specific container. The extracted root filesystem is only one component of a bootable system. A compatible kernel, machine model, flash/storage layout, boot arguments, and often device-specific services are needed to boot it faithfully.

## 2. Requirements

- Linux host recommended for Binwalk, QEMU, packet capture, and isolated network setup
- Python 3.10 or newer
- Binwalk on `PATH` for `inspect` and `extract`
- One of `qemu-system-arm`, `qemu-system-aarch64`, `qemu-system-mips`, or `qemu-system-mipsel` for emulation
- `tcpdump` for packet capture
- `radare2` for GDB-stub attachment
- Optional: pytest for the unit test suite

Install OS tools using the package manager for your distribution. Package names, Binwalk versions, and QEMU board support vary by distribution. Verify availability with `command -v binwalk`, `command -v qemu-system-arm`, `command -v tcpdump`, and `command -v r2`.

## 3. Build/install from source

From the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
```

The package uses Python's standard library for the application. The `test` extra installs pytest. The optional `trace` extra installs r2pipe for future scripted radare2 integration; the current `trace` command uses the `r2` executable directly.

Check the CLI:

```sh
firmsight --version
firmsight --help
```

## 4. Architecture

```text
CLI (firmsight.cli)
  ├── inspect  -> SHA-256 + Binwalk signature scan
  ├── extract  -> Binwalk recursive extraction into chosen directory
  ├── emulate  -> QEMU system emulator; snapshot disk; no NIC by default
  ├── capture  -> tcpdump on explicitly selected interface and bounded duration
  └── trace    -> radare2 debugger attached to loopback QEMU GDB endpoint
Core operations (firmsight.core)
  └── validate inputs, resolve tools, build argv arrays, run subprocesses without a shell
```

External executables are invoked as argument arrays, not shell command strings. Inspection reports the image size, SHA-256, Binwalk output lines, and architecture hints if the scan output contains recognizable architecture names. The architecture hint is heuristic and should not be treated as authoritative CPU identification.

## 5. Typical analysis workflow

### Step A: Preserve and fingerprint the sample

Keep the original image read-only and record its source and authorization separately. Run:

```sh
firmsight inspect firmware.bin
firmsight inspect firmware.bin --json > work/firmware-report.json
```

The digest provides a stable identifier for reports and sample handling. Binwalk scans signatures but does not validate vendor authenticity or determine whether the image is safe.

### Step B: Extract recognized content

```sh
mkdir -p work
firmsight extract firmware.bin --output work/extracted
```

FirmSight calls `binwalk -e -M -C <directory> <image>`. Binwalk creates its own extraction subdirectories beneath the requested destination. Extraction can fail when a format is unsupported or an external unpacker is unavailable. Treat all resulting files as untrusted and avoid executing them on the host.

### Step C: Prepare a bootable system

Review extracted partitions and identify the target CPU, bootloader expectations, root filesystem format, init program, and kernel compatibility. Prepare a raw disk image and obtain/build a compatible kernel. These steps are device-specific and deliberately remain explicit: a firmware update may not include a directly bootable kernel/disk pair, and generic emulation may not reproduce vendor peripherals or bootloader behavior.

The current launcher passes a raw disk as virtio (`/dev/vda`) and a generic console/root argument. Some guest kernels need different machine, CPU, console, root device, storage controller, or boot arguments. Edit the prototype profile for a known device before interpreting boot failure as firmware behavior.

### Step D: Boot with the network detached

```sh
firmsight emulate --arch mipsel --kernel work/vmlinux --disk work/rootfs.ext4
```

The command uses QEMU full-system mode, `-snapshot` so guest writes do not alter the disk source, and `-nic none` so the VM has no network adapter. Ctrl-C stops the emulator. `--print-command` displays the generated command without executing it.

To attach radare2 to the QEMU GDB stub, start the emulator with a loopback-only port:

```sh
firmsight emulate --arch arm --kernel work/zImage --disk work/rootfs.ext4 --gdb-port 1234
```

Then, in another terminal:

```sh
firmsight trace --endpoint 127.0.0.1:1234
```

This provides an interactive debugger connection. It does not automatically instrument every function or detect buffer overflows. Use radare2 debugger commands and symbols/addresses appropriate to the target. The listener is explicitly bound to loopback by the CLI.

### Step E: Capture traffic in a deliberately isolated lab

The default VM has no NIC. If traffic observation is needed, the operator must first configure an isolated virtual network (for example, a dedicated TAP/bridge in a disposable Linux VM, with no forwarding/NAT to the internet or production LAN) and deliberately adapt the QEMU network configuration for that lab. Then capture that dedicated interface:

```sh
sudo firmsight capture --interface firmsight0 --output captures/run.pcap --duration 90
```

`capture` runs tcpdump with numeric address/port output disabled (`-nn`), writes a pcap, and exits after the requested bounded duration. It does not create or secure the interface and does not guarantee containment. Verify firewall and routing rules independently before attaching any firmware. Do not point it at a general-purpose interface unless capture of that interface is intended and authorized.

## 6. Command reference

### `inspect FIRMWARE [--json]`

Computes SHA-256 and invokes Binwalk's scan. JSON includes `file`, `size_bytes`, `sha256`, `signatures`, and `likely_architectures`.

### `extract FIRMWARE --output DIRECTORY`

Invokes recursive Binwalk extraction. Output folder is created if needed. Existing contents are not deleted.

### `emulate --arch ARCH --kernel FILE --disk FILE [--memory SIZE] [--gdb-port PORT] [--print-command]`

Supported architecture labels: `arm`, `aarch64`, `mips`, `mipsel`. QEMU board/CPU defaults are generic starter profiles: ARM `virt/cortex-a15`, AArch64 `virt/cortex-a57`, and MIPS variants `malta/24Kf`. NIC is disabled and storage changes are in snapshot mode. The command does not consume the original vendor `.bin` directly.

### `capture --interface NAME --output FILE [--duration SECONDS]`

Records one selected interface for 1–86400 seconds. tcpdump may require elevated privileges. Choose an isolated lab interface.

### `trace [--endpoint 127.0.0.1:PORT]`

Starts `r2 -d gdb://HOST:PORT` after validating that the host is loopback. It requires a compatible QEMU GDB stub and local radare2.

## 7. Troubleshooting

- **Tool not found:** Install the relevant system package and check `PATH`.
- **Binwalk extraction errors:** Check Binwalk's external unpacker requirements and inspect its diagnostic output. Not every vendor container is supported.
- **QEMU exits or kernel does not boot:** Confirm kernel architecture, machine/CPU compatibility, disk format, root device, and console argument. Start with a kernel known to boot on the chosen machine profile.
- **No root filesystem appears:** Verify the disk image was prepared as raw and that the guest kernel includes the storage and filesystem drivers needed for it.
- **radare2 cannot connect:** Ensure `--gdb-port` is enabled, the VM is still running, the selected port matches, and local radare2 supports QEMU GDB remote targets.
- **tcpdump permission denied:** Run with appropriate privileges inside the disposable lab VM, or grant only the required capture capability according to local policy.

## 8. Security and limitations

- Firmware images and extracted filesystems are untrusted. Use a disposable analysis environment.
- Default emulation has no network device. Packet capture is a separate operator-selected action; this prototype does not implement firewall or namespace isolation.
- Never bridge samples to production networks or unrestricted internet access. If simulating C2 behavior, use a controlled local sinkhole on an isolated network.
- `-snapshot` protects the source disk from guest writes but is not a complete VM security boundary.
- Architecture detection is heuristic; inspect the actual ELF binaries, bootloader, and device documentation.
- Generic QEMU machine profiles cannot reproduce all hardware peripherals. A firmware may hang even when the image itself is valid.
- Dynamic tracing is an interactive GDB-stub attachment; automatic function-call coverage and memory-safety detection are not implemented in this prototype.
- The project does not elevate privileges itself, configure host networking, or execute extracted binaries directly.

## 9. Tests

```sh
python -m pip install -e '.[test]'
pytest
```

Unit tests cover report serialization, invalid architecture rejection, and missing boot asset validation. Integration checks for Binwalk, QEMU, tcpdump, and radare2 need those system tools and representative authorized samples.

## 10. Repository layout

```text
src/firmsight/       Python package and CLI
tests/               Unit tests
docs/                Build and operation documentation
pyproject.toml       Packaging metadata and entry point
```
