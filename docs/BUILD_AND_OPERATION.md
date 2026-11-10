# FirmSight build and operation guide

## 1. Purpose and scope

FirmSight is a command-line application for authorized defensive IoT firmware research. It organizes firmware fingerprinting, filesystem extraction, rootfs-to-initramfs preparation, isolated emulation, and observation support. It automates repeatable steps while exposing device-specific boot choices.

The normal input is a vendor firmware update file. Such a file may contain a header, checksums/signatures, multiple partitions, a compressed filesystem, a kernel, or a vendor-specific container. The extracted root filesystem is only one component of a bootable system. A compatible kernel, machine model, flash/storage layout, boot arguments, and often device-specific services are needed to boot it faithfully. `prepare` and `emulate-firmware` automate extraction, common rootfs/kernel discovery, initramfs generation, and QEMU launch, but cannot infer every vendor's hardware contract.

## 2. Requirements

- Linux host recommended for Binwalk, QEMU, packet capture, and isolated network setup
- Python 3.10 or newer
- Docker Engine for default sandboxed extraction and the isolated network lab
- Binwalk on `PATH` for `inspect` and optional `--extractor-mode host`
- `file` on `PATH` for kernel candidate identification
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
python -m pip install -e '.[test,dev]'
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
  ├── prepare  -> discover kernel/rootfs, produce initramfs and manifest
  ├── emulate-firmware -> boot vendor image using kernel + generated initramfs
  ├── emulate  -> QEMU system emulator for a prepared raw disk; no NIC by default
  ├── profiles -> list built-in board/CPU profiles
  ├── report   -> inventory static rootfs contents and produce HTML/JSON findings
  ├── lab      -> isolated Docker network, sinkhole, guest launch, and pcap capture
  ├── capture  -> tcpdump on explicitly selected interface and bounded duration
  ├── trace    -> interactive radare2 attach or bounded GDB trace
  └── tui      -> interactive case dashboard with streamed command progress
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

By default, extraction runs in a dedicated Docker image with `--network none`, a read-only container root, read-only firmware mount, one writable output mount, all capabilities dropped, no-new-privileges, and memory/process limits. The image includes Binwalk and common filesystem/archive unpackers. Building the image the first time may need package repository access; actual sample extraction runs without network access.

The output directory must be empty. Binwalk writes beneath it; FirmSight also saves `firmsight-extraction.json` (sample hash, tool versions, command, return code, status, and entry count) and `firmsight-extraction.log` (stdout/stderr). A failed unpack is recorded as `partial_failure` when it created files, and the partial output remains for review. `--extractor-mode host` is available if Docker is unavailable, but it runs unpackers directly on the host and is less isolated.

### Step C: Prepare the root filesystem and boot assets

The integrated workflow extracts the image and searches for a Linux root tree and likely kernel candidates:

```sh
firmsight prepare firmware.bin --workdir work/router
```

It writes `work/router/manifest.json` and a gzip-compressed `rootfs.cpio.gz` initramfs. The manifest records the source hash, chosen rootfs and kernel, architecture, candidate kernels, and initramfs hash. Rootfs traversal preserves symbolic links without following them. FirmSight adds conventional `/dev/console` and `/dev/null` nodes when they are missing.

If discovery is ambiguous, choose the assets explicitly. You can also supply a compatible kernel separately when the vendor container has an opaque kernel:

```sh
firmsight prepare firmware.bin --workdir work/router \\
  --kernel work/vendor-kernel --rootfs work/router/extracted/rootfs --arch mipsel
```

Use a new or empty work directory for each sample so stale extraction output cannot mix with the current firmware.

Generate a reviewable static report from the extracted rootfs:

```sh
firmsight report --firmware firmware.bin \\
  --rootfs work/router/extracted/rootfs --output-dir reports/router
```

The HTML report is self-contained; the JSON file is suitable for later automation. Findings link to inventory entries and carry line numbers where the source appears textual, plus byte offsets. Credential values are never included; the report lists matching key names only. URL query values are redacted, though analysts should still protect reports because hostnames, IP addresses, and file paths can be sensitive.

Review extracted partitions and identify the target CPU, bootloader expectations, root filesystem format, init program, and kernel compatibility. The generated initramfs avoids requiring a host loopback mount or root privileges to construct a disk image, but the kernel must support initramfs and the chosen QEMU board model.

Vendor kernels may require the original machine model, DTB, peripherals, flash layout, or bootloader. Firmware may not contain a directly usable kernel, and a generic profile cannot reproduce arbitrary hardware. A boot failure alone does not establish that an image is malicious or corrupt.

### Step D: Boot the firmware image with the network detached

```sh
firmsight emulate-firmware firmware.bin --workdir work/router
```

Pass device-specific assets and settings when needed:

```sh
firmsight emulate-firmware firmware.bin --workdir work/router \\
  --kernel work/vendor-kernel --rootfs work/router/extracted/rootfs --arch arm \\
  --dtb work/vendor.dtb --machine virt --cpu cortex-a15 \\
  --kernel-args 'console=ttyAMA0,115200 rdinit=/sbin/init'
```

`--print-command` prepares the assets and displays the QEMU command without starting the VM.

Use a reusable device profile when the same device settings recur:

```sh
firmsight profiles
firmsight emulate-firmware firmware.bin --workdir work/router --profile mipsel-malta
```

The built-ins (`arm-virt`, `aarch64-virt`, `mips-malta`, and `mipsel-malta`) are generic QEMU reference boards rather than router vendor profiles. Create a custom JSON profile for known hardware and keep it with the case notes:

```json
{
  "name": "my-router-rev-a",
  "architecture": "arm",
  "machine": "vexpress-a9",
  "cpu": "cortex-a9",
  "memory": "512M",
  "console": "ttyAMA0,115200",
  "init": "/etc/preinit",
  "dtb": "router.dtb",
  "devices": ["virtio-rng-device"],
  "drives": [
    {"file": "flash.bin", "format": "raw", "interface": "mtd", "readonly": true}
  ]
}
```

Paths in a profile are relative to that profile file. Additional drives are read-only by default; set `readonly` to `false` only when the analysis needs guest writes. Optional QEMU device strings let researchers attach emulated peripherals supported by their installed QEMU. Confirm machine compatibility with the kernel and vendor's device tree before interpreting boot behavior.

### Step E: Boot a previously prepared disk image with the network detached

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

This provides an interactive debugger connection. Use radare2 debugger commands and symbols/addresses appropriate to the target. The listener is explicitly bound to loopback by the CLI.

For a bounded trace log, use GDB batch mode with symbols and function breakpoints:

```sh
firmsight trace --endpoint 127.0.0.1:1234 --gdb --symbols work/vmlinux \\
  --function handle_request --function '*0x81234000' --duration 120
```

The trace logs requested breakpoint hits and bounded backtraces. By default it also installs breakpoints for common panic/abort/stack-check failure symbols, recording registers and a backtrace when one is hit. Named breakpoints require an unstripped ELF symbol file; raw addresses work without symbols. The generated `.gdb` script and log remain on disk. This is breakpoint-driven coverage: code that does not hit selected breakpoints is not traced.

### Step F: Capture traffic in the FirmSight isolated lab

FirmSight can generate and manage a Docker Compose network with `internal: true`, a QEMU service, and a local DNS/HTTP sinkhole. Docker's internal network prevents external connectivity; the guest can contact the sinkhole service on the private bridge. The standard `emulate` and `emulate-firmware` commands remain network-disconnected.

Initialize the lab and start its containers:

```sh
firmsight lab init --workdir work/router
firmsight lab up --workdir work/router
```

Start capture and emulation concurrently in separate terminals:

```sh
# Terminal A
firmsight lab capture --workdir work/router --output run.pcap --duration 90

# Terminal B
firmsight lab emulate --workdir work/router
```

For debugger traces inside the container, start the guest with `--gdb-port 1234` and run `firmsight lab trace --workdir work/router --symbols work/router/vmlinux --function handle_request` in another terminal.

Inspect DNS/HTTP/TLS attempt logs and stop the lab:

```sh
firmsight lab logs --workdir work/router
firmsight lab down --workdir work/router
```

The pcap is saved under `work/router/.firmsight-lab/captures/`. The sinkhole maps DNS A queries to its internal address, logs HTTP request metadata/body snippets, and records the start of TLS handshakes for HTTPS attempts. It does not provide a TLS certificate or emulate arbitrary C2 protocols. The sinkhole can return answers only while its container is running.

The lab requires Docker Engine and the Compose v2 plugin. `lab init` only writes local files; `lab up` builds two images and creates a private Docker network. It does not publish container ports to the host. `lab down` stops containers and removes the network; it leaves the pcap and analysis files on disk.

### Step G: Capture traffic from a separately configured lab interface

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

### `lab init|up|down|status|logs|emulate|capture|trace`

Manages the opt-in Docker Compose sandbox. `lab emulate` reads `manifest.json`, launches QEMU with a lab NIC and routes guest DNS to the local sinkhole. `lab capture` captures traffic reaching the sinkhole. `lab trace` runs GDB inside the emulator container against its loopback QEMU GDB stub. Keep capture and trace running in separate terminals while emulation runs. The guest has no route to external networks in the internal Docker bridge.

### `prepare FIRMWARE --workdir DIRECTORY [--kernel FILE] [--rootfs DIRECTORY] [--arch ARCH]`

Extracts the firmware, discovers a rootfs/kernel where possible, packages the rootfs as `rootfs.cpio.gz`, and writes a JSON manifest. Use a fresh work directory for each sample.

### `emulate-firmware FIRMWARE --workdir DIRECTORY [boot overrides]`

Runs the `prepare` workflow and launches QEMU with `-kernel`, `-initrd`, and `-nic none`. Optional overrides include `--kernel`, `--rootfs`, `--arch`, `--machine`, `--cpu`, `--kernel-args`, `--dtb`, `--memory`, and `--gdb-port`. `--print-command` prepares files but does not start QEMU.

### `profiles [--json]`

Lists the built-in ARM, AArch64, MIPS, and MIPS little-endian reference profiles. Pass a profile name or JSON path using `--profile` to `prepare`, `emulate-firmware`, or `lab emulate`.

### `report --firmware FILE --rootfs DIRECTORY --output-dir DIRECTORY`

Writes `firmsight-report.json` and `firmsight-report.html`. It inventories regular files, directories, symlinks, and devices; identifies common ELF architectures; lists startup/service config paths and passwd account names; and searches bounded files for URLs, IPs, domains, credential key names, and suspicious command strings. Files above `--max-file-size` are inventoried but not scanned for strings.

### `tui FIRMWARE --workdir DIRECTORY [--extractor-mode docker|host]`

Starts a line-oriented interactive case dashboard. It shows the sample hash, extraction status, boot asset manifest, static finding totals, latest pcap, Docker lab status, and recent sinkhole events. Menu actions launch scan, extraction, preparation, report, emulation, capture, trace, and lab lifecycle commands; command output streams into the same terminal session.

### `emulate --arch ARCH --kernel FILE --disk FILE [--memory SIZE] [--gdb-port PORT] [--print-command]`

Supported architecture labels: `arm`, `aarch64`, `mips`, `mipsel`. QEMU board/CPU defaults are generic starter profiles: ARM `virt/cortex-a15`, AArch64 `virt/cortex-a57`, and MIPS variants `malta/24Kf`. NIC is disabled and storage changes are in snapshot mode. The command does not consume the original vendor `.bin` directly.

### `capture --interface NAME --output FILE [--duration SECONDS]`

Records one selected interface for 1–86400 seconds. tcpdump may require elevated privileges. Choose an isolated lab interface.

### `trace [--endpoint 127.0.0.1:PORT]`

Starts `r2 -d gdb://HOST:PORT` after validating that the host is loopback. Pass `--gdb` or `--function NAME` for GDB batch tracing, with optional `--symbols`, `--output`, `--duration`, and `--stack-depth`. Interactive attach requires local radare2; batch tracing requires `gdb-multiarch`.

## 7. Troubleshooting

- **Tool not found:** Install the relevant system package and check `PATH`.
- **Binwalk extraction errors:** Check Binwalk's external unpacker requirements and inspect its diagnostic output. Not every vendor container is supported.
- **No rootfs/kernel discovered:** Select paths explicitly with `--rootfs` and `--kernel`. Some vendor formats need manual carving or external extraction.
- **QEMU exits or kernel does not boot:** Confirm kernel architecture, machine/CPU/DTB compatibility, initramfs support, init path, and console argument. Try the device's known kernel and matching QEMU board profile.
- **Initramfs fails to start init:** Check that `/sbin/init` exists or set `--kernel-args` with the correct `rdinit=` path; confirm the kernel has gzip initramfs support.
- **radare2 cannot connect:** Ensure `--gdb-port` is enabled, the VM is still running, the selected port matches, and local radare2 supports QEMU GDB remote targets.
- **tcpdump permission denied:** Run with appropriate privileges inside the disposable lab VM, or grant only the required capture capability according to local policy.

## 8. Security and limitations

- Firmware images and extracted filesystems are untrusted. Use a disposable analysis environment.
- Default emulation has no network device. The opt-in Docker lab uses an `internal` bridge with no external route and no published ports; review Docker daemon/network policy on the host before use.
- Never bridge samples to production networks or unrestricted internet access. If simulating C2 behavior, use a controlled local sinkhole on an isolated network.
- `-snapshot` protects the source disk from guest writes but is not a complete VM security boundary.
- Architecture detection is heuristic; inspect the actual ELF binaries, bootloader, and device documentation.
- Generic QEMU machine profiles cannot reproduce all hardware peripherals. A firmware may hang even when the image itself is valid.
- Device profiles make settings repeatable but do not emulate unsupported vendor-specific ASICs or undocumented peripherals automatically.
- Static report indicators are heuristic and may be false positives; they do not establish runtime behavior. Credential values are omitted, but reports still contain potentially sensitive host indicators.
- Dynamic tracing logs selected breakpoints and stack snapshots; complete function-call coverage and automatic memory-safety detection are not provided.
- The project does not elevate privileges itself, configure host networking, or execute extracted binaries directly.

## 9. Tests

```sh
python -m pip install -e '.[test,dev]'
ruff check src tests
pytest
python -m build
```

Unit tests cover report serialization, initramfs serialization, constrained extractor command generation and partial failures, network-disabled QEMU command generation, profile validation, sinkhole DNS responses, GDB script generation, and invalid asset validation. Full container runtime integration needs Docker Engine access and representative authorized firmware/kernel assets.

## 10. Repository layout

```text
src/firmsight/       Python package and CLI
tests/               Unit tests
docs/                Build and operation documentation
pyproject.toml       Packaging metadata and entry point
```

## 11. CI and releases

GitHub Actions runs Ruff, pytest, source/wheel builds, and an installed-wheel smoke test on Python 3.10, 3.11, and 3.12 for pushes and pull requests targeting `main` or `devlop`.

To publish a GitHub Release, create and push a tag matching the version in `pyproject.toml`:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The release workflow verifies the tag, builds the source distribution and wheel, and attaches both artifacts with generated release notes. It does not publish to PyPI.
