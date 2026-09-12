# Building

The supported Secure build tuple is Armv8-M on STM32H563. The root Makefile
includes `mk/target-stm32h563.mk`, `mk/arch-armv8m.mk`, and `mk/common.mk`
(target facts, architecture facts, and the shared build in that order) and
cross-compiles a freestanding Cortex-M33 image.

## Prerequisites

- GNU Make
- Python 3
- Git and initialized submodules
- GNU Arm Embedded tools with the `arm-none-eabi-` prefix
- a native C compiler for host tests
- for the AArch64 QEMU scenarios, `qemu-system-aarch64` and a toolchain with
  the `aarch64-none-elf-` prefix; CI uses `ghcr.io/wolfssl/wolfboot-ci-aarch64`,
  which also runs locally through Docker

Some submodule URLs use GitHub SSH. Configure GitHub SSH access or an
equivalent Git URL rewrite before initializing them.

```sh
git submodule update --init --recursive
```

The Zephyr guest build additionally uses a Python virtual environment, CMake,
Ninja, and network access to create its v4.2.0 workspace. The FreeRTOS guest
build uses the Arm cross-toolchain and network access; its default source
reference is the mutable `main` branch, not a pinned workspace.

## Secure image

```sh
make
```

The default target builds:

| Output | Purpose |
| --- | --- |
| `build/wolftrust.elf` | Secure image with symbols |
| `build/wolftrust.bin` | Flat Secure binary |
| `build/secure_cmse_implib.o` | CMSE import library for Non-secure linking |
| `build/manifest/wolftrust_manifest_generated.c` | Generated manifest source |
| `build/manifest/wolftrust_manifest_generated.h` | Generated partition and service constants |
| `build/nsc-syms.txt` | Symbol list used to enforce the five-veneer gateway |

Use another output directory or tool prefix as Make variables:

```sh
make BUILD_DIR=build-h5 TOOLPREFIX=/opt/gcc-arm/bin/arm-none-eabi-
```

The build records the variables enumerated by the
`secure_build_mode.stamp` recipe and regenerates when one of those values
changes. The current stamp omits `TOOLPREFIX`, `WT_GUEST_FLASH_WRP`, the VNET
tuning variables (`WT_VNET_POOL_SLOTS`, `WT_VNET_FRAME_MAX`,
`WT_VNET_RX_QUEUE_DEPTH`, `WT_VNET_RX_IRQ`, `WT_VNET_TIMEOUT_TICKS`, and
`WT_VNET_UNKNOWN_UCAST_FLOOD`), and the test-only
`WT_VAULT_FOREIGN_PROBE`, `WT_VAULT_PROBE_SECURED`, and
`WT_CONF_DIAG_TRAP` variables. Use a fresh `BUILD_DIR` or clean the active
output directory before changing an option that the recipe does not record.

## AArch64 EL3 monitor image

```sh
make ARCH=aarch64 TARGET=qemuvirt                            # virt, GICv3, cortex-a72
make ARCH=aarch64 TARGET=qemuvirt WT_GIC_VERSION=2 WT_CPU=cortex-a35
make ARCH=aarch64 TARGET=versal                              # WT_VERSAL_VIRT=1 today
```

Until the Secure Partition Manager runs at Secure EL1, the AArch64 default
goal is `el3-image`: the monitor archive `build/libwt_el3.a` (audited by
`tools/check-el3-symbols.sh` at link time) linked with the Secure EL1 stub
into `build/wolftrust_el3.elf` and `build/wolftrust_el3.bin`. The
`ghcr.io/wolfssl/wolfboot-ci-aarch64` container carries the toolchain and
QEMU; `make test-target-a` boots the result.

## Manifest generation

The default input is `port/stm32h563/manifest.json`.
`CONFIG_VNET=y` selects `manifest-vnet.json`, and
`WT_CONFORMANCE=1` selects `manifest-conformance.json`.

```sh
make CONFIG_VNET=y
make WT_CONFORMANCE=1
```

The generator is constrained to FF-M framework version `0x0100`,
feature mask `0x1` (connection-based IPC), and 32-bit addresses.
Unsupported capabilities or an invalid resource layout stop the build.

## Build controls

Examples:

```sh
make WT_TIMESLICE_MS=5
make WT_MAX_GUESTS=1
make BUILD_DIR=build-wrp WT_GUEST_FLASH_WRP=1
make CONFIG_VNET=y
```

Changing guest count, addresses, or sizes also requires matching manifest,
guest linker, emulator-load, flash, and measurement-record settings. See
[Macros](Macros.md) for the supported values and constraints.

## Reference guests

Set up the pinned Zephyr workspace, then build the Zephyr PSA guest and the
FreeRTOS PSA guest together:

```sh
make -C tests/firmware/zephyr-stm32h5 clone
make -C tests/firmware/zephyr-stm32h5 \
    build-guest0-psa build-freertos-guest1
```

This produces:

- `tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr/zephyr.bin`
- `tests/firmware/zephyr-stm32h5/build/freertos_guest1/freertos_guest1.bin`

The same Makefile also provides:

| Target | Result |
| --- | --- |
| `build-guest0` | Diagnostic Zephyr guest without the full PSA demo |
| `build-guest0-psa` | Zephyr PSA guest |
| `build-guest1` | Bare-metal heartbeat guest |
| `build-freertos-guest1` | FreeRTOS PSA guest |
| `run` | Zephyr PSA plus bare-metal guest under M33MU |
| `run-uarts` | Same pair with separated UART output |
| `run-tui` | Same pair with the M33MU TUI |
| `zephyr-freertos-uarts` | Zephyr and FreeRTOS PSA guests under M33MU |

## Authenticated image assembly

`make` alone produces an unsigned flat Secure binary. The target
runners perform the complete assembly:

1. build wolfBoot and the guest images;
2. copy the unpatched wolfTrust binary;
3. run `tools/measure/patch_guest_digests.py` with each guest ID,
   version, and binary;
4. sign the patched wolfTrust image with the wolfBoot key; and
5. load wolfBoot, signed wolfTrust, and guests at matching addresses.

Do not sign wolfTrust before patching the guest records. An unpatched record
count causes required guest launch to fail.

## Virtual network build

The optional wolfTrust virtual Ethernet switch for wolfIP guests is off by
default:

```sh
make CONFIG_VNET=y
make test-vnet
make test-vnet-target
```

The end-to-end VNET guests use
`tests/firmware/stm32h563-vnet/`, not the Zephyr and FreeRTOS demo
images.

## Clean builds

```sh
make clean
make -C tests/host clean
make -C tests/firmware/zephyr-stm32h5 clean
```

The root target removes the Secure build, bare-metal and VNET reference
firmware, and the host suites it names. The second command clears every native
host-suite build; the third clears Zephyr and FreeRTOS guest outputs. Downloaded
guest workspaces under ignored directories may remain.

See [Getting Started](Getting-Started.md) for the shortest path and [Testing](Testing.md) for validation
commands.
