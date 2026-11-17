# Footprint

This page records the measured size of the Secure image and lists every build
option that changes it. The lean default is the smallest image the build
offers. Each option below adds a feature back, and the table gives its cost.
[Macros](Macros.md#build-profiles) has the full description of each option.

## How sizes are measured

Every size here comes from the linked Secure ELF and its map, built with Arm
GNU 15.2.1 in `ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.25` with LTO at isolation
level 3:

```text
Flash = text + data
RAM   = reserved Secure RAM: SPM .data + .bss, the SPM main stack, and every
        partition data band and stack at its full length
```

`arm-none-eabi-size` cannot give the RAM figure. The level 3 partition stacks
and data bands are linker regions with no section in them, so `data + bss`
leaves them out. `tools/secure_ram.py` reads them from the map. TF-M places its
partition stacks inside its `.bss`, so its `data + bss` already counts them.

To reproduce a size, build the image and read it:

```sh
make TARGET=stm32h563 secure-image
make TARGET=stm32h563 size-report
```

`size-report` prints the reserved Secure RAM with its breakdown, and the
largest sections and `.bss` objects. Use a separate `BUILD_DIR` for each
configuration you compare. The cross-compile workflow fails if the lean native
default image on any port grows past 79,680 bytes of flash or 45,728 bytes of
reserved Secure RAM, TF-M level 3's figures on the STM32L562E-DK. A port that
runs code from a RAM band (`WT_RAMFUNC_SIZE`, 4 KiB on the MIMXRT700) is
allowed that band on top.

## Measured sizes

Measured 2026-11-16. The `full` profile turns on all four add-ons
(`WT_MAX_GUESTS=2 WT_FWU=1 WT_MANIFEST_RUNTIME_CHECK=1 WT_SHA256_FAST=1`).

| Port | Engine | Default flash | Default RAM | `full` flash | `full` RAM |
| --- | --- | ---: | ---: | ---: | ---: |
| STM32H563 | native | 79,388 | 44,236 | 89,876 | 57,724 |
| STM32H563 | hsm | 109,240 | 83,932 | 120,016 | 107,916 |
| MIMXRT700 | native | 79,608 | 48,632 | 90,160 | 62,116 |
| MIMXRT700 | hsm | 109,492 | 88,324 | 120,364 | 112,308 |
| MCX N947 | native | 78,160 | 44,432 | 88,712 | 57,916 |
| MCX N947 | hsm | 107,980 | 84,124 | 118,820 | 108,108 |
| STM32L562 | native | 78,448 | 44,256 | 88,936 | 57,756 |

The MIMXRT700 RAM includes its 4 KiB RAM code band (the NSC gateway and the
NOR program code). The STM32L562 figures were measured on the STM32L562 port,
which is under review and not yet in this tree, merged with these sources
before the shared port layer landed. That port builds the native engine only.
Update this table and its date when a change moves an image size.

## Options that change the size

Costs are over the native default on the STM32H563. Every option is off in
the default.

| Option | Adds | Flash / RAM | Speed |
| --- | --- | ---: | --- |
| `WT_MAX_GUESTS=2` | A second Non-secure guest, the scheduling between two, and an IPC message pool of 8 instead of 4 | +2,328 / +9,368 | Adds SAU, MPU and IRQ reprogramming on every guest switch |
| `WT_FWU=1` | PSA Firmware Update and its 4 KiB stack | +3,328 / +4,120 | None |
| `WT_MANIFEST_RUNTIME_CHECK=1` | The boot-time manifest and port-binding validator | +3,264 / 0 | Adds the validator run at boot |
| `WT_SHA256_FAST=1` | The unrolled SHA-256 transform | +1,472 / 0 | Faster guest verification at boot, attestation and the PSA hash service |
| `WT_ENGINE=hsm` | The wolfHSM server as the crypto engine, with its 10 KiB crypto stack and 24 KiB data band | +29,852 / +39,696 | Adds the wolfHSM request layer to each crypto call |
| `full` profile | The first four together | +10,488 / +13,488 | As above |

With the wolfHSM engine, `WT_MAX_GUESTS=2` costs +2,648 bytes of flash and
+19,864 bytes of RAM, because each guest gets its own server stack.

Each partition stack is sized from the high-water mark measured on M33MU
across the positive, restart, recovery, update and Arm conformance scenarios
on both engines, with headroom. `PSPLIM_S` faults a partition that overruns
its stack, so an undersized stack stops that partition and nothing else. A
data band its sections outgrow fails the link. Each size is a macro in
`port/common/armv8m/l3_layout.h` a port or build can override.

These options also add code but are not part of a production size budget:

- `CONFIG_VNET=y` links the virtual network switch for the two-guest VNET
  demo.
- `WT_CONFORMANCE=1` builds the Arm PSA API test manifest and sources.
- `WT_GUEST_FLASH_WRP=1` checks hardware write protection of each guest
  window before launch. Turn it on for hardened production images whatever
  the size.

## Smallest image

Build with no options:

```sh
make TARGET=<port> secure-image
```

That is the native engine, one guest, LTO on, and every add-on off. Keep
`WT_LTO=1`; `WT_LTO=0` is for toolchain diagnostics and builds a larger
image. `-Oz` was measured against the default `-Os` and gave no smaller
image. The default keeps Crypto, Internal Trusted Storage, Protected Storage
and Initial Attestation at isolation level 3; no build option removes them.

## Fastest image

Add the unrolled SHA-256 transform to the default:

```sh
make TARGET=<port> WT_SHA256_FAST=1 secure-image
```

Leave these at their defaults, which already favor speed:

- `WT_WOLFCRYPT_SP_ASM=1` and `WT_WOLFCRYPT_ARMASM=1` build wolfCrypt's
  Cortex-M assembly for ECC, AES and SHA-256.
- `WT_ENGINE=native` calls wolfCrypt directly.
- `WT_MAX_GUESTS=1` skips the per-switch reprogramming.
- `WT_MANIFEST_RUNTIME_CHECK=0` skips the boot-time validator.
