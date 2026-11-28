# Footprint

This page records the measured size of the Secure image and lists every build
option that changes it. The lean default is the smallest image that keeps
every PSA service; `WT_ATTEST_COSE=0` builds a smaller one without Initial
Attestation. Each option below adds a feature back, and the table gives its
cost.
[Macros](Macros.md#build-profiles) has the full description of each option.

## How sizes are measured

Every size here comes from the linked Secure ELF and its map, built with Arm
GNU 15.2.1 in `ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.25` with LTO at isolation
level 3. The `interface-footprint` CI job runs in `v1.15`, which ships the same
toolchain and gives byte-identical sizes:

```text
Flash = text + data
RAM   = reserved Secure RAM: SPM .data + .bss, the SPM main stack, and every
        partition data band and stack at its full length
```

`arm-none-eabi-size` cannot give the RAM figure. The level 3 partition stacks
and data bands are linker regions with no section in them, so `data + bss`
leaves them out. `tools/secure_ram.py` reads them from the map.

To reproduce a size, build the image and read it:

```sh
make TARGET=stm32h563 secure-image
make TARGET=stm32h563 size-report
```

`size-report` prints the reserved Secure RAM with its breakdown, and the
largest sections and `.bss` objects. Use a separate `BUILD_DIR` for each
configuration you compare. The cross-compile workflow fails if the lean native
default image on any port grows past 79,680 bytes of flash or 45,728 bytes of
reserved Secure RAM. A port that
runs code from a RAM band (`WT_RAMFUNC_SIZE`, 4 KiB on the MIMXRT700) is
allowed that band on top.

## Measured sizes

Measured 2026-11-27, with wolfCrypt built as portable C (the default). The `full` profile turns on all four add-ons
(`WT_MAX_GUESTS=2 WT_FWU=1 WT_MANIFEST_RUNTIME_CHECK=1 WT_SHA256_FAST=1`).
The native default serves PSA Crypto from the Secure image (`WT_SECURE_PSA=1`)
on every port but the STM32L562, whose default and the `WT_SECURE_PSA=0` rows
run wolfPSA in the guest. The wolfHSM engine always runs it in the guest.

| Port | Engine | Default flash | Default RAM | `full` flash | `full` RAM |
| --- | --- | ---: | ---: | ---: | ---: |
| STM32H563 | native | 96,317 | 37,880 | 107,864 | 48,872 |
| STM32H563 | native, `WT_SECURE_PSA=0` | 57,032 | 34,296 | 68,544 | 43,240 |
| STM32H563 | hsm | 88,124 | 72,264 | 99,924 | 91,744 |
| MIMXRT700 | native | 96,701 | 42,280 | 108,336 | 53,264 |
| MIMXRT700 | native, `WT_SECURE_PSA=0` | 57,412 | 38,696 | 68,980 | 47,632 |
| MIMXRT700 | hsm | 88,508 | 76,660 | 100,428 | 96,144 |
| MCX N947 | native | 95,253 | 38,080 | 106,832 | 49,064 |
| MCX N947 | native, `WT_SECURE_PSA=0` | 55,964 | 34,496 | 67,476 | 43,432 |
| MCX N947 | hsm | 87,028 | 72,460 | 98,860 | 91,944 |
| STM32L562 | native | 56,552 | 34,280 | 68,064 | 43,216 |

The MIMXRT700 RAM includes its 4 KiB RAM code band (the NSC gateway and the
NOR program code). The STM32L562 builds the native engine only.
Update this table and its date when a change moves an image size.

## Options that change the size

Costs are over the native `WT_SECURE_PSA=0` image on the STM32H563. Every
option is off in the default.

| Option | Adds | Flash / RAM | Speed |
| --- | --- | ---: | --- |
| `WT_MAX_GUESTS=2` | A second Non-secure guest, the scheduling between two, and 8 IPC transfers instead of 4 | +2,120 / +4,612 | Adds SAU, MPU and IRQ reprogramming on every guest switch |
| `WT_FWU=1` | PSA Firmware Update and its 4 KiB stack | +3,232 / +4,316 | None |
| `WT_MANIFEST_RUNTIME_CHECK=1` | The boot-time manifest and port-binding validator, with the descriptive manifest it reads | +5,516 / +16 | Adds the validator run at boot |
| `WT_SHA256_FAST=1` | The unrolled SHA-256 transform | +416 / 0 | Faster guest verification at boot, attestation and the PSA hash service |
| `WT_WOLFCRYPT_SP_ASM=1 WT_WOLFCRYPT_ARMASM=1` | wolfCrypt's Cortex-M assembly for ECC, AES and SHA-256, and the 9 KiB crypto stack its P-256 verify needs | +8,936 / +4,096 | Faster ECC, AES and SHA-256 |
| `WT_ENGINE=hsm` | The wolfHSM server as the crypto engine, with its 6 KiB crypto stack and 24 KiB data band, and the wolfHSM store with its 5 KiB vault stack and 4 KiB vault band | +31,092 / +37,968 | Adds the wolfHSM request layer to each crypto call |
| `WT_FFM_FORENSICS=1` | The SPM and store flash forensic words a debugger reads after a fault | +768 / +120 | None |
| `full` profile | The first four together | +11,512 / +8,944 | As above |

With the wolfHSM engine, `WT_MAX_GUESTS=2` costs +2,440 bytes of flash and
+15,152 bytes of RAM, because each guest gets its own server stack.

Building out what an image does not need saves, on the same image:
`WT_SP_RESTART=0` 708 bytes of flash, `WT_GUEST_RESTART=0` 64, and the three
Secure Partition call trims (`WT_FFM_SP_DOORBELL=0 WT_FFM_SP_RHANDLE=0
WT_FFM_SP_SKIP=0`) 96 together. See [Macros](Macros.md#build-selection).

Each partition stack is sized from the high-water mark measured on M33MU
across the positive, restart, recovery, update and Arm conformance scenarios
on both engines, with at least 512 bytes and 12.5% of headroom, in 1 KiB
steps. `PSPLIM_S` faults a partition that overruns its stack; the SPM restarts
it under its restart policy, and fails closed once that budget is spent. A
data band its sections outgrow fails the link. Each size is a macro in
`port/common/armv8m/l3_layout.h` a port or build can override.

Stack high-water marks on the STM32H563, read from M33MU RAM dumps filled
with `0xA5` (2026-11-25 for SPM main and crypto, 2026-11-27 for the native
storage stacks, 2026-11-24 for the rest). The native column is the `nativewire` scenario,
which runs the positive lifecycle and every native wire key op from the
guest; the wolfHSM column is `positive` on the default profile and `bothpsa`
on `full`.

| Stack | Size | Native, default | wolfHSM, default | wolfHSM, `full` |
| --- | ---: | ---: | ---: | ---: |
| SPM main | 3,072 | 2,264 | 1,056 | 1,244 |
| Crypto | 6,144 | 4,728 | 4,820 | 4,820 |
| Protected Storage | 3,072 | 1,968 | 1,880 | 1,880 |
| Internal Trusted Storage | 3,072 | 1,968 | 1,880 | 1,880 |
| Vault | 4,096 native, 5,120 wolfHSM | 2,784 | 3,640 | 3,628 |
| Attestation | 5,120 | 3,680 | 3,696 | 3,776 |
| Firmware Update | 4,096 | not built | not built | 1,872 |

Across 22 scenarios on both engines, the SPM main stack peaked at 2,296
bytes (native `vaultrecover`) and the wolfHSM crypto stack at 4,856 bytes
(`tpm`). The STM32L562 and MCX N947 pass `positive`, `restart`, `devcrypto`
and `confboot` at these sizes on each engine they build.

The Firmware Update stack peaks at 3,108 bytes in the native `full`
`fwustage` scenario, which stages an update candidate.

With `WT_WOLFCRYPT_SP_ASM=1` the P-256 verify peaks at 7,552 bytes on the
native crypto stack and 7,680 bytes under wolfHSM (`tpm`), which is why that
build reserves 9 KiB on either engine.

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
and Initial Attestation at isolation level 3. `WT_ATTEST_COSE=0` removes
Initial Attestation and wolfCOSE for a smaller image without that service;
CI compile-checks it in the MIMXRT700 and MCX N947 builds, while every M33MU
run and the size gates keep attestation.

## Fastest image

Add the unrolled SHA-256 transform and wolfCrypt's Cortex-M assembly for
ECC, AES and SHA-256 (+10,428 bytes of flash and +4,096 bytes of RAM together
on the STM32H563):

```sh
make TARGET=<port> WT_SHA256_FAST=1 WT_WOLFCRYPT_SP_ASM=1 WT_WOLFCRYPT_ARMASM=1 secure-image
```

Leave these at their defaults, which already favor speed:

- `WT_ENGINE=native` calls wolfCrypt directly.
- `WT_MAX_GUESTS=1` skips the per-switch reprogramming.
- `WT_MANIFEST_RUNTIME_CHECK=0` skips the boot-time validator.

## TPM 2.0 and PKCS#11

`CONFIG_TPM=y` or `CONFIG_PKCS11=y` replaces PSA Crypto as the application API,
so the comparison covers both images: the Secure image and the application that
calls it. `tools/measure_interface_footprint.sh` builds each port, engine and
API with `WT_INTERFACE_PROFILE=default` and checks that every pair is present;
the cross-compile workflow publishes its CSV. Measured 2026-11-27.

Flash is Secure plus application, in bytes; RAM is reserved Secure RAM.

| Port | Engine | PSA flash | TPM 2.0 flash | PKCS#11 flash | PSA RAM | TPM 2.0 RAM | PKCS#11 RAM |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| STM32H563 | native | 131,973 | 119,496 (-9.5%) | 102,208 (-22.6%) | 37,880 | 72,380 | 87,740 |
| STM32H563 | hsm | 166,396 | 162,384 (-2.4%) | 142,280 (-14.5%) | 72,264 | 112,396 | 127,756 |
| MIMXRT700 | native | 132,293 | 119,780 (-9.5%) | 102,560 (-22.5%) | 42,280 | 76,780 | 92,140 |
| MIMXRT700 | hsm | 166,780 | 162,704 (-2.4%) | 142,632 (-14.5%) | 76,660 | 116,792 | 132,152 |
| MCX N947 | native | 130,845 | 118,364 (-9.5%) | 101,128 (-22.7%) | 38,080 | 72,580 | 87,940 |
| MCX N947 | hsm | 165,300 | 161,256 (-2.4%) | 141,168 (-14.6%) | 72,460 | 112,592 | 127,952 |
| STM32L562 | native | 121,904 | 118,984 (-2.4%) | 101,740 (-16.5%) | 34,280 | 72,364 | 87,724 |

The application shrinks because it no longer links a PSA Crypto client: the
PKCS#11 proxy is under 8 KB. The Secure image grows by the provider (fwTPM or
wolfPKCS11) and its private wolfCrypt copy. The wolfTPM client keeps its own
wolfCrypt for sessions and takes its entropy from `TPM2_GetRandom`, so it links
no crypto engine client and is the same size under both engines.

TPM 2.0 includes fwTPM dictionary-attack lockout; `WT_TPM_DA=0` saves about
2.3 KB of Secure flash.

The extra RAM is the interface band above SPM RAM, sized from the `full`
profile on the STM32H563 with the stack method above:

| Band | Data used / reserved | Stack peak / reserved |
| --- | ---: | ---: |
| TPM 2.0, native | 24,736 / 28,672 | 7,712 / 9,216 |
| TPM 2.0, hsm | 26,144 / 28,672 | 7,384 / 9,216 |
| PKCS#11, native | 42,016 / 45,056 | 6,784 / 8,192 |
| PKCS#11, hsm | 43,008 / 45,056 | 5,288 / 8,192 |

PKCS#11 data includes its 28 KiB token heap (`WT_PKCS11_HEAP_SIZE`). With the
hsm engine the crypto partition band grows from 0x6000 to 0x6800 bytes, because
the interface provider holds its own wolfHSM client namespace. On the STM32L562
both interfaces use the 160 KiB Secure slot of the conformance layout; the
default 128 KiB slot leaves too little room once wolfBoot reserves its last
sector.
