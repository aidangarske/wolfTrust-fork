# STM32H5 Guide

This guide covers the NUCLEO-H563ZI reference board. Option-byte and
product-state changes can erase the device or remove debug access. Read the
current state first, keep the board in a recoverable state during development,
and never enter the permanent Locked state on a development board.

Supported silicon is STM32H563 revision X or W (DBGMCU_IDCODE REV_ID 0x1007 or
0x100F); the Secure image halts at boot on engineering samples A (0x1000) and
Z (0x1001), which need more flash wait states during read-while-write than the
port sets (ST ES0565 2.2.9), and on any other IDCODE.

## Required tools

- NUCLEO-H563ZI with ST-Link and USB serial
- STM32CubeProgrammer CLI
- Linux with Bash and GNU userland
- Docker and the configured build container for Secure and guest builds
- pyOCD with STM32H563 support
- a host-visible `arm-none-eabi-nm`, or an override in `ARM_NM`
- Python 3
- a serial device, default `/dev/ttyACM0`

Overrides:

| Variable | Purpose |
| --- | --- |
| `STM32_CLI` | Full path to `STM32_Programmer_CLI` |
| `STM32_CP` | STM32CubeProgrammer binary directory |
| `H5_SERIAL` | UART device |
| `WT_H5_DOCKER_IMAGE` | Container image holding the build toolchain |
| `WT_DA_DIR`, `WT_DA_OBK`, `WT_DA_KEY`, `WT_DA_CERT`, `WT_DA_PWD` | Debug Authentication material |

## Read-only preflight

Read the product state and Secure watermarks:

```sh
tests/target/provisioning_ctrl.sh status
tests/target/h5_lock_preflight.sh
```

The preflight validates an Open device with TrustZone and the OEM immutable
root-of-trust boot path enabled. It confirms that SECWM fields are present and
requires TrustedPackageCreator; its Debug Authentication help check is
informational. It does not compare watermark values, inspect the Debug
Authentication key, certificate, or OBK material, validate permitted actions,
or exercise recovery. Manually compare the printed values with the TrustZone
perimeter table below and validate the remaining items separately before
advancing lifecycle state. The preflight writes nothing.

## Reference flash layout

The current hardware runner uses:

| Image or region | Address or range |
| --- | ---: |
| wolfBoot | `0x0C000000` |
| wolfTrust | `0x0C060000` |
| wolfBoot update partition | `0x0C100000-0x0C13FFFF` |
| wolfBoot swap sector | `0x0C140000` |
| Guest 0 | `0x080A0000` |
| Guest 1 | `0x080E0000` |
| WRP-covered guest region | `0x080A0000-0x080FFFFF` |

These addresses come from `tests/target/run_h5_hardware.sh` and its
exported build variables. Use that runner for image assembly and flashing so
the build and flash addresses stay paired.

## TrustZone perimeter

`tests/target/provisioning_ctrl.sh set-perimeter` programs the
reference option bytes:

| Option | Value | Purpose |
| --- | ---: | --- |
| `TZEN` | `0xB4` | Enable TrustZone |
| `BOOT_UBE` | `0xB4` | Select the OEM immutable-root boot path |
| `SWAP_BANK` | `0x0` | Use the expected bank mapping |
| `SECWM1_STRT` | `0x0` | Start Secure bank-1 watermark |
| `SECWM1_END` | `0x4F` | Cover the complete wolfBoot and wolfTrust Secure region through `0x0809FFFF` |
| `SECWM2_STRT` | `0x0` | Start Secure bank-2 watermark |
| `SECWM2_END` | `0x7F` | Cover the configured bank-2 Secure region |

Changing `TZEN` can mass-erase the device. The command requires an
explicit write confirmation:

```sh
WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh set-perimeter
```

Do not copy these values to another STM32H5 part without checking its reference
manual, flash geometry, and intended image layout.

## Guest flash write protection

STM32H563 bank-1 WRP bits each cover four 8 KiB sectors, and a cleared bit
means protected. The reference value `WRPSGn1=0x000FFFFF` clears bits
20 through 31, protecting sectors `0x50-0x7F` and therefore the whole
guest region.

The `provisioning_ctrl.sh set-wrp` helper deliberately applies WRP only while
the device is Open. Treat that as wolfTrust's conservative supported workflow,
not the complete silicon rule: current ST guidance makes WRP nonmodifiable in
TZ-Closed, Closed, and Locked, and RM0481 separately defines the
`FLASH_WRPSGNxR.UNLOCK` condition. Program guest images first, then protect
them:

```sh
WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh set-wrp
```

Read back the live value:

```sh
STM32_CLI="${STM32_CLI:-$HOME/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI}"
"$STM32_CLI" -c port=SWD mode=HotPlug -ob displ | grep -i WRPSGn1
```

Build wolfTrust with `WT_GUEST_FLASH_WRP=1`. At each required launch,
the Secure port checks that every WRP group covering the full guest window is
protected. A missing bit refuses launch.

To reflash with the supported helper workflow, keep the device Open and clear
WRP:

```sh
WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh clear-wrp
```

Then flash and reapply WRP before allowing a hardened image to launch. The
hardware runner performs that clear/program/reapply sequence automatically
when `WT_GUEST_FLASH_WRP=1` is present.

## Build, flash, and verify

For a focused positive run with guest-flash enforcement, pass the flag into the
container build and repeat it for the host-side flash run:

```sh
docker run --rm \
    -e WT_GUEST_FLASH_WRP=1 \
    -v "$PWD":/workspace \
    -w /workspace \
    ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.15 \
    bash tests/target/run_h5_hardware.sh build positive
WT_GUEST_FLASH_WRP=1 \
    tests/target/run_h5_hardware.sh flash positive
```

The suite:

1. builds the matching wolfBoot, wolfTrust, Zephyr, and FreeRTOS images;
2. patches both guest measurement records into wolfTrust;
3. signs wolfTrust;
4. clears WRP if required;
5. flashes all images with verification;
6. restores WRP; and
7. resets the board, captures UART, and checks expected markers.

The current `run_h5_suite.sh` wrapper does not forward
`WT_GUEST_FLASH_WRP` into a Docker build, so do not replace the two-stage command
with the shorter `make test-hardware` form until that runner is fixed. Do not use
the direct-host build path either: it adds `safe.directory '*'` to the user's
global Git configuration. The detector checks the board/programmer path, not
every required host tool. It reports a skip when the CLI or serial VCP is absent
and, when `lsusb` is available, when no ST-Link is detected. Without `lsusb`, a
missing probe appears later as a flash failure.

## Reversible product-state flow

Product-state values used by the control script are:

| State | Value |
| --- | ---: |
| Open | `0xED` |
| Provisioning | `0x17` |
| TrustZone Closed | `0xC6` |
| Closed | `0x72` |
| Locked | `0x5C` |

`advance` refuses Locked, which is permanent; the real, gated command for
each state is `lock` (see [Locking a production part](#locking-a-production-part)).
The reversible development sequence is deliberately manual:

```sh
tests/target/provisioning_ctrl.sh status
WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh advance 0x17
WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh provision-da
tests/target/provisioning_ctrl.sh discover
WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh advance 0x72
WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh regress
```

`advance` to TrustZone Closed or Closed runs only from Provisioning: once a
part is TrustZone Closed, the debug link cannot write the next state, so each
closed state is reached directly from Provisioning, as ST's own provisioning
script does. `advance` also captures the UART across the reset its write
causes, so it reports whether wolfTrust booted in the new state.

Provision the certificate-based Debug Authentication data in Provisioning.
`discover` performs read-only device discovery; it supplies neither the key nor
certificate and does not authenticate the certificate chain or validate the
regression action. Do not close the device unless the exact certificate chain
and permitted regression action have been validated in a controlled,
recoverable test. Regression performs a full mass-erase back to Open.

After regression, rerun `set-perimeter`, rebuild and flash the complete chain
with the current hardware runner, reapply WRP, and rerun the positive checks.

Every board-writing control command requires `WT_LOCK_CONFIRM=1`.
The same script drives the MIMXRT700 with `TARGET=mimxrt700`; see the
[MIMXRT700 Guide](MIMXRT700-Guide.md).
Review the exact current command in
`tests/target/provisioning_ctrl.sh` before execution.

## Locking a production part

> **Production only.** `lock` moves a production part up the product-state
> ladder for good. Locked (`0x5C`) is **IRREVERSIBLE**: debug closes forever,
> with no Debug Authentication regression, no mass erase, and no reflash, and
> the software on the part stays bound to the keys you locked it with.
> Provisioning, TrustZone Closed, and Closed only come back through a Debug
> Authentication chain you have proven can regress the part, and that
> regression mass-erases it. Without such a chain they are permanent too.
> Never lock a development board. For development, use `advance` and `regress`
> above.

### What locking does

**To the device**:

| State | Debug | Way back |
| --- | --- | --- |
| Provisioning `0x17` | Secure debug closed, Non-secure open | DA regression (mass erase) |
| TrustZone Closed `0xC6` | Secure side sealed | DA regression (mass erase) |
| Closed `0x72` | fully closed; the SWD link drops | DA full regression (mass erase) |
| Locked `0x5C` | closed forever | none |

A closed part no longer answers `-ob displ`, so the script reads its state
through Debug Authentication discovery (`ST_LIFECYCLE_CLOSED`). With debug
closed, nothing outside the firmware can change the TrustZone perimeter or
the guest WRP, so set both before locking.

**To the firmware.** wolfBoot hands wolfTrust the PSA life cycle for the
state:
- Provisioning is `0x2000`.
- TrustZone Closed is `0x4000`.
- Closed and Locked are `0x3000` SECURED.

Past Provisioning, wolfTrust stops treating the part as a development board:

- It enforces each guest's rollback floor, so an older guest image is refused.
- It never reformats the vault, even a corrupt one: the sealed device key and
  write-once storage survive, and a damaged store stops boot provisioning
  instead of being wiped.
- The attestation token reports the new life cycle.

**How it binds the software.** Once debug is closed, the software on the part
can only change through wolfBoot's signed update path (`SERVICE_FWU`). The
keys that hold it in place are:

- the wolfBoot signing key, which decides which wolfTrust images wolfBoot boots;
- the guest measurement records, which decide which guests wolfTrust launches;
- the Debug Authentication certificate chain, which is the only way to regress
  a part that is not yet Locked.

On a Locked part, only the signed update path remains, and wolfBoot itself can
never be replaced. If you lose the signing key, the part can never be updated.

### The lock commands

`lock` is the real command for each state. ST's rule, confirmed on this board,
is that the closed states are written **from Provisioning**: once a part is
TrustZone Closed, the debug link can no longer write the next state. So
`lock` goes Open → Provisioning, then to exactly one final state:

| Command | Runs only from | Sets | Also needs |
| --- | --- | --- | --- |
| `lock 0x17` | Open `0xED` | Provisioning | a rehearsal of `0x17` |
| `lock 0xC6` | Provisioning `0x17` | TrustZone Closed | a rehearsal of `0xC6`; guest WRP; DA provisioned |
| `lock 0x72` | Provisioning `0x17` | Closed | a rehearsal of `0x72`; guest WRP; DA provisioned |
| `lock 0x5C` | Provisioning `0x17` | Locked (final) | a rehearsal of `0x72`; guest WRP |

### What `lock` checks before it writes

ST's `ROT_Provisioning` script offers the states as a menu and pauses with
"Press any key to continue". `lock` is stricter:

- **One step at a time**, checked against the product state read from the
  part.
- **Rehearse, then lock.** A state is rehearsed by `advance <state>` and then
  `regress`:
  - `advance` captures the UART across the reset that the write causes, and
    records that these exact images booted in that state.
  - `regress` records that Debug Authentication brought the part back to Open
    from it.
  - Both records hold a digest of the four images, so a rebuild needs a new
    rehearsal.
  - Locked cannot be rehearsed, so `lock 0x5C` requires a rehearsal of Closed:
    the same images with debug closed.
- **Provision first.** Every closed state needs the guest WRP
  (`WRPSGn1=0x000FFFFF`). TrustZone Closed and Closed also need Debug
  Authentication provisioned and offering Full Regression, which `lock` checks
  by live discovery. That is the brick ST warns about: a part closed without
  working Debug Authentication cannot come back.

Then it previews the exact write, and writes only with `WT_LOCK_CONFIRM=1`,
`WT_PRODUCTION_LOCK=1`, an interactive terminal, and a typed
`I ACCEPT <state>`.

### Step by step

The `STM32_Programmer_CLI` lines below are from the lock-ladder run on a
NUCLEO-H563ZI on 2026-08-19. The `[check]` lines, preview, and prompt are what
the current script adds, run offline against a stubbed CLI. No `lock` write
has been run on a wolfTrust board.

1. **Build and flash the production images**, with production signing keys
   and `WT_GUEST_FLASH_WRP=1`, then set the perimeter, protect the guests, and
   verify:

   ```sh
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh set-perimeter
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh flash
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh set-wrp
   tests/target/provisioning_ctrl.sh verify
   ```

   ```text
     [check] PASS  wolfTrust chain boots on silicon
   ```

2. **Rehearse Provisioning and Closed** on a production sample, with the
   production Debug Authentication chain (`WT_DA_*`), not ST's sample:

   > **Warning:** each regression mass-erases the sample. Repeat step 1 after
   > it.

   ```sh
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh advance 0x17
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh provision-da
   tests/target/provisioning_ctrl.sh discover
   ```

   ```text
   ADVANCING product state 0xED -> 0x17 (regress is the only way back)
   Option Bytes successfully programmed
     [check] PASS  wolfTrust chain boots in Provisioning
   now: 0x17
   [====...====] 100% OBKey Provisioned successfully
   discovery: PSA lifecycle...................:ST_LIFECYCLE_PROVISIONING
   discovery: ST provisioning integrity status:0xeaeaeaea
   discovery: permission if authorized........:(a/14) ==> Full Regression
   Debug Authentication: Discovery Success
   ```

   Only continue when discovery shows integrity `0xeaeaeaea` and Full
   Regression. Then close the sample and bring it back:

   ```sh
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh advance 0x72
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh regress
   ```

   ```text
   ADVANCING product state 0x17 -> 0x72 (regress is the only way back)
   Error: failed to reconnect after reset !
     [check] PASS  wolfTrust chain boots in Closed
   now: ST_LIFECYCLE_CLOSED
   DA certificate Full Regression -> Open (mass-erase):
   SDMAuthenticate: Authentication successful
   Debug Authentication Success
   state after regression: 0xED
   ```

   The "failed to reconnect" line is expected: Closed drops the debug link.
   This one rehearsal covers `lock 0x17`, `lock 0x72`, and `lock 0x5C`. For
   `lock 0xC6`, rehearse with `advance 0xC6` in place of `advance 0x72`.

3. **Preview each step.** Without `WT_LOCK_CONFIRM=1`, `lock` runs every check,
   prints the exact write, and writes nothing:

   ```text
   $ tests/target/provisioning_ctrl.sh lock 0x72
   Lock step: Provisioning (0x17) -> Closed (0x72)
     checked: order, rehearsal of Closed with images 6df4c1a1b2b7cf5c, guest WRP, DA provisioned
     will run: STM32_Programmer_CLI -c port=SWD mode=HotPlug -ob PRODUCT_STATE=0x72
   REFUSED: preview only, nothing was written. A production station re-runs this with WT_LOCK_CONFIRM=1.
   ```

4. **Lock the part**, on the production station only:

   ```sh
   export WT_PRODUCTION_LOCK=1
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh lock 0x17
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh provision-da
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh lock 0x72
   ```

   Each step prints the preview, then asks, and only a person at a terminal
   typing the acceptance exactly continues:

   ```text
   !!! Moving this STM32H563 to Closed (0x72)
   !!! Only a DA regression, which mass-erases the part, returns it to Open.
   !!! Are you sure? Type "I ACCEPT 0x72" to continue: I ACCEPT 0x72
   ```

   Expected output: the write, the benign reconnect error, the boot seen on
   the UART, and the read-back through Debug Authentication discovery:

   ```text
   Error: failed to reconnect after reset !
     [check] PASS  wolfTrust chain boots in Closed
     [check] PASS  product state is Closed (0x72)
   ```

   Stop here if field regression is wanted: a Closed part still regresses
   with your certificate chain.

5. **Lock for good** instead, only when field regression is not wanted. Run it
   from Provisioning, in place of `lock 0x72`:

   > **Warning:** this is IRREVERSIBLE. After it, debug never opens again, the
   > part cannot be regressed or reflashed, and wolfBoot and its key are fixed
   > for the life of the part.

   ```sh
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh lock 0x5C
   ```

   ```text
   Lock step: Provisioning (0x17) -> Locked (0x5C)
     checked: order, rehearsal of Closed with images 6df4c1a1b2b7cf5c, guest WRP
     will run: STM32_Programmer_CLI -c port=SWD mode=HotPlug -ob PRODUCT_STATE=0x5C

   !!! Locking this STM32H563: product state 0x17 -> 0x5C (Locked)
   !!! This is IRREVERSIBLE: debug closes for good, no regression or mass erase, and only a wolfBoot-signed update can change the firmware.
   !!! Are you sure? Type "I ACCEPT 0x5C" to continue:
   ```

   `lock` confirms Locked through Debug Authentication discovery. If discovery
   no longer answers, it fails with "the write may still have landed, so do
   not repeat it". In that case, confirm the state from the part's attestation
   token instead.

6. **Verify** from the firmware: the attestation token must report `0x3000`
   SECURED, and the production scenarios must pass.

A refused `lock` exits with status 2 and writes nothing. Examples from the
offline gate tests:

```text
REFUSED: the part is Open (0xED); lock 0x72 runs only from Provisioning (0x17).
REFUSED: no rehearsal of Closed (0x72) with these images: run 'advance 0x72' and 'regress' first.
REFUSED: guest flash is not write protected (WRPSGn1=0xFFFFFFFF): run 'set-wrp' in Open first.
REFUSED: Debug Authentication is not provisioned (no intact OBK offering Full Regression): run 'provision-da' and 'discover'.
REFUSED: confirmation did not match; nothing was changed.
```

`advance 0x5C` stays refused. `lock` uses the same `PRODUCT_STATE` option-byte
write as `advance`.

## Recovery rules

- If guest programming fails, confirm WRP is clear and the product state is
  Open.
- If wolfBoot rejects wolfTrust, confirm the Secure watermark covers the full
  boot partition and that guest records were patched before signing.
- If wolfTrust refuses a guest, compare the built guest address and size with
  the manifest, inspect the signed measurement record, and read back WRP.
- Debug Authentication discovery alone does not validate the regression
  credential or permitted action. Do not close the device until both have been
  tested through the controlled recovery procedure.
- Never use a generic option-byte recipe from another H5 layout; a wrong
  watermark can silently discard flash writes or expose a Secure region.

See [Testing](Testing.md) for scenario selection and [Security Model](Security-Model.md) for the policy
enforced after boot.
