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

## Provisioning and product state

This section is the STM32H5 part of [Provisioning](Provisioning.md). That page
covers the shared flow (rehearse, validate, then lock), the command table, the
gates, and what a production lock does to the firmware. Here are the STM32H5
product states, the mock lock on the NUCLEO-H563ZI, and the real lock, with
output. Every output block below is from a NUCLEO-H563ZI run on 2026-09-30,
unless it says otherwise.

| State | Value | Debug | Way back | PSA life cycle |
| --- | ---: | --- | --- | --- |
| Open | `0xED` | open | none needed | `0x1000` |
| Provisioning | `0x17` | open; the wolfTrust chain does not run | DA regression | `0x2000` |
| TrustZone Closed | `0xC6` | Secure side sealed | DA regression (mass erase) | `0x4000` |
| Closed | `0x72` | closed; the SWD link drops | DA full regression (mass erase) | `0x3000` |
| Locked | `0x5C` | closed forever | **none** | `0x3000` |

Each state has two commands:

- **`advance <state>`** is the mock lock: it writes the product state, and a
  Debug Authentication (DA) regression takes the part back to Open. `advance`
  refuses Locked.
- **`lock <state>`** is the real, gated production step.

The STM32H5 has three quirks, all seen on the board:

- **The closed states are written only from Provisioning.** Once a part is
  TrustZone Closed, the debug link cannot write the next state. So TrustZone
  Closed, Closed, and Locked are each reached directly from Provisioning,
  which is also how ST's own provisioning script works. `advance` and `lock`
  both refuse anything else.
- **A closed part drops the SWD link.** Its option bytes cannot be read, so the
  script reads its state through DA discovery (`ST_LIFECYCLE_CLOSED`). The CLI
  also reports `Unable to reconnect after setting the Option Bytes` after
  every closing write. That is expected; the script judges the write by the
  read-back, not by the CLI's exit status.
- **Provisioning does not run the wolfTrust chain**, even after a reset. The
  boot proof in a rehearsal therefore comes from the closed states.

### Stage 1: prepare the production chain

Build the production images with production signing keys and
`WT_GUEST_FLASH_WRP=1`, then set the perimeter, flash, protect the guests, and
verify. `restore` does all four:

```sh
WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh restore
tests/target/provisioning_ctrl.sh status
```

```text
Setting wolfTrust OEM-iRoT perimeter: TZEN=0xB4 BOOT_UBE=0xB4 SWAP_BANK=0x0 SECWM1_STRT=0x0 SECWM1_END=0x4F SECWM2_STRT=0x0 SECWM2_END=0x7F
Option Bytes successfully programmed
Download verified successfully
Write-protecting guest flash (bank1 sectors 0x50-0x7F): WRPSGn1=0x000FFFFF
     WRPSGn1      : 0xFFFFF  (0x8000000)
  [check] PASS  wolfTrust chain boots on silicon
PASS: wolfTrust restored and booting
     PRODUCT_STATE: 0xED (Open)
     BOOT_UBE     : 0xB4 (OEM-iRoT (user flash) selected)
     TZEN         : 0xB4 (Trust zone enabled)
```

### Stage 2: rehearse a state (mock lock)

Enter Provisioning, provision the DA certificate, confirm discovery offers
Full Regression, then close the part:

```sh
WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh advance 0x17
WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh provision-da
tests/target/provisioning_ctrl.sh discover
WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh advance 0x72
```

```text
  [check] PASS  the images on the part match the host build (c1f89defe6238bcc)
ADVANCING product state 0xED -> 0x17 (regress is the only way back)
Option Bytes successfully programmed
Provisioning does not run the wolfTrust chain; a closed-state rehearsal proves the boot
now: 0x17
Provisioning DA OBK (ST obk_provisioning.sh order): .../ROT_Provisioning/DA/Binary/DA_Config.obk
discovery: PSA lifecycle...................:ST_LIFECYCLE_PROVISIONING
discovery: ST provisioning integrity status:0xeaeaeaea
discovery: permission if authorized...........:(a/14) ==> Full Regression
discovery: permission if authorized...........:(b/12) ==> To TZ Regression
Debug Authentication: Discovery Success
ADVANCING product state 0x17 -> 0x72 (regress is the only way back)
Error: failed to reconnect after reset !
Error: Unable to reconnect after setting the Option Bytes
  [check] PASS  wolfTrust chain boots in Closed
now: ST_LIFECYCLE_CLOSED
```

> **Warning:** only close the part when discovery shows integrity
> `0xeaeaeaea` and Full Regression. Without them, Closed cannot be regressed
> and the part is closed for good.

`advance 0x17` reads the four images back over SWD while the part is still
Open: Provisioning closes Secure debug, so this is the last point where the
Secure images can be read. A closing `advance` requires that read-back for the
current images, and `flash` or `regress` discards it. `advance` also captures
the UART across the reset that the write causes. The
`[check]` line proves the images booted in Closed, with debug closed. That is
what records the Closed rehearsal.

### Stage 3: validate, then regress

In Closed, check the part behaves like the product:
- the boot check above passed;
- discovery reports `ST_LIFECYCLE_CLOSED`;
- the attestation token from the guests reports the life cycle you expect.

`status` cannot read a closed part, and `lock` refuses one:

```text
$ tests/target/provisioning_ctrl.sh lock 0x5C
REFUSED: cannot read the product state over SWD.
```

Then regress, which mass-erases the part back to Open and completes the
rehearsal, and restore the chain:

```sh
WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh regress
WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh restore
```

```text
DA certificate Full Regression -> Open (mass-erase):
SDMAuthenticate               :  1634 : client     : Authentication successful
Debug Authentication Success
state after regression: 0xED
  [check] PASS  wolfTrust chain boots on silicon
PASS: wolfTrust restored and booting
```

The rehearsal records hold the SHA-256 of the four images with their
addresses and sizes. Before any closing write, `advance` reads those images
back off the part and refuses if they differ from the host build. The
regression record also holds a fingerprint of every DA input the regression
used: key, certificate chain, OBK, and password. The first 16 hex digits of
each are shown:

```text
h5-booted-0x72: c1f89defe6238bcc...
h5-regressed-0x72: c1f89defe6238bcc... 0b5e16e7754c68c1...
```

> **Warning:** rehearse with the production DA chain (`WT_DA_OBK`,
> `WT_DA_KEY`, `WT_DA_CERT`), not ST's sample. A production `lock` refuses
> ST's sample, and accepts only a rehearsal whose regression used the same
> certificate chain it is about to rely on. The run above used ST's sample, as
> a development board does.

One Closed rehearsal covers `lock 0x17`, `lock 0x72`, and `lock 0x5C`. For
`lock 0xC6`, rehearse with `advance 0xC6` in place of `advance 0x72`.

Refused commands change nothing and exit with status 2:

```text
$ tests/target/provisioning_ctrl.sh lock 0x72
REFUSED: the part is Open (0xED); lock 0x72 runs only from Provisioning (0x17).
$ WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh advance 0x72
REFUSED: advance to Closed runs only from Provisioning (0x17); state=0xED.
```

### Stage 4: production lock

> **Production only.** `lock` moves a production part up the product-state
> ladder for good.
>
> - Locked (`0x5C`) is **IRREVERSIBLE**. Debug closes forever, with no DA
>   regression, no mass erase, and no reflash. wolfBoot and its signing key
>   stay fixed for the life of the part.
> - Provisioning, TrustZone Closed, and Closed only come back through a DA
>   chain you have proven can regress the part, and that regression
>   mass-erases it. Without such a chain they are permanent too.
>
> Never lock a development board.

**What each state does to the part.**
- **Provisioning** is where the DA certificate is provisioned.
- **TrustZone Closed** seals the Secure side.
- **Closed** closes debug and drops the SWD link. Your certificate chain can
  still regress it.
- **Locked** closes debug for good.

From TrustZone Closed on, wolfTrust enforces guest rollback floors, never
reformats the vault, and attests the new life cycle. See
[what a production lock does to the firmware](Provisioning.md#what-a-production-lock-does-to-the-firmware).

**How it binds the software.** With debug closed, nothing outside the firmware
can change the TrustZone perimeter, the guest WRP, or the images. After that,
the software only changes through wolfBoot's signed update path. It is held in
place by:
- the wolfBoot signing key;
- the guest measurement records;
- the DA certificate chain, until the part is Locked.

See [how a production lock binds the software](Provisioning.md#how-a-production-lock-binds-the-software).

| Command | Runs only from | Sets | Also needs |
| --- | --- | --- | --- |
| `lock 0x17` | Open `0xED` | Provisioning | a DA regression rehearsed from Provisioning or a closed state |
| `lock 0xC6` | Provisioning `0x17` | TrustZone Closed | a rehearsal of `0xC6` with the production DA chain; guest WRP; DA provisioned |
| `lock 0x72` | Provisioning `0x17` | Closed | a rehearsal of `0x72` with the production DA chain; guest WRP; DA provisioned |
| `lock 0x5C` | Provisioning `0x17` | Locked (final) | a rehearsal of `0x72`; guest WRP |

On top of [the shared gates](Provisioning.md#gates-on-a-real-lock), `lock`
checks more on this port:
- `WRPSGn1=0x000FFFFF`, the guest WRP.
- For TrustZone Closed and Closed:
  - a live DA discovery showing an intact OBK that offers Full Regression;
  - a production DA credential: `WT_DA_OBK`, `WT_DA_KEY`, and `WT_DA_CERT`
    set explicitly, none matching ST's sample. `provision-da` refuses the
    sample too when `WT_PRODUCTION_LOCK=1`.

After the write, it confirms the new state through DA discovery. For
TrustZone Closed, Closed, and Locked it also requires the wolfTrust boot on
the UART, and fails (without repeating the write) if the chain did not boot.

1. **Flash the production part** as in stage 1. Keep the images you
   rehearsed with: a rebuild invalidates the rehearsal.

2. **Preview each step.** Without `WT_LOCK_CONFIRM=1`, `lock` runs every check,
   prints the exact write, and writes nothing:

   ```text
   $ tests/target/provisioning_ctrl.sh lock 0x17
   Lock step: Open (0xED) -> Provisioning (0x17)
     checked: order, rehearsal of Provisioning with images 78ec12f957707ed0
     will run: STM32_Programmer_CLI -c port=SWD mode=HotPlug -ob PRODUCT_STATE=0x17
   REFUSED: preview only, nothing was written. A production station re-runs this with WT_LOCK_CONFIRM=1.
   ```

   From Provisioning, with DA provisioned. This board carries ST's sample
   credential, so the preview says a production lock would refuse it:

   ```text
   $ tests/target/provisioning_ctrl.sh lock 0x72
   Lock step: Provisioning (0x17) -> Closed (0x72)
     checked: order, rehearsal of Closed with images 78ec12f957707ed0, guest WRP, DA credential is ST's sample or unset (a production lock refuses it), DA provisioned
     will run: STM32_Programmer_CLI -c port=SWD mode=HotPlug -ob PRODUCT_STATE=0x72
   REFUSED: preview only, nothing was written. A production station re-runs this with WT_LOCK_CONFIRM=1.
   $ tests/target/provisioning_ctrl.sh lock 0x5C
   Lock step: Provisioning (0x17) -> Locked (0x5C)
     checked: order, rehearsal of Closed with images 78ec12f957707ed0, guest WRP
     will run: STM32_Programmer_CLI -c port=SWD mode=HotPlug -ob PRODUCT_STATE=0x5C
   REFUSED: preview only, nothing was written. A production station re-runs this with WT_LOCK_CONFIRM=1.
   ```

3. **Enter Provisioning and provision the production DA chain** (`WT_DA_*`,
   not ST's sample):

   ```sh
   export WT_PRODUCTION_LOCK=1
   export WT_DA_OBK=production/DA_Config.obk WT_DA_KEY=production/leaf.pem \
          WT_DA_CERT=production/leaf_chain.b64
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh lock 0x17
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh provision-da
   tests/target/provisioning_ctrl.sh discover
   ```

   Each `lock` prints the preview, then asks. Only a person at a terminal
   typing the acceptance exactly continues:

   ```text
   !!! Moving this STM32H563 to Provisioning (0x17)
   !!! Only a DA regression, which mass-erases the part, returns it to Open.
   !!! Are you sure? Type "I ACCEPT 0x17" to continue:
   ```

4. **Close the part.** A Closed part still regresses with your certificate
   chain, so stop here if field regression is wanted:

   > **Warning:** only continue when discovery showed integrity `0xeaeaeaea`
   > and Full Regression in step 3.

   ```sh
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh lock 0x72
   ```

   ```text
   !!! Moving this STM32H563 to Closed (0x72)
   !!! Only a DA regression, which mass-erases the part, returns it to Open.
   !!! Are you sure? Type "I ACCEPT 0x72" to continue: I ACCEPT 0x72
   ```

   Expected output, which matches the rehearsal above. It shows the
   reconnect error, the boot seen on the UART, and the read-back through DA
   discovery:

   ```text
   Error: Unable to reconnect after setting the Option Bytes
     [check] PASS  wolfTrust chain boots in Closed
     [check] PASS  product state is Closed (0x72)
   ```

5. **Or lock for good**, only when field regression is not wanted. Run it from
   Provisioning, in place of step 4:

   > **Warning:** this is IRREVERSIBLE. After it, debug never opens again, the
   > part cannot be regressed or reflashed, and wolfBoot and its key are fixed
   > for the life of the part.

   ```sh
   WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh lock 0x5C
   ```

   ```text
   !!! Locking this STM32H563: product state 0x17 -> 0x5C (Locked)
   !!! This is IRREVERSIBLE: debug closes for good, no regression or mass erase, and only a wolfBoot-signed update can change the firmware.
   !!! Are you sure? Type "I ACCEPT 0x5C" to continue:
   ```

   `lock` confirms Locked through DA discovery. If discovery no longer
   answers, `lock` fails with "the write may still have landed, so do not
   repeat it". Confirm the state from the attestation token instead.

6. **Verify** from the firmware: the attestation token must report `0x3000`
   SECURED, and the production scenarios must pass.

The production gates, as refused on the board without writing anything:

```text
$ WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 tests/target/provisioning_ctrl.sh provision-da
REFUSED: a production part needs its own DA credential: set WT_DA_OBK, WT_DA_KEY, and WT_DA_CERT, not ST's sample.
$ WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 tests/target/provisioning_ctrl.sh lock 0x72
REFUSED: a production part needs its own DA credential: set WT_DA_OBK, WT_DA_KEY, and WT_DA_CERT, not ST's sample.
$ WT_LOCK_CONFIRM=1 tests/target/provisioning_ctrl.sh lock 0x72
REFUSED: Moving this STM32H563 to Closed (0x72) is a production lock step. Only a production station sets WT_PRODUCTION_LOCK=1.
$ echo "I ACCEPT 0x5C" | WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 tests/target/provisioning_ctrl.sh lock 0x5C
REFUSED: a production lock needs an interactive terminal, not a pipe or script.
```

Refusals from the offline gate tests:

```text
REFUSED: guest flash is not write protected (WRPSGn1=0xFFFFFFFF): run 'set-wrp' in Open first.
REFUSED: Debug Authentication is not provisioned (no intact OBK offering Full Regression): run 'provision-da' and 'discover'.
REFUSED: no rehearsal of Closed (0x72) with these images and DA certificate: run 'advance 0x72' and 'regress' first.
REFUSED: confirmation did not match; nothing was changed.
```

`advance 0x5C` stays refused. The Locked write has never been run on a
wolfTrust board.

### Verified on the NUCLEO-H563ZI

Run on 2026-09-30, from Open, with the `positive` production images:

| Step | Result |
| --- | --- |
| `lock 0x72`, `advance 0x72` from Open | refused: only from Provisioning |
| `advance 0x17` | Provisioning; the chain does not run there |
| `provision-da`, `discover` | integrity `0xeaeaeaea`, Full Regression offered |
| `advance 0x72` | Closed; wolfTrust booted (2444 UART bytes across the reset); DA discovery `ST_LIFECYCLE_CLOSED` |
| `lock 0x5C` while Closed | refused: the link is down |
| `regress` from Closed, then from Provisioning | certificate authentication succeeded; back to Open |
| `restore` | perimeter, images, and guest WRP back; chain boots |
| `lock 0x17` preview from Open | preview printed; nothing written |
| `lock 0x72`, `lock 0x5C` previews from Provisioning | preview printed; nothing written |
| `lock 0x72` without `WT_PRODUCTION_LOCK=1` | refused |
| `lock 0x5C` with a piped acceptance | refused: needs a terminal |
| rerun after the security review: `provision-da` and `lock 0x72` with `WT_PRODUCTION_LOCK=1` and ST's sample | refused: production DA credential required |
| rerun: Closed rehearsal | records the image SHA-256 and the DA certificate SHA-256 |

The board ended Open with the chain booting.

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
