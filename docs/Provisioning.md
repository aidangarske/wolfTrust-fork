# Provisioning

Provisioning takes a board from development to production. You flash the
production images, set the protections the part will ship with, and move the
device life cycle forward until debug is closed and the part can no longer be
reflashed from outside. The last step, the production lock, is permanent.

wolfTrust drives both reference ports through one script,
`tests/target/provisioning_ctrl.sh`. `TARGET` selects the backend:
`stm32h563` (the default) or `mimxrt700`. This page covers what the two ports
share: the flow, the commands, the gates, and what a lock does to the part.
Each port guide has the board-specific states, quirks, and a full walkthrough
with real output:

- [STM32H5 Guide: Provisioning and product state](STM32H5-Guide.md#provisioning-and-product-state)
- [MIMXRT700 Guide: Provisioning and life cycle](MIMXRT700-Guide.md#provisioning-and-life-cycle)

> **Production locks are permanent.** Everything on this page up to `lock` is
> reversible and safe on a development board. `lock` is not: run it only on a
> production station, on a part you intend to ship. Never run it on a
> development board.

## The flow: rehearse, validate, then lock

A production lock is never the first time a state is tried. Every state is
first entered as a mock, checked, and backed out of. Only then is the same
step made real:

```text
 1. Prepare         2. Rehearse (mock)      3. Validate            4. Lock (real)
 ------------       ------------------      -----------            --------------
 restore / flash    advance <state>         status                 lock <state>
 production    -->  (reversible)       -->  attestation       -->    preview, no write
 images             regress                 guests, fence            then with gates +
                    (back to start)                                  typed I ACCEPT
                                                                     (permanent)
```

1. **Prepare.** Flash the production images with production signing keys and
   the guest flash protection enabled (`WT_GUEST_FLASH_WRP=1`).
2. **Rehearse.** `advance <state>` puts the part into the target state in a
   way that can be undone. On the MIMXRT700 that means the OTP shadow
   registers, which any reset reloads. On the STM32H5 it means the product
   state, which a Debug Authentication regression undoes. `advance` records a
   rehearsal only if wolfTrust booted in that state, with the life cycle it
   should see. The one exception is STM32H5 Provisioning, where the chain does
   not run; closed states prove the boot there. `regress` takes the part back
   and completes the record.
3. **Validate.** While the part is in the rehearsed state, check that it
   behaves like the product you intend to ship:
   - `status` shows the life cycle and the guest protection;
   - the guests launch verified;
   - the attestation token reports the expected life cycle.

   What the part does in the rehearsal is what it will do once the step is
   made permanent.
4. **Lock.** `lock <state>` first runs as a preview. It checks everything,
   prints the exact write, and changes nothing. On a production station, the
   same command with the production gates set, followed by a typed acceptance,
   makes the step permanent.

Repeat stages 2 to 4 for each further state the product needs.

## Commands

Every command runs through `tests/target/provisioning_ctrl.sh`. Commands that
write to the board refuse without `WT_LOCK_CONFIRM=1`.

| Command | What it does | Kind | STM32H5 | MIMXRT700 |
| --- | --- | --- | --- | --- |
| `status` | life cycle, debug, and protection state | read-only | yes | yes |
| `discover` | preflight: STM32H5 Debug Authentication discovery; MIMXRT700 fused-state and shadow-override check | read-only | yes | yes |
| `verify` | reset and check the chain boots | read-only | yes | use `restore` |
| `verify-wrp` | the running guest fence is armed | read-only | no | yes |
| `set-perimeter`, `flash`, `set-wrp`, `clear-wrp` | set option bytes, flash images, guest WRP | reversible write | yes | no persistent form |
| `restore` | put the production chain back and verify it | reversible write | yes | yes |
| `provision-da` | provision the Debug Authentication certificate | reversible write (Provisioning only) | yes | refused, see `lock` |
| `advance <state>` | enter a state as a mock and record a rehearsal | reversible write | yes | yes |
| `regress` | return to the start state and complete the rehearsal | reversible write | yes, mass erase | yes, hardware reset |
| `lock <state>` | preview, then make one step permanent | **permanent write** | yes | yes |

## Environment

| Variable | Meaning |
| --- | --- |
| `TARGET` | `stm32h563` (default) or `mimxrt700` |
| `WT_LOCK_CONFIRM=1` | allow a board write; without it `lock` only previews |
| `WT_PRODUCTION_LOCK=1` | marks a production station; `lock` never writes without it |
| `WT_PROVISION_STATE`, `RT700_PROVISION_STATE` | where rehearsal records are kept (default `~/.cache/wolftrust`) |
| `RT700_ISP` | MIMXRT700 blhost ISP connection, for example `-u 0x1fc9,0x014f` |
| `RT700_GUEST_MASK` | guests a MIMXRT700 rehearsal must launch verified (default `0x3`) |
| `RT700_REHEARSAL_MAX_AGE` | seconds a MIMXRT700 rehearsal stays valid (default `3600`) |
| `STM32_CLI`, `H5_SERIAL` | STM32CubeProgrammer CLI path and the board UART |
| `WT_DA_*` | STM32H5 Debug Authentication key, certificate, and OBK; a production lock requires all three, and not ST's sample |

## Gates on a real lock

`lock <state>` runs these checks in order and stops at the first one that
fails, with exit status 2 and nothing written:

1. **The state is known** and is the next step the port allows.
2. **The part is in the state just before it.** `lock` reads the real state:
   the burned fuses over ISP on the MIMXRT700, the product state over SWD on
   the STM32H5. The silicon would accept some skips, for example MIMXRT700
   Develop straight to In Field Locked. `lock` refuses them.
3. **A rehearsal of that state exists for the current images.** It holds the
   SHA-256 of the images that are flashed, so a rebuild invalidates it. On the
   MIMXRT700 the rehearsal also read those images back off the part, required
   every guest to launch verified, and must have run through the same single
   debug probe, at most an hour ago. On the
   STM32H5 `advance` first reads the four images back off the part before a
   closing write, and the regression record holds a fingerprint of every DA
   input it used: key, certificate chain, OBK, and password.
4. **The part is provisioned first**:
   - on the MIMXRT700, the guest fence and all 12 root key hash words, and a
     first stage the BootROM authenticates (until the port builds one, `lock`
     refuses In Field and later);
   - on the STM32H5, the guest WRP and a working Debug Authentication chain
     that is your own, never ST's sample.

   The life cycle is always written last.
5. **Preview.** `lock` prints the exact write. Without `WT_LOCK_CONFIRM=1` it
   stops here.
6. **Production station.** `WT_PRODUCTION_LOCK=1` must be set.
7. **A person at a terminal.** A pipe or script is refused.
8. **Typed acceptance.** Only the exact phrase `I ACCEPT <state>` continues;
   anything else changes nothing.
9. **Read back.** After the write, `lock` reads the state back and fails
   unless it moved. On the STM32H5 it also fails if wolfTrust did not boot in
   a closed state.

These follow the pattern of the vendors' own provisioning tools:
- NXP's MCUXpresso Secure Provisioning tool offers a "Test life cycle" mode
  and shows a confirmation dialog listing each irreversible operation. SPSDK's
  `nxpfuses write` requires `--yes`.
- ST's `ROT_Provisioning` scripts provision keys and Debug Authentication
  first and set the product state last, pausing with "Press any key to
  continue".
- TF-M advances its PSA life cycle in firmware, only once provisioning is
  complete.

`lock` adds the one-step-at-a-time check, the rehearsal requirement, and a
typed acceptance instead of a single keypress.

## What a production lock does to the firmware

The boot chain passes the device life cycle to wolfTrust as a PSA life cycle
value. Once it is past `0x2000` PSA_ROT_PROVISIONING, wolfTrust stops treating
the part as a development board:

- **Rollback floors are enforced.** A guest image older than the floor
  recorded for it is refused at launch. In `0x1000` and `0x2000` the floors
  are not enforced, so development images can move backwards.
- **The vault is never reformatted.** In development, a store written by an
  older firmware generation, or a corrupt one, is reformatted so the board
  keeps booting. On a closed part the sealed device key and write-once storage
  are never wiped: a damaged store stops boot provisioning instead.
- **Attestation reports the new life cycle**, so a relying party can tell a
  production part from a development one: `0x3000` SECURED once debug is
  closed, `0x4000` or `0x5000` while some debug remains open.
- **Guest flash protection stays in force** at every launch when the image
  was built with `WT_GUEST_FLASH_WRP=1`. That is the STM32H5 WRP, and the
  MIMXRT700 XSPI fence.

## How a production lock binds the software

With debug closed, nothing outside the firmware can reflash the part. The
software can then only change through wolfBoot's signed update path
(`SERVICE_FWU`, which stages a candidate into the wolfBoot update partition).
These keys hold the software in place for the life of the part:

| Key | What it decides |
| --- | --- |
| wolfBoot signing key | which wolfTrust images wolfBoot boots and accepts as updates |
| guest measurement records (signed into the wolfTrust image) | which guest images wolfTrust launches |
| MIMXRT700 root key table hash (fused) | which first-stage images the BootROM boots |
| STM32H5 Debug Authentication certificate chain | whether a part short of Locked can be regressed and reopened |

Treat these as production secrets and back them up before the first lock. If a
signing key is lost, the parts locked with it can never be updated. If a key
leaks, every part locked with it trusts whoever holds it.

## PSA life cycle by port

| PSA life cycle | STM32H5 product state | MIMXRT700 life cycle |
| --- | --- | --- |
| `0x1000` ASSEMBLY_AND_TEST | Open `0xED` | Develop `0x03` |
| `0x2000` PSA_ROT_PROVISIONING | Provisioning `0x17` | Develop2 `0x07` |
| `0x4000` NON_PSA_ROT_DEBUG | TrustZone Closed `0xC6`, or Closed with only Non-secure debug open | In Field with only Non-secure debug open |
| `0x5000` RECOVERABLE_PSA_ROT_DEBUG | Closed with Secure debug open | In Field with Secure debug open |
| `0x3000` SECURED | Closed `0x72`, Locked `0x5C` | In Field `0x0F`, In Field Locked `0xCF` |
| `0x6000` DECOMMISSIONED | none | In Field Return `0x1F` |
| `0x0000` UNKNOWN | any other value | copies disagree, or an NXP-internal state |

The STM32H5 refines Closed and Locked by the debug state, and the MIMXRT700
refines In Field by the fused debug state. A rehearsal on a board whose debug
is still open therefore attests `0x5000`, not `0x3000`.

## Where the records live

`advance` and `regress` write rehearsal records under `~/.cache/wolftrust`
(override with `WT_PROVISION_STATE` or `RT700_PROVISION_STATE`). Each record
holds the SHA-256 of the images it proved:

- On the STM32H5, a record is kept until the images or any DA input
  change, because each rehearsal of a closed state mass-erases the sample.
- On the MIMXRT700, each burn uses its record up, and a record expires after
  an hour, so every part is rehearsed at the station right before its own
  burn. No silicon UID is documented to bind a record to one part, so this
  freshness is the binding.

Keep the records, the burn scripts `lock` writes next to them, and the
terminal output with the production records for each part.
