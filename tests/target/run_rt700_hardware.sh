#!/usr/bin/env bash
# MIMXRT700-EVK hardware runner (sibling of run_h5_hardware.sh and
# run_m33mu_scenario.sh; one CLI shape, assertions via lib/expect.sh once it
# lands on main). Runs on the host that owns the probe (pi5).
#
#   run_rt700_hardware.sh <scenario>
#
# Scenarios:
#   romsmoke  the BootROM boots our own XIP image from XSPI0: build
#             tests/firmware/mimxrt700-smoke, wrap it (EVK FCB + plain MBI at
#             flash+0x4000), flash with pyOCD, hard-reset through the pi4 line,
#             then assert the SRAM marker and a moving counter over SWD.
#   positive  the full chain: wolfBoot (TrustZone loader) authenticates the
#             wolfTrust Secure image, which launches both Non-secure guests.
#             Builds wolfTrust + the guests, pins the guest measurements,
#             wolfBoot-signs the Secure image, flashes the chain at its XSPI0
#             offsets, resets from a fresh vault, verifies every image by
#             readback, and asserts both guest mailboxes over SWD.
#   ahbscneg  positive plus the guest isolation negative: guest0 stores into
#             guest1's RAM, which the per-dispatch SAU window keeps Secure; the
#             store must be blocked, guest1's RAM must not hold the sentinel,
#             and guest1 must keep running.
#   wrpfence  a WT_GUEST_FLASH_WRP=1 wolfTrust behind a wolfBoot that arms the
#             XSPI guest fence: the fence reads back sealed over SWD and both
#             guests launch.
#   wrpoff    the same wolfTrust behind an unfenced wolfBoot: wolfTrust must
#             refuse both guests (launch refused mask 0x3, no mailbox written).
#   wrpneg    wrpfence with wolfBoot's flash-protect selftest: the silicon must
#             refuse an erase inside the guest fence and leave the block as is.
#
# The wolfBoot first stage is RT700_WOLFBOOT_REF plus the carried patches
# (lib/rt700_wolfboot.sh), cached under ~/.cache/wolftrust, unless
# RT700_WOLFBOOT_DIR names a prebuilt tree.
set -euo pipefail

scenario="${1:-}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="${RT700_WORK:-$repo/test-results/rt700-hardware/$(date -u +%Y%m%dT%H%M%SZ)-${WT_ENGINE:-native}-$scenario-$$}"
target="${RT700_TARGET:-mimxrt798sgfob}"
fcb="${RT700_FCB:-$HOME/rt700-boot/fcb.bin}"
wolfboot_dir="${RT700_WOLFBOOT_DIR:-}"
spsdk_venv="${RT700_SPSDK_VENV:-$HOME/spsdk-venv}"
xspi0_base=0x28000000
mbi_offset=0x4000
secure_flash_addr=0x28040000
guest0_flash_addr=0x28080000
guest1_flash_addr=0x28100000
hsm_nvm_addr=0x281E0000
hsm_nvm_size=0x2000
guest_build="$repo/tests/firmware/mimxrt700-baremetal/build"

# shellcheck source=lib/rt700_fence.sh disable=SC1091
. "$here/lib/rt700_fence.sh"
# shellcheck source=lib/rt700_wolfboot.sh disable=SC1091
. "$here/lib/rt700_wolfboot.sh"
# shellcheck source=lib/rt700_guests.sh disable=SC1091
. "$here/lib/rt700_guests.sh"
# shellcheck source=lib/rt700_swd.sh disable=SC1091
. "$here/lib/rt700_swd.sh"
# shellcheck source=lib/scenario.sh disable=SC1091
. "$here/lib/scenario.sh"
case "$scenario" in
    wrpfence|wrpneg) guest_fence=1; export WT_GUEST_FLASH_WRP=1 ;;
    wrpoff)   guest_fence=0; export WT_GUEST_FLASH_WRP=1 ;;
    *)        guest_fence="${WT_XSPI_GUEST_FENCE:-${WT_GUEST_FLASH_WRP:-0}}" ;;
esac

log() { printf '%s\n' "$*"; }
stage() { printf '  ... %s\n' "$*"; }
fail() { log "FAIL: $*" >&2; exit 1; }
check() {
    if [ "$1" -eq 0 ]; then log "  [check] PASS  $2"; else log "  [check] FAIL  $2"; fail "$2"; fi
}

uart_pid=""
stop_uart() {
    if [ -n "$uart_pid" ]; then
        kill "$uart_pid" 2>/dev/null || true
        wait "$uart_pid" 2>/dev/null || true
        uart_pid=""
    fi
}
trap stop_uart EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_uart() {
    local device="${RT700_UART:-/dev/ttyACM0}"
    stty -F "$device" 115200 raw -echo || fail "could not configure UART $device"
    timeout "${RT700_UART_TIMEOUT:-180}" cat "$device" > "$work/uart.log" &
    uart_pid=$!
    log "  [uart] capturing $device at 115200 to $work/uart.log"
}

record_build() {
    local dependency actual expected zephyr_revision freertos_revision
    {
        printf 'date_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'commit=%s\n' "$(git -C "$repo" rev-parse HEAD)"
        printf 'scenario=%s\nengine=%s\n' "$scenario" "${WT_ENGINE:-native}"
        printf 'guest_fixture=%s\n' "${WT_RT700_GUEST_FIXTURE:-baremetal}"
        if [ "${WT_RT700_GUEST_FIXTURE:-baremetal}" = os ]; then
            zephyr_revision="$(git -C "${ZEPHYR_BASE:-$repo/tests/firmware/zephyr-stm32h5/.workspace/zephyrproject/zephyr}" rev-parse HEAD)" || \
                fail "could not identify the Zephyr source"
            freertos_revision="$(git -C "${FREERTOS_DIR:-$repo/tests/firmware/rt700-os/.workspace/freertos}/FreeRTOS/Source" rev-parse HEAD)" || \
                fail "could not identify the FreeRTOS kernel source"
            printf 'zephyr_commit=%s\nfreertos_kernel_commit=%s\n' \
                "$zephyr_revision" "$freertos_revision"
        fi
        for dependency in wolfSSL wolfHSM wolfCOSE wolfPSA; do
            actual="$(git -C "$repo/lib/$dependency" rev-parse HEAD)" || \
                fail "could not identify dependency $dependency"
            expected="$(git -C "$repo" rev-parse "HEAD:lib/$dependency")" || \
                fail "could not identify the recorded $dependency pin"
            [ "$actual" = "$expected" ] || fail "$dependency source does not match the recorded pin"
            printf '%s_commit=%s\n' "$dependency" "$actual"
        done
        printf 'attestation=%s\nsecure_header=%s\n' \
            "${WT_ATTEST_COSE:-0}" "${WT_SECURE_IMAGE_HEADER_SIZE:-0}"
        printf 'guest_flags=%s\n' "$1"
        printf 'secure_flags=%s\n' "${secure_flags:-}"
        if [ "$scenario" = writeonce ]; then
            printf 'reset=individual probe hardware resets, retained vault\n'
        else
            printf 'reset=hardware reset plus GPIO20, retained SRAM\n'
        fi
        printf 'vault_policy=%s\n' "${2:-unchanged}"
        git -C "$repo" status --short --untracked-files=no
        git -C "$repo" submodule status
        arm-none-eabi-gcc --version | sed -n '1p'
        pyocd --version
    } > "$work/build-record.txt"
}

# Serialize direct invocations as well as suites. The suite holds this lock
# across all cases and passes its already-held descriptor to the runner.
if [ "${WT_RT700_LOCK_HELD:-0}" != 1 ]; then
    exec 9>"${RT700_LOCK_FILE:-/tmp/wolftrust-rt700-hardware.lock}"
    flock -n 9 || fail "RT700 hardware is already in use"
fi

# SPSDK (nxpimage) and pyOCD live in a virtualenv; put it on PATH when the bare
# tools are not already resolvable.
ensure_spsdk() {
    if ! command -v pyocd >/dev/null 2>&1 || ! command -v nxpimage >/dev/null 2>&1; then
        [ -x "$spsdk_venv/bin/pyocd" ] || fail "pyocd/nxpimage not found (set RT700_SPSDK_VENV)"
        PATH="$spsdk_venv/bin:$PATH"
        export PATH
    fi
}

# Observation uses the generic Cortex-M attach: the device-pack target resets
# the chip on connect, so a read would land in a fresh boot, not the one under
# test.
dap() {
    timeout 60 pyocd cmd -t cortex_m "$@" 2>&1 |
        tee -a "$work/swd.log" | grep -viE "rom table|APB-AP|coresight|cidr"
}

wrap_xip() {
    local app="$1" out="$2" exec_addr="$3"
    [ -s "$fcb" ] || fail "FCB binary missing at $fcb (RT700_FCB)"
    cat > "$work/mbi.yaml" <<YAML
family: mimxrt798s
revision: latest
outputImageExecutionTarget: xip
outputImageAuthenticationType: plain
masterBootOutputFile: $work/mbi.bin
inputImageFile: $app
outputImageExecutionAddress: $exec_addr
imageVersion: 0
YAML
    nxpimage mbi export -c "$work/mbi.yaml" >/dev/null
    cat > "$work/bootimg.yaml" <<YAML
family: mimxrt798s
revision: latest
memory_type: xspi_nor
output: $out
output_format: bin
init_offset: 0
fcb: $fcb
mbi: $work/mbi.bin
YAML
    nxpimage bootable-image export -c "$work/bootimg.yaml" >/dev/null
}

# Read an image back through XIP and compare it. Conformance resets make
# post-boot reads unsafe; flush the parked read path before its first boot.
verify_at() {
    local addr="$1" image="$2" size readback
    size="$(wc -c < "$image" | tr -d ' ')"
    readback="$work/readback-$(printf '%08x' "$((addr))").bin"
    if [ "${3:-running}" = parked ]; then
        timeout 120 python3 "$here/lib/rt700_readback.py" "$addr" "$image" \
            "$readback" > "$readback.log" 2>&1 || \
            fail "parked readback of $addr failed (see $readback.log)"
    else
        timeout 120 pyocd cmd -t cortex_m \
            -c "savemem $addr $size $readback" > "$readback.log" 2>&1 || \
            fail "readback of $addr failed (see $readback.log)"
    fi
    [ -f "$readback" ] && [ "$(wc -c < "$readback" | tr -d ' ')" = "$size" ] || \
        fail "readback of $addr missing or incomplete (see $readback.log)"
    cmp -s "$readback" "$image" || \
        fail "flash verify mismatch at $addr ($(basename "$image"))"
    log "  [flash] verified $(basename "$image") @ $addr"
}

# Park the core before wolfTrust owns it: pyOCD's flash algorithm runs in RAM
# and faults under wolfTrust's Secure MPU whitelist. A running wolfTrust sets
# AIRCR.SYSRESETREQS, so only the probe's hardware reset is honoured; the halt
# can still land after boot code starts, so the MPU is disabled explicitly.
park_core() {
    timeout 60 pyocd cmd -t "$target" -O resume_on_disconnect=false \
        -O reset_type=hw -c "reset halt" -c "write32 0xE000ED94 0" \
        >/dev/null 2>&1 || fail "could not park the core"
}

# A failed or partial flash must stop the run: a stale image either boots old
# code or fails its pinned measurement and looks like a port bug.
flash_at() {
    local addr="$1" image="$2" out
    [ -s "$image" ] || fail "flash image missing: $image"
    park_core
    if ! out="$(timeout 300 pyocd flash -t "$target" -O resume_on_disconnect=false \
            --no-reset -a "$addr" -e sector "$image" 2>&1)"; then
        printf '%s\n' "$out" | grep -vE "AP#3 IDR" | tail -6
        fail "flash of $(basename "$image") at $addr failed"
    fi
}

# Erase a sector range with the core parked; the board keeps NVM state across
# runs where the emulator starts fresh (mirrors the H5 runner's vault erase).
erase_range() {
    local range="$1"
    park_core
    timeout 120 pyocd erase -t "$target" -O resume_on_disconnect=false \
        -s "$range" >/dev/null 2>&1 || fail "erase of $range failed"
}

# SRAM survives a warm reset, so the last run's mailboxes, sentinel, and launch
# masks would otherwise read back as this run's result.
clear_mailboxes() {
    local verified refused restarts quarantines fault_addr
    local -a clear_counters=()
    verified="$(elf_sym g_wt_launch_verified_mask)"
    refused="$(elf_sym g_wt_launch_refused_mask)"
    # Resolve only counters this case asserts. LTO legitimately removes the
    # guest restart counter in the conformance image, which has no such path.
    if [ "$scenario" = ahbscneg ] || [ "$scenario" = restart ]; then
        restarts="$(elf_sym g_wt_restart_events)"
        quarantines="$(elf_sym g_wt_quarantine_events)"
        fault_addr="$(elf_sym g_last_fault_address)"
        clear_counters=(-c "write32 $restarts 0" -c "write32 $quarantines 0"
                        -c "write32 $fault_addr 0")
    fi
    [ -n "$verified" ] && [ -n "$refused" ] || fail "launch masks not found in wolftrust.elf"
    park_core
    timeout 60 pyocd cmd -t "$target" -O resume_on_disconnect=false \
        -c "write32 0x20100000 0 0 0 0 0 0 0 0 0 0" \
        -c "write32 0x20140000 0 0 0 0 0 0 0 0 0 0" \
        -c "write32 0x20170000 0" \
        -c "write32 0x20180080 0 0 0 0 0 0 0 0 0 0 0 0" \
        -c "write32 $verified 0" -c "write32 $refused 0" \
        "${clear_counters[@]}" >/dev/null 2>&1 || \
        fail "could not clear the guest mailboxes"
}

# Parking leaves the reset vector catch armed; a resuming reset clears it so
# the warm reset below boots the chain instead of halting in the BootROM.
reset_board() {
    local reset_target="$target"
    # The device-pack connection itself resets the chip; a generic attach
    # lets writeonce observe one boot per explicit hardware reset.
    [ "$scenario" = writeonce ] && reset_target=cortex_m
    timeout 60 pyocd reset -t "$reset_target" -m hw >/dev/null 2>&1 || \
        fail "could not release the core"
    # Each observed writeonce phase needs one boot, without an intervening
    # second reset changing SEEDED to VERIFIED before it can be observed.
    if [ "$scenario" != writeonce ]; then
        "$here/lib/rt700_reset.sh" reset
    fi
}


# The first stage to flash: a prebuilt RT700_WOLFBOOT_DIR as-is (a fence run
# must still match the pin), otherwise the pinned build for this fence setting.
ensure_wolfboot() {
    local fence_cflags=""

    if [ "$guest_fence" = "1" ]; then
        fence_cflags="$(rt700_fence_cflags)" || fail "guest fence bounds"
    fi
    if [ "$scenario" = "wrpneg" ]; then
        fence_cflags="$fence_cflags -DXSPI_FLASH_PROTECT_SELFTEST"
    fi
    if [ -n "$wolfboot_dir" ]; then
        if [ -n "${WT_GUEST_FLASH_WRP:-}" ]; then
            rt700_wolfboot_current "$wolfboot_dir" \
                "$(rt700_wolfboot_stamp "CFLAGS_EXTRA=$fence_cflags")" || \
                fail "RT700_WOLFBOOT_DIR=$wolfboot_dir was not built by lib/rt700_wolfboot.sh with this guest fence"
        fi
    else
        wolfboot_dir="$HOME/.cache/wolftrust/wolfboot-rt700"
        [ "$guest_fence" = "1" ] && wolfboot_dir="$wolfboot_dir-fence"
        [ "$scenario" = "wrpneg" ] && wolfboot_dir="$wolfboot_dir-selftest"
        mkdir -p "$(dirname "$wolfboot_dir")"
        stage "wolfBoot $RT700_WOLFBOOT_REF (imx-rt700-tz${fence_cflags:+, guest fence})"
        rt700_wolfboot_build "$wolfboot_dir" "CFLAGS_EXTRA=$fence_cflags" \
            > "$work/wolfboot-build.log" 2>&1 || {
            tail -20 "$work/wolfboot-build.log"
            fail "wolfBoot build failed"
        }
    fi
    [ -s "$wolfboot_dir/wolfboot.bin" ] || \
        fail "wolfBoot TZ image missing at $wolfboot_dir/wolfboot.bin (RT700_WOLFBOOT_DIR)"
}

# Build wolfTrust and both guests, pin the guest measurements, sign, flash the
# whole chain, boot it from a fresh vault, and verify every image by readback.
run_chain() {
    local guest_flags="$1"
    local secure_flags
    secure_flags="$(scenario_secure_flags "$scenario")"
    # Guest Makefiles recursively build the CMSE library. Their build mode
    # must match the Secure image or that rebuild invalidates wolftrust.bin.
    if [ -n "$secure_flags" ]; then
        # shellcheck disable=SC2086,SC2163
        export $secure_flags
    fi

    ensure_spsdk
    mkdir -p "$work"
    ensure_wolfboot

    # RT700 wolfBoot uses a 1024-byte image header, so wolfTrust links at the
    # boot base + 0x400 and is signed with a matching header. Exported so the
    # secure image and the guest CMSE import library agree (mirrors the H5 runner).
    export WT_SECURE_IMAGE_HEADER_SIZE=0x400
    export WT_ATTEST_COSE=1
    export WT_CONF_DIAG_TRAP=0
    rm -rf "$repo/build"
    mkdir -p "$work"

    stage "build wolfTrust secure image + CMSE import library"
    # The vocabulary helper supplies trusted make assignments, not shell code.
    # shellcheck disable=SC2086
    make -s -C "$repo" TARGET=mimxrt700 secure-image TOOLPREFIX=arm-none-eabi- \
        $secure_flags

    if [ "$scenario" = devattestqcbor ]; then
        "$repo/tests/upstream/fetch_qcbor.sh" >/dev/null
    fi
    rt700_build_guests "$guest_flags" 0x1000u
    record_build "$guest_flags" fresh

    # Keep the ELFs that define this run's result addresses, even when the next
    # case rebuilds the image. The suite log records the actual readbacks.
    mkdir -p "$work/images"
    cp "$repo/build/wolftrust.elf" "$work/images/"
    cp "$guest_build/guest0.elf" "$guest1_build/guest1.elf" "$work/images/"
    arm-none-eabi-nm "$repo/build/wolftrust.elf" > "$work/secure-symbols.txt"

    stage "pin both guest measurements, then wolfBoot-sign wolfTrust"
    python3 "$repo/tools/measure/patch_guest_digests.py" "$repo/build/wolftrust.bin" \
        "0:1:$guest_build/guest0.bin" "1:1:$guest1_build/guest1.bin"
    IMAGE_HEADER_SIZE=1024 WOLFBOOT_PARTITION_SIZE=0x40000 WOLFBOOT_SECTOR_SIZE=0x1000 \
        "$wolfboot_dir/tools/keytools/sign" --ecc256 \
        "$repo/build/wolftrust.bin" \
        "$wolfboot_dir/wolfboot_signing_private_key.der" 1

    expected_measurement="$(python3 "$repo/tests/scripts/read_wolfboot_measurement.py" \
        "$repo/build/wolftrust_v1_signed.bin")"
    if [ "$scenario" = authneg ]; then
        cp "$guest_build/guest0.bin" "$work/images/guest0-before-tamper.bin"
        python3 - "$guest_build/guest0.bin" <<'PYEOF'
from pathlib import Path
import sys
path = Path(sys.argv[1])
image = bytearray(path.read_bytes())
image[0x40] ^= 1
path.write_bytes(image)
PYEOF
    fi
    cp "$repo/build/wolftrust_v1_signed.bin" "$guest_build/guest0.bin" \
        "$guest1_build/guest1.bin" "$work/images/"
    (cd "$work/images" && sha256sum *.bin *.elf) > "$work/image-sha256.txt"

    stage "wrap wolfBoot (FCB + MBI) and flash the chain"
    wrap_xip "$wolfboot_dir/wolfboot.bin" "$work/flash_wolfboot.bin" \
        "$(printf '0x%08x' $((xspi0_base + mbi_offset)))"
    flash_at "$xspi0_base" "$work/flash_wolfboot.bin"
    flash_at "$secure_flash_addr" "$repo/build/wolftrust_v1_signed.bin"
    flash_at "$guest0_flash_addr" "$guest_build/guest0.bin"
    flash_at "$guest1_flash_addr" "$guest1_build/guest1.bin"
    stage "erase the wolfHSM NVM store so the run starts from a fresh vault"
    erase_range "$(printf '0x%08x-0x%08x' "$hsm_nvm_addr" $((hsm_nvm_addr + hsm_nvm_size)))"
    if [ "$(rt700_guest_kind "$scenario")" = conformance ]; then
        # Clear only before a new suite. Its deliberate platform resets must
        # preserve this distinct boot/status sector and the vault.
        erase_range "0x281E8000-0x281E9000"
        export RT700_UART_TIMEOUT="${RT700_UART_TIMEOUT:-900}"
    fi
    clear_mailboxes

    if [ "$(rt700_guest_kind "$scenario")" = conformance ] || [ "$scenario" = restart ]; then
        # Conformance writes NOR and resets; restart deliberately faults.
        # Verify while the core stays parked, before either operation begins.
        verify_at "$xspi0_base" "$work/flash_wolfboot.bin" parked
        verify_at "$secure_flash_addr" "$repo/build/wolftrust_v1_signed.bin" parked
        verify_at "$guest0_flash_addr" "$guest_build/guest0.bin" parked
        verify_at "$guest1_flash_addr" "$guest1_build/guest1.bin" parked
    fi
    start_uart
    os_boot_started=$SECONDS
    reset_board
    sleep 2
    if [ "$(rt700_guest_kind "$scenario")" != conformance ] && [ "$scenario" != restart ]; then
        verify_at "$xspi0_base" "$work/flash_wolfboot.bin"
        verify_at "$secure_flash_addr" "$repo/build/wolftrust_v1_signed.bin"
        verify_at "$guest0_flash_addr" "$guest_build/guest0.bin"
        verify_at "$guest1_flash_addr" "$guest1_build/guest1.bin"
    fi
}

# One 32-bit word at base+offset over SWD, as eight lowercase hex digits.
mailbox_word() {
    local address output
    address="$(rt700_word_address "$1" "$2")" || \
        fail "invalid SWD word address or offset"
    output="$(dap -c "read32 $address")" || return 1
    printf '%s\n' "$output" | rt700_parse_word "$address"
}

# Each guest records its progress at the base of its own RAM window.
check_guest() {
    local id="$1" base="$2" sig fw st uart
    sig="$(mailbox_word "$base" 0)"
    fw="$(mailbox_word "$base" 8)"
    st="$(mailbox_word "$base" 20)"
    uart="$(mailbox_word "$base" 24)"
    check "$([ "$sig" = "47543030" ]; echo $?)" "guest$id launched: signature 0x47543030 ($sig)"
    check "$([ "$fw" = "00000100" ]; echo $?)" "guest$id psa_framework_version 0x0100 ($fw)"
    check "$([ "$st" = "600d600d" ]; echo $?)" \
        "guest$id done: FF-M connect verified, status 0x600D600D ($st)"
    check "$([ -n "$uart" ] && [ "$uart" != "00000000" ]; echo $?)" \
        "guest$id reaches its Non-secure console (LPUART0 VERID 0x$uart)"
}

# Result addresses come from this run's guest ELF, not assumed RAM offsets.
guest_symbol() {
    local addr
    addr="$(arm-none-eabi-nm "$work/images/guest$1.elf" |
        awk -v symbol="$2" '$3 == symbol { addr = "0x" $1; n++ }
            END { if (n != 1) exit 1; print addr }')" || \
        fail "guest$1 symbol $2 missing or ambiguous in its ELF"
    printf '%s\n' "$addr"
}

guest_result_addr() {
    guest_symbol "$1" g_guest_mailbox
}

check_os_guests() {
    local id base a b elapsed_a elapsed_b errors signature crypto expected
    local deadline=$((os_boot_started + 30))
    for id in 0 1; do
        base="$(guest_symbol "$id" g_os_progress)"
        while :; do
            a="$(mailbox_word "$base" 0)"
            b="$(mailbox_word "$base" 4)"
            crypto="$(mailbox_word "$base" 24)"
            elapsed_a="$(mailbox_word "$base" 8)"
            elapsed_b="$(mailbox_word "$base" 28)"
            [ "$a" = 0000000a ] && [ "$b" = 0000000a ] && \
                [ "$crypto" = 0000000a ] && [ $((0x$elapsed_a)) -ge 1000 ] && \
                [ $((0x$elapsed_b)) -ge 1000 ] && break
            [ "$SECONDS" -lt "$deadline" ] || fail "guest$id OS timers did not complete within 30 seconds"
            sleep 1
        done
        errors="$(mailbox_word "$base" 12)"
        signature="$(mailbox_word "$base" 20)"
        expected=5a455048
        [ "$id" = 1 ] && expected=46524545
        check "$([ "$signature" = "$expected" ]; echo $?)" \
            "guest$id real OS signature (0x$signature)"
        check "$([ "$errors" = 00000000 ] && [ $((0x$elapsed_a)) -le 30000 ] && \
            [ $((0x$elapsed_b)) -le 30000 ]; echo $?)" \
            "guest$id both OS tasks slept ten times with bounded timers and peer crypto"
        check_peer_progress "$base" 16
    done
}

check_psa_guest() {
    local id="$1" base deadline signature lifecycle bits failed keyneg neg
    local measurement handoff_lifecycle measured_lifecycle
    base="$(guest_result_addr "$id")"
    deadline=$((SECONDS + 30))
    while :; do
        lifecycle="$(mailbox_word "$base" 4)"
        [ "$lifecycle" = 000000ff ] && break
        [ "$SECONDS" -lt "$deadline" ] || fail "guest$id PSA lifecycle timed out (0x$lifecycle)"
        sleep 1
    done
    signature="$(mailbox_word "$base" 0)"
    check "$([ "$signature" = 50534147 ]; echo $?)" "guest$id PSA result signature (0x$signature)"
    check "$([ "$lifecycle" = 000000ff ]; echo $?)" "guest$id complete PSA lifecycle (0x$lifecycle)"
    bits="$(mailbox_word "$base" 20)"
    failed="$(mailbox_word "$base" 24)"
    check "$([ "$bits" = 00000007 ] && [ "$failed" = 00000000 ]; echo $?)" \
        "guest$id RNG, SHA-256 and AES-CTR encrypt/decrypt KATs (0x$bits, failed 0x$failed)"
    keyneg="$(mailbox_word "$base" 28)"
    check "$([ "$keyneg" = 00000001 ]; echo $?)" "guest$id key ownership/signature negatives (0x$keyneg)"
    neg="$(mailbox_word "$base" 8)"
    check "$([ "$neg" = 0000000f ]; echo $?)" "guest$id all four FF-M rejection checks (0x$neg)"
    # The Secure attestation service retains the consumed, authenticated boot
    # handoff. Match its lifecycle as well as the measurement in both tokens.
    handoff_lifecycle="$(mailbox_word "$(elf_sym g_boot_handoff)" 12)"
    measured_lifecycle="$(mailbox_word "$base" 40)"
    check "$([ "$measured_lifecycle" = "$handoff_lifecycle" ] && \
        [ "$measured_lifecycle" = 00001000 ]; echo $?)" \
        "guest$id token matches development boot lifecycle (0x$measured_lifecycle)"
    timeout 60 pyocd cmd -t cortex_m \
        -c "savemem $(printf '0x%x' $((base + 44))) 32 $work/guest$id-measurement.bin" \
        >/dev/null 2>&1 || fail "guest$id token measurement read failed"
    measurement="$(python3 - "$work/guest$id-measurement.bin" <<'PYEOF'
from pathlib import Path
import sys
print(Path(sys.argv[1]).read_bytes().hex())
PYEOF
    )"
    check "$([ "$measurement" = "$expected_measurement" ]; echo $?)" \
        "guest$id token measurement matches the signed Secure image ($measurement)"
}

check_storage_reset() {
    local want="$1" base signature phase bits status its_flags ps_flags
    base="$(guest_symbol 0 g_storage_reset)"
    signature="$(mailbox_word "$base" 0)"
    phase="$(mailbox_word "$base" 4)"
    bits="$(mailbox_word "$base" 8)"
    status="$(mailbox_word "$base" 12)"
    its_flags="$(mailbox_word "$base" 16)"
    ps_flags="$(mailbox_word "$base" 20)"
    check "$([ "$signature" = 57545352 ] && [ "$phase" = "$want" ]; echo $?)" \
        "storage reset phase 0x$phase (want 0x$want, signature 0x$signature)"
    check "$([ "$bits" = 000003ff ] && [ "$status" = 00000000 ]; echo $?)" \
        "ITS/PS exact data, metadata, set/remove refusal and unchanged data (0x$bits/0x$status)"
    check "$([ "$its_flags" = 00000001 ] && [ "$ps_flags" = 00000001 ]; echo $?)" \
        "both objects retain WRITE_ONCE metadata (0x$its_flags/0x$ps_flags)"
}

check_peer_progress() {
    local base="$1" offset="$2" before after
    before="$(mailbox_word "$base" "$offset")"
    sleep 1
    after="$(mailbox_word "$base" "$offset")"
    check "$([ -n "$before" ] && [ -n "$after" ] && [ "$before" != "$after" ]; echo $?)" \
        "peer remains live (0x$before -> 0x$after)"
}

check_conformance_guest() {
    local base deadline lifecycle signature status
    base="$(guest_result_addr 0)"
    deadline=$((SECONDS + ${RT700_CONF_TIMEOUT:-900}))
    while :; do
        # Intentional whole-platform resets briefly disable the debug AP.
        # Retry unavailable observations, but never extend the suite deadline.
        if lifecycle="$(mailbox_word "$base" 4)"; then
            [ $((0x$lifecycle & 0x80)) -ne 0 ] && break
        else
            lifecycle=unavailable
            log "  [observe] SWD unavailable during suite execution; retrying"
        fi
        [ "$SECONDS" -lt "$deadline" ] || fail "Arm conformance did not complete (0x$lifecycle)"
        sleep 1
    done
    signature="$(mailbox_word "$base" 0)"
    status="$(mailbox_word "$base" 76)"
    check "$([ "$signature" = 50534147 ] && [ "$lifecycle" = 0000009f ]; echo $?)" \
        "guest0 completed service setup and the Arm suite (0x$signature/0x$lifecycle)"
    check "$([ "$status" = 00000000 ]; echo $?)" "Arm val_entry returned success (0x$status)"
    stop_uart
    log="$work/uart.log"
    expect "complete Arm ACS report retained" "END OF ACS"
    conf_totals
    case "$scenario" in
        confboot)
            check "$([ "$conf_passed" -eq 85 ] && [ "$conf_skipped" -eq 4 ] && \
                [ "$conf_failed" -eq 0 ]; echo $?)" \
                "Arm IPC: $conf_passed passed, $conf_skipped skipped, $conf_failed failed (85/4/0 required)"
            check "$([ "$(count 'wolfBoot HAL init: MIMXRT798S')" -ge 2 ]; echo $?)" \
                "panic tests rebooted the authenticated chain and resumed the suite" ;;
        devstorage)
            check "$([ "$conf_failed" -eq 0 ] && \
                [ "$((conf_passed + conf_skipped))" -eq 17 ]; echo $?)" \
                "Arm storage: $conf_passed passed, $conf_skipped skipped, $conf_failed failed (17 scheduled)" ;;
        devcrypto|vaultrecover)
            check "$([ "$conf_failed" -eq 0 ] && \
                [ "$((conf_passed + conf_skipped))" -eq 77 ]; echo $?)" \
                "Arm crypto: $conf_passed passed, $conf_skipped skipped, $conf_failed failed (77 scheduled)" ;;
        devattest|devattestqcbor)
            check "$([ "$conf_passed" -eq 1 ] && [ "$conf_skipped" -eq 0 ] && \
                [ "$conf_failed" -eq 0 ]; echo $?)" \
                "Arm initial attestation: 1 passed, 0 skipped, 0 failed" ;;
    esac
    grep -a -i -n -B5 -A2 'skip' "$log" > "$work/conformance-skips.log" || true
    check_guest 1 0x20140000
    check_peer_progress 0x20140000 36
}

# A wolfTrust global's address, from the image this run built and flashed.
elf_sym() {
    local addr
    addr="$(arm-none-eabi-nm "$repo/build/wolftrust.elf" |
        awk -v s="$1" '$3 == s || $3 ~ "^" s "\\.lto_priv\\.[0-9]+$" {
            addr = "0x" $1; n++
        } END { if (n != 1) exit 1; print addr }'
    )" || fail "required symbol $1 missing or ambiguous in wolftrust.elf"
    printf '%s\n' "$addr"
}

# All eight XSPI0 FRADs as "start end acp word3" lines, in one debugger
# session; only words 0-3 of each 0x20 stride are readable.
frad_dump() {
    local -a cmds=()
    local n
    for n in 0 1 2 3 4 5 6 7; do
        cmds+=(-c "read32 $(printf '0x%x' $((0x50184800 + n * 0x20))) 16")
    done
    dap "${cmds[@]}" | awk '/^50184[89]/ { print $2, $3, $4, $5 }'
}

# wolfBoot sealed the SFP configuration until the next reset.
sfp_sealed() {
    local mgc mdad
    mgc=$((0x$(mailbox_word 0x50184920 0)))
    mdad=$((0x$(mailbox_word 0x50184900 0)))
    [ $((mgc & 0xA8000000)) -eq $((0xA8000000)) ] && [ $((mgc & 0xC00)) -ne 0 ] &&
        [ $((mdad & 0xA0000000)) -eq $((0xA0000000)) ]
}

# One valid, hard-reset-locked (EAL clear), write-denying FRAD spans the guest
# windows; the Secure-side predicate is the authority, this is the evidence.
fence_armed() {
    local w0 w1 w2 w3 lock
    rt700_fence_bounds || fail "guest fence bounds"
    while read -r w0 w1 w2 w3; do
        lock=$((0x$w3 & 0x63000000))
        if [ $((0x$w0 & 0xFFFF0000)) -le $((RT700_GUEST_FENCE_START)) ] &&
           [ $(((0x$w1 & 0xFFFF0000) | 0xFFFF)) -ge $((RT700_GUEST_FENCE_END - 1)) ] &&
           [ $((0x$w3 & 0x80000000)) -ne 0 ] && [ $((0x$w2 & 0x3F)) -eq 0 ] &&
           { [ "$lock" -eq $((0x20000000)) ] || [ "$lock" -eq $((0x60000000)) ]; }; then
            return 0
        fi
    done < <(frad_dump)
    return 1
}

check_launch_masks() {
    local want_verified="$1" want_refused="$2" verified refused
    verified="$(mailbox_word "$(elf_sym g_wt_launch_verified_mask)" 0)"
    refused="$(mailbox_word "$(elf_sym g_wt_launch_refused_mask)" 0)"
    check "$([ "$verified" = "$want_verified" ]; echo $?)" \
        "launch-verified guest mask 0x$verified (want 0x$want_verified)"
    check "$([ "$refused" = "$want_refused" ]; echo $?)" \
        "launch-refused guest mask 0x$refused (want 0x$want_refused)"
}

case "$scenario" in
writeonce)
    run_chain "$(rt700_guest_flags "$scenario" 0)"
    check_launch_masks 00000003 00000000
    check_psa_guest 0
    check_psa_guest 1
    check_storage_reset 00000001
    check_peer_progress "$(guest_result_addr 1)" 16
    stage "independent second hardware reset with vault and images retained"
    clear_mailboxes
    reset_board
    sleep 2
    check_launch_masks 00000003 00000000
    check_psa_guest 0
    check_psa_guest 1
    check_storage_reset 00000002
    check_peer_progress "$(guest_result_addr 1)" 16
    stop_uart
    log "PASS: hardware/$scenario"
    ;;
authneg)
    run_chain ""
    check_launch_masks 00000002 00000001
    signature="$(mailbox_word 0x20100000 0)"
    check "$([ "$signature" = 00000000 ]; echo $?)" \
        "tampered guest0 never wrote its result signature (0x$signature)"
    check_guest 1 0x20140000
    check_peer_progress 0x20140000 36
    log "PASS: hardware/$scenario"
    ;;
confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover)
    run_chain "$(rt700_guest_flags "$scenario" 0)"
    check_launch_masks 00000003 00000000
    check_conformance_guest
    if [ "$scenario" = vaultrecover ]; then
        probe_symbol=g_native_foreign_probe_fired
        [ "${WT_ENGINE:-native}" = hsm ] && probe_symbol=g_foreign_probe_fired
        probe="$(mailbox_word "$(elf_sym "$probe_symbol")" 0)"
        reformatted="$(mailbox_word "$(elf_sym g_vault_reformatted)" 0)"
        lifecycle="$(mailbox_word "$(elf_sym g_boot_lifecycle)" 0)"
        check "$([ "$probe" = 00000001 ]; echo $?)" \
            "blocked-provisioning probe executed (0x$probe)"
        check "$([ "$lifecycle" = 00001000 ] && [ "$reformatted" = 00000001 ]; echo $?)" \
            "development vault recovered through the production reformat path (0x$lifecycle/0x$reformatted)"
    fi
    log "PASS: hardware/$scenario"
    ;;
bothpsa|bothiso|attestneg|hsmattackneg|fwustage)
    if [ "$scenario" = hsmattackneg ] && [ "${WT_ENGINE:-native}" != hsm ]; then
        fail "hsmattackneg requires WT_ENGINE=hsm"
    fi
    run_chain "$(rt700_guest_flags "$scenario" 0)"
    check_launch_masks 00000003 00000000
    for id in 0 1; do
        check_psa_guest "$id"
    done
    if [ "${WT_RT700_GUEST_FIXTURE:-baremetal}" = os ]; then
        check_os_guests
    else
        check_peer_progress "$(guest_result_addr 1)" 16
    fi
    case "$scenario" in
        attestneg)
            mask="$(mailbox_word "$(guest_result_addr 0)" 32)"
            check "$([ "$mask" = 0000000f ]; echo $?)" "all attestation negatives passed (0x$mask)" ;;
        hsmattackneg)
            mask="$(mailbox_word "$(guest_result_addr 0)" 12)"
            check "$([ "$mask" = 00000007 ]; echo $?)" "all HSM identity/namespace checks passed (0x$mask)" ;;
        fwustage)
            mask="$(mailbox_word "$(guest_result_addr 0)" 36)"
            check "$([ "$mask" = 0000001f ]; echo $?)" "all FWU staging and error checks passed (0x$mask)"
            trailer="$(mailbox_word 0x281bfffc 0)"
            check "$([ "$trailer" = ffffffff ]; echo $?)" "update trigger disarmed after cleanup (0x$trailer)"
            # The later out-of-order negative rewrites only sector zero.
            # Independently retain and compare the remaining 128 KiB body
            # and its 32-byte tail, beyond that intentionally replaced sector.
            python3 - "$work/fwu-body-expected.bin" <<'PYEOF'
from pathlib import Path
import sys
body = b"".join(bytes([(offset // 512) & 0xff]) * 512
                for offset in range(0x1000, 0x21000, 512))
Path(sys.argv[1]).write_bytes(body + bytes([0x22]) * 32)
PYEOF
            verify_at 0x28181000 "$work/fwu-body-expected.bin"
            sha256sum "$work/fwu-body-expected.bin" "$work/readback-28181000.bin" \
                > "$work/fwu-body-sha256.txt" ;;
    esac
    log "PASS: hardware/$scenario"
    ;;
romsmoke)
    mkdir -p "$work"
    ensure_spsdk
    make -s -C "$repo/tests/firmware/mimxrt700-smoke" BUILD="$work/smoke" all
    wrap_xip "$work/smoke/smoke.bin" "$work/flash_smoke.bin" \
        "$(printf '0x%08x' $((xspi0_base + mbi_offset)))"
    flash_at "$xspi0_base" "$work/flash_smoke.bin"
    record_build "romsmoke"
    start_uart
    reset_board
    verify_at "$xspi0_base" "$work/flash_smoke.bin"
    s1="$(dap -c 'read32 0x20180000 8' | tail -1)"
    sleep 1
    s2="$(dap -c 'read32 0x20180000 8' | tail -1)"
    m1="$(printf '%s' "$s1" | awk '{print $2}')"
    c1="$(printf '%s' "$s1" | awk '{print $3}')"
    c2="$(printf '%s' "$s2" | awk '{print $3}')"
    check "$([ "$m1" = "52543030" ]; echo $?)" "ROM booted the XIP image: marker RT00 at 0x20180000 ($m1)"
    check "$([ "$c1" != "$c2" ]; echo $?)" "smoke loop alive: counter $c1 -> $c2"
    pc="$(dap -c halt -c 'reg pc' -c go | sed -n 's/^pc = //p')"
    check "$(case "$pc" in 0x2800[4-9]*|0x2800[a-f]*) echo 0;; *) echo 1;; esac)" "PC inside the XIP image ($pc)"
    log "PASS: hardware/romsmoke"
    ;;
positive|ahbscneg|restart)
    guest_flags="$(rt700_guest_flags "$scenario" 0)"
    run_chain "$guest_flags"

    check_launch_masks 00000003 00000000
    check_guest 1 0x20140000
    if [ "$scenario" = "positive" ]; then
        check_guest 0 0x20100000
    fi

    if [ "$scenario" = "ahbscneg" ] || [ "$scenario" = restart ]; then
        # ahbscneg stores into peer RAM; restart reads Secure RAM on launch.
        # The SAU denies both accesses while preserving the live peer.
        # Restart/quarantine scrubs guest0's RAM, including its probe latch.
        # Use Secure records to distinguish the intended fault from an image
        # that never ran or an unrelated fault. Completion remains bounded.
        deadline=$((SECONDS + 30))
        while :; do
            restarts="$(mailbox_word "$(elf_sym g_wt_restart_events)" 0)"
            quarantines="$(mailbox_word "$(elf_sym g_wt_quarantine_events)" 0)"
            [ "$quarantines" != 00000000 ] && break
            [ "$SECONDS" -lt "$deadline" ] || fail "guest0 quarantine timed out"
            sleep 1
        done
        check "$([ "$restarts" = 00000003 ] && [ "$quarantines" = 00000001 ]; echo $?)" \
            "guest0 spent three restarts, then quarantined (0x$restarts/0x$quarantines)"
        fault_addr="$(mailbox_word "$(elf_sym g_last_fault_address)" 0)"
        want_fault=20170000
        [ "$scenario" = restart ] && want_fault=30188000
        check "$([ "$fault_addr" = "$want_fault" ]; echo $?)" \
            "fault identifies guest0's denied access (0x$fault_addr, want 0x$want_fault)"
        peer="$(mailbox_word 0x20170000 0)"
        check "$([ "$peer" = "00000000" ]; echo $?)" \
            "guest1 target RAM remains unchanged (0x$peer)"
        # Containment means the peer keeps running, not only that the mailboxes
        # were written before the probes: an all-guests-faulted monitor also
        # idles in thread mode.
        beat1="$(mailbox_word 0x20140000 36)"
        sleep 1
        beat2="$(mailbox_word 0x20140000 36)"
        check "$([ -n "$beat1" ] && [ -n "$beat2" ] && [ "$beat1" != "$beat2" ]; echo $?)" \
            "guest1 still running after guest0's faults (beat 0x$beat1 -> 0x$beat2)"
        g0beat="$(mailbox_word 0x20100000 36)"
        check "$([ "$g0beat" = "00000000" ]; echo $?)" \
            "guest0 never got past its denied access (beat 0x$g0beat)"
        ipsr="$(dap -c halt -c 'reg xpsr' -c go | sed -n 's/^xpsr = 0x\([0-9a-fA-F]*\).*/\1/p')"
        ipsr=$((0x${ipsr:-3} & 0x1ff))
        check "$([ "$ipsr" -lt 2 ] || [ "$ipsr" -gt 7 ]; echo $?)" \
            "system still scheduling after the probes (IPSR $ipsr, not a fault handler)"
        valid="$(mailbox_word 0x5017CF00 0)"
        log "  [fabric] AHBSC0 violation latches valid 0x$valid"
        for port in $(seq 0 28); do
            [ $(((0x$valid >> port) & 1)) -eq 1 ] || continue
            log "  [fabric]   port $port addr 0x$(mailbox_word 0x5017CE00 $((4 * port)))" \
                "info 0x$(mailbox_word 0x5017CE80 $((4 * port)))"
        done
    fi
    log "PASS: hardware/$scenario"
    ;;
wrpfence)
    run_chain ""
    rt700_fence_bounds || fail "guest fence bounds"
    check "$(sfp_sealed; echo $?)" "XSPI SFP configuration valid and sealed until reset"
    check "$(fence_armed; echo $?)" \
        "a locked, write-denying FRAD spans the guest windows ($RT700_GUEST_FENCE_START-$RT700_GUEST_FENCE_END)"
    check_launch_masks 00000003 00000000
    for g in 0:0x20100000 1:0x20140000; do
        check_guest "${g%%:*}" "${g##*:}"
    done
    log "PASS: hardware/$scenario"
    ;;
wrpoff)
    run_chain ""
    rt700_fence_bounds || fail "guest fence bounds"
    check "$(sfp_sealed; echo $?)" "XSPI SFP configuration valid and sealed until reset"
    check "$(fence_armed && echo 1 || echo 0)" \
        "no FRAD fences the guest windows (unfenced wolfBoot)"
    check_launch_masks 00000000 00000003
    for g in 0:0x20100000 1:0x20140000; do
        sig="$(mailbox_word "${g##*:}" 0)"
        check "$([ "$sig" = "00000000" ]; echo $?)" \
            "guest${g%%:*} never entered its domain (mailbox 0x$sig)"
    done
    log "PASS: hardware/$scenario"
    ;;
wrpneg)
    run_chain ""
    rt700_fence_bounds || fail "guest fence bounds"
    check "$(fence_armed; echo $?)" \
        "a locked, write-denying FRAD spans the guest windows ($RT700_GUEST_FENCE_START-$RT700_GUEST_FENCE_END)"
    # wolfBoot's selftest verdicts (hal/imx_rt7xx.c PST mailbox).
    pst() { mailbox_word 0x20180080 $((4 * $1)); }
    check "$([ "$(pst 0)" = "50510002" ]; echo $?)" "wolfBoot's flash-protect selftest ran to completion"
    # Only the refusal: the block's contents depend on what the board held.
    check "$([ "$(pst 3)" = "$(pst 4)" ]; echo $?)" \
        "the boot-root erase at 0x$(pst 1) returned the FRAD check error ($(pst 3))"
    check "$([ "$(pst 9)" = "$(pst 4)" ]; echo $?)" \
        "the erase at 0x$(pst 7) in the guest fence returned the FRAD check error ($(pst 9))"
    check "$([ "$(pst 11)" = "505150aa" ]; echo $?)" \
        "the guest-fence block is unchanged (0x$(pst 8) -> 0x$(pst 10))"
    check_launch_masks 00000003 00000000
    for g in 0:0x20100000 1:0x20140000; do
        check_guest "${g%%:*}" "${g##*:}"
    done
    log "PASS: hardware/$scenario"
    ;;
*)
    log "usage: $0 romsmoke|positive|ahbscneg|authneg|restart|wrpfence|wrpoff|wrpneg|bothpsa|bothiso|attestneg|hsmattackneg|fwustage|writeonce|confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover"
    exit 2
    ;;
esac
