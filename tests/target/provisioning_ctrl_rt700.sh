#!/usr/bin/env bash
# wolfTrust MIMXRT700 provisioning + lock control, the RT700 sibling of
# provisioning_ctrl.sh. Runs on the host that owns the probe (pi5).
#
# BRICK SAFETY (non-negotiable):
#   * board-writing commands refuse to run without WT_LOCK_CONFIRM=1
#   * no command programs a fuse: the life cycle only ever moves in the OTP
#     shadow registers, which every hardware reset reloads from the fuses
#   * regress is a hardware reset through the pi4 line, which the debug port
#     cannot veto, so a shadow state that closes debug is still recoverable
#   * advance needs a clean read-only discover, and past Develop2 a proven
#     regress, the RT700 form of "recovery before any advance"
#
# Commands:
#   status               life cycle, debug, and XSPI fence state (read-only)
#   discover             preflight that gates advance (read-only)
#   verify-wrp           the running chain's guest fence is armed (read-only)
#   restore              rebuild, flash, and verify the fenced production chain
#   advance <hexstate>   move the life cycle shadow: 0x07 Develop2, 0x0F
#                        In-Field, 0xCF In-Field Locked (GATED)
#   regress              hardware reset back to the fused life cycle (GATED)
#   provision-da, burn   refused: both program fuses (production only)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
target="${RT700_TARGET:-mimxrt798sgfob}"
spsdk_venv="${RT700_SPSDK_VENV:-$HOME/spsdk-venv}"
state_dir="${RT700_PROVISION_STATE:-$HOME/.cache/wolftrust}"
elf="$repo/build/wolftrust.elf"

# OTP shadow words (fuse index * 4 from 0x50018000, both silicon revisions).
LC_STATE=0x5001823C
LC_STATE_RED=0x50018094
LOCK_CFG3=0x5001800C
DAUTHSTATUS=0xE000EFB8
XSPI_MGC=0x50184920
XSPI_TG0MDAD=0x50184900
LC_DEVELOP=0x03

# shellcheck source=lib/rt700_fence.sh disable=SC1091
. "$here/lib/rt700_fence.sh"

pass()  { printf '  [check] PASS  %s\n' "$1"; }
fail()  { printf '  [check] FAIL  %s  (%s)\n' "$1" "$2"; exit 1; }
confirm() { [ "${WT_LOCK_CONFIRM:-0}" = "1" ] || {
    echo "REFUSED: '$cmd' writes to the board. Re-run with WT_LOCK_CONFIRM=1." >&2; exit 2; }; }

ensure_spsdk() {
    if ! command -v pyocd >/dev/null 2>&1; then
        [ -x "$spsdk_venv/bin/pyocd" ] || fail "tools" "pyocd not found (set RT700_SPSDK_VENV)"
        PATH="$spsdk_venv/bin:$PATH"
        export PATH
    fi
}

# Words over SWD with the generic attach, which never resets the chip.
read_words() {
    local -a cmds=()
    local a
    for a in "$@"; do
        cmds+=(-c "read32 $a")
    done
    timeout 60 pyocd cmd -t cortex_m "${cmds[@]}" 2>&1 |
        awk '/^[0-9a-f]+:/ { print $2 }'
}

psa_name() {
    case "$1" in
        00001000) echo "ASSEMBLY_AND_TEST" ;; 00002000) echo "PSA_ROT_PROVISIONING" ;;
        00003000) echo "SECURED" ;; 00004000) echo "NON_PSA_ROT_DEBUG" ;;
        00005000) echo "RECOVERABLE_PSA_ROT_DEBUG" ;; 00006000) echo "DECOMMISSIONED" ;;
        *) echo "UNKNOWN" ;;
    esac
}

lc_name() {
    case "$(printf '0x%02X' $(( $1 & 0xFF )))" in
        0x03) echo "Develop" ;; 0x07) echo "Develop2" ;; 0x0F) echo "In-Field" ;;
        0x1F) echo "In-Field Return" ;; 0xCF) echo "In-Field Locked" ;;
        *) echo "NXP-internal or unknown" ;;
    esac
}

# The life cycle wolfBoot handed wolfTrust: the raw handoff record while it is
# intact (WT_ATTEST_COSE=0 builds leave it), else wolfTrust's consumed copy.
handoff_lifecycle() {
    local magic inv lc sym
    read -r magic inv lc < <(read_words 0x30180000 0x30180004 0x3018000C |
        tr '\n' ' '; echo)
    if [ "${magic:-}" = "5742484f" ] &&
       [ $((0x$magic ^ 0x${inv:-0})) -eq $((0xFFFFFFFF)) ]; then
        echo "$lc"
        return 0
    fi
    [ -s "$elf" ] || return 1
    sym="$(arm-none-eabi-nm "$elf" | awk '$3 == "g_boot_lifecycle" { print "0x" $1; exit }')"
    [ -n "$sym" ] || return 1
    read_words "$sym"
}

fence_line() {
    local -a cmds=()
    local w0 w1 w2 w3 n=0 out=""
    rt700_fence_bounds || return 1
    for w0 in 0 1 2 3 4 5 6 7; do
        cmds+=(-c "read32 $(printf '0x%x' $((0x50184800 + w0 * 0x20))) 16")
    done
    while read -r w0 w1 w2 w3; do
        if [ $((0x$w0 & 0xFFFF0000)) -le $((RT700_GUEST_FENCE_START)) ] &&
           [ $(((0x$w1 & 0xFFFF0000) | 0xFFFF)) -ge $((RT700_GUEST_FENCE_END - 1)) ] &&
           [ $((0x$w3 & 0x80000000)) -ne 0 ]; then
            out="FRAD$n acp=0x$w2 word3=0x$w3"
            if [ $((0x$w2 & 0x3F)) -eq 0 ] &&
               { [ $((0x$w3 & 0x63000000)) -eq $((0x20000000)) ] ||
                 [ $((0x$w3 & 0x63000000)) -eq $((0x60000000)) ]; }; then
                echo "armed $out"
                return 0
            fi
        fi
        n=$((n + 1))
    done < <(timeout 60 pyocd cmd -t cortex_m "${cmds[@]}" 2>&1 |
             awk '/^50184/ { print $2, $3, $4, $5 }')
    echo "open ${out:-no descriptor spans the guest windows}"
    return 1
}

cmd="${1:-status}"
case "$cmd" in
  status)
    ensure_spsdk
    read -r lc lcr lock dauth mgc mdad < <(read_words "$LC_STATE" "$LC_STATE_RED" \
        "$LOCK_CFG3" "$DAUTHSTATUS" "$XSPI_MGC" "$XSPI_TG0MDAD" | tr '\n' ' '; echo)
    echo "OTP life cycle   LC_STATE=0x${lc: -2} ($(lc_name "0x$lc"))  LC_STATE_RED=0x${lcr: -2}"
    echo "LOCK_CFG3        0x$lock (LIFE_CYCLE_LOCK=$((0x$lock & 7)): 0 = shadow override and fuse burn both open)"
    echo "DAUTHSTATUS      0x$dauth"
    echo "XSPI SFP         MGC=0x$mgc TG0MDAD=0x$mdad"
    echo "guest fence      $(fence_line || true)"
    if hl="$(handoff_lifecycle)"; then
        echo "wolfTrust saw    0x$hl ($(psa_name "$hl"))"
    fi
    ;;

  discover)
    ensure_spsdk
    mkdir -p "$state_dir"
    rm -f "$state_dir/rt700-discovery-ok" "$state_dir/rt700-regress-ok"
    command -v shadowregs >/dev/null 2>&1 || PATH="$spsdk_venv/bin:$PATH"
    shadowregs get-families 2>/dev/null | grep -qi mimxrt798s || \
        fail "discover" "SPSDK shadowregs has no mimxrt798s support"
    pass "SPSDK shadowregs supports mimxrt798s"
    read -r lc lcr lock dauth < <(read_words "$LC_STATE" "$LC_STATE_RED" \
        "$LOCK_CFG3" "$DAUTHSTATUS" | tr '\n' ' '; echo)
    [ $((0x$lc & 0xFF)) -eq $((LC_DEVELOP)) ] && [ $((0x$lcr & 0xFF)) -eq $((LC_DEVELOP)) ] || \
        fail "discover" "fused life cycle is not Develop (LC 0x$lc, RED 0x$lcr)"
    pass "fused life cycle is Develop and its redundant copy agrees"
    [ $((0x$lock & 2)) -eq 0 ] || \
        fail "discover" "LIFE_CYCLE_LOCK over-ride protect is set (0x$lock)"
    pass "life cycle shadow over-ride is open (LOCK_CFG3 0x$lock)"
    hl="$(handoff_lifecycle)" || \
        fail "discover" "no readable boot handoff: run tests/target/run_rt700_hardware.sh first"
    pass "the boot handoff life cycle is readable (0x$hl, $(psa_name "$hl"))"
    printf 'LC=0x%s RED=0x%s LOCK_CFG3=0x%s DAUTH=0x%s\n' "$lc" "$lcr" "$lock" "$dauth" \
        > "$state_dir/rt700-discovery-ok"
    echo "PASS: discovery stamped ($state_dir/rt700-discovery-ok)"
    ;;

  verify-wrp)
    ensure_spsdk
    line="$(fence_line)" || fail "verify-wrp" "$line"
    pass "guest fence $line"
    ;;

  restore)
    confirm
    "$here/run_rt700_hardware.sh" wrpfence
    ;;

  advance)
    confirm
    value="${2:-}"
    [[ "$value" =~ ^0[xX][0-9A-Fa-f]{1,2}$ ]] || {
        echo "REFUSED: advance takes 0x07, 0x0F, or 0xCF, got '${value:-none}'." >&2; exit 2; }
    case "$(printf '0x%02X' $((value)))" in
      0x07) ;;
      0x0F|0xCF)
        [ -s "$state_dir/rt700-regress-ok" ] || {
            echo "REFUSED: prove 'regress' from Develop2 before advancing to $value." >&2; exit 2; } ;;
      *) echo "REFUSED: advance takes 0x07, 0x0F, or 0xCF, got '${value:-none}'." >&2; exit 2 ;;
    esac
    [ -s "$state_dir/rt700-discovery-ok" ] || {
        echo "REFUSED: run 'discover' first." >&2; exit 2; }
    ensure_spsdk
    entry="$(read_words 0x28004004)"
    [ -n "$entry" ] && [ "$entry" != "00000000" ] && [ "$entry" != "ffffffff" ] || \
        fail "advance" "no wolfBoot reset vector at 0x28004004 (flash the chain first)"
    echo "ADVANCING the life cycle shadow to $value ($(lc_name "$value")); regress or any reset undoes it"
    "$spsdk_venv/bin/python" - "0x$entry" "$value" "$LC_STATE" "$LC_STATE_RED" "$target" <<'PYEOF'
import sys
import time
from pyocd.core.helpers import ConnectHelper
from pyocd.core.target import Target

# The ROM loads the OTP shadows before wolfBoot; wolfBoot reads the life cycle
# only when it builds the handoff, so the write must land in between.
WOLFBOOT_TEXT = (0x28004000, 0x28040000)
entry, value, lc, lc_red = (int(a, 0) for a in sys.argv[1:5])
with ConnectHelper.session_with_chosen_probe(
        options={"target_override": sys.argv[5], "resume_on_disconnect": True,
                 "reset_type": "hw"}) as s:
    t = s.target
    t.reset_and_halt()
    pc = t.read_core_register("pc")
    if pc < WOLFBOOT_TEXT[0]:
        t.set_breakpoint(entry & ~1)
        t.resume()
        deadline = time.time() + 10
        while t.get_state() != Target.State.HALTED or \
                t.read_core_register("pc") != (entry & ~1):
            if time.time() > deadline:
                sys.exit("wolfBoot entry breakpoint not reached")
            time.sleep(0.02)
        t.remove_breakpoint(entry & ~1)
        pc = t.read_core_register("pc")
    if not WOLFBOOT_TEXT[0] <= pc < WOLFBOOT_TEXT[1]:
        sys.exit("halted at 0x%08x, outside wolfBoot: too late to move the life cycle" % pc)
    t.write32(lc, value)
    t.write32(lc_red, value)
    got = (t.read32(lc) & 0xFF, t.read32(lc_red) & 0xFF)
    t.resume()
print("halted in wolfBoot at 0x%08x; shadow LC_STATE=0x%02x LC_STATE_RED=0x%02x"
      % (pc, got[0], got[1]))
sys.exit(0 if got == (value, value) else 3)
PYEOF
    sleep 3
    if hl="$(handoff_lifecycle)"; then
        echo "wolfTrust saw 0x$hl ($(psa_name "$hl"))"
    fi
    ;;

  regress)
    confirm
    ensure_spsdk
    timeout 60 pyocd reset -t "$target" -m hw >/dev/null 2>&1 || true
    "$here/lib/rt700_reset.sh" reset
    sleep 3
    read -r lc lcr < <(read_words "$LC_STATE" "$LC_STATE_RED" | tr '\n' ' '; echo)
    [ $((0x$lc & 0xFF)) -eq $((LC_DEVELOP)) ] && [ $((0x$lcr & 0xFF)) -eq $((LC_DEVELOP)) ] || \
        fail "regress" "life cycle after reset is 0x$lc/0x$lcr, not the fused Develop"
    pass "hardware reset reloaded the fused Develop life cycle"
    if hl="$(handoff_lifecycle)"; then
        [ "$hl" = "00001000" ] || fail "regress" "wolfTrust saw 0x$hl after regress"
        pass "wolfTrust booted ASSEMBLY_AND_TEST again"
    fi
    mkdir -p "$state_dir"
    date -u +%FT%TZ > "$state_dir/rt700-regress-ok"
    ;;

  provision-da|burn)
    cat >&2 <<EOF
REFUSED: '$cmd' programs OTP fuses, which is permanent on the MIMXRT700
(LOCK_CFG3 is open on this board, so nothing in silicon would stop it). A
production line burns RKTH, the debug credential root, and the life cycle
through NXP's secure provisioning flow (SB3.1 or blhost fuse-program) with a
debug credential chain it has already validated; this script never does.
EOF
    exit 2
    ;;

  set-perimeter|set-wrp|clear-wrp)
    cat >&2 <<EOF
'$cmd' has no MIMXRT700 form: the TrustZone perimeter and the XSPI guest fence
are programmed by wolfBoot and wolfTrust on every boot and cleared by every
reset, so there is no persistent state to set or clear. Use 'restore' to flash
the fenced chain and 'verify-wrp' to check the running fence.
EOF
    exit 2
    ;;

  *) echo "usage: $0 status|discover|verify-wrp|restore|advance <hexstate>|regress" >&2; exit 2 ;;
esac
