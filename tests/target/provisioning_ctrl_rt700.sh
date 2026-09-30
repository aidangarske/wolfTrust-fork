#!/usr/bin/env bash
# wolfTrust MIMXRT700 provisioning + lock control, the RT700 sibling of
# provisioning_ctrl.sh. Runs on the host that owns the probe (pi5).
#
# BRICK SAFETY (non-negotiable):
#   * board-writing commands refuse to run without WT_LOCK_CONFIRM=1
#   * advance and regress never program a fuse: they move the OTP shadow
#     registers, which every hardware reset reloads from the fuses
#   * regress is a hardware reset through the pi4 line, which the debug port
#     cannot veto, so a shadow state that closes debug is still recoverable
#   * advance needs a clean read-only discover, and past Develop2 a proven
#     regress, the RT700 form of "recovery before any advance"
#   * only 'lock' burns, one life cycle step at a time, after a rehearsal of
#     that exact step, and only on a production station
#
# Commands:
#   status               life cycle, debug, and XSPI fence state (read-only)
#   discover             preflight that gates advance (read-only)
#   verify-wrp           the running chain's guest fence is armed (read-only)
#   restore              rebuild, flash, and verify the fenced production chain
#   advance <hexstate>   move the life cycle shadow: 0x07 Develop2, 0x0F
#                        In Field, 0xCF In Field Locked, 0x1F In Field Return
#                        (GATED); with a following regress it rehearses a lock
#   regress              hardware reset back to the fused life cycle (GATED)
#   lock <hexstate> [fuses.yaml]
#                        PERMANENT burn of the next life cycle state (0x07 from
#                        Develop, 0x0F from Develop2, 0xCF or 0x1F from In
#                        Field), optionally with a reviewed SPSDK fuse
#                        configuration. Needs RT700_ISP and a rehearsal;
#                        previews without WT_LOCK_CONFIRM=1, burns only with
#                        WT_PRODUCTION_LOCK=1 and a typed "I ACCEPT <state>"
#   provision-da, burn   refused: fuses are burned only through 'lock'
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
# OTP fuse word indexes blhost addresses (not shadow addresses).
FUSE_LC_RED=0x25
FUSE_LC=0x8F
FUSE_ROTKH=0x58
ROTKH_WORDS=12

# shellcheck source=lib/rt700_fence.sh disable=SC1091
. "$here/lib/rt700_fence.sh"

pass()  { printf '  [check] PASS  %s\n' "$1"; }
fail()  { printf '  [check] FAIL  %s  (%s)\n' "$1" "$2"; exit 1; }
confirm() { [ "${WT_LOCK_CONFIRM:-0}" = "1" ] || {
    echo "REFUSED: '$cmd' writes to the board. Re-run with WT_LOCK_CONFIRM=1." >&2; exit 2; }; }
refuse() { echo "REFUSED: $1" >&2; exit 2; }
lc_hex() { printf '0x%02X' $(( $1 & 0xFF )); }

# The life cycle fused when discover ran (the shadow can differ until a reset).
fused_lc() {
    local w
    w="$(sed -n 's/^LC=\(0x[0-9A-Fa-f]*\) .*/\1/p' "$state_dir/rt700-discovery-ok" 2>/dev/null)"
    [ -n "$w" ] && lc_hex "$w"
}

# The PSA life cycles wolfTrust may report while the life cycle is $1.
expect_psa() {
    case "$1" in
        0x03) echo "00001000" ;; 0x07) echo "00002000" ;;
        0x0F|0xCF) echo "00003000 00004000 00005000" ;; 0x1F) echo "00006000" ;;
    esac
}

# The states one burn may reach from fused $1; the fuses would take any bit
# superset, so skipping ahead is refused here.
next_lc() {
    case "$1" in
        0x03) echo "0x07" ;; 0x07) echo "0x0F" ;; 0x0F) echo "0xCF 0x1F" ;;
    esac
}

# Rehearsal records hold this digest, so a rebuild needs a fresh rehearsal.
image_digest() {
    [ -s "$elf" ] || return 1
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum < "$elf" | cut -c1-16
    else
        shasum -a 256 < "$elf" | cut -c1-16
    fi
}

# fuse_word <index>: the burned OTP word over the ISP connection, not the shadow.
fuse_word() {
    # shellcheck disable=SC2086  # RT700_ISP is a blhost option list
    blhost $RT700_ISP -j efuse-read-once "$1" 2>/dev/null |
        "$spsdk_venv/bin/python" -c '
import json, sys
r = json.load(sys.stdin)
if r.get("status", {}).get("value") != 0 or len(r.get("response", [])) != 2:
    sys.exit(1)
print("0x%08X" % r["response"][1])'
}

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
        0x03) echo "Develop" ;; 0x07) echo "Develop2" ;; 0x0F) echo "In Field" ;;
        0x1F) echo "In Field Return" ;; 0xCF) echo "In Field Locked" ;;
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

elf_sym() {
    arm-none-eabi-nm "$elf" | awk -v s="$1" '$3 == s { print "0x" $1; exit }'
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
    if [ -s "$elf" ]; then
        read -r vm rm < <(read_words "$(elf_sym g_wt_launch_verified_mask)" \
            "$(elf_sym g_wt_launch_refused_mask)" | tr '\n' ' '; echo)
        echo "guest launches   verified=0x${vm:-?} refused=0x${rm:-?}"
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
    [ "$(lc_hex "0x$lc")" = "$(lc_hex "0x$lcr")" ] || \
        fail "discover" "life cycle copies disagree (LC 0x$lc, RED 0x$lcr)"
    case "$(lc_hex "0x$lc")" in
      0x03|0x07|0x0F) ;;
      *) fail "discover" "fused life cycle $(lc_hex "0x$lc") ($(lc_name "0x$lc")) has no further rehearsal step" ;;
    esac
    pass "fused life cycle is $(lc_name "0x$lc") and its redundant copy agrees"
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
    [[ "$value" =~ ^0[xX][0-9A-Fa-f]{1,2}$ ]] || \
        refuse "advance takes 0x07, 0x0F, 0xCF, or 0x1F, got '${value:-none}'."
    value="$(lc_hex "$value")"
    case "$value" in
      0x07) ;;
      0x0F|0xCF|0x1F)
        [ -s "$state_dir/rt700-regress-ok" ] || \
            refuse "prove 'regress' from Develop2 before advancing to $value." ;;
      *) refuse "advance takes 0x07, 0x0F, 0xCF, or 0x1F, got '$value'." ;;
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
    mkdir -p "$state_dir"
    rm -f "$state_dir/rt700-booted-$value"
    echo "$value" > "$state_dir/rt700-advanced"
    hl="$(handoff_lifecycle)" || fail "advance" "no readable boot handoff after the advance"
    echo "wolfTrust saw 0x$hl ($(psa_name "$hl"))"
    case " $(expect_psa "$value") " in
      *" $hl "*) pass "wolfTrust booted with the $(lc_name "$value") life cycle" ;;
      *) fail "advance" "wolfTrust saw 0x$hl, not the life cycle of $value" ;;
    esac
    # In Field Return is decommissioned: wolfTrust need not launch guests there.
    if [ "$value" != "0x1F" ]; then
        read -r vm rm < <(read_words "$(elf_sym g_wt_launch_verified_mask)" \
            "$(elf_sym g_wt_launch_refused_mask)" | tr '\n' ' '; echo)
        [ -n "${vm:-}" ] && [ $((0x$vm)) -ne 0 ] && [ $((0x${rm:-1})) -eq 0 ] || \
            fail "advance" "guests did not all launch (verified=0x${vm:-?} refused=0x${rm:-?})"
        pass "guests launched (verified=0x$vm refused=0x$rm)"
    fi
    fence="open"
    if fence_line >/dev/null; then
        fence="armed"
    fi
    digest="$(image_digest)" || fail "advance" "no $elf to fingerprint the rehearsal"
    echo "fused=$(fused_lc) image=$digest fence=$fence" > "$state_dir/rt700-booted-$value"
    echo "rehearsal of $value recorded; 'regress' completes it"
    ;;

  regress)
    confirm
    ensure_spsdk
    timeout 60 pyocd reset -t "$target" -m hw >/dev/null 2>&1 || true
    "$here/lib/rt700_reset.sh" reset
    sleep 3
    fused="$(fused_lc || echo "$LC_DEVELOP")"
    read -r lc lcr < <(read_words "$LC_STATE" "$LC_STATE_RED" | tr '\n' ' '; echo)
    [ "$(lc_hex "0x$lc")" = "$fused" ] && [ "$(lc_hex "0x$lcr")" = "$fused" ] || \
        fail "regress" "life cycle after reset is 0x$lc/0x$lcr, not the fused $fused (run discover)"
    pass "hardware reset reloaded the fused $(lc_name "$fused") life cycle"
    if hl="$(handoff_lifecycle)"; then
        case " $(expect_psa "$fused") " in
          *" $hl "*) pass "wolfTrust booted $(psa_name "$hl") again" ;;
          *) fail "regress" "wolfTrust saw 0x$hl after regress" ;;
        esac
    fi
    mkdir -p "$state_dir"
    date -u +%FT%TZ > "$state_dir/rt700-regress-ok"
    advanced="$(cat "$state_dir/rt700-advanced" 2>/dev/null || true)"
    rm -f "$state_dir/rt700-advanced"
    if [ -n "$advanced" ] && [ -s "$state_dir/rt700-booted-$advanced" ]; then
        mv "$state_dir/rt700-booted-$advanced" "$state_dir/rt700-rehearsed-$advanced"
        pass "rehearsal of $advanced ($(lc_name "$advanced")) complete"
    fi
    ;;

  lock)
    # PERMANENT. One burn per life cycle step, only to the next state, only
    # after that step was rehearsed in the shadow registers with this image.
    # Without WT_LOCK_CONFIRM=1 everything up to the burn runs as a preview.
    value="${2:-}"
    config="${3:-}"
    [[ "$value" =~ ^0[xX][0-9A-Fa-f]{1,2}$ ]] || \
        refuse "lock takes the next life cycle state and an optional fuse configuration: lock <0x07|0x0F|0xCF|0x1F> [fuses.yaml]"
    value="$(lc_hex "$value")"
    case "$value" in
      0x07|0x0F|0xCF|0x1F) ;;
      *) refuse "lock takes 0x07, 0x0F, 0xCF, or 0x1F (got $value)." ;;
    esac
    [ -z "$config" ] || [ -s "$config" ] || refuse "no fuse configuration at $config."
    [ -n "${RT700_ISP:-}" ] || \
        refuse "set RT700_ISP to the blhost ISP connection (for example '-u 0x1fc9,0x014f')."
    ensure_spsdk
    command -v blhost >/dev/null 2>&1 || PATH="$spsdk_venv/bin:$PATH"

    if ! lc="$(fuse_word "$FUSE_LC")" || ! lcr="$(fuse_word "$FUSE_LC_RED")"; then
        refuse "cannot read the life cycle fuses over RT700_ISP ($RT700_ISP)."
    fi
    cur="$(lc_hex "$lc")"
    [ "$cur" = "$(lc_hex "$lcr")" ] || refuse "the life cycle fuses disagree (LC $lc, RED $lcr)."
    nx="$(next_lc "$cur")"
    case " $nx " in
      *" $value "*) ;;
      *) refuse "the part is fused $(lc_name "$cur") ($cur); its next step is ${nx:-none}, not $value." ;;
    esac

    digest="$(image_digest)" || refuse "no $elf: build the production image first."
    rec="$(cat "$state_dir/rt700-rehearsed-$value" 2>/dev/null || true)"
    rfused="$(sed -n 's/.*fused=\(0x[0-9A-F]*\).*/\1/p' <<<"$rec")"
    [ -n "$rfused" ] && [ $((rfused & ~cur & 0xFF)) -eq 0 ] &&
        [[ "$rec" == *" image=$digest "* ]] || \
        refuse "no rehearsal of $value ($(lc_name "$value")) with this image: run 'discover', 'advance $value', and 'regress' first."
    [ "$value" = "0x07" ] || [[ "$rec" == *" fence=armed" ]] || \
        refuse "the rehearsal of $value ran without the guest fence: 'restore' the fenced chain and rehearse again."

    mkdir -p "$state_dir"
    script="$state_dir/rt700-lock-$value-$(date -u +%Y%m%dT%H%M%SZ).bls"
    if [ -n "$config" ]; then
        command -v shadowregs >/dev/null 2>&1 || PATH="$spsdk_venv/bin:$PATH"
        shadowregs fuses-script -c "$config" -o "$script.raw" >/dev/null || \
            fail "lock" "shadowregs fuses-script could not build the burn script"
    else
        printf 'efuse-program-once %s %08X --no-verify\nefuse-program-once %s %08X --no-verify\n' \
            "$FUSE_LC_RED" "$((value))" "$FUSE_LC" "$((value))" > "$script.raw"
    fi
    # SPSDK 3.11 writes each command's --no-verify on its own line, which blhost
    # batch would run as a separate command after the fuse before it burned.
    rotkh="$("$spsdk_venv/bin/python" - "$script.raw" "$script" "$value" <<'PYEOF'
import re
import sys

target = int(sys.argv[3], 0)
cmds = []
for line in open(sys.argv[1]):
    text = line.split("#", 1)[0].rstrip()
    if not text.strip():
        continue
    if text[:1].isspace() and text.strip().startswith("--") and cmds:
        cmds[-1] += " " + text.strip()
    else:
        cmds.append(text.strip())
num = r"(0x[0-9a-fA-F]+|[0-9]+)"
shape = re.compile(r"^efuse-program-once %s (0x)?[0-9a-fA-F]+( --(no-)?verify)?( lock)?$" % num)
bad = [c for c in cmds if not shape.match(c)]
if bad:
    sys.exit("unexpected line: %s" % bad[0])
# The life cycle words (0x25 LC_STATE_RED, 0x8F LC_STATE) burn last, carry
# exactly the target state, and stay unlocked until the last step.
lc = [c for c in cmds if int(c.split()[1], 0) in (0x25, 0x8F)]
if sorted(int(c.split()[1], 0) for c in lc) != [0x25, 0x8F]:
    sys.exit("the burn must write both life cycle words exactly once")
for c in lc:
    if int(c.split()[2], 16) & 0xFF != target:
        sys.exit("life cycle word does not carry 0x%02X: %s" % (target, c))
    if c.endswith(" lock") and target not in (0xCF, 0x1F):
        sys.exit("locking a life cycle word before the last step: %s" % c)
cmds = [c for c in cmds if c not in lc] + lc
open(sys.argv[2], "w").write("".join(c + "\n" for c in cmds))
print(sum(1 for c in cmds if 0x58 <= int(c.split()[1], 0) <= 0x63))
PYEOF
)" || fail "lock" "the burn script is not safe to run as is"

    if [ "$value" = "0x0F" ] || [ "$value" = "0xCF" ]; then
        if [ "$rotkh" -lt "$ROTKH_WORDS" ]; then
            n=0
            while [ "$n" -lt "$ROTKH_WORDS" ]; do
                w="$(fuse_word "$((FUSE_ROTKH + n))")" || refuse "cannot read the root key hash fuses."
                [ $((w)) -eq 0 ] || break
                n=$((n + 1))
            done
            [ "$n" -lt "$ROTKH_WORDS" ] || \
                refuse "the root key table hash is not burned: provision it first (a fuse configuration with RKTH) so the ROM authenticates wolfBoot."
        fi
    fi

    echo "Lock step: fused $(lc_name "$cur") ($cur) -> $(lc_name "$value") ($value)"
    echo "  checked: order, rehearsal of $value with image $digest, guest fence, root key hash"
    echo "  will run: blhost $RT700_ISP batch $script"
    sed 's/^/    /' "$script"
    [ "${WT_LOCK_CONFIRM:-0}" = "1" ] || \
        refuse "preview only, nothing was written. A production station re-runs this with WT_LOCK_CONFIRM=1."
    # shellcheck source=lib/lock_confirm.sh disable=SC1091
    . "$here/lib/lock_confirm.sh"
    lock_confirm "I ACCEPT $value" \
        "Burning life cycle $(lc_name "$value") ($value) into this MIMXRT700's fuses" \
        "This is IRREVERSIBLE: fuses cannot be unburned, and the part never returns to $(lc_name "$cur")." || exit 2
    # shellcheck disable=SC2086  # RT700_ISP is a blhost option list
    blhost $RT700_ISP batch "$script"
    if ! lc="$(fuse_word "$FUSE_LC")" || ! lcr="$(fuse_word "$FUSE_LC_RED")"; then
        fail "lock" "cannot read the life cycle fuses back"
    fi
    [ "$(lc_hex "$lc")" = "$value" ] && [ "$(lc_hex "$lcr")" = "$value" ] || \
        fail "lock" "fuses read LC $lc, RED $lcr after the burn, expected $value"
    rm -f "$state_dir/rt700-rehearsed-$value"
    pass "life cycle fuses are $(lc_name "$value") ($value); reset the part, then run: $0 status"
    ;;

  provision-da|burn)
    cat >&2 <<EOF
REFUSED: '$cmd' programs OTP fuses, which is permanent on the MIMXRT700
(LOCK_CFG3 is open on a development EVK, so nothing in silicon would stop it).
A production station burns the root key hash, debug credential root, and life
cycle with 'lock <fuses.yaml>', from a configuration already rehearsed in the
shadow registers; see the MIMXRT700 Guide.
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

  *) echo "usage: $0 status|discover|verify-wrp|restore|advance <hexstate>|regress|lock <hexstate> [fuses.yaml]" >&2; exit 2 ;;
esac
