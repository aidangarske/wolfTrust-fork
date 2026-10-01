#!/usr/bin/env bash
# wolfTrust STM32H563 provisioning + lock control. One flag-driven entry point
# for the whole silicon lifecycle: set the OEM-iRoT option-byte perimeter, flash
# the wolfTrust chain, advance/regress product state for the reversible lock, and
# restore. It supersedes wolfBoot's set-stm32-tz-option-bytes.sh (which computes
# the wrong SECWM for wolfTrust's secure-alias layout and never sets BOOT_UBE)
# with the exact values captured from a known-good wolfTrust board, and folds in
# ST's tested DA provisioning/regression command order (ROT_Provisioning/DA).
#
# BRICK SAFETY (non-negotiable):
#   * board-writing commands refuse to run without WT_LOCK_CONFIRM=1
#   * the permanent Locked product state (0x5C) is refused outright
#   * regression returns to Open (fully debuggable, reflashable) — never a brick
#   * DA uses the certificate OBK that matches TZEN-enabled (ST AN6008 pairing)
#   * restore reproduces the captured-verified perimeter, so recovery is proven
#     on the Open board BEFORE any state advance is ever attempted
#
# Commands:
#   status                 read product state + option bytes (read-only)
#   set-perimeter          set the wolfTrust OEM-iRoT option bytes (restore pt 1)
#   flash                  flash wolfBoot + wolfTrust + guests (restore pt 2)
#   verify                 reset + capture UART, assert the wolfTrust chain boots
#   restore                set-perimeter + flash + verify (full recovery)
#   provision-da           -sdp the DA OBK (only valid in Provisioning state)
#   discover               prove the DA credential authenticates (non-destructive)
#   advance <hexstate>     set PRODUCT_STATE (GATED; Locked refused); rehearses it
#   regress                DA-authenticate + full regression back to Open (GATED)
#   lock <hexstate>        production step: 0x17 from Open; 0xC6, 0x72, or 0x5C
#                          (PERMANENT) from Provisioning. Needs a rehearsal of that
#                          state with these images; previews without
#                          WT_LOCK_CONFIRM=1, writes only with WT_PRODUCTION_LOCK=1
#                          and a typed "I ACCEPT <state>"
#
# TARGET=mimxrt700 runs the MIMXRT700 backend (provisioning_ctrl_rt700.sh).
set -euo pipefail

case "${TARGET:-stm32h563}" in
  stm32h563) ;;
  mimxrt700) exec "$(dirname "$0")/provisioning_ctrl_rt700.sh" "$@" ;;
  *) echo "no provisioning backend for TARGET=$TARGET (stm32h563|mimxrt700)" >&2; exit 2 ;;
esac

CP="${STM32_CP:-$HOME/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin}"
CLI="${STM32_CLI:-$CP/STM32_Programmer_CLI}"
SERIAL="${H5_SERIAL:-/dev/ttyACM0}"
repo="$(cd "$(dirname "$0")/../.." && pwd)"
state_dir="${WT_PROVISION_STATE:-$HOME/.cache/wolftrust}"
rehearsal_max_age="${WT_REHEARSAL_MAX_AGE:-3600}"

# ST DA credential from the pinned NUCLEO-H563ZI ROT_Provisioning/DA folder.
# wolfTrust runs with TrustZone ENABLED, so DA is CERTIFICATE-based: AN6008
# requires the certificate method when TZEN=0xB4, and a password OBK provisioned
# here cannot authenticate and blocks regression (verified on board
# 2026-08-19). Use DA_Config.obk with the leaf key and certificate chain, not
# DA_ConfigWithPassword.obk. Override once a wolfTrust-owned certificate chain
# replaces ST's sample.
DA_SAMPLE_DIR="$HOME/st-rot-h5/Projects/NUCLEO-H563ZI/ROT_Provisioning/DA"
# SHA-256 of every file in ST's public NUCLEO-H563ZI sample DA material
# (Binary, Keys, Certificates), so a renamed copy is caught without the tree.
DA_SAMPLE_SHA256="
2cafcf533300aebe1ebaaa2b6bd6e99c3502ef88acd668b2d41f910515527862
f4d40b1b669a635e15719eaf0f6fd9f7b5494e3616a6337d2c350eca7f2d4547
774e73f4c0ec7f9617da41405b0eb02d560ea498af8717de91b411203d1af499
32227fc98010224ab39dd8fb5bb3b917820047fb52a1be91551e9c7e6e424590
ef86c2ea01df5fdf526fb7a68fb4876436131f575093b3bc90f7428e677e72b2
b00d6ad78f9d8a5b1a9299bc618fd651b7637ed0873fb9104a674edd5a19569b
d21811a12f5533f474901f2bec27ae4c85c76a4968394e221edc55f4c291ac0a
1c343faca2e1c81c913afe520aa0de26b8b01a71c0ab2d7796a356cd4d127a59
67ba2294171501a8df9864da5d18ecee386b69f1f197138cb3452ed4aed8d854
d4ac966902c0129bd311a23794d5430d4e4ecb75071195135adfd64373c56d19
10ef8afae7bad8608cb01d803347dfc396210c65eaa2f808ce1b52b757a3ea3d
9c6c7589abc052671f107a5b3cc7e9437865b342ed5909d8fef73c3f5771b560
d8617a54b88c6061f310d75b66d6319e9b87212a8f53401f039067f9aa520894
9a77fd6ab8533715976bc83dc72182c3c1cb568f30fc3630e911eb1c64a33e59
"
DA_DIR="${WT_DA_DIR:-$DA_SAMPLE_DIR}"
DA_OBK="${WT_DA_OBK:-$DA_DIR/Binary/DA_Config.obk}"
DA_PWD="${WT_DA_PWD:-$DA_DIR/Binary/password.bin}"
DA_KEY="${WT_DA_KEY:-$DA_DIR/Keys/key_3_leaf.pem}"
DA_CERT="${WT_DA_CERT:-$DA_DIR/Certificates/cert_leaf_chain.b64}"
# ST ROT_Provisioning/DA connect strings (regression is sensitive to these).
DA_CONN="-c port=SWD speed=fast ap=1 mode=Hotplug"
DA_CONN_RST="-c port=SWD speed=fast ap=1 mode=Hotplug -hardRst"

# wolfTrust OEM-iRoT perimeter — the EXACT option bytes read from a known-good
# wolfTrust STM32H563 board. BOOT_UBE
# selects the OEM-iRoT boot path (so SECBOOTADD is unused); SECWM1 covers the
# secure wolfBoot+wolfTrust region, SECWM2 the secure bank-2 window.
# SECWM1_END must span the WHOLE boot partition (through 0x0809FFFF): with the
# earlier 0x3F, flash writes past 0x08080000 were silently dropped and wolfBoot
# integrity-rejected any secure image over 128K (found by MP5 confboot).
WT_OB=(TZEN=0xB4 BOOT_UBE=0xB4 SWAP_BANK=0x0
       SECWM1_STRT=0x0 SECWM1_END=0x4F SECWM2_STRT=0x0 SECWM2_END=0x7F)

# Guest-flash write protection (WRPSGn1, 0 = protected, 4 sectors per bit).
# 0x000FFFFF clears bits 20-31 -> bank-1 sectors 0x50-0x7F protected, the guest
# region; 0xFFFFFFFF leaves all sectors writable (factory default).
WRP_GUEST=0x000FFFFF; WRP_OPEN=0xFFFFFFFF

# Product-state codes (RM0481).
PS_OPEN=0xED; PS_PROVISIONING=0x17; PS_TZCLOSED=0xC6; PS_CLOSED=0x72; PS_LOCKED=0x5C

# Flash layout (matches run_h5_hardware.sh).
WOLFBOOT=0x0C000000; WOLFTRUST=0x0C060000; GUEST0=0x080A0000; GUEST1=0x080E0000
wb="$repo/wolfBoot/wolfboot.bin"
wt="$repo/build/wolftrust_v1_signed.bin"
g0="$repo/tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr/zephyr.bin"
g1="$repo/tests/firmware/zephyr-stm32h5/build/freertos_guest1/freertos_guest1.bin"

strip() { sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g'; }
pass()  { printf '  [check] PASS  %s\n' "$1"; }
fail()  { printf '  [check] FAIL  %s  (%s)\n' "$1" "$2"; exit 1; }
confirm() { [ "${WT_LOCK_CONFIRM:-0}" = "1" ] || {
    echo "REFUSED: '$cmd' writes to the board. Re-run with WT_LOCK_CONFIRM=1." >&2; exit 2; }; }
# A read right after a reset can return garbage, so only a known code counts.
product_state() {
  local v
  for _ in 1 2 3; do
    v="$("$CLI" -c port=SWD mode=HotPlug -ob displ 2>&1 | strip \
      | grep -iE "PRODUCT_STATE" | grep -oE "0x[0-9A-Fa-f]+" | head -1 || true)"
    case "$(printf '0x%02X' "$(( ${v:-0x100} ))")" in
      0xED|0x17|0x2E|0xC6|0x72|0x5C) echo "$v"; return 0 ;;
    esac
    sleep 2
  done
  return 1
}
hexstate() { printf '0x%02X' "$(( $1 ))"; }
ps_name() {
  case "$(hexstate "$1")" in
    0xED) echo "Open" ;; 0x17) echo "Provisioning" ;; 0xC6) echo "TZ-Closed" ;;
    0x72) echo "Closed" ;; 0x5C) echo "Locked" ;; *) echo "unknown" ;;
  esac
}
refuse() { echo "REFUSED: $1" >&2; exit 2; }
st_lifecycle() {
  case "$1" in
    0x17) echo "ST_LIFECYCLE_PROVISIONING" ;; 0xC6) echo "ST_LIFECYCLE_TZ_CLOSED" ;;
    0x72) echo "ST_LIFECYCLE_CLOSED" ;; 0x5C) echo "ST_LIFECYCLE_LOCKED" ;;
  esac
}
da_discovery() { "$CLI" $DA_CONN pwd="$DA_PWD" debugauth=2 2>&1 | strip; }
# A closed part drops the debug link, so its state is read by DA discovery.
da_lifecycle() { da_discovery | grep -oE "ST_LIFECYCLE_[A-Z_]+" | head -1; }
# Capture the UART across a reset the caller triggers; booted() reads it.
uart_capture() {
  stty -F "$SERIAL" 115200 raw -echo 2>/dev/null || true
  ( timeout "$1" cat "$SERIAL" > "$2" 2>/dev/null & )
}
booted() { strip < "$1" | grep -aqE "guest0_psa|heartbeat|TEE client"; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi
}
# Rehearsal records hold the digest of the images they proved, so a rebuild
# needs a fresh rehearsal before any lock step.
flashed_images() {
  printf '%s %s\n' "$WOLFBOOT" "$wb" "$WOLFTRUST" "$wt" "$GUEST0" "$g0" "$GUEST1" "$g1"
}
image_digest() {
  local a f
  while read -r a f; do [ -s "$f" ] || return 1; done < <(flashed_images)
  flashed_images | while read -r a f; do
    printf '%s %s\n' "$a" "$(wc -c < "$f" | tr -d ' ')"
    cat "$f"
  done | sha256 | cut -c1-64
}
# The flashed images read back over SWD match the host build. The running
# chain's protections hide guest flash from the debugger, so read under reset.
images_on_device() {
  local a f n=0 rc=0
  local -a reads=()
  while read -r a f; do
    reads+=(-u "$a" "$(wc -c < "$f" | tr -d ' ')" "/tmp/wt-readback.$n.bin")
    n=$((n + 1))
  done < <(flashed_images)
  "$CLI" -c port=SWD mode=UR "${reads[@]}" >/dev/null 2>&1 || rc=1
  "$CLI" -c port=SWD mode=UR -rst >/dev/null 2>&1 || true
  n=0
  while read -r a f; do
    [ "$rc" = 0 ] && cmp -s "/tmp/wt-readback.$n.bin" "$f" || rc=1
    n=$((n + 1))
  done < <(flashed_images)
  return "$rc"
}
# Every DA input a regression used: key, certificate chain, OBK, and password.
da_fingerprint() {
  local f
  for f in "$DA_KEY" "$DA_CERT" "$DA_OBK" "$DA_PWD"; do [ -s "$f" ] || return 1; done
  for f in "$DA_KEY" "$DA_CERT" "$DA_OBK" "$DA_PWD"; do sha256 < "$f"; done | sha256 | cut -c1-64
}
# da_is_sample <file>: the file is one of ST's sample DA files, by content.
da_is_sample() {
  local h s
  h="$(sha256 < "$1" | cut -c1-64)"
  case "$DA_SAMPLE_SHA256" in *"$h"*) return 0 ;; esac
  if [ -d "$DA_SAMPLE_DIR" ]; then
    while IFS= read -r s; do
      [ "$(sha256 < "$s" | cut -c1-64)" != "$h" ] || return 0
    done < <(find "$DA_SAMPLE_DIR" -type f)
  fi
  return 1
}
# A production part must not carry ST's public sample DA credential.
da_production_ready() {
  local f
  [ -n "${WT_DA_OBK:-}" ] && [ -n "${WT_DA_KEY:-}" ] && [ -n "${WT_DA_CERT:-}" ] || return 1
  for f in "$DA_OBK" "$DA_KEY" "$DA_CERT" "$DA_PWD"; do
    [ -s "$f" ] || return 1
    ! da_is_sample "$f" || return 1
  done
}
# The 96-bit device UID (RM0481 UID_BASE). It reads only under reset in Open;
# Provisioning masks it to zero.
device_uid() {
  local u
  u="$("$CLI" -c port=SWD mode=UR -r32 0x08FFF800 12 2>&1 | strip \
    | awk '$1 == "0x08FFF800" { print $3 $4 $5 }')"
  "$CLI" -c port=SWD mode=UR -rst >/dev/null 2>&1 || true
  case "$u" in
    ""|000000000000000000000000|ffffffffffffffffffffffff|FFFFFFFFFFFFFFFFFFFFFFFF) return 1 ;;
  esac
  echo "$u"
}
# One hash over the values of the perimeter and guest WRP option bytes this
# script sets (SECBOOTADD is unused with BOOT_UBE and a regression resets it).
ob_hash() {
  local lines
  lines="$("$CLI" -c port=SWD mode=HotPlug -ob displ 2>&1 | strip \
    | awk '$1 ~ /^(TZEN|BOOT_UBE|SWAP_BANK|SECWM[12]_(STRT|END)|WRPSGn1)$/ && $2 == ":" { print $1 "=" $3 }' \
    | sort || true)"
  [ "$(grep -c . <<<"$lines")" -eq 8 ] || return 1
  sha256 <<<"$lines" | cut -c1-64
}
# A read near a reset can be transient, so two reads in a row must agree.
ob_snapshot() {
  local a b
  a="$(ob_hash || true)"
  for _ in 1 2 3; do
    sleep 1
    b="$(ob_hash || true)"
    if [ -n "$b" ] && [ "$a" = "$b" ]; then
      echo "$b"
      return 0
    fi
    a="$b"
  done
  return 1
}
put() { mkdir -p "$state_dir"; echo "$2" > "$state_dir/h5-$1"; }
field() { sed -n "s/.* $1=\([^ ]*\).*/\1/p" <<<" $2"; }
fresh() {
  local age
  [ -n "${1:-}" ] || return 1
  age=$(($(date +%s) - $1))
  [ "$age" -ge 0 ] && [ "$age" -le "$rehearsal_max_age" ]
}
# rehearsed <state>: on one device, these images booted in <state> and a DA
# regression with these DA inputs brought it back, recently. Provisioning runs
# no wolfTrust chain, so its step needs only a regression from it or a closed
# state. Sets R_UID and R_OB from the record.
rehearsed() {
  local d s fp rec b=""
  d="$(image_digest)" || return 1
  fp="$(da_fingerprint || echo none)"
  if [ "$1" != "$PS_PROVISIONING" ]; then
    b="$(cat "$state_dir/h5-booted-$1" 2>/dev/null || true)"
    [ "$(field image "$b")" = "$d" ] || return 1
  fi
  for s in "$1" $([ "$1" = "$PS_PROVISIONING" ] && echo "$PS_TZCLOSED $PS_CLOSED"); do
    rec="$(cat "$state_dir/h5-regressed-$s" 2>/dev/null || true)"
    [ "$(field image "$rec")" = "$d" ] && [ "$(field da "$rec")" = "$fp" ] &&
      fresh "$(field time "$rec")" || continue
    [ -z "$b" ] || [ "$(field uid "$b")" = "$(field uid "$rec")" ] || continue
    R_UID="$(field uid "$rec")"
    R_OB="$(field ob "$rec")"
    return 0
  done
  return 1
}

cmd="${1:-status}"
case "$cmd" in
  status)
    "$CLI" -c port=SWD mode=HotPlug -ob displ 2>&1 | strip \
      | grep -iE "PRODUCT_STATE|TZEN|BOOT_UBE|SECWM|SECBOOT" | head -20
    ;;

  set-perimeter)
    confirm
    echo "Setting wolfTrust OEM-iRoT perimeter: ${WT_OB[*]}"
    # TZEN first (an off->on flip mass-erases); then the rest. Setting the same
    # values on an already-provisioned board is a safe no-op.
    "$CLI" -c port=SWD mode=UR -ob TZEN=0xB4 2>&1 | strip | tail -3
    "$CLI" -c port=SWD mode=UR -ob "${WT_OB[@]}" 2>&1 | strip | tail -4
    ;;

  set-wrp)
    # Write-protect the guest flash region so a privileged Non-secure guest
    # cannot reprogram a peer guest's image (WT-SYS-0002 hardware root fix).
    # WRPSGn1 groups four 8 KiB sectors per bit and 0 means protected, so
    # 0x000FFFFF protects bank-1 sectors 0x50-0x7F (0x080A0000-0x080FFFFF),
    # the whole guest region, and leaves the secure/FWU region writable. WRP is
    # mutable only in Open; run this AFTER flashing the guests (a protected
    # sector rejects the image write) and before advancing product state.
    confirm
    [ "$(product_state)" = "$PS_OPEN" ] || \
      fail "set-wrp" "WRP is settable only in Open ($PS_OPEN); state=$(product_state)"
    echo "Write-protecting guest flash (bank1 sectors 0x50-0x7F): WRPSGn1=$WRP_GUEST"
    "$CLI" -c port=SWD mode=UR -ob WRPSGn1="$WRP_GUEST" 2>&1 | strip | tail -4
    "$CLI" -c port=SWD mode=HotPlug -ob displ 2>&1 | strip | grep -iE "WRPSGn1"
    ;;

  clear-wrp)
    # Remove guest-flash write protection so the images can be reflashed.
    confirm
    echo "Clearing guest-flash write protection: WRPSGn1=$WRP_OPEN"
    "$CLI" -c port=SWD mode=UR -ob WRPSGn1="$WRP_OPEN" 2>&1 | strip | tail -4
    ;;

  flash)
    confirm
    rm -f "$state_dir/h5-readback"
    for f in "$wb" "$wt" "$g0" "$g1"; do
      [ -s "$f" ] || fail "flash" "missing image: $f (build first)"; done
    "$CLI" -c port=SWD mode=UR \
      -d "$wb" "$WOLFBOOT" -d "$wt" "$WOLFTRUST" \
      -d "$g0" "$GUEST0" -d "$g1" "$GUEST1" --verify -hardRst 2>&1 | strip \
      | grep -iE "verified successfully|error|download" | tail -4
    ;;

  verify)
    uart_capture 8 /tmp/wt-verify.log
    "$CLI" -c port=SWD mode=UR -rst >/dev/null 2>&1 || true
    sleep 7
    if booted /tmp/wt-verify.log; then
      pass "wolfTrust chain boots on silicon"
    else
      fail "verify" "no wolfTrust boot markers on $SERIAL"
    fi
    ;;

  restore)
    confirm
    WT_LOCK_CONFIRM=1 "$0" set-perimeter
    WT_LOCK_CONFIRM=1 "$0" clear-wrp
    WT_LOCK_CONFIRM=1 "$0" flash
    WT_LOCK_CONFIRM=1 "$0" set-wrp
    "$0" verify
    echo "PASS: wolfTrust restored and booting"
    ;;

  provision-da)
    confirm
    [ -s "$DA_OBK" ] || fail "provision-da" "DA OBK not found: $DA_OBK"
    [ "${WT_PRODUCTION_LOCK:-0}" != "1" ] || da_production_ready || \
      refuse "a production part needs its own DA credential: set WT_DA_OBK, WT_DA_KEY, and WT_DA_CERT, not ST's sample."
    [ "$(product_state)" = "$PS_PROVISIONING" ] || \
      fail "provision-da" "must be in Provisioning ($PS_PROVISIONING); state=$(product_state)"
    echo "Provisioning DA OBK (ST obk_provisioning.sh order): $DA_OBK"
    "$CLI" $DA_CONN_RST >/dev/null 2>&1 || true
    "$CLI" $DA_CONN -sdp "$DA_OBK" 2>&1 | strip | tail -5
    "$CLI" $DA_CONN_RST >/dev/null 2>&1 || true
    ;;

  discover)
    echo "DA discovery (non-destructive) with $DA_PWD:"
    da_discovery | grep -iE "PSA lifecycle|integrity|permission|Discovery Success|not supported|error" || true
    ;;

  advance)
    confirm
    state="${2:-}"
    case "$state" in
      "$PS_LOCKED"|0x5c) refuse "Locked (0x5C) is permanent, never on a dev board; production uses 'lock'." ;;
      "$PS_PROVISIONING"|"$PS_TZCLOSED"|"$PS_CLOSED"|0x17|0xc6|0x72) ;;
      *) refuse "advance needs a reversible state (0x17/0xC6/0x72), got '${state:-none}'." ;;
    esac
    state="$(hexstate "$state")"
    cur="$(product_state || true)"
    # From TZ-Closed the link cannot write the next state (seen 2026-08-19).
    if [ "$state" != "$PS_PROVISIONING" ] &&
       { [ -z "$cur" ] || [ "$(hexstate "$cur")" != "$PS_PROVISIONING" ]; }; then
      refuse "advance to $(ps_name "$state") runs only from Provisioning (0x17); state=${cur:-unreadable}."
    fi
    # Provisioning closes Secure debug, so the images are read back in Open.
    if [ "$state" = "$PS_PROVISIONING" ]; then
      rm -f "$state_dir/h5-readback"
      ob="$(ob_snapshot || true)"
      uid="$(device_uid || true)"
      if [ -n "$uid" ] && [ -n "$ob" ] && images_on_device; then
        put readback "image=$(image_digest) uid=$uid ob=$ob time=$(date +%s)"
        pass "the images on device $uid match the host build ($(image_digest | cut -c1-16))"
      else
        echo "could not read back the images, device UID, and option bytes; a closed-state rehearsal will refuse"
      fi
    else
      # Closed states are reversible only through a provisioned DA chain.
      disc="$(da_discovery)"
      grep -q "0xeaeaeaea" <<<"$disc" && grep -q "Full Regression" <<<"$disc" || \
        refuse "Debug Authentication is not provisioned (no intact OBK offering Full Regression): without it $(ps_name "$state") cannot be regressed. Run 'provision-da' and 'discover'."
      rb="$(cat "$state_dir/h5-readback" 2>/dev/null || true)"
      [ "$(field image "$rb")" = "$(image_digest)" ] && fresh "$(field time "$rb")" || \
        refuse "no recent read-back of these images: 'restore', then 'advance 0x17' from Open reads them back."
    fi
    echo "ADVANCING product state ${cur:-?} -> $state (regress is the only way back)"
    uart_capture 12 /tmp/wt-advance.log
    # The CLI fails its post-write reconnect once debug closes; the read-back decides.
    "$CLI" -c port=SWD mode=HotPlug -ob PRODUCT_STATE="$state" 2>&1 | strip | tail -4 || true
    mkdir -p "$state_dir"
    echo "$state" > "$state_dir/h5-advanced"
    sleep 10
    # The read-back above resets the part, so only a closed state's capture,
    # with nothing resetting it before the write, proves the boot.
    if [ "$state" = "$PS_PROVISIONING" ]; then
      echo "Provisioning does not run the wolfTrust chain; a closed-state rehearsal proves the boot"
    elif booted /tmp/wt-advance.log; then
      pass "wolfTrust chain boots in $(ps_name "$state")"
      put "booted-$state" "image=$(field image "$rb") uid=$(field uid "$rb") ob=$(field ob "$rb") time=$(date +%s)"
    else
      echo "no wolfTrust boot markers on $SERIAL after the write; the rehearsal needs them"
    fi
    now="$(product_state || true)"
    echo "now: ${now:-$(da_lifecycle || true)}"
    ;;

  lock)
    # One production step at a time, and only after 'advance' and 'regress'
    # rehearsed that state with these images. ST's rule: the closed states are
    # written from Provisioning, while the debug link can still write them.
    # Without WT_LOCK_CONFIRM=1 this is a read-only preview.
    [[ "${2:-}" =~ ^0[xX][0-9A-Fa-f]{2}$ ]] || \
      refuse "lock takes the next product state: 0x17, 0xC6, 0x72, or 0x5C."
    target="$(hexstate "$2")"
    case "$target" in
      0x17) from="$PS_OPEN"; rehearse=0x17 ;;
      0xC6) from="$PS_PROVISIONING"; rehearse=0xC6 ;;
      0x72) from="$PS_PROVISIONING"; rehearse=0x72 ;;
      0x5C) from="$PS_PROVISIONING"; rehearse=0x72 ;;
      *) refuse "lock takes the next product state: 0x17, 0xC6, 0x72, or 0x5C (got $target)." ;;
    esac
    cur="$(product_state || true)"
    [ -n "$cur" ] || refuse "cannot read the product state over SWD."
    cur="$(hexstate "$cur")"
    [ "$cur" = "$from" ] || \
      refuse "the part is $(ps_name "$cur") ($cur); lock $target runs only from $(ps_name "$from") ($from)."
    rehearsed "$rehearse" || \
      refuse "no rehearsal of $(ps_name "$rehearse") ($rehearse) with these images and DA certificate: run 'advance $rehearse' and 'regress' first."
    ob="$(ob_snapshot)" || refuse "cannot read the option bytes over SWD."
    [ "$ob" = "$R_OB" ] || \
      refuse "the perimeter or guest WRP option bytes differ from the rehearsal."
    # Provisioning hides the UID, so it is checked when the part enters it.
    if [ "$target" = "0x17" ]; then
      uid="$(device_uid)" || refuse "cannot read the device UID over SWD."
      [ "$uid" = "$R_UID" ] || \
        refuse "this part (UID $uid) is not the one rehearsed (UID $R_UID): rehearse this part."
      images_on_device || \
        refuse "the images on this part differ from the rehearsed build: 'restore' it first."
    else
      sess="$(cat "$state_dir/h5-session" 2>/dev/null || true)"
      uid="$(field uid "$sess")"
      [ -n "$uid" ] && [ "$uid" = "$R_UID" ] && fresh "$(field time "$sess")" &&
        [ "$(field image "$sess")" = "$(image_digest)" ] || \
        refuse "no recent 'lock 0x17' of the rehearsed part (UID $R_UID) on this station."
    fi
    digest="$(image_digest)"
    checked="order, rehearsal of $(ps_name "$rehearse") with images ${digest:0:16} on device $uid, same option bytes"
    [ "$target" != "0x17" ] || checked="$checked, images read back"
    if [ "$target" != "0x17" ]; then
      wrp="$("$CLI" -c port=SWD mode=HotPlug -ob displ 2>&1 | strip \
        | grep -iE "WRPSGn1" | grep -oE "0x[0-9A-Fa-f]+" | head -1 || true)"
      [ -n "$wrp" ] && [ $((wrp)) -eq $((WRP_GUEST)) ] || \
        refuse "guest flash is not write protected (WRPSGn1=${wrp:-unreadable}): run 'set-wrp' in Open first."
      checked="$checked, guest WRP"
    fi
    if [ "$target" = "0xC6" ] || [ "$target" = "0x72" ]; then
      if da_production_ready; then
        checked="$checked, production DA credential"
      else
        [ "${WT_PRODUCTION_LOCK:-0}" != "1" ] || \
          refuse "a production part needs its own DA credential: set WT_DA_OBK, WT_DA_KEY, and WT_DA_CERT, not ST's sample."
        checked="$checked, DA credential is ST's sample or unset (a production lock refuses it)"
      fi
      disc="$(da_discovery)"
      grep -q "0xeaeaeaea" <<<"$disc" && grep -q "Full Regression" <<<"$disc" || \
        refuse "Debug Authentication is not provisioned (no intact OBK offering Full Regression): run 'provision-da' and 'discover'."
      checked="$checked, DA provisioned"
    fi
    echo "Lock step: $(ps_name "$cur") ($cur) -> $(ps_name "$target") ($target)"
    echo "  checked: $checked"
    echo "  will run: $CLI -c port=SWD mode=HotPlug -ob PRODUCT_STATE=$target"
    [ "${WT_LOCK_CONFIRM:-0}" = "1" ] || \
        refuse "preview only, nothing was written. A production station re-runs this with WT_LOCK_CONFIRM=1."
    # shellcheck source=lib/lock_confirm.sh disable=SC1091
    . "$(dirname "$0")/lib/lock_confirm.sh"
    if [ "$target" = "$PS_LOCKED" ]; then
      lock_confirm "I ACCEPT $target" \
        "Locking this STM32H563: product state $cur -> $target (Locked)" \
        "This is IRREVERSIBLE: debug closes for good, no regression or mass erase, and only a wolfBoot-signed update can change the firmware." || exit 2
    else
      lock_confirm "I ACCEPT $target" \
        "Moving this STM32H563 to $(ps_name "$target") ($target)" \
        "Only a DA regression, which mass-erases the part, returns it to Open." || exit 2
    fi
    uart_capture 12 /tmp/wt-lock.log
    "$CLI" -c port=SWD mode=HotPlug -ob PRODUCT_STATE="$target" 2>&1 | strip | tail -4 || true
    sleep 10
    booted_ok=0
    if [ "$target" != "0x17" ] && booted /tmp/wt-lock.log; then
      booted_ok=1
      pass "wolfTrust chain boots in $(ps_name "$target")"
    fi
    if [ "$target" = "0x17" ]; then
      now="$(product_state || true)"
      [ -n "$now" ] && [ "$(hexstate "$now")" = "$target" ] || \
        fail "lock" "product state reads ${now:-unreadable} after the write, expected $target"
    else
      now="$(da_lifecycle || true)"
      [ "$now" = "$(st_lifecycle "$target")" ] || \
        fail "lock" "DA discovery reports ${now:-nothing} after the write, expected $(st_lifecycle "$target"); the write may still have landed, so do not repeat it"
      [ "$booted_ok" = "1" ] || \
        fail "lock" "the part is $(ps_name "$target") but wolfTrust did not boot on $SERIAL; do not ship it"
    fi
    pass "product state is $(ps_name "$target") ($target)"
    if [ "$target" = "0x17" ]; then
      put session "uid=$uid image=$digest time=$(date +%s)"
    else
      rm -f "$state_dir"/h5-booted-* "$state_dir"/h5-regressed-* \
        "$state_dir/h5-session" "$state_dir/h5-readback"
    fi
    ;;

  regress)
    confirm
    # Certificate DA Full Regression -> Open. VERIFIED on board 2026-08-19.
    # wolfTrust runs TZEN enabled, so the credential is the certificate (per=a).
    # Do NOT send debugauth=3 first: it locks the debug session and then blocks
    # AP access for the handshake. Reset to clear any stale lock, then
    # authenticate on a bare "-c port=SWD" (default NORMAL/under-reset so the RSS
    # answers) with the key+cert; CubeProgrammer selects the certificate because
    # TZEN is enabled and the RSS mass-erases the device back to Open.
    advanced="$(cat "$state_dir/h5-advanced" 2>/dev/null || true)"
    rb="$(cat "$state_dir/h5-readback" 2>/dev/null || true)"
    rm -f "$state_dir/h5-readback"
    echo "DA certificate Full Regression -> Open (mass-erase):"
    "$CLI" -c port=SWD mode=HotPlug -rst 2>&1 | strip | tail -1 || true
    "$CLI" -c port=SWD per=a key="$DA_KEY" cert="$DA_CERT" pwd="$DA_PWD" \
      debugauth=1 </dev/null 2>&1 | strip | tail -14
    # A Closed regression self-resets the part, so the first reconnect can race.
    after=""
    for _ in 1 2 3; do
      after="$(product_state || true)"
      [ -z "$after" ] || break
      sleep 3
    done
    echo "state after regression: ${after:-unreadable}"
    if [ -n "$after" ] && [ "$(hexstate "$after")" = "$PS_OPEN" ] && [ -n "$advanced" ]; then
      uid="$(device_uid || true)"
      if [ -n "$uid" ] && [ "$uid" = "$(field uid "$rb")" ]; then
        put "regressed-$advanced" "image=$(field image "$rb") da=$(da_fingerprint || echo none) uid=$uid ob=$(field ob "$rb") time=$(date +%s)"
        pass "regression of device $uid from $(ps_name "$advanced") recorded"
      else
        echo "device UID ${uid:-unreadable} does not match the rehearsal read-back; not recorded"
      fi
      rm -f "$state_dir/h5-advanced"
    fi
    ;;

  *) echo "usage: $0 status|set-perimeter|flash|verify|restore|provision-da|discover|advance <hexstate>|regress|lock <hexstate>" >&2; exit 2 ;;
esac
