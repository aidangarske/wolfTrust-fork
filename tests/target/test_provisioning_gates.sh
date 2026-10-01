#!/usr/bin/env bash
# Offline tests of the production lock gates in provisioning_ctrl.sh (STM32H5)
# and provisioning_ctrl_rt700.sh (MIMXRT700). Every vendor tool is a stub that
# records writes to a file; nothing here touches a board.
# shellcheck disable=SC2015  # result lines are "cond && pass || fail" on purpose
set -u
SRC="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
R="$T/repo"
mkdir -p "$R/build" "$R/wolfBoot" "$R/tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr" \
    "$R/tests/firmware/zephyr-stm32h5/build/freertos_guest1" "$T/st" "$T/bin" "$T/venv/bin"
cp -R "$SRC/tests/target" "$R/tests/"
echo wb > "$R/wolfBoot/wolfboot.bin"; echo wt > "$R/build/wolftrust_v1_signed.bin"
echo g0 > "$R/tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr/zephyr.bin"
echo g1 > "$R/tests/firmware/zephyr-stm32h5/build/freertos_guest1/freertos_guest1.bin"
echo elf > "$R/build/wolftrust.elf"
mkdir -p "$R/build/rt700" "$R/tests/firmware/mimxrt700-baremetal/build"
echo rwb > "$R/build/rt700/flash_wolfboot.bin"
echo rg0 > "$R/tests/firmware/mimxrt700-baremetal/build/guest0.bin"
echo rg1 > "$R/tests/firmware/mimxrt700-baremetal/build/guest1.bin"
SD="$T/home/st-rot-h5/Projects/NUCLEO-H563ZI/ROT_Provisioning/DA"
mkdir -p "$SD/Binary" "$SD/Keys" "$SD/Certificates" "$T/prodda"
echo sobk > "$SD/Binary/DA_Config.obk"; echo spwd > "$SD/Binary/password.bin"
echo skey > "$SD/Keys/key_3_leaf.pem"; echo scert > "$SD/Certificates/cert_leaf_chain.b64"
echo pobk > "$T/prodda/obk"; echo pkey > "$T/prodda/key"; echo pcert > "$T/prodda/cert"; echo ppwd > "$T/prodda/pwd"
echo pkey2 > "$T/prodda/key2"
mkdir -p "$T/flash"

# STM32 CLI stub: state in $T/ps, $T/wrp; logs writes to $T/writes.
cat > "$T/bin/stcli" <<EOF
#!/usr/bin/env bash
ps=\$(cat $T/ps)
args=("\$@")
for i in "\${!args[@]}"; do
  if [ "\${args[\$i]}" = "-u" ]; then cp "$T/flash/\${args[\$((i+1))]}" "\${args[\$((i+3))]}"; read_done=1; fi
  if [ "\${args[\$i]}" = "-r32" ]; then
    if [ "\$ps" = 0xED ] && [[ " \$* " == *" mode=UR "* ]]; then echo "0x08FFF800 : \$(cat $T/uid)"; else echo "0x08FFF800 : 00000000 00000000 00000000"; fi; exit 0; fi
done
[ -z "\${read_done:-}" ] || exit 0
for a in "\$@"; do
  case "\$a" in
    displ) case "\$ps" in 0x72|0xC6|0x5C) echo "Error: Cannot connect to access port 1!"; exit 1 ;; esac
           echo "     PRODUCT_STATE: \$ps"; echo "     TZEN         : \$(cat $T/tzen) (Trust zone)"
           echo "     BOOT_UBE     : 0xB4 (OEM-iRoT)"; echo "     SWAP_BANK    : 0x0 (0x0)"
           echo "     SECBOOTADD   : 0x\$RANDOM (0x0)"
           echo "     SECWM1_STRT  : 0x0 (0x8000000)"; echo "     SECWM1_END   : 0x4F  (0x809E000)"
           echo "     SECWM2_STRT  : 0x0 (0x8100000)"; echo "     SECWM2_END   : 0x7F  (0x81FE000)"
           echo "     WRPSGn1      : \$(cat $T/wrp) (0x\$RANDOM)" ;;
    debugauth=2) case "\$ps" in 0xED) l=OPEN ;; 0x17) l=PROVISIONING ;; 0xC6) l=TZ_CLOSED ;; 0x72) l=CLOSED ;; *) exit 1 ;; esac
           echo "discovery: PSA lifecycle...................:ST_LIFECYCLE_\$l"
           echo "discovery: ST provisioning integrity status:\$(cat $T/da)"
           [ "\$(cat $T/da)" = 0xeaeaeaea ] && echo "discovery: permission if authorized........:(a/14) ==> Full Regression"; true ;;
    debugauth=1) echo 0xED > $T/ps; echo "Debug Authentication Success" ;;
    PRODUCT_STATE=*) echo "\$a" >> $T/writes; echo "\${a#PRODUCT_STATE=}" > $T/ps; echo "Error: failed to reconnect after reset !"; exit 1 ;;
  esac
done
EOF
printf '#!/bin/sh\nshift\nexec "$@"\n' > "$T/bin/timeout"; chmod +x "$T/bin/timeout"
echo "guest0_psa heartbeat" > "$T/uart"; echo 0xf5f5f5f5 > "$T/da"
# blhost stub: fuses in $T/fuse.<index-decimal>; batch logs to $T/writes.
cat > "$T/venv/bin/blhost" <<EOF
#!/usr/bin/env bash
while [ "\${1:-}" != "efuse-read-once" ] && [ "\${1:-}" != "batch" ] && [ \$# -gt 0 ]; do shift; done
case "\$1" in
  efuse-read-once) i=\$((\$2)); v=\$(cat $T/fuse.\$i 2>/dev/null || echo 0)
    printf '{"command":"efuse-read-once","response":[4,%d],"status":{"value":0}}\n' \$((v)) ;;
  batch) cat "\$2" >> $T/writes
    while read -r c a d _; do i=\$((a)); o=\$(cat $T/fuse.\$i 2>/dev/null || echo 0)
      echo \$(( o | 0x\$d )) > $T/fuse.\$i; done < "\$2" ;;
esac
EOF
cat > "$T/venv/bin/pyocd" <<EOF
#!/bin/sh
[ "\$1" = list ] || exit 0
echo "  #   Probe/Board   Unique ID   Target"
echo "-----------------------------------"
n=0; for u in \$(cat $T/probe 2>/dev/null); do echo "  \$n   NXP MCU-LINK on-board   \$u   n/a"; n=\$((n+1)); done
EOF
echo PROBEA > "$T/probe"
cp "$T/bin/timeout" "$T/venv/bin/timeout"
printf '#!/bin/sh\nexec %s "$@"\n' "$(command -v python3)" > "$T/venv/bin/python"; chmod +x "$T/venv/bin/python"
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; }
subst() { sed "s/$1/$2/" "$3" > "$3.tmp" && mv "$3.tmp" "$3"; }
have_expect=0; command -v expect >/dev/null 2>&1 && have_expect=1
chmod +x "$T/bin/stcli" "$T/venv/bin/blhost" "$T/venv/bin/pyocd"

pass=0; failn=0
check() { # check <name> <expected-rc> <grep-in-output> -- cmd...
  local name="$1" want="$2" pat="$3"; shift 4
  out="$("$@" 2>&1 </dev/null)"; rc=$?
  if [ "$rc" = "$want" ] && grep -q -- "$pat" <<<"$out"; then pass=$((pass+1)); echo "ok   $name"
  else failn=$((failn+1)); echo "FAIL $name (rc=$rc want=$want)"; echo "$out" | sed 's/^/     /' | tail -6; fi
}
nowrite() { if [ -s "$T/writes" ]; then failn=$((failn+1)); echo "FAIL a refusal wrote: $(cat "$T/writes")"; : > "$T/writes"; fi; }

H5=(env HOME="$T/home" PATH="$T/bin:$PATH" STM32_CLI="$T/bin/stcli" H5_SERIAL="$T/uart" WT_PROVISION_STATE="$T/st" "$R/tests/target/provisioning_ctrl.sh")
dafp() { for f in "$@"; do sha < "$f"; done | sha | cut -c1-64; }
SFP="$(dafp "$SD/Keys/key_3_leaf.pem" "$SD/Certificates/cert_leaf_chain.b64" "$SD/Binary/DA_Config.obk" "$SD/Binary/password.bin")"
PFP="$(dafp "$T/prodda/key" "$T/prodda/cert" "$T/prodda/obk" "$T/prodda/pwd")"
flashsync() { cp "$R/wolfBoot/wolfboot.bin" "$T/flash/0x0C000000"; cp "$R/build/wolftrust_v1_signed.bin" "$T/flash/0x0C060000"
  cp "$R/tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr/zephyr.bin" "$T/flash/0x080A0000"
  cp "$R/tests/firmware/zephyr-stm32h5/build/freertos_guest1/freertos_guest1.bin" "$T/flash/0x080E0000"; }
flashsync
# The STM32H5 image digest provisioning_ctrl.sh records (address, size, bytes).
dig() {
  local a p
  for a in 0x0C000000 0x0C060000 0x080A0000 0x080E0000; do
    p="$T/flash/$a"; printf '%s %s\n' "$a" "$(wc -c < "$p" | tr -d ' ')"; cat "$p"
  done | sha | cut -c1-64
}
PROD=(WT_DA_OBK="$T/prodda/obk" WT_DA_KEY="$T/prodda/key" WT_DA_CERT="$T/prodda/cert" WT_DA_PWD="$T/prodda/pwd")
: > "$T/writes"; echo 0xED > "$T/ps"; echo 0x000FFFFF > "$T/wrp"; echo 0xB4 > "$T/tzen"; echo "00210045 33325112 38363236" > "$T/uid"
echo "== H5"
check "no state"             2 "lock takes the next"   -- "${H5[@]}" lock
check "unknown state"        2 "lock takes the next"   -- "${H5[@]}" lock 0x99
check "Locked from Open"     2 "runs only from Provisioning" -- "${H5[@]}" lock 0x5C
check "Closed from Open"     2 "runs only from Provisioning" -- "${H5[@]}" lock 0x72
check "Provisioning unrehearsed" 2 "no rehearsal of Provisioning" -- "${H5[@]}" lock 0x17
check "advance Closed from Open" 2 "runs only from Provisioning" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance 0x72
nowrite
echo x >> "$R/build/wolftrust_v1_signed.bin"
check "advance 0x17 with host images not on the part" 0 "could not read back" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance 0x17
echo 0xeaeaeaea > "$T/da"
check "closing advance without a read-back" 2 "no recent read-back" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance 0x72
echo 0xf5f5f5f5 > "$T/da"
echo wt > "$R/build/wolftrust_v1_signed.bin"; echo 0xED > "$T/ps"; : > "$T/writes"
check "advance 0x17 reads back images and UID in Open" 0 "the images on device 002100453332511238363236 match" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance 0x17
: > "$T/writes"
check "Closed unrehearsed"   2 "no rehearsal of Closed" -- "${H5[@]}" lock 0x72
check "closed advance without DA" 2 "cannot be regressed" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance 0x72
nowrite
echo 0xeaeaeaea > "$T/da"
check "advance Closed, boot captured, DA readback" 0 "now: ST_LIFECYCLE_CLOSED" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance 0x72
: > "$T/writes"
check "lock while Closed (link down)" 2 "cannot read the product state" -- "${H5[@]}" lock 0x72
check "regress records the device" 0 "regression of device 002100453332511238363236 from Closed recorded" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" regress
grep -q "da=$SFP uid=002100453332511238363236" "$T/st/h5-regressed-0x72" && { pass=$((pass+1)); echo "ok   regression record binds DA inputs and UID"; } || { failn=$((failn+1)); echo "FAIL regressed record: $(cat "$T/st/h5-regressed-0x72")"; }
check "lock 0x17 preview on the rehearsed part" 2 "on device 002100453332511238363236, same option bytes" -- "${H5[@]}" lock 0x17
echo "11111111 22222222 33333333" > "$T/uid"
check "lock 0x17 on another part" 2 "is not the one rehearsed" -- "${H5[@]}" lock 0x17
echo "00210045 33325112 38363236" > "$T/uid"
echo bad > "$T/flash/0x080A0000"
check "lock 0x17 with different flash" 2 "differ from the rehearsed build" -- "${H5[@]}" lock 0x17
flashsync
echo 0xC3 > "$T/tzen"
check "option bytes changed since the rehearsal" 2 "option bytes differ from the rehearsal" -- "${H5[@]}" lock 0x17
echo 0xB4 > "$T/tzen"
cp "$T/st/h5-regressed-0x72" "$T/regressed.keep"
subst "time=[0-9]*" "time=$(( $(date +%s) - 7200 ))" "$T/st/h5-regressed-0x72"
check "expired rehearsal"    2 "no rehearsal of Provisioning" -- "${H5[@]}" lock 0x17
cp "$T/regressed.keep" "$T/st/h5-regressed-0x72"
nowrite
H5X="env HOME=$T/home PATH=$T/bin:$PATH STM32_CLI=$T/bin/stcli H5_SERIAL=$T/uart WT_PROVISION_STATE=$T/st WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 $R/tests/target/provisioning_ctrl.sh"
if [ "$have_expect" = 1 ]; then
out="$(expect -c "set timeout 30; spawn $H5X lock 0x17; expect \"to continue: \"; send \"I ACCEPT 0x17\r\"; expect eof; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 0 ] && [ "$(cat "$T/ps")" = 0x17 ] && grep -q "uid=002100453332511238363236" "$T/st/h5-session" && { pass=$((pass+1)); echo "ok   lock 0x17 (stub) opens a session for the verified UID"; } || { failn=$((failn+1)); echo "FAIL lock 0x17 rc=$rc"; echo "$out" | tail -4; }
else
  echo "skip typed lock 0x17 (no expect); simulating its session"
  echo "uid=002100453332511238363236 image=$(dig) time=$(date +%s)" > "$T/st/h5-session"; echo 0x17 > "$T/ps"
fi
: > "$T/writes"; echo 0xf5f5f5f5 > "$T/da"
check "Closed without DA"    2 "Debug Authentication is not provisioned" -- "${H5[@]}" lock 0x72
echo 0xeaeaeaea > "$T/da"
check "Closed preview with sample DA" 2 "DA credential is ST's sample" -- "${H5[@]}" lock 0x72
check "Locked preview from Provisioning" 2 "Provisioning (0x17) -> Locked (0x5C)" -- "${H5[@]}" lock 0x5C
check "no production opt-in" 2 "Only a production station" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" lock 0x72
check "production lock with ST sample DA" 2 "needs its own DA credential" -- env WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${H5[@]}" lock 0x72
check "production DA set to sample copies" 2 "needs its own DA credential" -- env WT_DA_OBK="$SD/Binary/DA_Config.obk" WT_DA_KEY="$SD/Keys/key_3_leaf.pem" WT_DA_CERT="$SD/Certificates/cert_leaf_chain.b64" WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${H5[@]}" lock 0x72
check "production provision-da with sample" 2 "needs its own DA credential" -- env WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${H5[@]}" provision-da
check "rehearsed with sample, locking with production DA" 2 "no rehearsal of Closed" -- env "${PROD[@]}" "${H5[@]}" lock 0x72
subst "da=$SFP" "da=$PFP" "$T/st/h5-regressed-0x72"
check "DA key swapped after the rehearsal" 2 "no rehearsal of Closed" -- env "${PROD[@]}" WT_DA_KEY="$T/prodda/key2" "${H5[@]}" lock 0x72
check "production DA preview" 2 "production DA credential" -- env "${PROD[@]}" "${H5[@]}" lock 0x72
mv "$T/st/h5-session" "$T/session.keep"
check "closing lock without a session" 2 "no recent 'lock 0x17'" -- env "${PROD[@]}" "${H5[@]}" lock 0x72
mv "$T/session.keep" "$T/st/h5-session"
check "piped confirmation"   2 "interactive terminal"   -- env "${PROD[@]}" WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${H5[@]}" lock 0x72
check "TZ-Closed unrehearsed" 2 "no rehearsal of TZ-Closed" -- env "${PROD[@]}" "${H5[@]}" lock 0xC6
echo x >> "$R/build/wolftrust_v1_signed.bin"
check "rebuilt images"       2 "no rehearsal of Closed" -- env "${PROD[@]}" "${H5[@]}" lock 0x72
echo wt > "$R/build/wolftrust_v1_signed.bin"
nowrite
if [ "$have_expect" = 1 ]; then
H5X="env HOME=$T/home WT_DA_OBK=$T/prodda/obk WT_DA_KEY=$T/prodda/key WT_DA_CERT=$T/prodda/cert WT_DA_PWD=$T/prodda/pwd PATH=$T/bin:$PATH STM32_CLI=$T/bin/stcli H5_SERIAL=$T/uart WT_PROVISION_STATE=$T/st WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 $R/tests/target/provisioning_ctrl.sh"
for phrase in "yes" "LOCK 0x72" "I ACCEPT 0x5C" "i accept 0x72"; do
  expect -c "set timeout 5; spawn $H5X lock 0x72; expect \"to continue: \"; send \"$phrase\r\"; expect eof; catch wait r; exit [lindex \$r 3]" >/dev/null
  rc=$?; [ $rc = 2 ] && [ ! -s "$T/writes" ] && { pass=$((pass+1)); echo "ok   wrong phrase '$phrase' refused"; } || { failn=$((failn+1)); echo "FAIL phrase '$phrase' rc=$rc"; }
done
mv "$T/uart" "$T/uart.ok"; : > "$T/uart"
out="$(expect -c "set timeout 30; spawn $H5X lock 0x72; expect \"to continue: \"; send \"I ACCEPT 0x72\r\"; expect eof; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 1 ] && grep -q "wolfTrust did not boot" <<<"$out" && [ -e "$T/st/h5-regressed-0x72" ] && { pass=$((pass+1)); echo "ok   Closed write without a boot fails and keeps the records"; } || { failn=$((failn+1)); echo "FAIL no-boot lock rc=$rc"; echo "$out" | tail -4; }
mv "$T/uart.ok" "$T/uart"; : > "$T/writes"; echo 0x17 > "$T/ps"
out="$(expect -c "set timeout 30; spawn $H5X lock 0x72; expect \"to continue: \"; send \"I ACCEPT 0x72\r\"; expect eof; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 0 ] && grep -q "PRODUCT_STATE=0x72" "$T/writes" && grep -q "product state is Closed" <<<"$out" && ! ls "$T"/st/h5-regressed-* >/dev/null 2>&1 && [ ! -e "$T/st/h5-session" ] && { pass=$((pass+1)); echo "ok   exact phrase writes 0x72 (stub) and consumes the rehearsal"; } || { failn=$((failn+1)); echo "FAIL exact phrase rc=$rc"; echo "$out" | tail -5; }
: > "$T/writes"; echo 0x17 > "$T/ps"
else
  echo "skip typed confirmation tests (no expect)"
  rm -f "$T"/st/h5-regressed-* "$T"/st/h5-booted-*
fi
check "a consumed rehearsal cannot lock again" 2 "no rehearsal of Closed" -- env "${PROD[@]}" "${H5[@]}" lock 0x5C
nowrite

echo "== RT700"
RT=(env TARGET=mimxrt700 RT700_SPSDK_VENV="$T/venv" RT700_PROVISION_STATE="$T/st" PATH="$T/venv/bin:$PATH" "$R/tests/target/provisioning_ctrl.sh")
ISP=(RT700_ISP="-u 0x1fc9,0x014f")
fuse() { echo "$2" > "$T/fuse.$(($1))"; }
edig() { cat "$R/build/rt700/flash_wolfboot.bin" "$R/build/wolftrust_v1_signed.bin" \
  "$R/tests/firmware/mimxrt700-baremetal/build/guest0.bin" \
  "$R/tests/firmware/mimxrt700-baremetal/build/guest1.bin" | sha | cut -c1-64; }
rec() { echo "fused=$1 image=$2 fence=$3 probe=${6:-PROBEA} time=${4:-$(date +%s)}" > "$T/st/rt700-rehearsed-$5"; }
rm -f "$T"/fuse.* "$T"/st/rt700-*; fuse 0x8F 0x03; fuse 0x25 0x03
check "no state"             2 "lock takes the next"   -- "${RT[@]}" lock
check "unknown state"        2 "lock takes 0x07"       -- "${RT[@]}" lock 0x05
for s in 0x0F 0xCF 0x1F; do
  check "$s refused until ROM auth" 2 "needs the BootROM to authenticate wolfBoot" -- env "${ISP[@]}" "${RT[@]}" lock $s
done
check "no ISP"               2 "set RT700_ISP"          -- "${RT[@]}" lock 0x07
fuse 0x25 0x07
check "copies disagree"      2 "disagree"               -- env "${ISP[@]}" "${RT[@]}" lock 0x07
fuse 0x25 0x03
check "Develop2 unrehearsed" 2 "no rehearsal of 0x07"   -- env "${ISP[@]}" "${RT[@]}" lock 0x07
rec 0x03 0000 open "" 0x07
check "rehearsed other images" 2 "no rehearsal of 0x07" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
rec 0x03 "$(edig)" open $(( $(date +%s) - 7200 )) 0x07
check "stale rehearsal"      2 "not from the last 3600s" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
rec 0x03 "$(edig)" open $(( $(date +%s) + 600 )) 0x07
check "future-dated rehearsal" 2 "not from the last 3600s" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
rec 0x03 "$(edig)" open $(( $(date +%s) - 3590 )) 0x07
check "rehearsal just inside the hour" 2 "preview only" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
rec 0x03 "$(edig)" open "" 0x07
echo x >> "$R/tests/firmware/mimxrt700-baremetal/build/guest1.bin"
check "guest image changed"  2 "no rehearsal of 0x07"   -- env "${ISP[@]}" "${RT[@]}" lock 0x07
echo rg1 > "$R/tests/firmware/mimxrt700-baremetal/build/guest1.bin"
rec 0x03 "$(edig)" open "" 0x07 PROBEB
check "rehearsed through another probe" 2 "not run through this part's probe" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
rec 0x03 "$(edig)" open "" 0x07
: > "$T/probe"
check "no probe attached"    2 "attach exactly one debug probe" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
echo "PROBEA PROBEB" > "$T/probe"
check "two probes attached"  2 "attach exactly one debug probe" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
echo PROBEA > "$T/probe"
check "Develop2 preview"     2 "efuse-program-once 0x8F 00000007" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
check "preview names the probe" 2 "through probe PROBEA" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
check "no production opt-in" 2 "Only a production station" -- env WT_LOCK_CONFIRM=1 "${ISP[@]}" "${RT[@]}" lock 0x07
check "piped confirmation"   2 "interactive terminal"   -- env WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${ISP[@]}" "${RT[@]}" lock 0x07
nowrite
check "fuse configuration refused" 2 "cannot be burned yet" -- env "${ISP[@]}" "${RT[@]}" lock 0x07 "$T/fuses.yaml"
nowrite
if [ "$have_expect" = 1 ]; then
RTX="env TARGET=mimxrt700 RT700_SPSDK_VENV=$T/venv RT700_PROVISION_STATE=$T/st PATH=$T/venv/bin:$PATH RT700_ISP=-u0x1fc9,0x014f WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 $R/tests/target/provisioning_ctrl.sh"
expect -c "set timeout 5; spawn $RTX lock 0x07; expect \"to continue: \"; send \"BURN 0x07\r\"; expect eof; catch wait r; exit [lindex \$r 3]" >/dev/null
rc=$?; [ $rc = 2 ] && [ ! -s "$T/writes" ] && { pass=$((pass+1)); echo "ok   old phrase refused"; } || { failn=$((failn+1)); echo "FAIL old phrase rc=$rc"; }
expect -c "set timeout 5; spawn $RTX lock 0x07; expect \"to continue: \"; send \"I ACCEPT 0x07\r\"; expect eof; catch wait r; exit [lindex \$r 3]" >/dev/null
rc=$?; [ $rc = 0 ] && [ "$(cat "$T/fuse.143")" = 7 ] && [ "$(cat "$T/fuse.37")" = 7 ] && [ ! -e "$T/st/rt700-rehearsed-0x07" ] && { pass=$((pass+1)); echo "ok   exact phrase burns 0x07 (stub), rehearsal consumed"; } || { failn=$((failn+1)); echo "FAIL exact phrase rc=$rc"; }
[ "$(head -1 "$T/writes" | cut -d' ' -f2)" = 0x25 ] && { pass=$((pass+1)); echo "ok   LC words in burn order RED then LC"; } || { failn=$((failn+1)); echo "FAIL order"; }
: > "$T/writes"
: > "$T/writes"
else
  echo "skip typed burn tests (no expect)"; fuse 0x8F 0x07; fuse 0x25 0x07
fi
check "again after burn"     2 "next step is 0x0F, not 0x07" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
nowrite
echo "provisioning gates: $pass passed, $failn failed"
[ "$failn" = 0 ]
