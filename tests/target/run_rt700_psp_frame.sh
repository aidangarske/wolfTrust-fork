#!/usr/bin/env bash
# Observe the compiled monitor under the authenticated real OS fixture.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
m33mu="${M33MU:-/tmp/m33mu_rt700_src/build/m33mu}"
boot="${RT700_WOLFBOOT_DIR:-/tmp/wolfboot_rt700}"
gdb="${ARM_GDB:-arm-none-eabi-gdb}"
port="${RT700_PSP_GDB_PORT:-19360}"
budget="${RT700_PSP_TIMEOUT:-180}"
[[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -gt 0 ] && [ "$port" -le 65535 ]
[[ "$budget" =~ ^[0-9]+$ ]] && [ "$budget" -gt 0 ]
for file in build/wolftrust.elf build/wolftrust_v1_signed.bin \
    tests/firmware/rt700-os/build/guest0.bin \
    tests/firmware/rt700-os/build/guest1.bin \
    "$boot/wolfboot.elf" "$boot/wolfboot.bin"; do
    [ -f "$file" ] || { echo "FAIL: missing PSP fixture artifact $file" >&2; exit 1; }
done
command -v "$gdb" > /dev/null
log=build/rt700_psp_frame
"$m33mu" --cpu imxrt700 --gdb --port "$port" \
    "$boot/wolfboot.bin" build/wolftrust_v1_signed.bin:0x40000 \
    tests/firmware/rt700-os/build/guest0.bin:0x80000 \
    tests/firmware/rt700-os/build/guest1.bin:0x100000 \
    --uart-stdout --timeout "$budget" > "$log.emulator.log" 2>&1 &
emulator_pid=$!
cleanup() {
    kill "$emulator_pid" 2>/dev/null || true
    wait "$emulator_pid" 2>/dev/null || true
}
trap cleanup EXIT
for attempt in $(seq 1 50); do
    grep -F 'Waiting for GDB connection' "$log.emulator.log" > /dev/null && break
    kill -0 "$emulator_pid" 2>/dev/null || { cat "$log.emulator.log"; exit 1; }
    sleep 0.1
done
if ! timeout "$budget" "$gdb" --batch \
    -ex "file build/wolftrust.elf" \
    -ex "add-symbol-file $boot/wolfboot.elf" \
    -ex "target remote localhost:$port" \
    -x tests/scripts/check_armv8m_psp_frame.gdb > "$log.gdb.log" 2>&1; then
    cat "$log.gdb.log"
    exit 1
fi
cat "$log.gdb.log"
grep -F 'PASS: NS PSP task frame metadata and independent MSP survive guest switches' \
    "$log.gdb.log" > /dev/null
