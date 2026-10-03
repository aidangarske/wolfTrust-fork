#!/usr/bin/env bash
# Check the same signed storage fixture over two resets with NOR retained.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
m33mu="${M33MU:-/tmp/m33mu_rt700_src/build/m33mu}"
boot="${RT700_WOLFBOOT_DIR:-/tmp/wolfboot_rt700}"
gdb="${ARM_GDB:-arm-none-eabi-gdb}"
port="${RT700_STORAGE_GDB_PORT:-19361}"
# The total covers two full PSA boots, each normally given 180 seconds.
budget="${RT700_STORAGE_TIMEOUT:-360}"
[[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -gt 0 ] && [ "$port" -le 65535 ]
[[ "$budget" =~ ^[0-9]+$ ]] && [ "$budget" -gt 0 ]
guest=tests/firmware/psa-guest/build
for file in build/wolftrust.elf build/wolftrust_v1_signed.bin \
    "$guest/guest0.elf" "$guest/guest1.elf" "$guest/guest0.bin" "$guest/guest1.bin" \
    "$boot/wolfboot.elf" "$boot/wolfboot.bin"; do
    [ -f "$file" ] || { echo "FAIL: missing storage fixture $file" >&2; exit 1; }
done
command -v "$gdb" > /dev/null
symbol() {
    arm-none-eabi-nm "$guest/guest$1.elf" |
        awk -v name="$2" '$3 == name { addr = "0x" $1; n++ }
            END { if (n != 1) exit 1; print addr }'
}
storage="$(symbol 0 g_storage_reset)"
mailbox="$(symbol 0 g_guest_mailbox)"
peer="$(symbol 1 g_guest_mailbox)"
measurement="$(python3 tests/scripts/read_wolfboot_measurement.py build/wolftrust_v1_signed.bin)"
[[ "$measurement" =~ ^[0-9a-f]{64}$ ]]
expected="$(python3 - "$measurement" <<'PYEOF'
import sys
print("{" + ",".join(f"0x{x:02x}" for x in bytes.fromhex(sys.argv[1])) + "}")
PYEOF
)"
log=build/rt700_storage_reset
"$m33mu" --cpu imxrt700 --gdb --port "$port" \
    "$boot/wolfboot.bin" build/wolftrust_v1_signed.bin:0x40000 \
    "$guest/guest0.bin:0x80000" "$guest/guest1.bin:0x100000" \
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
    -ex "set \$storage = (unsigned int *)$storage" \
    -ex "set \$guest = (unsigned int *)$mailbox" \
    -ex "set \$peer = (unsigned int *)$peer" \
    -ex "set \$expected = $expected" \
    -x tests/scripts/check_rt700_storage_reset.gdb > "$log.gdb.log" 2>&1; then
    cat "$log.gdb.log"
    exit 1
fi
cat "$log.gdb.log"
grep -F 'PASS: WT-FFM-0045 ITS and PS WRITE_ONCE data and flags survive reset' \
    "$log.gdb.log" > /dev/null
