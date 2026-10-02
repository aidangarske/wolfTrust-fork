#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
base="$root/tests/firmware/rt700-os"
psa="$root/tests/firmware/psa-guest"
h5="$root/tests/firmware/zephyr-stm32h5"
freertos="${FREERTOS_DIR:-$base/.workspace/freertos}/FreeRTOS/Source"
port="$freertos/portable/GCC/ARM_CM33_NTZ/non_secure"
export ZEPHYR_BASE="${ZEPHYR_BASE:-$h5/.workspace/zephyrproject/zephyr}"
west="${WEST_BIN:-$h5/.venv/bin/west}"
export WT_EXPECTED_LIFECYCLE="${WT_EXPECTED_LIFECYCLE:-0x1000u}"
rm -rf "$base/build/psa-zephyr" "$base/build/psa-freertos"
mkdir -p "$base/build"
make -s -C "$psa" TARGET=mimxrt700 WT_GUEST_OS=zephyr \
    BUILD="$base/build/psa-zephyr" "$base/build/psa-zephyr/guest0.a"
"$west" build -p always -d "$base/build/zephyr" -b wolftrust_rt700_ns \
    "$base/zephyr" -- \
    "-DUSER_CACHE_DIR=$base/build/cache" \
    "-DWOLFTRUST_CMSE_IMPLIB=$root/build/secure_cmse_implib.o" \
    "-DWOLFTRUST_PSA_ARCHIVE=$base/build/psa-zephyr/guest0.a"
make -s -C "$psa" TARGET=mimxrt700 WT_GUEST_OS=1 \
    BUILD="$base/build/psa-freertos" "$base/build/psa-freertos/guest1.a"
arm-none-eabi-gcc -mcpu=cortex-m33 -mthumb -mgeneral-regs-only \
    -ffreestanding -fno-builtin -nostdlib -Os -g -Wall -Wextra \
    -ffunction-sections -fdata-sections \
    -I"$base/freertos" -I"$psa/boards/mimxrt700" \
    -I"$freertos/include" -I"$port" \
    "$base/freertos/main.c" "$freertos/tasks.c" "$freertos/list.c" \
    "$freertos/queue.c" "$port/port.c" "$port/portasm.c" \
    "$freertos/portable/MemMang/heap_4.c" \
    "$base/build/psa-freertos/guest1.a" "$root/build/secure_cmse_implib.o" \
    -Wl,-T"$psa/guest.ld" -Wl,--gc-sections \
    -Wl,--defsym=GUEST_FLASH_ORIGIN=0x28100000 \
    -Wl,--defsym=GUEST_FLASH_LENGTH=0x40000 \
    -Wl,--defsym=GUEST_RAM_ORIGIN=0x20140000 \
    -Wl,--defsym=GUEST_RAM_LENGTH=0x40000 \
    -o "$base/build/guest1.elf" -lgcc
cp "$base/build/zephyr/zephyr/zephyr.elf" "$base/build/guest0.elf"
cp "$base/build/zephyr/zephyr/zephyr.bin" "$base/build/guest0.bin"
arm-none-eabi-objcopy -O binary "$base/build/guest1.elf" "$base/build/guest1.bin"
arm-none-eabi-size "$base/build/guest0.elf" "$base/build/guest1.elf"

for id in 0 1; do
    symbols="$(arm-none-eabi-nm "$base/build/guest$id.elf")"
    if printf '%s\n' "$symbols" | grep -Eq 'WolfTrust_HSM_(Submit|Poll|Cancel)|WolfTrust_Attest_'; then
        echo "FAIL: retired direct veneer in OS guest$id" >&2
        exit 1
    fi
    if [ "${WT_ENGINE:-native}" = native ]; then
        printf '%s\n' "$symbols" | grep -q wt_crypto_native_call
        ! printf '%s\n' "$symbols" | grep -q wh_Client
    else
        printf '%s\n' "$symbols" | grep -q wt_hsm_psa_transport_cb
    fi
    printf '%s\n' "$symbols" | grep -q g_os_progress
done
