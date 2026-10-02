#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
base="$root/tests/firmware/rt700-os"
h5="$root/tests/firmware/zephyr-stm32h5"
freertos="${FREERTOS_DIR:-$base/.workspace/freertos}"
ref=f4fcc3b228643144727e9257ba12db1cb632b6e6
make -C "$h5" workspace WEST_PROJECTS="cmsis cmsis_6"
if [ ! -d "$freertos/.git" ]; then
    mkdir -p "$freertos"
    git -C "$freertos" init
    git -C "$freertos" remote add origin https://github.com/FreeRTOS/FreeRTOS.git
    git -C "$freertos" fetch --depth 1 origin "$ref"
    git -C "$freertos" checkout --detach "$ref"
fi
[ "$(git -C "$freertos" rev-parse HEAD)" = "$ref" ] || {
    echo "FAIL: FreeRTOS workspace does not match pinned revision" >&2
    exit 1
}
git -C "$freertos" submodule update --init --depth 1 FreeRTOS/Source
