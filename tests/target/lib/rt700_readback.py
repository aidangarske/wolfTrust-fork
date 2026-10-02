#!/usr/bin/env python3
"""Read freshly programmed RT700 NOR with the core parked and caches invalidated."""

import argparse
from pathlib import Path
import time

from pyocd.core.helpers import ConnectHelper


def wait_clear(target, address, mask):
    deadline = time.monotonic() + 2.0
    while target.read32(address) & mask:
        if time.monotonic() >= deadline:
            raise RuntimeError(f"read-path flush timed out at {address:#010x}")


def flush_read_path(target):
    # NXP XSPI SPTRCLR.ABRT_CLR clears the AHB prefetch pointer. The cache
    # sequence follows fsl_cache.c: invalidate both ways, wait, clear commands.
    address = 0x50184000 + 0x16C
    target.write32(address, target.read32(address) | 0x10000)
    target.flush()
    wait_clear(target, address, 0x10000)
    for address in (0x50033000, 0x50034000, 0x50035800):
        target.write32(address, target.read32(address) | 0x85000000)
        target.flush()
        wait_clear(target, address, 0x80000000)
        target.write32(address, target.read32(address) & ~0x05000000)
        target.flush()
        print(f"flushed cache {address:#010x}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", type=lambda value: int(value, 0))
    parser.add_argument("image", type=Path)
    parser.add_argument("readback", type=Path)
    parser.add_argument("--probe")
    args = parser.parse_args()
    expected = args.image.read_bytes()
    if not expected:
        raise RuntimeError("empty flash image")
    session = ConnectHelper.session_with_chosen_probe(
        unique_id=args.probe,
        options={"target_override": "cortex_m", "connect_mode": "attach",
                 "resume_on_disconnect": False})
    if session is None:
        raise RuntimeError("RT700 probe unavailable")
    with session:
        target = session.board.target
        target.halt()
        flush_read_path(target)
        actual = bytes(target.read_memory_block8(args.address, len(expected)))
        args.readback.write_bytes(actual)
    if actual != expected:
        raise RuntimeError(f"flash verify mismatch at {args.address:#010x}")
    print(f"verified {len(actual)} bytes at {args.address:#010x}", flush=True)


if __name__ == "__main__":
    main()
