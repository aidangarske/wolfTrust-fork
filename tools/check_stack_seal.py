#!/usr/bin/env python3
"""Check that no allocated section reaches the Secure main-stack seal."""

import argparse
import re
import sys


SEAL_BYTES = 8
SECTION_LINE = re.compile(
    r"^(\S+)\s+(0x[0-9a-f]+|[0-9]+)\s+(0x[0-9a-f]+|[0-9]+)\s*$",
    re.IGNORECASE)


def sections(lines):
    found = []
    for line in lines:
        match = SECTION_LINE.match(line.strip())
        if match is None or match.group(1) == "Total":
            continue
        found.append((match.group(1), int(match.group(2), 0),
                      int(match.group(3), 0)))
    return found


def check(lines, estack):
    found = sections(lines)
    if not found:
        return ["no sections found in the size listing"]
    if estack < SEAL_BYTES or (estack & 7) != 0:
        return ["stack top 0x%08x is not a usable 8-byte aligned address"
                % estack]
    seal = estack - SEAL_BYTES
    errors = []
    for name, size, addr in found:
        if size != 0 and addr < estack and addr + size > seal:
            errors.append("section %s (0x%08x..0x%08x) overlaps the stack "
                          "seal at 0x%08x" % (name, addr, addr + size, seal))
    return errors


def self_test():
    estack = 0x30096000
    base = ["build/wolftrust.elf  :\n",
            "section      size         addr\n",
            ".text      0x1000    0xc060400\n",
            ".data       0x100   0x30028000\n",
            ".debug_info 0x9000         0x0\n",
            "Total      0xa100\n"]
    cases = (
        ("bss well below the seal", [".bss 0x2000 0x30028100\n"], True),
        ("bss ending exactly at the seal", [".bss 0x8 0x30095ff0\n"], True),
        ("bss reaching into the seal", [".bss 0x9 0x30095ff0\n"], False),
        ("bss covering the whole stack top", [".bss 0x10 0x30095ff0\n"],
         False),
        ("section starting inside the seal", [".noinit 0x4 0x30095ffc\n"],
         False),
        ("section in the next region", [".spstacks 0x100 0x30096000\n"],
         True),
        ("empty section at the seal", [".empty 0x0 0x30095ffc\n"], True),
    )
    failures = 0
    for name, extra, want_ok in cases:
        if (check(base + extra, estack) == []) != want_ok:
            print("self-test failed: %s" % name, file=sys.stderr)
            failures += 1
    if check([], estack) == [] or check(base, 0x30096004) == []:
        print("self-test accepted unusable input", file=sys.stderr)
        failures += 1
    if failures != 0:
        return 1
    print("PASS: stack_seal_layout")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("listing", nargs="?",
                        help="output of 'size -A -x' for the Secure image")
    parser.add_argument("--estack", help="address of the main stack top")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if args.listing is None or not args.estack:
        parser.error("listing and --estack are required")
    try:
        estack = int(args.estack, 16)
        with open(args.listing, "r", errors="replace") as handle:
            errors = check(handle, estack)
    except (OSError, ValueError) as error:
        errors = ["cannot check %s: %s" % (args.listing, error)]
    for error in errors:
        print("FAIL: %s" % error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
