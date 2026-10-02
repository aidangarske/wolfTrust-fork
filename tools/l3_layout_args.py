#!/usr/bin/env python3
"""Print check_secure_layout.py band arguments from a port's memory_map.h.

The keystore bands and the conformance data window come from the shared
Armv8-M layout, so the post-link check reads the same macros the C code and
the linker fragments are placed by instead of a copied address list."""

import argparse
import re
import subprocess
import sys


MACROS = (
    "WT_SP_VAULT_DATA_BASE", "WT_SP_VAULT_DATA_SIZE",
    "WT_SP_ATTEST_DATA_BASE", "WT_SP_ATTEST_DATA_SIZE",
    "WT_SP_HSM_DATA_BASE", "WT_SP_HSM_DATA_SIZE",
    "WT_CONF_SP_DATA_BASE", "WT_CONF_SERVER_MMIO_BASE",
)
INTEGER = re.compile(r"\b(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*\b")
EXPRESSION = re.compile(r"^[0-9a-fA-FxX+\-*() ]+$")


def evaluate(cc, header):
    probe = '#include "%s"\n' % header
    probe += "".join("%d=%s\n" % (index, name)
                     for index, name in enumerate(MACROS))
    result = subprocess.run(
        [cc, "-E", "-P", "-x", "c", "-"], input=probe, text=True,
        capture_output=True, check=False)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit("FAIL: preprocessing %s failed" % header)
    values = {}
    for line in result.stdout.splitlines():
        index, separator, text = line.partition("=")
        if not separator or not index.isdigit() or int(index) >= len(MACROS):
            continue
        name = MACROS[int(index)]
        if name == text.strip():
            continue
        text = INTEGER.sub(r"\1", text).strip()
        if not EXPRESSION.match(text):
            raise SystemExit("FAIL: %s does not reduce to a constant: %s" %
                             (name, text))
        values[name] = eval(text, {"__builtins__": {}})
    missing = [name for name in MACROS if name not in values]
    if missing:
        raise SystemExit("FAIL: %s defines no %s" %
                         (header, ", ".join(missing)))
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="arm-none-eabi-gcc")
    parser.add_argument("memory_map")
    args = parser.parse_args()

    v = evaluate(args.cc, args.memory_map)
    args_out = []
    for band, prefix in (("vault", "WT_SP_VAULT_DATA"),
                         ("attest", "WT_SP_ATTEST_DATA"),
                         ("hsm", "WT_SP_HSM_DATA")):
        base = v[prefix + "_BASE"]
        args_out.append("--band %s=0x%08X:0x%08X" %
                        (band, base, base + v[prefix + "_SIZE"]))
    args_out.append("--confdata 0x%08X:0x%08X" %
                    (v["WT_CONF_SP_DATA_BASE"], v["WT_CONF_SERVER_MMIO_BASE"]))
    print(" ".join(args_out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
