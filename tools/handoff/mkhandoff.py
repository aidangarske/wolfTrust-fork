#!/usr/bin/env python3
"""Build, validate, or print a wolfBoot secure boot-handoff record.

The record is the 56-byte little-endian structure wolfBoot writes at the
port's handoff address (wolfBoot include/wolfboot/secure_handoff.h) and
wolfTrust consumes through wt_boot_handoff_consume (src/services/boot_handoff.c).
Emulator runners preload one so the record path runs without a bootloader.

  mkhandoff.py --out FILE (--measure IMAGE | --digest HEX)
               [--image-version N] [--lifecycle NAME|0xNNNN] [--print]
  mkhandoff.py --check FILE
  mkhandoff.py --selftest
"""
import argparse
import hashlib
import struct
import sys

MAGIC = 0x5742484F
VERSION = 1
HASH_SHA256 = 1
DIGEST_SIZE = 32
FORMAT = "<IIHHIIHH32s"
SIZE = struct.calcsize(FORMAT)
LIFECYCLE = {
    "UNKNOWN": 0x0000,
    "ASSEMBLY_AND_TEST": 0x1000,
    "PSA_ROT_PROVISIONING": 0x2000,
    "SECURED": 0x3000,
    "NON_PSA_ROT_DEBUG": 0x4000,
    "RECOVERABLE_DEBUG": 0x5000,
}
FIELDS = ("magic", "magic_inverse", "version", "size", "lifecycle",
          "image_version", "hash_algorithm", "measurement_size", "measurement")


def build(digest, image_version, lifecycle):
    if len(digest) != DIGEST_SIZE:
        raise ValueError("digest must be %d bytes" % DIGEST_SIZE)
    return struct.pack(FORMAT, MAGIC, (~MAGIC) & 0xFFFFFFFF, VERSION, SIZE,
                       lifecycle & 0xFFFFFFFF, image_version & 0xFFFFFFFF,
                       HASH_SHA256, DIGEST_SIZE, digest)


def parse(data):
    """Return the record fields or raise ValueError naming the failed check."""
    if len(data) < SIZE:
        raise ValueError("record is %d bytes, need %d" % (len(data), SIZE))
    rec = dict(zip(FIELDS, struct.unpack(FORMAT, data[:SIZE])))
    checks = (
        ("magic", rec["magic"] == MAGIC),
        ("magic_inverse", rec["magic_inverse"] == (~MAGIC) & 0xFFFFFFFF),
        ("version", rec["version"] == VERSION),
        ("size", rec["size"] == SIZE),
        ("hash_algorithm", rec["hash_algorithm"] == HASH_SHA256),
        ("measurement_size", rec["measurement_size"] == DIGEST_SIZE),
    )
    for name, ok in checks:
        if not ok:
            raise ValueError("%s check failed" % name)
    return rec


def lifecycle_name(value):
    for name, code in LIFECYCLE.items():
        if code == value:
            return name
    return "0x%04X" % value


def describe(rec):
    return ("magic=0x%08X version=%u size=%u lifecycle=%s image_version=%u "
            "hash_algorithm=%u measurement=%s" % (
                rec["magic"], rec["version"], rec["size"],
                lifecycle_name(rec["lifecycle"]), rec["image_version"],
                rec["hash_algorithm"], rec["measurement"].hex()))


def parse_lifecycle(text):
    key = text.strip().upper()
    if key in LIFECYCLE:
        return LIFECYCLE[key]
    return int(text, 0)


def selftest():
    digest = bytes(range(DIGEST_SIZE))
    record = build(digest, 7, LIFECYCLE["SECURED"])
    assert len(record) == SIZE == 56
    rec = parse(record)
    assert rec["measurement"] == digest and rec["image_version"] == 7
    assert rec["lifecycle"] == 0x3000
    for offset, label in ((0, "magic"), (4, "magic_inverse"), (8, "version"),
                          (10, "size"), (20, "hash_algorithm"),
                          (22, "measurement_size")):
        bad = bytearray(record)
        bad[offset] ^= 0x01
        try:
            parse(bytes(bad))
        except ValueError as err:
            assert label in str(err), (label, err)
        else:
            raise AssertionError("%s corruption accepted" % label)
    try:
        parse(record[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError("short record accepted")
    measured = build(hashlib.sha256(b"image").digest(), 1, 0)
    assert parse(measured)["measurement"] == hashlib.sha256(b"image").digest()
    assert parse_lifecycle("secured") == 0x3000 and parse_lifecycle("0x1000") == 0x1000
    print("SELFTEST: ok")


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", help="write the record here")
    ap.add_argument("--measure", help="image file to SHA-256 into the measurement")
    ap.add_argument("--digest", help="32-byte measurement as hex")
    ap.add_argument("--image-version", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--lifecycle", type=parse_lifecycle, default=LIFECYCLE["UNKNOWN"],
                    help="|".join(LIFECYCLE) + " or a numeric code")
    ap.add_argument("--print", action="store_true", help="describe the record built")
    ap.add_argument("--check", help="validate and describe an existing record")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        selftest()
        return 0
    if args.check:
        with open(args.check, "rb") as handle:
            data = handle.read()
        try:
            rec = parse(data)
        except ValueError as err:
            print("INVALID: %s (%s)" % (args.check, err))
            return 1
        print("OK: %s" % describe(rec))
        return 0
    if args.out is None or (args.measure is None) == (args.digest is None):
        ap.error("--out with exactly one of --measure or --digest is required")
    if args.measure is not None:
        with open(args.measure, "rb") as handle:
            digest = hashlib.sha256(handle.read()).digest()
    else:
        digest = bytes.fromhex(args.digest)
    record = build(digest, args.image_version, args.lifecycle)
    with open(args.out, "wb") as handle:
        handle.write(record)
    if args.print:
        print(describe(parse(record)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
