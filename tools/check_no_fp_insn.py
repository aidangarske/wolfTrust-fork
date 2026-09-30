#!/usr/bin/env python3
"""Reject floating-point code in a disassembled Secure image."""

import argparse
import re
import sys


# Cortex-M33 has no MVE, so every mnemonic that starts with "v" belongs to the
# FP extension (vlstm/vlldm included); objdump also prints the deprecated
# fldm/fstm spellings of the VFP multi-register load and store.
FP_MNEMONIC = re.compile(r"^(v[a-z0-9]|f(ld|st)m(ia|db|ea|fd)x?\b)",
                         re.IGNORECASE)
INSN_LINE = re.compile(r"^\s*[0-9a-f]+:\t(\S+)(?:\s+(.*))?$", re.IGNORECASE)
PROBE_INSN = ("vmov", "s0, r0")
# Soft-float runtime helpers the compiler calls for float and double math.
SOFT_FLOAT = re.compile(
    r"^__(aeabi_(c?[fd][a-z0-9]+|u?[il]2[fd]|h2f\w*|[fd]2h\w*)|"
    r"gnu_([fd]2h|h2f|float2h)_\w+|"
    r"gnu_(sat)?fract\w*(sf|df)\w*|"
    r"(fix|float)\w+|"
    r"\w*(sf|df|hf|tf|xf|sc|dc)[0-9]?)$")
LABEL_LINE = re.compile(r"^[0-9a-f]+ <([^>+]+)>:$", re.IGNORECASE)


def fp_instructions(lines):
    found = []
    count = 0
    for line in lines:
        label = LABEL_LINE.match(line.strip())
        if label is not None and SOFT_FLOAT.match(label.group(1)):
            found.append(("soft-float", label.group(1), line.strip()))
        match = INSN_LINE.match(line.rstrip("\n"))
        if match is None:
            continue
        count += 1
        mnemonic = match.group(1)
        if FP_MNEMONIC.match(mnemonic):
            operands = (match.group(2) or "").split("@")[0].strip()
            found.append((mnemonic.split(".")[0].lower(), operands,
                          line.strip()))
    return count, found


def check(lines, allow_probe):
    count, found = fp_instructions(lines)
    if count == 0:
        return ["no instructions found in the disassembly"]
    if allow_probe:
        probes = [item for item in found if item[:2] == PROBE_INSN]
        others = [item for item in found if item[:2] != PROBE_INSN]
        errors = ["unexpected FP code: %s" % item[2]
                  for item in others]
        if len(probes) != 1:
            errors.append("expected exactly one probe instruction, found %d"
                          % len(probes))
        return errors
    return ["FP code: %s" % item[2] for item in found]


def self_test():
    clean = ["08000000 <f>:\n", " 8000000:\tpush\t{r4, lr}\n",
             " 8000002:\tbl\t8000010 <vmov_helper>\n",
             " 8000006:\tpop\t{r4, pc}\n"]
    probe = " 8000008:\tvmov\ts0, r0\n"
    cases = (
        ("clean image", clean, False, True),
        ("empty disassembly", [], False, False),
        ("symbol named like an FP mnemonic", clean, False, True),
        ("probe build carries its one instruction", clean + [probe], True,
         True),
        ("probe build without the instruction", clean, True, False),
        ("probe build with two probe instructions", clean + [probe, probe],
         True, False),
        ("production build carrying the probe", clean + [probe], False,
         False),
    )
    failures = 0
    for helper in ("__aeabi_fadd", "__aeabi_dmul", "__aeabi_i2d",
                   "__aeabi_ul2f", "__aeabi_cdcmple", "__aeabi_d2iz",
                   "__addsf3", "__muldf3", "__fixunsdfsi", "__floatsidf",
                   "__gnu_h2f_ieee", "__gnu_f2h_ieee",
                   "__gnu_d2h_alternative", "__gnu_h2f_internal",
                   "__gnu_float2h_internal", "__extendhfsf2",
                   "__truncdfhf2", "__muldc3", "__divsc3", "__powidf2",
                   "__gnu_fractdadf", "__gnu_satfractsfha",
                   "__aeabi_f2h", "__floatundisf", "__unorddf2"):
        lines = clean + ["08000100 <%s>:\n" % helper,
                         " 8000100:\tbx\tlr\n"]
        if check(lines, False) == [] or check(lines + [probe], True) == []:
            print("self-test did not reject %s" % helper, file=sys.stderr)
            failures += 1
    for helper in ("__aeabi_uldivmod", "__aeabi_memcpy", "__aeabi_idiv",
                   "__aeabi_lmul", "__aeabi_llsr", "__udivmoddi4",
                   "__divdi3", "__clzsi2", "__popcountdi2", "__mulvsi3",
                   "__gnu_cmse_nonsecure_call", "__acle_se_f"):
        lines = clean + ["08000100 <%s>:\n" % helper,
                         " 8000100:\tbx\tlr\n"]
        if check(lines, False) != []:
            print("self-test rejected integer helper %s" % helper,
                  file=sys.stderr)
            failures += 1
    for mnemonic in ("vadd.f32\ts0, s0, s1", "vldr\td0, [r0]",
                     "vpush\t{d8}", "vmrs\tAPSR_nzcv, fpscr",
                     "vlstm\tsp", "vlldm\tsp", "vcvt.f64.f32\td0, s0",
                     "vsqrt.f32\ts0, s0", "vsel.f32\ts0, s0, s1",
                     "fldmiax\tr0, {d0-d15}", "fstmiax\tr0, {d0-d15}",
                     "fldmdbx\tr0!, {d0-d15}", "fstmdbx\tr0!, {d0-d15}"):
        line = " 8000008:\t%s\n" % mnemonic
        name = mnemonic.split("\t")[0]
        if check(clean + [line], False) == []:
            print("self-test did not reject %s" % name, file=sys.stderr)
            failures += 1
        if check(clean + [probe, line], True) == []:
            print("self-test probe build did not reject %s" % name,
                  file=sys.stderr)
            failures += 1
    for name, lines, allow_probe, want_ok in cases:
        ok = check(lines, allow_probe) == []
        if ok != want_ok:
            print("self-test failed: %s" % name, file=sys.stderr)
            failures += 1
    if failures != 0:
        return 1
    print("PASS: no_fp_insn")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disassembly", nargs="?",
                        help="objdump -d --no-show-raw-insn output")
    parser.add_argument("--allow-probe", action="store_true",
                        help="require exactly one 'vmov s0, r0' and nothing "
                             "else (FP negative-probe build)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if args.disassembly is None:
        parser.error("disassembly file required")
    try:
        with open(args.disassembly, "r", errors="replace") as handle:
            errors = check(handle, args.allow_probe)
    except OSError as error:
        errors = ["cannot read %s: %s" % (args.disassembly, error)]
    for error in errors[:20]:
        print("FAIL: %s" % error, file=sys.stderr)
    if errors:
        print("FAIL: Secure FP is unsupported; the Secure image must not "
              "contain FP instructions or soft-float helpers",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
