# shellcheck shell=bash
# Shared RT700 guest selection and build recipe for emulator and EVK runners.

rt700_guest_kind() {
    case "$1:${WT_RT700_GUEST_FIXTURE:-baremetal}" in
        bothpsa:os|bothiso:os) echo os; return ;;
    esac
    case "$1" in
        bothpsa|bothiso|attestneg|hsmattackneg|fwustage) echo psa ;;
        confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover|vaultrecoversec)
            echo conformance ;;
        *) echo basic ;;
    esac
}

rt700_set_guest_paths() {
    case "$(rt700_guest_kind "$scenario")" in
        os) guest_dir=tests/firmware/rt700-os; guest1_dir="$guest_dir" ;;
        psa) guest_dir=tests/firmware/psa-guest; guest1_dir="$guest_dir" ;;
        conformance)
            guest_dir=tests/firmware/psa-guest
            guest1_dir=tests/firmware/mimxrt700-baremetal ;;
        *) guest_dir=tests/firmware/mimxrt700-baremetal; guest1_dir="$guest_dir" ;;
    esac
    guest_build="$repo/$guest_dir/build"
    guest1_build="$repo/$guest1_dir/build"
}

rt700_guest_flags() {
    local trap="${2:-0}"
    case "$1" in
        ahbscneg) echo "WT_AHBSC_PROBE=1" ;;
        restart) echo "WT_GUEST_FAULT_PROBE=1" ;;
        attestneg) echo "WT_ATTEST_NEG_PROBE=1" ;;
        hsmattackneg) echo "WT_HSM_ATTACK_PROBE=1" ;;
        fwustage)
            echo "WT_FWU_PROBE=1 WT_FWU_PROBE_STREAM_BYTES=0x21000u WT_FWU_PROBE_SEQUENTIAL=1" ;;
        confboot) echo "WT_RUN_CONFORMANCE=1 WT_M33MU_EXPECT_BKPT=$trap" ;;
        devstorage)
            echo "WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=storage WT_M33MU_EXPECT_BKPT=$trap" ;;
        devcrypto|vaultrecover|vaultrecoversec)
            echo "WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=crypto WT_M33MU_EXPECT_BKPT=$trap" ;;
        devattest)
            echo "WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=attestation WT_M33MU_EXPECT_BKPT=$trap" ;;
        devattestqcbor)
            echo "WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=attestation WT_ATTEST_CBOR=qcbor WT_M33MU_EXPECT_BKPT=$trap" ;;
        *) echo "" ;;
    esac
}

rt700_build_guests() {
    local flags="$1" lifecycle="$2"
    case "${WT_RT700_GUEST_FIXTURE:-baremetal}" in
        baremetal) ;;
        os)
            case "$scenario" in
                bothpsa|bothiso) ;;
                *) fail "OS fixture supports bothpsa and bothiso" ;;
            esac ;;
        *) fail "unknown RT700 guest fixture" ;;
    esac
    rt700_set_guest_paths
    stage "build the Non-secure guests from $guest_dir ${flags:-(no probes)}"
    if [ "$(rt700_guest_kind "$scenario")" = os ]; then
        WT_EXPECTED_LIFECYCLE="$lifecycle" "$repo/$guest_dir/build.sh"
        return
    fi
    make -s -C "$repo/$guest_dir" clean
    # Flags come only from rt700_guest_flags, not from arbitrary shell input.
    # shellcheck disable=SC2086
    make -s -C "$repo/$guest_dir" TARGET=mimxrt700 \
        WT_EXPECTED_LIFECYCLE="$lifecycle" $flags
    if [ "$guest1_dir" != "$guest_dir" ]; then
        make -s -C "$repo/$guest1_dir" clean
        make -s -C "$repo/$guest1_dir" TARGET=mimxrt700
    fi
}
