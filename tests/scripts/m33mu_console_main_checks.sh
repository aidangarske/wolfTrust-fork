# Assertion snapshot from wolfSSL/wolfTrust main 0c435cef5791d8f5575002b57baabcdf01c34b0b
log="$RUNNER_TEMP/wolfboot-wolftrust-m33mu.log"
if grep -Eq '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)' "$log"; then
  exit 1
fi
# Both guests raw-write the same UART, so guest1 can splice into the
# middle of a secure/guest0 marker line. Flatten (strip guest1 text,
# rejoin the split line) before matching those markers; match guest1's
# own markers against the raw log. Mirrors run_m33mu_scenario.sh's
# expect_flat.
flat=$(sed 's/freertos_guest1:.*$//' "$log" | tr -d '\r\n')
need()     { printf '%s' "$flat" | grep -Fq "$1" || { echo "missing: $1" >&2; exit 1; }; }
need_raw() { grep -Fq "$1" "$log" || { echo "missing: $1" >&2; exit 1; }; }
need "wolfTrust TEE client initialized"
need "wolfTrust FF-M mediated crypto dispatch verified"
need "wolfTrust ITS set/get verified"
need "wolfTrust PS sealed set/get verified"
need "wolfTrust key-ops sign/verify verified"
need "wolfTrust key negatives verified"
need "wolfTrust FF-M forged-handle call rejected"
need "wolfTrust FF-M oversized-vector call rejected"
need "psa_initial_attestation short-buffer rejected correctly"
need "psa_hash_compute(SHA-256) KAT verified"
need "psa_cipher_encrypt(AES-CTR) st=0"
need "psa_initial_attestation st=0"
need "wolfTrust attestation: wolfCOSE COSE_Sign1 signed by wolfHSM"
need "wolfTrust attestation: COSE_Sign1 verified"
need "wolfTrust attestation: token measurement=$WT_EXPECTED_MEASUREMENT_HEX"
need "attestation verify=0 challenge=ok identity=ok lifecycle=0x1000 measurement=ok cose=ES256"
need "secured lifecycle policy rejected development token"
need "[EXPECT BKPT] Success"
if [ "$WT_TEST_GUEST" = "zephyr" ]; then
  need "psa_generate_random st=0"
  need "psa_hash_compute(SHA-256) KAT verified"
  need "psa_cipher_encrypt(AES-CTR) st=0"
else
  need_raw "freertos_guest1: ffm sha256 ok"
  need_raw "freertos_guest1: ffm rng ok"
  need_raw "freertos_guest1: psa_crypto_init st=0"
  need_raw "freertos_guest1: psa rng ok"
  need_raw "freertos_guest1: psa hash ok"
fi
