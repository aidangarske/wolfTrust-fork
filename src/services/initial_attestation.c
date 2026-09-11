/* initial_attestation.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 *
 * wolfTrust is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTrust is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include "wolftrust/services/initial_attestation.h"

#include "wolftrust/guest_verify.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/arch.h"

#include "wolftrust/services/attestation_cose.h"
#include "wolftrust/services/hsm.h"

#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/hash.h"

#include "wolfhsm/wh_error.h"

#include <wolfcose/wolfcose.h>

#include <stdbool.h>
#include <string.h>

#define WT_EAT_CLAIM_NONCE 10
#define WT_EAT_CLAIM_UEID 256
#define WT_EAT_CLAIM_PROFILE 265
#define WT_EAT_CLAIM_BOOT_SEED 268
#define WT_PSA_CLAIM_CLIENT_ID 2394
#define WT_PSA_CLAIM_LIFECYCLE 2395
#define WT_PSA_CLAIM_IMPLEMENTATION_ID 2396
#define WT_PSA_CLAIM_CERT_REFERENCE 2398
#define WT_PSA_CLAIM_SW_COMPONENTS 2399
#define WT_PSA_CLAIM_VERIFICATION_SERVICE 2400
#define WT_PSA_SW_MEASUREMENT_TYPE 1
#define WT_PSA_SW_MEASUREMENT_VALUE 2
#define WT_PSA_SW_MEASUREMENT_SIGNER_ID 5
#define WT_PSA_SW_MEASUREMENT_DESCRIPTION 6
#define WT_UEID_TYPE_RANDOM 0x01u
/* Sized for the standard claim set plus one lean measurement+signer component
 * per verified guest (WT-FFM-0049); the signed token stays under the 640-byte
 * WT_ATTEST_MAX_TOKEN_SIZE / PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE ceiling the
 * conformance suite compiles with. */
#define WT_ATTEST_PAYLOAD_SIZE 512u
#define WT_ATTEST_SCRATCH_SIZE 768u

static const uint8_t g_measurement_type[] = "sha-256";
static const uint8_t g_measurement_description[] = "wolftrust";
/* RFC 9783 final profile identifier for the PSA claim set (registered CBOR
 * keys 2394-2400 plus the EAT nonce, UEID, profile, and boot-seed claims). */
static const uint8_t g_profile_definition[] =
    "tag:psacertified.org,2023:psa#tfm";
#ifdef WT_ATTEST_CERT_REFERENCE
static const uint8_t g_cert_reference[] = WT_ATTEST_CERT_REFERENCE;
#endif
#ifdef WT_ATTEST_VERIFICATION_SERVICE
static const uint8_t g_verification_service[] = WT_ATTEST_VERIFICATION_SERVICE;
#endif
static const uint8_t g_implementation_name[] = "wolfTrust Cortex-M runtime";
/* Identifies the wolfBoot signing authority that measured the component; the
 * signing key itself is not carried in the handoff, so hash its name. */
static const uint8_t g_signer_name[] = "wolfBoot";

static wt_boot_handoff_t g_boot_handoff;
static uint8_t g_ueid[33];
static uint8_t g_boot_seed[WC_SHA256_DIGEST_SIZE];
static uint8_t g_implementation_id[WC_SHA256_DIGEST_SIZE];
static uint8_t g_signer_id[WC_SHA256_DIGEST_SIZE];
static bool g_handoff_ready;
static bool g_attest_ready;

static void wt_attest_force_zero(void* memory, size_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)memory;

    while (size > 0u) {
        *bytes++ = 0u;
        size--;
    }
}

static int wt_attest_hsm_sign(void* context, const uint8_t* digest,
    size_t digestSize, uint8_t* signature, size_t signatureCapacity,
    size_t* signatureSize)
{
    (void)context;
    return wt_hsm_attest_sign(digest, digestSize, signature,
                              signatureCapacity, signatureSize);
}

static int wt_attest_prepare(void)
{
    uint8_t publicKey[WT_ATTEST_IAK_PUBLIC_KEY_SIZE];
    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    size_t publicKeySize = sizeof(publicKey);
    wc_Sha256 sha;
    int ret;

    if (g_attest_ready) {
        return WT_ATTEST_SUCCESS;
    }
    if (!g_handoff_ready) {
        return WT_ATTEST_ERROR_NOT_READY;
    }

    ret = wt_hsm_attest_public_key(publicKey, sizeof(publicKey),
                                   &publicKeySize);
    if (ret == WH_ERROR_NOTREADY) {
        ret = WT_ATTEST_ERROR_NOT_READY;
    }
    else if (ret != 0) {
        ret = WT_ATTEST_ERROR_CRYPTO;
    }
    if ((ret == 0) && (publicKeySize != sizeof(publicKey))) {
        ret = WT_ATTEST_ERROR_CRYPTO;
    }
    if (ret == 0) {
        ret = wc_Sha256Hash(publicKey, (word32)publicKeySize, digest);
        if (ret != 0) {
            ret = WT_ATTEST_ERROR_CRYPTO;
        }
    }
    if (ret == 0) {
        g_ueid[0] = WT_UEID_TYPE_RANDOM;
        (void)memcpy(&g_ueid[1], digest, sizeof(digest));
    }
    /* Boot-seed binds the token to this measured boot of this device: it hashes
     * the boot measurement with the device instance id, so it is stable across
     * a boot cycle and reproducible for the golden conformance vector. */
    if (ret == 0) {
        ret = wc_InitSha256(&sha);
    }
    if (ret == 0) {
        ret = wc_Sha256Update(&sha, g_boot_handoff.measurement,
                              (word32)g_boot_handoff.measurement_size);
        if (ret == 0) {
            ret = wc_Sha256Update(&sha, g_ueid, sizeof(g_ueid));
        }
        if (ret == 0) {
            ret = wc_Sha256Final(&sha, g_boot_seed);
        }
        wc_Sha256Free(&sha);
        if (ret != 0) {
            ret = WT_ATTEST_ERROR_CRYPTO;
        }
    }
    if (ret == 0) {
        g_attest_ready = true;
    }

    wt_attest_force_zero(publicKey, sizeof(publicKey));
    wt_attest_force_zero(digest, sizeof(digest));
    return ret;
}

/* Measurement access seam: the confined attest partition cannot reach the
 * monitor's table, so it snapshots records through the read-only SVC gate;
 * privileged and host callers read the table directly. */
static size_t wt_attest_measurement_count(void)
{
#if defined(WT_TARGET_BUILD)
    if (wt_arch_thread_unprivileged()) {
        unsigned int count = 0u;

        if (wt_spm_measure_read_call(0u, NULL, 0u, &count) != 0) {
            return 0u;
        }
        return (size_t)count;
    }
#endif
    return wt_guest_measurement_count();
}

static int wt_attest_measurement_get(size_t index,
                                     wt_guest_measurement_t* record)
{
    const wt_guest_measurement_t* rec;

#if defined(WT_TARGET_BUILD)
    if (wt_arch_thread_unprivileged()) {
        return wt_spm_measure_read_call((unsigned int)index, record,
                                        (unsigned int)sizeof(*record), NULL);
    }
#endif
    rec = wt_guest_measurement_get(index, NULL);
    if (rec == NULL) {
        return -1;
    }
    (void)memcpy(record, rec, sizeof(*record));
    return 0;
}

static int wt_attest_encode_payload(wt_guest_id_t guestId,
    const uint8_t* challenge, size_t challengeSize, uint8_t* payload,
    size_t payloadCapacity, size_t* payloadSize)
{
    WOLFCOSE_CBOR_CTX cbor;
    unsigned int claimCount;
    int ret;

    if ((challenge == NULL) || (payload == NULL) || (payloadSize == NULL)) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }

    (void)memset(&cbor, 0, sizeof(cbor));
    cbor.buf = payload;
    cbor.bufSz = payloadCapacity;

    /* nonce, ueid, profile, boot-seed, implementation-id, client-id,
     * lifecycle, software-components, plus any build-configured claims. */
    claimCount = 8u;
#ifdef WT_ATTEST_CERT_REFERENCE
    claimCount += 1u;
#endif
#ifdef WT_ATTEST_VERIFICATION_SERVICE
    claimCount += 1u;
#endif

    ret = wc_CBOR_EncodeMapStart(&cbor, claimCount);
    if (ret == 0) {
        ret = wc_CBOR_EncodeInt(&cbor, WT_EAT_CLAIM_NONCE);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeBstr(&cbor, challenge, challengeSize);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeInt(&cbor, WT_EAT_CLAIM_UEID);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeBstr(&cbor, g_ueid, sizeof(g_ueid));
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeInt(&cbor, WT_EAT_CLAIM_PROFILE);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeTstr(&cbor, g_profile_definition,
                                 sizeof(g_profile_definition) - 1u);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeInt(&cbor, WT_EAT_CLAIM_BOOT_SEED);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeBstr(&cbor, g_boot_seed, sizeof(g_boot_seed));
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeInt(&cbor, WT_PSA_CLAIM_IMPLEMENTATION_ID);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeBstr(&cbor, g_implementation_id,
                                 sizeof(g_implementation_id));
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeInt(&cbor, WT_PSA_CLAIM_CLIENT_ID);
    }
    if (ret == 0) {
        /* The claim carries the caller's PSA client id; NSPE callers are
         * negative (guest N maps to -(N + 1)), never a positive value. */
        ret = wc_CBOR_EncodeInt(&cbor, -((int64_t)guestId + 1));
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeInt(&cbor, WT_PSA_CLAIM_LIFECYCLE);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&cbor, g_boot_handoff.lifecycle);
    }
#ifdef WT_ATTEST_CERT_REFERENCE
    if (ret == 0) {
        ret = wc_CBOR_EncodeInt(&cbor, WT_PSA_CLAIM_CERT_REFERENCE);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeTstr(&cbor, g_cert_reference,
                                 sizeof(g_cert_reference) - 1u);
    }
#endif
#ifdef WT_ATTEST_VERIFICATION_SERVICE
    if (ret == 0) {
        ret = wc_CBOR_EncodeInt(&cbor, WT_PSA_CLAIM_VERIFICATION_SERVICE);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeTstr(&cbor, g_verification_service,
                                 sizeof(g_verification_service) - 1u);
    }
#endif
    if (ret == 0) {
        ret = wc_CBOR_EncodeInt(&cbor, WT_PSA_CLAIM_SW_COMPONENTS);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeArrayStart(&cbor,
                  1u + (unsigned int)wt_attest_measurement_count());
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeMapStart(&cbor, 4u);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&cbor, WT_PSA_SW_MEASUREMENT_TYPE);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeTstr(&cbor, g_measurement_type,
                                 sizeof(g_measurement_type) - 1u);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&cbor, WT_PSA_SW_MEASUREMENT_VALUE);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeBstr(&cbor, g_boot_handoff.measurement,
                                 g_boot_handoff.measurement_size);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&cbor, WT_PSA_SW_MEASUREMENT_SIGNER_ID);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeBstr(&cbor, g_signer_id, sizeof(g_signer_id));
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&cbor,
                                 WT_PSA_SW_MEASUREMENT_DESCRIPTION);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeTstr(&cbor, g_measurement_description,
                                 sizeof(g_measurement_description) - 1u);
    }

    /* One lean component per launch-verified guest (WT-FFM-0049): the pinned
     * digest and the boot-chain signer that authenticated the pin. */
    if (ret == 0) {
        size_t component;

        for (component = 0u;
             (ret == 0) && (component < wt_attest_measurement_count());
             component++) {
            wt_guest_measurement_t guest;

            if (wt_attest_measurement_get(component, &guest) != 0) {
                ret = -1;
                break;
            }
            ret = wc_CBOR_EncodeMapStart(&cbor, 2u);
            if (ret == 0) {
                ret = wc_CBOR_EncodeUint(&cbor, WT_PSA_SW_MEASUREMENT_VALUE);
            }
            if (ret == 0) {
                ret = wc_CBOR_EncodeBstr(&cbor, guest.digest,
                                         sizeof(guest.digest));
            }
            if (ret == 0) {
                ret = wc_CBOR_EncodeUint(&cbor,
                                         WT_PSA_SW_MEASUREMENT_SIGNER_ID);
            }
            if (ret == 0) {
                ret = wc_CBOR_EncodeBstr(&cbor, g_signer_id,
                                         sizeof(g_signer_id));
            }
        }
    }
    if (ret != 0) {
        return WT_ATTEST_ERROR_BUFFER_TOO_SMALL;
    }

    *payloadSize = cbor.idx;
    return WT_ATTEST_SUCCESS;
}

int wt_initial_attest_init(const wt_boot_handoff_t* handoff)
{
    int ret;

    if (handoff == NULL) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    if ((handoff->hash_algorithm != WT_BOOT_HANDOFF_HASH_SHA256) ||
        (handoff->measurement_size != WT_BOOT_HANDOFF_DIGEST_SIZE)) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }

    ret = wc_Sha256Hash(g_implementation_name,
        (word32)(sizeof(g_implementation_name) - 1u),
        g_implementation_id);
    if (ret == 0) {
        ret = wc_Sha256Hash(g_signer_name,
            (word32)(sizeof(g_signer_name) - 1u), g_signer_id);
    }
    if (ret == 0) {
        (void)memcpy(&g_boot_handoff, handoff, sizeof(g_boot_handoff));
        g_handoff_ready = true;
    }

    return ret == 0 ? WT_ATTEST_SUCCESS : WT_ATTEST_ERROR_CRYPTO;
}

int wt_initial_attest_get_token_size(size_t challengeSize,
    size_t* tokenSize)
{
    uint8_t challenge[WT_ATTEST_CHALLENGE_SIZE_64];
    uint8_t payload[WT_ATTEST_PAYLOAD_SIZE];
    wt_attest_cose_signer_t signer;
    size_t payloadSize = 0u;
    int ret;

    if (tokenSize == NULL) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    *tokenSize = 0u;
    if ((challengeSize != WT_ATTEST_CHALLENGE_SIZE_32) &&
        (challengeSize != WT_ATTEST_CHALLENGE_SIZE_48) &&
        (challengeSize != WT_ATTEST_CHALLENGE_SIZE_64)) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }

    ret = wt_attest_prepare();
    if (ret == WT_ATTEST_SUCCESS) {
        (void)memset(challenge, 0, sizeof(challenge));
        ret = wt_attest_encode_payload(0u, challenge, challengeSize, payload,
                                       sizeof(payload), &payloadSize);
    }
    if (ret == WT_ATTEST_SUCCESS) {
        (void)memset(&signer, 0, sizeof(signer));
        signer.sign = wt_attest_hsm_sign;
        ret = wt_attest_cose_sign1_size(&signer, payloadSize, 0u, tokenSize);
    }

    wt_attest_force_zero(challenge, sizeof(challenge));
    wt_attest_force_zero(payload, sizeof(payload));
    return ret;
}

int wt_initial_attest_get_token(wt_guest_id_t guestId,
    const uint8_t* challenge, size_t challengeSize, uint8_t* token,
    size_t tokenCapacity, size_t* tokenSize)
{
    uint8_t payload[WT_ATTEST_PAYLOAD_SIZE];
    uint8_t scratch[WT_ATTEST_SCRATCH_SIZE];
    wt_attest_cose_signer_t signer;
    size_t payloadSize = 0u;
    int ret;

    if ((challenge == NULL) || (token == NULL) || (tokenSize == NULL)) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    *tokenSize = 0u;
    if ((challengeSize != WT_ATTEST_CHALLENGE_SIZE_32) &&
        (challengeSize != WT_ATTEST_CHALLENGE_SIZE_48) &&
        (challengeSize != WT_ATTEST_CHALLENGE_SIZE_64)) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }

    ret = wt_attest_prepare();
    if (ret == WT_ATTEST_SUCCESS) {
        ret = wt_attest_encode_payload(guestId, challenge, challengeSize,
                                       payload, sizeof(payload), &payloadSize);
    }
    if (ret == WT_ATTEST_SUCCESS) {
        (void)memset(&signer, 0, sizeof(signer));
        signer.sign = wt_attest_hsm_sign;
        ret = wt_attest_cose_sign1_encode(&signer, payload, payloadSize,
            0u, scratch, sizeof(scratch), token,
            tokenCapacity, tokenSize);
        if (ret == WT_ATTEST_COSE_E_BUFFER) {
            ret = WT_ATTEST_ERROR_BUFFER_TOO_SMALL;
        }
    }

    wt_attest_force_zero(payload, sizeof(payload));
    wt_attest_force_zero(scratch, sizeof(scratch));
    return ret;
}

int wt_initial_attest_get_iak_public_key(uint8_t* publicKey,
    size_t publicKeyCapacity, size_t* publicKeySize)
{
    int ret;

    if (publicKeySize == NULL) {
        return WT_ATTEST_ERROR_INVALID_ARGUMENT;
    }
    ret = wt_attest_prepare();
    if (ret == WT_ATTEST_SUCCESS) {
        ret = wt_hsm_attest_public_key(publicKey, publicKeyCapacity,
                                       publicKeySize);
        if (ret != 0) {
            ret = WT_ATTEST_ERROR_CRYPTO;
        }
    }
    return ret;
}
