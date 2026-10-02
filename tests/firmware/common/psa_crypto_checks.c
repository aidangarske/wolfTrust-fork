/* psa_crypto_checks.c
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

/* Shared assertions for bare-metal, Zephyr and FreeRTOS clients. Logging
 * and result placement belong to the adapters; these bodies use only PSA.
 * AES-128 CTR vectors: NIST SP 800-38A, sections F.5.1 and F.5.2, block 1.
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 */
#include <string.h>
#include "psa_crypto_checks.h"

static const uint8_t ctr_iv[16] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

psa_status_t wt_guest_psa_rng_check(uint8_t* output, size_t size)
{
    psa_status_t status;
    size_t i;
    uint8_t any = 0u;

    if (output == NULL || size == 0u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    memset(output, 0, size);
    status = psa_generate_random(output, size);
    if (status != PSA_SUCCESS) {
        return status;
    }
    for (i = 0u; i < size; i++) {
        any |= output[i];
    }
    return (any != 0u) ? PSA_SUCCESS : PSA_ERROR_CORRUPTION_DETECTED;
}

psa_status_t wt_guest_psa_sha256_check(void)
{
    static const uint8_t input[] = "wolfTrust/wolfPSA/wolfHSM/CMSE chain test";
    static const uint8_t expected[32] = {
        0x02, 0x7b, 0x1a, 0xec, 0xb3, 0x27, 0x3a, 0x54,
        0x38, 0x6a, 0xea, 0x85, 0x66, 0x45, 0xa2, 0x6a,
        0xe1, 0xce, 0xc4, 0xdf, 0x1e, 0x00, 0x72, 0x71,
        0xab, 0x5f, 0x10, 0x21, 0x40, 0x57, 0xed, 0x67
    };
    uint8_t output[sizeof(expected)];
    size_t size = 0u;
    psa_status_t status;

    status = psa_hash_compute(PSA_ALG_SHA_256, input, sizeof(input) - 1u,
                              output, sizeof(output), &size);
    if (status == PSA_SUCCESS && (size != sizeof(expected) ||
            memcmp(output, expected, sizeof(expected)) != 0)) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    return status;
}

static psa_status_t ctr_direction(psa_key_id_t key, int decrypt,
                                  const uint8_t* input,
                                  const uint8_t* expected)
{
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    uint8_t output[32];
    size_t size = 0u;
    size_t tail = 0u;
    psa_status_t status;
    psa_status_t cleanup;

    status = decrypt ? psa_cipher_decrypt_setup(&operation, key, PSA_ALG_CTR) :
                       psa_cipher_encrypt_setup(&operation, key, PSA_ALG_CTR);
    if (status == PSA_SUCCESS) {
        status = psa_cipher_set_iv(&operation, ctr_iv, sizeof(ctr_iv));
    }
    if (status == PSA_SUCCESS) {
        status = psa_cipher_update(&operation, input, 16u, output,
                                   sizeof(output), &size);
    }
    if (status == PSA_SUCCESS && size > sizeof(output)) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status == PSA_SUCCESS) {
        status = psa_cipher_finish(&operation, output + size,
                                   sizeof(output) - size, &tail);
    }
    if (status == PSA_SUCCESS && (tail > sizeof(output) - size ||
            size + tail != 16u || memcmp(output, expected, 16u) != 0)) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    cleanup = psa_cipher_abort(&operation);
    return (status == PSA_SUCCESS) ? cleanup : status;
}

psa_status_t wt_guest_psa_ctr_check(void)
{
    static const uint8_t material[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    static const uint8_t plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    static const uint8_t ciphertext[16] = {
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
        0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce
    };
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t status;
    psa_status_t cleanup;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT |
                                         PSA_KEY_USAGE_DECRYPT);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
    psa_set_key_bits(&attributes, 128u);
    status = psa_import_key(&attributes, material, sizeof(material), &key);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = ctr_direction(key, 0, plaintext, ciphertext);
    if (status == PSA_SUCCESS) {
        status = ctr_direction(key, 1, ciphertext, plaintext);
    }
    cleanup = psa_destroy_key(key);
    return (status == PSA_SUCCESS) ? cleanup : status;
}
