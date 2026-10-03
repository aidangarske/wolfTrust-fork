/* psa_storage_reset_checks.c
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

/* SRC-PSA-STORAGE 3.2.14, 5.3.3 to 5.3.6 and 5.4.3 to 5.4.6. */
#include <stddef.h>
#include <string.h>

#include "psa/internal_trusted_storage.h"
#include "psa/protected_storage.h"
#include "psa_storage_reset_checks.h"

typedef struct wt_storage_test_api {
    psa_status_t (*set)(psa_storage_uid_t, size_t, const void*,
                         psa_storage_create_flags_t);
    psa_status_t (*get)(psa_storage_uid_t, size_t, size_t, void*, size_t*);
    psa_status_t (*info)(psa_storage_uid_t, struct psa_storage_info_t*);
    psa_status_t (*remove)(psa_storage_uid_t);
} wt_storage_test_api_t;

static const wt_storage_test_api_t g_storage_api[2] = {
    { psa_its_set, psa_its_get, psa_its_get_info, psa_its_remove },
    { psa_ps_set, psa_ps_get, psa_ps_get_info, psa_ps_remove }
};

static const uint8_t g_storage_value[16] = {
    0x57, 0x54, 0x2D, 0x52, 0x45, 0x53, 0x45, 0x54,
    0x2D, 0x53, 0x54, 0x4F, 0x52, 0x45, 0x2D, 0x31
};

static psa_status_t wt_storage_check_value(const wt_storage_test_api_t* api,
                                         psa_storage_uid_t uid,
                                         struct psa_storage_info_t* info)
{
    uint8_t data[sizeof(g_storage_value)];
    size_t length = 0U;
    psa_status_t status;

    (void)memset(info, 0, sizeof(*info));
    status = api->info(uid, info);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (info->size != sizeof(g_storage_value) ||
            info->capacity < info->size ||
            info->flags != PSA_STORAGE_FLAG_WRITE_ONCE) {
        return PSA_ERROR_DATA_CORRUPT;
    }
    (void)memset(data, 0, sizeof(data));
    status = api->get(uid, 0U, sizeof(data), data, &length);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (length != sizeof(data) ||
            memcmp(data, g_storage_value, sizeof(data)) != 0) {
        return PSA_ERROR_DATA_CORRUPT;
    }
    return PSA_SUCCESS;
}

psa_status_t wt_guest_storage_reset_check(wt_storage_reset_result_t* result)
{
    const psa_storage_uid_t uid = 0x57545253U;
    struct psa_storage_info_t info[2];
    psa_status_t present[2];
    psa_status_t status;
    uint8_t replacement[sizeof(g_storage_value)];
    uint32_t phase;
    uint32_t bit;
    size_t i;

    if (result == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void)memset(result, 0, sizeof(*result));
    result->signature = WT_STORAGE_RESET_SIGNATURE;
    result->phase = WT_STORAGE_RESET_FAILED;
    result->status = PSA_ERROR_GENERIC_ERROR;
    (void)memset(info, 0, sizeof(info));
    for (i = 0U; i < 2U; i++) {
        present[i] = g_storage_api[i].info(uid, &info[i]);
    }
    if (present[0] == PSA_ERROR_DOES_NOT_EXIST &&
            present[1] == PSA_ERROR_DOES_NOT_EXIST) {
        phase = WT_STORAGE_RESET_SEEDED;
        for (i = 0U; i < 2U; i++) {
            status = g_storage_api[i].set(uid, sizeof(g_storage_value),
                g_storage_value, PSA_STORAGE_FLAG_WRITE_ONCE);
            if (status != PSA_SUCCESS) {
                goto exit;
            }
        }
    }
    else if (present[0] == PSA_SUCCESS && present[1] == PSA_SUCCESS) {
        phase = WT_STORAGE_RESET_VERIFIED;
    }
    else {
        /* Partial state must not be repaired into a false reset pass. */
        status = present[0] != PSA_SUCCESS ? present[0] : present[1];
        goto exit;
    }

    (void)memset(replacement, 0xA5, sizeof(replacement));
    for (i = 0U; i < 2U; i++) {
        bit = 1U << (i * 5U);
        status = wt_storage_check_value(&g_storage_api[i], uid, &info[i]);
        if (status != PSA_SUCCESS) {
            goto exit;
        }
        result->passed |= bit | (bit << 1U);
        status = g_storage_api[i].set(uid, sizeof(replacement), replacement,
                                     PSA_STORAGE_FLAG_NONE);
        if (status != PSA_ERROR_NOT_PERMITTED) {
            status = status == PSA_SUCCESS ? PSA_ERROR_GENERIC_ERROR : status;
            goto exit;
        }
        result->passed |= bit << 2U;
        status = g_storage_api[i].remove(uid);
        if (status != PSA_ERROR_NOT_PERMITTED) {
            status = status == PSA_SUCCESS ? PSA_ERROR_GENERIC_ERROR : status;
            goto exit;
        }
        result->passed |= bit << 3U;
        status = wt_storage_check_value(&g_storage_api[i], uid, &info[i]);
        if (status != PSA_SUCCESS) {
            goto exit;
        }
        result->passed |= bit << 4U;
    }
    result->its_flags = info[0].flags;
    result->ps_flags = info[1].flags;
    result->phase = phase;
    status = PSA_SUCCESS;
exit:
    result->status = status;
    return status;
}
