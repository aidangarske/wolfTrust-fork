/* key_client.c
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

/* The crypto partition's client for the vault's key face (native engine):
 * every keyvault store access is one SERVICE_VAULT call, and the client
 * context lives in that partition's own band. */

#include "wolftrust/services/vault_ipc.h"
#include "wolftrust/services/vault_service.h"
#include "wolftrust/services/crypto_native.h"

#include <string.h>

static wt_svc_client_t g_kv_client;

/* One key-face call. The vault stamps the owner, so only the IAK read, which
 * attestation makes with the IAK triple, is sent with an owner of its own. */
static psa_status_t wt_hsm_kv_remote(int32_t type, int32_t owner, int32_t sub,
                                     uint64_t uid, uint32_t label,
                                     uint32_t select, uint32_t offset,
                                     const uint8_t* in, size_t in_len,
                                     uint8_t* out, size_t out_len)
{
    wt_vault_req_t req;
    size_t got = out_len;
    psa_status_t status = PSA_ERROR_COMMUNICATION_FAILURE;

    if (owner == WT_VAULT_IAK_OWNER) {
        if (type != WT_VAULT_OP_KEY_GET || sub != WT_VAULT_IAK_SUB ||
                uid != WT_VAULT_IAK_UID) {
            return PSA_ERROR_NOT_PERMITTED;
        }
        select |= WT_VAULT_KEY_SEL_IAK;
    }
    (void)memset(&req, 0, sizeof(req));
    req.uid = uid;
    req.flags = label;
    req.offset = offset;
    req.sub_owner = sub;
    req.select = select;
    if (wt_svc_client_call(&g_kv_client, type, &req, sizeof(req), in, in_len,
                           out, &got, &status) != WT_FFM_SUCCESS) {
        status = PSA_ERROR_COMMUNICATION_FAILURE;
    }
    else if (status == PSA_SUCCESS && got != out_len) {
        status = PSA_ERROR_STORAGE_FAILURE;
    }
    return status;
}

static psa_status_t wt_hsm_kv_remote_put(int32_t owner, int32_t sub,
                                         uint64_t uid, uint32_t label,
                                         const uint8_t* data, size_t len)
{
    return wt_hsm_kv_remote(WT_VAULT_OP_KEY_PUT, owner, sub, uid, label, 0U,
                            0U, data, len, NULL, 0U);
}

static psa_status_t wt_hsm_kv_remote_get(int32_t owner, int32_t sub,
                                         uint64_t uid, uint32_t want,
                                         uint32_t select, uint32_t offset,
                                         uint8_t* data, size_t len)
{
    return wt_hsm_kv_remote(WT_VAULT_OP_KEY_GET, owner, sub, uid, want, select,
                            offset, NULL, 0U, data, len);
}

static psa_status_t wt_hsm_kv_remote_del(int32_t owner, int32_t sub,
                                         uint64_t uid)
{
    return wt_hsm_kv_remote(WT_VAULT_OP_KEY_DEL, owner, sub, uid, 0U, 0U, 0U,
                            NULL, 0U, NULL, 0U);
}

static const wt_vault_keystore_t g_kv_remote = {
    wt_hsm_kv_remote_put,
    wt_hsm_kv_remote_get,
    wt_hsm_kv_remote_del
};

int wt_hsm_keyvault_bind_client(wt_spm_transport_fn transport,
                                wt_ffm_runtime_t* runtime,
                                int32_t partition_id, uint32_t vault_sid)
{
    if (transport == NULL || partition_id <= 0) {
        return -1;
    }
    (void)memset(&g_kv_client, 0, sizeof(g_kv_client));
    g_kv_client.transport = transport;
    g_kv_client.runtime = runtime;
    g_kv_client.partition_id = partition_id;
    g_kv_client.sid = vault_sid;
    return wt_hsm_keyvault_init(&g_kv_remote);
}

void wt_hsm_keyvault_vault_restarted(void)
{
    g_kv_client.restarted = 1U;
}
