/* nvm_client.c
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

#include "wolftrust/services/nvm_client.h"
#include "wolftrust/services/vault_service.h"

#include "wolfhsm/wh_error.h"

#include <string.h>

static int wt_nvm_client_xfer(wt_nvm_client_t* client, wt_spm_call_t* call)
{
    if (client->transport(client->runtime, call) != WT_FFM_SUCCESS ||
            call->ret_int == WT_FFM_ERROR_NOT_READY) {
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

/* Release a connection the vault's fault dropped to the error state: FF-M
 * lets the client close such a handle, never call it again. */
static void wt_nvm_client_close(wt_nvm_client_t* client)
{
    wt_spm_call_t call;

    if (client->vault_handle > 0) {
        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_CLOSE;
        call.partition_id = client->partition_id;
        call.msg_handle = client->vault_handle;
        (void)wt_nvm_client_xfer(client, &call);
    }
    client->vault_handle = 0;
    client->vault_restarted = 0U;
}

void wt_nvm_client_vault_restarted(wt_nvm_client_t* client)
{
    if (client != NULL) {
        client->vault_restarted = 1U;
    }
}

/* Lazy SP-to-SP connection to the vault, cached across operations. */
static int wt_nvm_client_connect(wt_nvm_client_t* client)
{
    wt_spm_call_t call;

    if (client->vault_restarted != 0U) {
        wt_nvm_client_close(client);
    }
    if (client->vault_handle > 0) {
        return WH_ERROR_OK;
    }
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CONNECT;
    call.partition_id = client->partition_id;
    call.sid = client->vault_sid;
    call.version = 1U;
    if (wt_nvm_client_xfer(client, &call) != WH_ERROR_OK ||
            call.ret_int != WT_FFM_SUCCESS || call.ret_handle <= 0) {
        return WH_ERROR_ABORTED;
    }
    client->vault_handle = call.ret_handle;
    return WH_ERROR_OK;
}

static int wt_nvm_client_status(psa_status_t status)
{
    int rc;

    switch (status) {
    case PSA_SUCCESS:
        rc = WH_ERROR_OK;
        break;
    case PSA_ERROR_DOES_NOT_EXIST:
        rc = WH_ERROR_NOTFOUND;
        break;
    case PSA_ERROR_NOT_PERMITTED:
        rc = WH_ERROR_ACCESS;
        break;
    case PSA_ERROR_INSUFFICIENT_STORAGE:
        rc = WH_ERROR_NOSPACE;
        break;
    case PSA_ERROR_INVALID_ARGUMENT:
        rc = WH_ERROR_BADARGS;
        break;
    default:
        rc = WH_ERROR_ABORTED;
        break;
    }
    return rc;
}

/* One door call: invec[0] is the request, invec[1] optional data,
 * outvec[0] optional reply. */
static int wt_nvm_client_call(wt_nvm_client_t* client, int32_t type,
                              const wt_vault_nvm_req_t* req,
                              const void* in_data, size_t in_len,
                              void* out, size_t out_cap)
{
    wt_spm_call_t call;
    int rc;

    rc = wt_nvm_client_connect(client);
    if (rc != WH_ERROR_OK) {
        return rc;
    }
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CALL;
    call.partition_id = client->partition_id;
    call.msg_handle = client->vault_handle;
    call.call_type = type;
    call.sp_in[0].base = req;
    call.sp_in[0].len = sizeof(*req);
    call.sp_in_len = 1U;
    if (in_data != NULL) {
        call.sp_in[1].base = in_data;
        call.sp_in[1].len = in_len;
        call.sp_in_len = 2U;
    }
    if (out != NULL) {
        call.sp_out[0].base = out;
        call.sp_out[0].len = out_cap;
        call.sp_out_len = 1U;
    }
    if (wt_nvm_client_xfer(client, &call) != WH_ERROR_OK ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WH_ERROR_ABORTED;
    }
    if (call.ret_status == PSA_ERROR_COMMUNICATION_FAILURE) {
        /* The vault faulted under this request (WT-FFM-0017): the request
         * is not replayed, and the dropped connection is closed now. */
        wt_nvm_client_close(client);
        return WH_ERROR_ABORTED;
    }
    rc = wt_nvm_client_status(call.ret_status);
    if (rc == WH_ERROR_OK && out != NULL &&
            call.sp_out[0].len != out_cap) {
        rc = WH_ERROR_ABORTED;
    }
    return rc;
}

static int wt_nvm_client_cb_init(void* context, const void* config)
{
    (void)config;
    return (context != NULL) ? WH_ERROR_OK : WH_ERROR_BADARGS;
}

static int wt_nvm_client_cb_cleanup(void* context)
{
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }
    wt_nvm_client_close((wt_nvm_client_t*)context);
    return WH_ERROR_OK;
}

static int wt_nvm_client_cb_get_available(void* context,
                                          uint32_t* out_avail_size,
                                          whNvmId* out_avail_objects,
                                          uint32_t* out_reclaim_size,
                                          whNvmId* out_reclaim_objects)
{
    wt_vault_nvm_req_t req;
    wt_vault_nvm_avail_t avail;
    int rc;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }
    (void)memset(&req, 0, sizeof(req));
    (void)memset(&avail, 0, sizeof(avail));
    rc = wt_nvm_client_call((wt_nvm_client_t*)context,
                            WT_VAULT_OP_NVM_GET_AVAILABLE, &req, NULL, 0U,
                            &avail, sizeof(avail));
    if (rc == WH_ERROR_OK) {
        if (out_avail_size != NULL) {
            *out_avail_size = avail.avail_size;
        }
        if (out_avail_objects != NULL) {
            *out_avail_objects = avail.avail_objects;
        }
        if (out_reclaim_size != NULL) {
            *out_reclaim_size = avail.reclaim_size;
        }
        if (out_reclaim_objects != NULL) {
            *out_reclaim_objects = avail.reclaim_objects;
        }
    }
    return rc;
}

static int wt_nvm_client_cb_add_object(void* context, whNvmMetadata* meta,
                                       whNvmSize data_len,
                                       const uint8_t* data)
{
    wt_vault_nvm_req_t req;

    if (context == NULL || meta == NULL || (data == NULL && data_len != 0U)) {
        return WH_ERROR_BADARGS;
    }
    (void)memset(&req, 0, sizeof(req));
    req.id = meta->id;
    req.access = meta->access;
    req.flags = meta->flags;
    req.len = data_len;
    (void)memcpy(req.label, meta->label, sizeof(req.label));
    return wt_nvm_client_call((wt_nvm_client_t*)context,
                              WT_VAULT_OP_NVM_ADD_OBJECT, &req, data,
                              (size_t)data_len, NULL, 0U);
}

static int wt_nvm_client_cb_get_metadata(void* context, whNvmId id,
                                         whNvmMetadata* meta)
{
    wt_vault_nvm_req_t req;
    wt_vault_nvm_meta_t reply;
    int rc;

    /* A NULL meta is the keystore's existence probe (unique-id allocation). */
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }
    (void)memset(&req, 0, sizeof(req));
    req.id = id;
    (void)memset(&reply, 0, sizeof(reply));
    rc = wt_nvm_client_call((wt_nvm_client_t*)context,
                            WT_VAULT_OP_NVM_GET_METADATA, &req, NULL, 0U,
                            &reply, sizeof(reply));
    if (rc == WH_ERROR_OK && meta != NULL) {
        (void)memset(meta, 0, sizeof(*meta));
        meta->id = reply.id;
        meta->access = reply.access;
        meta->flags = reply.flags;
        meta->len = reply.len;
        (void)memcpy(meta->label, reply.label, sizeof(meta->label));
    }
    return rc;
}

static int wt_nvm_client_cb_destroy_objects(void* context,
                                            whNvmId list_count,
                                            const whNvmId* id_list)
{
    wt_vault_nvm_req_t req;
    uint16_t ids[WT_VAULT_NVM_DESTROY_MAX];
    size_t i;

    if (context == NULL || (id_list == NULL && list_count != 0U) ||
            list_count > WT_VAULT_NVM_DESTROY_MAX) {
        return WH_ERROR_BADARGS;
    }
    (void)memset(&req, 0, sizeof(req));
    req.count = list_count;
    for (i = 0U; i < list_count; i++) {
        ids[i] = id_list[i];
    }
    return wt_nvm_client_call((wt_nvm_client_t*)context,
                              WT_VAULT_OP_NVM_DESTROY, &req,
                              (list_count != 0U) ? (const void*)ids : NULL,
                              (size_t)list_count * sizeof(ids[0]), NULL, 0U);
}

static int wt_nvm_client_cb_read(void* context, whNvmId id, whNvmSize offset,
                                 whNvmSize data_len, uint8_t* data)
{
    wt_vault_nvm_req_t req;

    if (context == NULL || (data == NULL && data_len != 0U)) {
        return WH_ERROR_BADARGS;
    }
    (void)memset(&req, 0, sizeof(req));
    req.id = id;
    req.offset = offset;
    req.len = data_len;
    return wt_nvm_client_call((wt_nvm_client_t*)context,
                              WT_VAULT_OP_NVM_READ, &req, NULL, 0U,
                              (data_len != 0U) ? data : NULL,
                              (size_t)data_len);
}

/* List is a client-facing NVM-group operation the relay refuses before it
 * can reach a server, so the door does not carry it. */
const whNvmCb wt_nvm_client_cb = {
    wt_nvm_client_cb_init,
    wt_nvm_client_cb_cleanup,
    wt_nvm_client_cb_get_available,
    wt_nvm_client_cb_add_object,
    NULL,
    wt_nvm_client_cb_get_metadata,
    wt_nvm_client_cb_destroy_objects,
    wt_nvm_client_cb_read
};

#ifdef WOLFHSM_CFG_THREADSAFE
static int wt_nvm_client_lock_init(void* context, const void* config)
{
    (void)context;
    (void)config;
    return WH_ERROR_OK;
}

static int wt_nvm_client_lock_cleanup(void* context)
{
    (void)context;
    return WH_ERROR_OK;
}

static int wt_nvm_client_lock_acquire(void* context)
{
    (void)context;
    return WH_ERROR_OK;
}

static int wt_nvm_client_lock_release(void* context)
{
    (void)context;
    return WH_ERROR_OK;
}

static const whLockCb g_nvm_client_lock_cb = {
    wt_nvm_client_lock_init,
    wt_nvm_client_lock_cleanup,
    wt_nvm_client_lock_acquire,
    wt_nvm_client_lock_release
};
#endif /* WOLFHSM_CFG_THREADSAFE */

int wt_nvm_client_bind(wt_nvm_client_t* client, whNvmContext* nvm,
                       wt_spm_transport_fn transport,
                       wt_ffm_runtime_t* runtime, int32_t partition_id,
                       uint32_t vault_sid)
{
    whNvmConfig cfg;
#ifdef WOLFHSM_CFG_THREADSAFE
    whLockConfig lock_cfg;
#endif

    if (client == NULL || nvm == NULL || transport == NULL ||
            partition_id <= 0) {
        return -1;
    }
    (void)memset(client, 0, sizeof(*client));
    client->transport = transport;
    client->runtime = runtime;
    client->partition_id = partition_id;
    client->vault_sid = vault_sid;
    client->vault_handle = 0;

    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.cb = (whNvmCb*)&wt_nvm_client_cb;
    cfg.context = client;
    cfg.config = NULL;
#ifdef WOLFHSM_CFG_THREADSAFE
    (void)memset(&lock_cfg, 0, sizeof(lock_cfg));
    lock_cfg.cb = &g_nvm_client_lock_cb;
    cfg.lockConfig = &lock_cfg;
#endif
    (void)memset(nvm, 0, sizeof(*nvm));
    if (wh_Nvm_Init(nvm, &cfg) != WH_ERROR_OK) {
        return -1;
    }
    return 0;
}

static wt_nvm_client_t g_nvm_client;
static whNvmContext g_nvm_client_ctx;

int wt_nvm_client_bind_partition(wt_spm_transport_fn transport,
                                 wt_ffm_runtime_t* runtime,
                                 int32_t partition_id, uint32_t vault_sid)
{
    return wt_nvm_client_bind(&g_nvm_client, &g_nvm_client_ctx, transport,
                              runtime, partition_id, vault_sid);
}

whNvmContext* wt_nvm_client_partition_nvm(void)
{
    return &g_nvm_client_ctx;
}

void wt_nvm_client_partition_pin(void)
{
    g_nvm_client_ctx.cb = (whNvmCb*)&wt_nvm_client_cb;
    g_nvm_client_ctx.context = &g_nvm_client;
#ifdef WOLFHSM_CFG_THREADSAFE
    g_nvm_client_ctx.lock.cb = &g_nvm_client_lock_cb;
    g_nvm_client_ctx.lock.context = NULL;
#endif
}

#if defined(WT_HSM_PIN_NEG_PROBE) && (WT_HSM_PIN_NEG_PROBE == 1)
int wt_nvm_client_partition_pin_probe(void)
{
    void* sentinel = (void*)0x30028001u;
    int healed;

    g_nvm_client_ctx.cb = (whNvmCb*)sentinel;
    g_nvm_client_ctx.context = sentinel;
#ifdef WOLFHSM_CFG_THREADSAFE
    g_nvm_client_ctx.lock.cb = (const whLockCb*)sentinel;
    g_nvm_client_ctx.lock.context = sentinel;
#endif

    wt_nvm_client_partition_pin();

    healed = (g_nvm_client_ctx.cb == (whNvmCb*)&wt_nvm_client_cb) &&
             (g_nvm_client_ctx.context == (void*)&g_nvm_client);
#ifdef WOLFHSM_CFG_THREADSAFE
    healed = healed &&
             (g_nvm_client_ctx.lock.cb == &g_nvm_client_lock_cb) &&
             (g_nvm_client_ctx.lock.context == NULL);
#endif
    return healed;
}
#endif

void wt_nvm_client_partition_vault_restarted(void)
{
    wt_nvm_client_vault_restarted(&g_nvm_client);
}
