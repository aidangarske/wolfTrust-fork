/* vault_service.c
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

#include "wolftrust/services/vault_ipc.h"
#include "wolftrust/services/vault_service.h"
#include "wolftrust/zeroize.h"

#include <string.h>

/* Fail-closed default: no backing store means no storage capability is
 * advertised or silently faked (no always-success stubs). */
static psa_status_t wt_vault_default_set(int32_t owner, int32_t sub,
                                         uint64_t uid, uint32_t flags,
                                         const uint8_t* data, size_t len)
{
    (void)owner; (void)sub; (void)uid; (void)flags; (void)data; (void)len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_get(int32_t owner, int32_t sub,
                                         uint64_t uid, uint32_t offset,
                                         uint8_t* data, size_t size,
                                         size_t* out_len)
{
    (void)owner; (void)sub; (void)uid; (void)offset; (void)data; (void)size;
    (void)out_len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_get_info(int32_t owner, int32_t sub,
                                              uint64_t uid,
                                              wt_vault_info_t* info)
{
    (void)owner; (void)sub; (void)uid; (void)info;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_remove(int32_t owner, int32_t sub,
                                            uint64_t uid)
{
    (void)owner; (void)sub; (void)uid;
    return PSA_ERROR_NOT_SUPPORTED;
}

static const wt_vault_backend_t g_vault_default_backend = {
    wt_vault_default_set,
    wt_vault_default_get,
    wt_vault_default_get_info,
    wt_vault_default_remove
};

static psa_status_t wt_vault_default_rng(uint8_t* out, size_t len)
{
    (void)out; (void)len;
    return PSA_ERROR_NOT_SUPPORTED;
}

/* Fail-closed keystore door defaults: no store backend, no door. */
static psa_status_t wt_vault_default_nvm_get_available(
    wt_vault_nvm_avail_t* avail)
{
    (void)avail;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_nvm_get_metadata(uint16_t id,
                                                      wt_vault_nvm_meta_t* meta)
{
    (void)id; (void)meta;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_nvm_add_object(
    const wt_vault_nvm_meta_t* meta, const uint8_t* data, size_t len)
{
    (void)meta; (void)data; (void)len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_nvm_destroy(const uint16_t* ids,
                                                 size_t count)
{
    (void)ids; (void)count;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wt_vault_default_nvm_read(uint16_t id, uint32_t offset,
                                              uint8_t* data, size_t len)
{
    (void)id; (void)offset; (void)data; (void)len;
    return PSA_ERROR_NOT_SUPPORTED;
}

static const wt_vault_nvm_backend_t g_vault_default_nvm_backend = {
    wt_vault_default_nvm_get_available,
    wt_vault_default_nvm_get_metadata,
    wt_vault_default_nvm_add_object,
    wt_vault_default_nvm_destroy,
    wt_vault_default_nvm_read
};

static const wt_vault_backend_t* g_vault_backend = &g_vault_default_backend;
static const wt_vault_nvm_backend_t* g_vault_nvm_backend =
    &g_vault_default_nvm_backend;
static int32_t g_vault_keystore_client;
static wt_vault_rng_fn g_vault_rng = wt_vault_default_rng;
static wt_spm_transport_fn g_vault_transport = WT_SPM_TRANSPORT_DEFAULT;

#if defined(WT_RESTART_NEG_PROBE) && (WT_RESTART_NEG_PROBE != 0)
#include "wolftrust/spm_transport.h"
WT_RESTART_PROBE_DEFINE(wt_vault_restart_probe)
#endif

void wt_vault_service_set_backend(const wt_vault_backend_t* backend)
{
    g_vault_backend = (backend != NULL) ? backend : &g_vault_default_backend;
}

void wt_vault_service_set_rng(wt_vault_rng_fn fn)
{
    g_vault_rng = (fn != NULL) ? fn : wt_vault_default_rng;
}

void wt_vault_service_set_transport(wt_spm_transport_fn fn)
{
    g_vault_transport = (fn != NULL) ? fn : WT_SPM_TRANSPORT_DEFAULT;
}

void wt_vault_service_set_keystore_client(int32_t partition_id)
{
    g_vault_keystore_client = (partition_id > 0) ? partition_id : 0;
}

void wt_vault_service_set_nvm_backend(const wt_vault_nvm_backend_t* backend)
{
    g_vault_nvm_backend = (backend != NULL) ? backend :
                          &g_vault_default_nvm_backend;
}

#if defined(WT_VAULT_WIPE_PROBE) && (WT_VAULT_WIPE_PROBE == 1)
void wt_vault_wipe_probe(const uint8_t* buf, size_t len);
#define WT_VAULT_WIPED(buf, len) wt_vault_wipe_probe((buf), (len))
#else
#define WT_VAULT_WIPED(buf, len) ((void)0)
#endif

static psa_status_t wt_vault_service_serve(const wt_svc_t* svc,
                                           const psa_msg_t* msg,
                                           uint8_t* data)
{
    wt_vault_req_t req;
    wt_vault_info_t info;
    size_t req_len = 0U;
    size_t data_len = 0U;
    size_t out_len = 0U;
    size_t cap;
    psa_status_t status;

    status = PSA_ERROR_INVALID_ARGUMENT;
    if (msg->in_size[0] == sizeof(req) &&
            wt_svc_read(svc, 0U, &req, sizeof(req), &req_len) ==
                WT_FFM_SUCCESS && req_len == sizeof(req)) {
        switch (msg->type) {
        case WT_VAULT_OP_SET:
            if (msg->in_size[1] > WT_VAULT_OBJECT_MAX) {
                status = PSA_ERROR_INSUFFICIENT_STORAGE;
            }
            else if (wt_svc_read(svc, 1U, data, WT_VAULT_OBJECT_MAX,
                                 &data_len) != WT_FFM_SUCCESS) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                status = g_vault_backend->set(msg->client_id, req.sub_owner,
                                              req.uid, req.flags, data, data_len);
            }
            break;
        case WT_VAULT_OP_GET:
            /* A caller buffer larger than the object bound is legal PSA usage.
             * Clamp it because no object exceeds the transfer buffer. */
            data_len = msg->out_size[0];
            if (data_len > WT_VAULT_OBJECT_MAX) {
                data_len = WT_VAULT_OBJECT_MAX;
            }
            status = g_vault_backend->get(msg->client_id, req.sub_owner, req.uid,
                                          req.offset, data, data_len, &out_len);
            if (status == PSA_SUCCESS &&
                    wt_svc_write(svc, 0U, data, out_len) != WT_FFM_SUCCESS) {
                status = PSA_ERROR_GENERIC_ERROR;
            }
            break;
        case WT_VAULT_OP_GET_INFO:
            if (msg->out_size[0] < sizeof(info)) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                status = g_vault_backend->get_info(msg->client_id, req.sub_owner,
                                                   req.uid, &info);
                if (status == PSA_SUCCESS &&
                        wt_svc_write(svc, 0U, &info, sizeof(info)) !=
                            WT_FFM_SUCCESS) {
                    status = PSA_ERROR_GENERIC_ERROR;
                }
            }
            break;
        case WT_VAULT_OP_REMOVE:
            status = g_vault_backend->remove(msg->client_id, req.sub_owner,
                                             req.uid);
            break;
        case WT_VAULT_OP_RANDOM:
            cap = msg->out_size[0];
            if (cap == 0U || cap > WT_VAULT_RANDOM_MAX) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                status = g_vault_rng(data, cap);
                if (status == PSA_SUCCESS &&
                        wt_svc_write(svc, 0U, data, cap) != WT_FFM_SUCCESS) {
                    status = PSA_ERROR_GENERIC_ERROR;
                }
            }
            break;
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
        }
    }
    return status;
}

/* The copied transfers carry caller objects and key material: wipe the
 * buffers before the frame is released. */
static psa_status_t wt_vault_service_call(const wt_svc_t* svc,
                                          const psa_msg_t* msg)
{
    uint8_t data[WT_VAULT_OBJECT_MAX];
    psa_status_t status;

    status = wt_vault_service_serve(svc, msg, data);
    wt_forceZero(data, sizeof(data));
    WT_VAULT_WIPED(data, sizeof(data));
    return status;
}

/* Keystore object door (WT_VAULT_OP_NVM_*): the crypto partition's NVM
 * callbacks, served only for the registered keystore client. Object data
 * crosses in copied IOVECs bounded by WT_VAULT_OBJECT_MAX. */
static psa_status_t wt_vault_nvm_serve(const wt_svc_t* svc,
                                       const psa_msg_t* msg, uint8_t* data)
{
    uint16_t ids[WT_VAULT_NVM_DESTROY_MAX];
    wt_vault_nvm_req_t req;
    wt_vault_nvm_meta_t meta;
    wt_vault_nvm_avail_t avail;
    size_t req_len = 0U;
    size_t data_len = 0U;
    size_t count;
    psa_status_t status;

    if (g_vault_keystore_client == 0 ||
            msg->client_id != g_vault_keystore_client) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (msg->in_size[0] != sizeof(req)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (wt_svc_read(svc, 0U, &req, sizeof(req), &req_len) !=
            WT_FFM_SUCCESS || req_len != sizeof(req)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (msg->type) {
    case WT_VAULT_OP_NVM_GET_AVAILABLE:
        if (msg->out_size[0] < sizeof(avail)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        (void)memset(&avail, 0, sizeof(avail));
        status = g_vault_nvm_backend->get_available(&avail);
        if (status == PSA_SUCCESS &&
                wt_svc_write(svc, 0U, &avail, sizeof(avail)) !=
                    WT_FFM_SUCCESS) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
        break;
    case WT_VAULT_OP_NVM_GET_METADATA:
        if (msg->out_size[0] < sizeof(meta)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        (void)memset(&meta, 0, sizeof(meta));
        status = g_vault_nvm_backend->get_metadata(req.id, &meta);
        if (status == PSA_SUCCESS &&
                wt_svc_write(svc, 0U, &meta, sizeof(meta)) != WT_FFM_SUCCESS) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
        break;
    case WT_VAULT_OP_NVM_ADD_OBJECT:
        if (msg->in_size[1] > WT_VAULT_OBJECT_MAX ||
                req.len != msg->in_size[1]) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (wt_svc_read(svc, 1U, data, WT_VAULT_OBJECT_MAX, &data_len) !=
                WT_FFM_SUCCESS) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        (void)memset(&meta, 0, sizeof(meta));
        meta.id = req.id;
        meta.access = req.access;
        meta.flags = req.flags;
        meta.len = (uint16_t)data_len;
        (void)memcpy(meta.label, req.label, sizeof(meta.label));
        status = g_vault_nvm_backend->add_object(&meta, data, data_len);
        break;
    case WT_VAULT_OP_NVM_DESTROY:
        count = req.count;
        if (count > WT_VAULT_NVM_DESTROY_MAX ||
                msg->in_size[1] != count * sizeof(ids[0])) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (count != 0U &&
                (wt_svc_read(svc, 1U, ids, count * sizeof(ids[0]),
                             &data_len) != WT_FFM_SUCCESS ||
                 data_len != count * sizeof(ids[0]))) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = g_vault_nvm_backend->destroy(ids, count);
        break;
    case WT_VAULT_OP_NVM_READ:
        if (req.len > WT_VAULT_OBJECT_MAX || msg->out_size[0] < req.len) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = g_vault_nvm_backend->read(req.id, req.offset, data,
                                           (size_t)req.len);
        if (status == PSA_SUCCESS &&
                wt_svc_write(svc, 0U, data, (size_t)req.len) !=
                    WT_FFM_SUCCESS) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
        break;
    default:
        status = PSA_ERROR_NOT_SUPPORTED;
        break;
    }
    return status;
}

static psa_status_t wt_vault_nvm_call(const wt_svc_t* svc,
                                      const psa_msg_t* msg)
{
    uint8_t data[WT_VAULT_OBJECT_MAX];
    psa_status_t status;

    status = wt_vault_nvm_serve(svc, msg, data);
    wt_forceZero(data, sizeof(data));
    WT_VAULT_WIPED(data, sizeof(data));
    return status;
}

static psa_status_t wt_vault_handle(void* ctx, const wt_svc_t* svc,
                                    const psa_msg_t* msg)
{
    psa_status_t status;

    (void)ctx;
    if (msg->type == PSA_IPC_CONNECT) {
        /* Defense in depth on top of nonsecure_clients=false: the vault
         * serves Secure Partitions only (WT-FFM-0047). */
        status = (msg->client_id > 0) ? PSA_SUCCESS :
                 PSA_ERROR_CONNECTION_REFUSED;
    } else if (msg->type == PSA_IPC_DISCONNECT) {
        status = PSA_SUCCESS;
    } else if (msg->type >= WT_VAULT_OP_SET &&
               msg->type <= WT_VAULT_OP_RANDOM) {
        if (g_vault_keystore_client != 0 &&
                msg->client_id == g_vault_keystore_client) {
            status = PSA_ERROR_NOT_PERMITTED;
        } else {
            status = wt_vault_service_call(svc, msg);
        }
    } else if (msg->type >= WT_VAULT_OP_NVM_GET_AVAILABLE &&
               msg->type <= WT_VAULT_OP_NVM_READ) {
        status = wt_vault_nvm_call(svc, msg);
    } else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }
    return status;
}

int wt_vault_service_dispatch(void* context, wt_ffm_runtime_t* runtime,
                              int32_t partition_id)
{
    (void)context;
    return wt_svc_dispatch(g_vault_transport, runtime, partition_id,
                           wt_vault_handle, NULL);
}
