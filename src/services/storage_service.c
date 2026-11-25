/* storage_service.c
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
#include "wolftrust/services/storage_service.h"
#include "wolftrust/zeroize.h"

#include <string.h>

/* One vault request on a connection held for this request only: the vault
 * may restart between requests, and a handle kept across that is unusable. */
static psa_status_t wt_storage_vault_call(wt_svc_client_t* vault,
                                          int32_t type,
                                          const wt_vault_req_t* vreq,
                                          const uint8_t* set_data,
                                          size_t set_len,
                                          void* out, size_t out_cap,
                                          size_t* out_len)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    size_t len = out_cap;

    if (wt_svc_client_call(vault, type, vreq, sizeof(*vreq), set_data,
                           set_len, out, &len, &status) != WT_FFM_SUCCESS) {
        status = PSA_ERROR_GENERIC_ERROR;
    }
    else if (out_len != NULL) {
        *out_len = len;
    }
    return status;
}

static psa_status_t wt_storage_service_call(wt_storage_service_ctx_t* ctx,
                                            const wt_svc_t* svc,
                                            const psa_msg_t* msg)
{
    uint8_t buffer[sizeof(wt_its_req_t) + WT_VAULT_OBJECT_MAX];
    wt_its_req_t req;
    wt_vault_req_t vreq;
    wt_vault_info_t info;
    size_t in_len = 0U;
    size_t out_len = 0U;
    size_t cap;
    wt_svc_client_t vault;
    psa_status_t status;

    (void)memset(&vault, 0, sizeof(vault));
    vault.transport = svc->transport;
    vault.runtime = svc->runtime;
    vault.partition_id = svc->partition_id;
    vault.sid = ctx->vault_sid;
    status = PSA_ERROR_INVALID_ARGUMENT;
    if (msg->in_size[0] >= sizeof(req)) {
        if (msg->in_size[0] > sizeof(buffer)) {
            status = PSA_ERROR_INSUFFICIENT_STORAGE;
        }
        else if (wt_svc_read(svc, 0U, buffer, sizeof(buffer), &in_len) !=
                    WT_FFM_SUCCESS || in_len < sizeof(req)) {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
        else {
            (void)memcpy(&req, buffer, sizeof(req));
            /* PSA Storage: uid 0 is invalid for every operation. */
            if (req.uid == 0U) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            /* Optional PS features (create/set_extended): psa_ps_get_support
             * advertises none, so refuse them until implemented. */
            else if (msg->type == WT_PS_OP_CREATE ||
                    msg->type == WT_PS_OP_SET_EXTENDED) {
                status = PSA_ERROR_NOT_SUPPORTED;
            }
            else {
                status = PSA_SUCCESS;
            }
        }
    }

    if (status == PSA_SUCCESS) {
        /* The vault namespaces by (this partition, end client, uid): the
         * SPM-stamped message client id is the delegated sub_owner. */
        (void)memset(&vreq, 0, sizeof(vreq));
        vreq.uid = req.uid;
        vreq.flags = req.flags;
        vreq.offset = req.offset;
        vreq.sub_owner = msg->client_id;

        switch (msg->type) {
        case WT_ITS_OP_SET:
            if ((req.flags & ~ctx->client_flags_mask) != 0U) {
                status = PSA_ERROR_NOT_SUPPORTED;
                break;
            }
            /* The vault request header shares the forwarded transfer budget. */
            if (in_len - sizeof(req) > WT_SPM_TRANSFER_BYTES - sizeof(vreq)) {
                status = PSA_ERROR_INSUFFICIENT_STORAGE;
                break;
            }
            vreq.flags = req.flags | ctx->vault_flags;
            status = wt_storage_vault_call(&vault, WT_VAULT_OP_SET, &vreq,
                                           buffer + sizeof(req),
                                           in_len - sizeof(req), NULL, 0U,
                                           NULL);
            break;
        case WT_ITS_OP_GET:
            cap = msg->out_size[0];
            if (cap > WT_VAULT_OBJECT_MAX) {
                cap = WT_VAULT_OBJECT_MAX;
            }
            /* The vault request header shares the reply's transfer budget. */
            if (cap > WT_SPM_TRANSFER_BYTES - sizeof(vreq)) {
                cap = WT_SPM_TRANSFER_BYTES - sizeof(vreq);
            }
            status = wt_storage_vault_call(&vault, WT_VAULT_OP_GET, &vreq,
                                           NULL, 0U, buffer, cap, &out_len);
            if (status == PSA_SUCCESS &&
                    wt_svc_write(svc, 0U, buffer, out_len) !=
                        WT_FFM_SUCCESS) {
                status = PSA_ERROR_GENERIC_ERROR;
            }
            break;
        case WT_ITS_OP_GET_INFO:
            if (msg->out_size[0] < sizeof(info)) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
            else {
                status = wt_storage_vault_call(&vault, WT_VAULT_OP_GET_INFO,
                                               &vreq, NULL, 0U, &info,
                                               sizeof(info), NULL);
                if (status == PSA_SUCCESS) {
                    /* Hide the frontend's internal sealing flag. */
                    info.flags &= ~ctx->vault_flags;
                }
                if (status == PSA_SUCCESS &&
                        wt_svc_write(svc, 0U, &info, sizeof(info)) !=
                            WT_FFM_SUCCESS) {
                    status = PSA_ERROR_GENERIC_ERROR;
                }
            }
            break;
        case WT_ITS_OP_REMOVE:
            status = wt_storage_vault_call(&vault, WT_VAULT_OP_REMOVE,
                                           &vreq, NULL, 0U, NULL, 0U, NULL);
            break;
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
        }
    }
    wt_svc_client_close(&vault);
    wt_forceZero(buffer, sizeof(buffer));
    return status;
}

static psa_status_t wt_storage_handle(void* context, const wt_svc_t* svc,
                                      const psa_msg_t* msg)
{
    wt_storage_service_ctx_t* ctx = (wt_storage_service_ctx_t*)context;
    psa_status_t status;
    uint32_t caps;

    if (msg->type == PSA_IPC_CONNECT || msg->type == PSA_IPC_DISCONNECT) {
        status = PSA_SUCCESS;
    } else if (msg->type == WT_PS_OP_GET_SUPPORT) {
        caps = ctx->caps;
        if (msg->out_size[0] < sizeof(caps)) {
            status = PSA_ERROR_INVALID_ARGUMENT;
        } else if (wt_svc_write(svc, 0U, &caps, sizeof(caps)) !=
                       WT_FFM_SUCCESS) {
            status = PSA_ERROR_GENERIC_ERROR;
        } else {
            status = PSA_SUCCESS;
        }
    } else if (msg->type >= WT_ITS_OP_SET &&
               msg->type <= WT_PS_OP_SET_EXTENDED) {
        status = wt_storage_service_call(ctx, svc, msg);
    } else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }
    return status;
}

int wt_storage_service_dispatch(void* context, wt_ffm_runtime_t* runtime,
                                int32_t partition_id)
{
    wt_storage_service_ctx_t* ctx = (wt_storage_service_ctx_t*)context;

    if (ctx == NULL || ctx->transport == NULL) {
        return WT_FFM_ERROR_STATE;
    }
    return wt_svc_dispatch(ctx->transport, runtime, partition_id,
                           wt_storage_handle, ctx);
}
