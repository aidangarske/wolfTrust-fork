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

#include "wolftrust/services/service_ipc.h"
#include "wolftrust/services/storage_service.h"
#include "wolftrust/zeroize.h"

#include <string.h>

/* One completed gate op: both transports finish blocking SP-as-client ops
 * before returning (the SVC transport re-issues around the coroutine block;
 * the direct transport dispatches the pending message inline). A residual
 * NOT_READY is therefore a failure, never a reason to spin. */
static int wt_storage_xfer(const wt_svc_t* svc, wt_spm_call_t* call)
{
    call->partition_id = svc->partition_id;
    if (svc->transport(svc->runtime, call) != WT_FFM_SUCCESS ||
            call->ret_int == WT_FFM_ERROR_NOT_READY) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}

/* SP-to-SP connection to the vault, held for one request: the vault may
 * restart between requests, and a handle kept across that is unusable. */
static psa_status_t wt_storage_vault_handle(wt_storage_service_ctx_t* ctx,
                                            const wt_svc_t* svc)
{
    wt_spm_call_t call;

    if (ctx->vault_handle > 0) {
        return PSA_SUCCESS;
    }
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CONNECT;
    call.sid = ctx->vault_sid;
    call.version = 1U;
    if (wt_storage_xfer(svc, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS || call.ret_handle <= 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    ctx->vault_handle = call.ret_handle;
    return PSA_SUCCESS;
}

static void wt_storage_vault_close(wt_storage_service_ctx_t* ctx,
                                   const wt_svc_t* svc)
{
    wt_spm_call_t call;

    if (ctx->vault_handle > 0) {
        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_CLOSE;
        call.msg_handle = ctx->vault_handle;
        (void)wt_storage_xfer(svc, &call);
    }
    ctx->vault_handle = 0;
}

static psa_status_t wt_storage_vault_call(wt_storage_service_ctx_t* ctx,
                                          const wt_svc_t* svc, int32_t type,
                                          const wt_vault_req_t* vreq,
                                          const uint8_t* set_data,
                                          size_t set_len,
                                          void* out, size_t out_cap,
                                          size_t* out_len)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CALL;
    call.msg_handle = ctx->vault_handle;
    call.call_type = type;
    call.sp_in[0].base = vreq;
    call.sp_in[0].len = sizeof(*vreq);
    call.sp_in_len = 1U;
    if (set_data != NULL) {
        call.sp_in[1].base = set_data;
        call.sp_in[1].len = set_len;
        call.sp_in_len = 2U;
    }
    if (out != NULL) {
        call.sp_out[0].base = out;
        call.sp_out[0].len = out_cap;
        call.sp_out_len = 1U;
    }
    if (wt_storage_xfer(svc, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    if (out_len != NULL) {
        *out_len = call.sp_out[0].len;
    }
    return call.ret_status;
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
    psa_status_t status;

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
                status = wt_storage_vault_handle(ctx, svc);
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
            if (in_len - sizeof(req) > WT_FFM_TRANSFER_BYTES - sizeof(vreq)) {
                status = PSA_ERROR_INSUFFICIENT_STORAGE;
                break;
            }
            vreq.flags = req.flags | ctx->vault_flags;
            status = wt_storage_vault_call(ctx, svc, WT_VAULT_OP_SET, &vreq,
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
            if (cap > WT_FFM_TRANSFER_BYTES - sizeof(vreq)) {
                cap = WT_FFM_TRANSFER_BYTES - sizeof(vreq);
            }
            status = wt_storage_vault_call(ctx, svc, WT_VAULT_OP_GET, &vreq,
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
                status = wt_storage_vault_call(ctx, svc, WT_VAULT_OP_GET_INFO,
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
            status = wt_storage_vault_call(ctx, svc, WT_VAULT_OP_REMOVE,
                                           &vreq, NULL, 0U, NULL, 0U, NULL);
            break;
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
        }
    }
    wt_storage_vault_close(ctx, svc);
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
