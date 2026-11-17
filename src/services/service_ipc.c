/* service_ipc.c
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

#include <string.h>

int wt_svc_read(const wt_svc_t* svc, uint32_t idx, void* buffer,
                size_t capacity, size_t* out_len)
{
    wt_spm_call_t call;
    size_t len = 0U;
    int ret = WT_FFM_SUCCESS;

    while (ret == WT_FFM_SUCCESS && len < capacity) {
        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_READ;
        call.partition_id = svc->partition_id;
        call.msg_handle = svc->handle;
        call.vec_idx = idx;
        call.buffer = (uint8_t*)buffer + len;
        call.num_bytes = capacity - len;
        if (svc->transport(svc->runtime, &call) != WT_FFM_SUCCESS) {
            ret = WT_FFM_ERROR_STATE;
        }
        else if (call.ret_size == 0U) {
            break;
        }
        else {
            len += call.ret_size;
        }
    }
    *out_len = len;
    return ret;
}

int wt_svc_write(const wt_svc_t* svc, uint32_t idx, const void* data,
                 size_t len)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WRITE;
    call.partition_id = svc->partition_id;
    call.msg_handle = svc->handle;
    call.vec_idx = idx;
    call.buffer = (void*)(uintptr_t)data;
    call.num_bytes = len;
    if (svc->transport(svc->runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}

int wt_svc_dispatch(wt_spm_transport_fn transport, wt_ffm_runtime_t* runtime,
                    int32_t partition_id, wt_svc_handler_fn handler,
                    void* ctx)
{
    psa_signal_t asserted = 0U;
    psa_msg_t msg;
    wt_spm_call_t call;
    wt_svc_t svc;
    psa_status_t status;

    if (wt_spm_wait_service_signal(transport, runtime, partition_id,
                                   &asserted, NULL) != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    if (asserted == 0U) {
        return WT_FFM_SUCCESS;
    }

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_GET;
    call.partition_id = partition_id;
    call.signal = asserted;
    call.msg = &msg;
    if (transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_status != PSA_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }

    svc.transport = transport;
    svc.runtime = runtime;
    svc.partition_id = partition_id;
    svc.handle = msg.handle;
    status = handler(ctx, &svc, &msg);

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_REPLY;
    call.partition_id = partition_id;
    call.msg_handle = msg.handle;
    call.status = status;
    if (transport(runtime, &call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return WT_FFM_ERROR_STATE;
    }
    return WT_FFM_SUCCESS;
}
