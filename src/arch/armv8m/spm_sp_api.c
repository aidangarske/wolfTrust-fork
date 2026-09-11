/* spm_sp_api.c
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

/* Secure-Partition-side psa_* API (WT-FFM-0014): every call marshals a
 * wt_spm_call_t and traps to the privileged gate via SVC, so unmodified Arm
 * partition code links these symbols and runs unprivileged inside its manifest
 * MPU domain. Replaces the direct src/ffm_api.c implementations in the target
 * image — those touch SPM state an unprivileged thread cannot reach. */

#include <string.h>

#include "psa/client.h"
#include "psa/lifecycle.h"
#include "psa/service.h"

#include "wolftrust/spm_transport.h"
#include "wolftrust/spm_gate.h"

/* A failed service-side call is a programmer error: fault the partition so
 * the SPM's fault path deals with it instead of running on bad state. The
 * faulting read also identifies the failing wrapper in the emulator's
 * register dump (PC/LR) — a silent spin here is undebuggable on target. */
__attribute__((noreturn, noinline))
static void wt_sp_api_panic(uint32_t op, uint32_t code, uint32_t extra)
{
    /* Pin the diagnostics into callee-saved registers the fault dump prints;
     * plain unused params get optimized out of the call sites entirely. */
    register uint32_t diag_op __asm__("r4") = op;
    register uint32_t diag_code __asm__("r5") = code;
    register uint32_t diag_extra __asm__("r6") = extra;
    volatile uint32_t probe;

    __asm__ volatile("" : : "r"(diag_op), "r"(diag_code), "r"(diag_extra));
    probe = *(const volatile uint32_t*)0xEFFFFFF4u;
    (void)probe;
    for (;;) {
    }
}

psa_signal_t psa_wait(psa_signal_t signal_mask, uint32_t timeout)
{
    wt_spm_call_t call;
    psa_signal_t asserted = 0U;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WAIT;
    call.signal_mask = signal_mask;
    call.timeout = timeout;
    call.asserted = &asserted;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return 0U;
    }
    return asserted;
}

psa_status_t psa_get(psa_signal_t signal, psa_msg_t* msg)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_GET;
    call.signal = signal;
    call.msg = msg;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    return call.ret_status;
}

void psa_set_rhandle(psa_handle_t msg_handle, void* rhandle)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_SET_RHANDLE;
    call.msg_handle = msg_handle;
    call.rhandle = rhandle;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        wt_sp_api_panic(call.op, (uint32_t)call.ret_int,
                        (uint32_t)msg_handle);
    }
}

size_t psa_read(psa_handle_t msg_handle, uint32_t invec_idx,
                void* buffer, size_t num_bytes)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_READ;
    call.msg_handle = msg_handle;
    call.vec_idx = invec_idx;
    call.buffer = buffer;
    call.num_bytes = num_bytes;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS) {
        return 0U;
    }
    return call.ret_size;
}

size_t psa_skip(psa_handle_t msg_handle, uint32_t invec_idx, size_t num_bytes)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_SKIP;
    call.msg_handle = msg_handle;
    call.vec_idx = invec_idx;
    call.num_bytes = num_bytes;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS) {
        return 0U;
    }
    return call.ret_size;
}

void psa_write(psa_handle_t msg_handle, uint32_t outvec_idx,
               const void* buffer, size_t num_bytes)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_WRITE;
    call.msg_handle = msg_handle;
    call.vec_idx = outvec_idx;
    call.buffer = (void*)(uintptr_t)buffer;
    call.num_bytes = num_bytes;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        wt_sp_api_panic(call.op, (uint32_t)call.ret_int,
                        (uint32_t)msg_handle);
    }
}

void psa_reply(psa_handle_t msg_handle, psa_status_t status)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_REPLY;
    call.msg_handle = msg_handle;
    call.status = status;
    /* The gate reports REPLY success in ret_int; ret_status keeps its
     * default error, so checking it would panic on every reply. */
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        wt_sp_api_panic(call.op, (uint32_t)call.ret_int,
                        (uint32_t)msg_handle);
    }
}

void psa_notify(int32_t partition_id)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_NOTIFY;
    call.notify_partition = partition_id;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        wt_sp_api_panic(call.op, (uint32_t)call.ret_int,
                        (uint32_t)partition_id);
    }
}

void psa_clear(void)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CLEAR;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        wt_sp_api_panic(call.op, (uint32_t)call.ret_int, 0u);
    }
}

void psa_eoi(psa_signal_t irq_signal)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_EOI;
    call.signal_mask = irq_signal;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        wt_sp_api_panic(call.op, (uint32_t)call.ret_int, irq_signal);
    }
}

void psa_irq_enable(psa_signal_t irq_signal)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_IRQ_ENABLE;
    call.signal_mask = irq_signal;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        wt_sp_api_panic(call.op, (uint32_t)call.ret_int, irq_signal);
    }
}

void psa_panic(void)
{
    wt_sp_api_panic(0xAB0u, 0u, 0u);
}

uint32_t psa_rot_lifecycle_state(void)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_LIFECYCLE;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return PSA_LIFECYCLE_UNKNOWN;
    }
    return call.ret_version;
}

uint32_t psa_framework_version(void)
{
    return PSA_FRAMEWORK_VERSION;
}

/* SP-as-client IPC (WT-FFM-0014): the request enqueues at the gate, this
 * partition suspends, the scheduler runs the serving partition, and the
 * completed message is harvested on wake — all inside wt_spm_sp_call's
 * NOT_READY retry loop. */
uint32_t psa_version(uint32_t sid)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_VERSION;
    call.sid = sid;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return PSA_VERSION_NONE;
    }
    return call.ret_version;
}

psa_handle_t psa_connect(uint32_t sid, uint32_t version)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CONNECT;
    call.sid = sid;
    call.version = version;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return (psa_handle_t)PSA_ERROR_CONNECTION_REFUSED;
    }
    return call.ret_handle;
}

psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec* in_vec, size_t in_len,
                      psa_outvec* out_vec, size_t out_len)
{
    wt_spm_call_t call;
    size_t i;

    if (in_len > WT_SPM_SP_IOVEC || out_len > WT_SPM_SP_IOVEC) {
        /* FF-M: a Secure caller exceeding PSA_MAX_IOVEC is a PROGRAMMER ERROR
         * the framework must panic the partition for, never a status. */
        wt_sp_api_panic(WT_SPM_OP_CALL, (uint32_t)in_len, (uint32_t)out_len);
    }
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CALL;
    call.msg_handle = handle;
    call.call_type = type;
    for (i = 0u; i < in_len; i++) {
        call.sp_in[i] = in_vec[i];
    }
    for (i = 0u; i < out_len; i++) {
        call.sp_out[i] = out_vec[i];
    }
    call.sp_in_len = (uint8_t)in_len;
    call.sp_out_len = (uint8_t)out_len;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    for (i = 0u; i < out_len; i++) {
        out_vec[i].len = call.sp_out[i].len;
    }
    return call.ret_status;
}

void psa_close(psa_handle_t handle)
{
    wt_spm_call_t call;

    /* Only PSA_NULL_HANDLE closes as a no-op (FF-M); any other invalid
     * handle, error statuses included, is a PROGRAMMER ERROR the SPM panics
     * this partition for through the gate's must_panic classification. */
    if (handle == PSA_NULL_HANDLE) {
        return;
    }
    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_CLOSE;
    call.msg_handle = handle;
    if (wt_spm_sp_call(&call) != WT_FFM_SUCCESS ||
            call.ret_int != WT_FFM_SUCCESS) {
        wt_sp_api_panic(call.op, (uint32_t)call.ret_int, (uint32_t)handle);
    }
}
