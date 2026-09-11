/* spm_svc.c
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

/* Armv8-M SVC #1 transport: the privileged frame decoder in front of the
 * neutral gate dispatch, the SP-side trap, and the trap-level primitives the
 * architecture contract owes the gate (stack forensics, panic redirect,
 * deliberate faults, privilege assertion, diagnostic trap). */

#include "wolftrust/arch/armv8m/spm_svc.h"
#include "wolftrust/arch/armv8m/context.h"

#include "wolftrust/arch.h"
#include "wolftrust/ffm.h"
#include "wolftrust/platform.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/spm_transport.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Production landing pad for an FF-M PROGRAMMER ERROR: the SVC dispatcher
 * points the erring partition's resume PC here so it faults on an undefined
 * instruction and takes the graceful quarantine path (WT-SYS-0008). */
__attribute__((naked, used))
static void wt_spm_sp_panic_trap(void)
{
    __asm volatile("udf #0x50");
}

/* Tail-called from SVC_Handler with r0 = the exception frame; the stacked r0
 * carries the call block in and the gate-level status out. */
__attribute__((used))
void wt_spm_svc_entry(uint32_t* frame)
{
    wt_spm_call_t* call = (wt_spm_call_t*)(uintptr_t)frame[0];

    frame[0] = (uint32_t)wt_spm_dispatch_call(call, (wt_trap_frame_t*)frame);
}

uintptr_t wt_arch_sp_stack_pointer(void)
{
    uint32_t psp;

    __asm volatile("mrs %0, psp" : "=r"(psp));
    return psp;
}

void wt_arch_sp_redirect_to_panic_trap(wt_trap_frame_t* frame)
{
    frame->pc = (uint32_t)(uintptr_t)&wt_spm_sp_panic_trap & ~1u;
    /* Clear EPSR ICI/IT so the redirected resume executes the trap. */
    frame->xpsr &= ~0x0600FC00u;
}

void wt_arch_assert_privileged_thread(void)
{
    uint32_t ctrl;

    __asm volatile("mrs %0, control" : "=r"(ctrl));
    if ((ctrl & 1u) != 0u) {
        ctrl &= ~1u;
        __asm volatile("msr control, %0\n isb" : : "r"(ctrl));
    }
}

/* Deliberate undefined-instruction faults keyed by the test-build probes;
 * the immediate is what the fault dump shows. */
void wt_arch_sp_fault_probe(unsigned int code)
{
    switch (code) {
    case 1u:
        __asm volatile("udf #1");
        break;
    case 2u:
        __asm volatile("udf #2");
        break;
    case 3u:
        __asm volatile("udf #3");
        break;
    case 4u:
        __asm volatile("udf #4");
        break;
    default:
        __asm volatile("udf #0");
        break;
    }
}

/* r0 = call in, r0 = gate-level status out (written into the stacked frame
 * by the privileged dispatcher). */
__attribute__((naked))
int wt_arch_sp_trap(wt_spm_call_t* call __attribute__((unused)))
{
    __asm__ volatile (
        "svc  #1   \n"
        "bx   lr   \n"
    );
}

/* SP-side transport: trap each request to the privileged gate. A blocking op
 * (wait, or an SP-to-SP connect/call/close) comes back with the stale
 * NOT_READY result after the coroutine is rewoken, so re-issue until the
 * request really completes. Only a call that actually suspended is re-issued:
 * a PSA_POLL wait miss also reports NOT_READY but must return, not spin. */
int wt_spm_svc_transport(wt_ffm_runtime_t* runtime, wt_spm_call_t* call)
{
    int status;

    (void)runtime;
    for (;;) {
        status = wt_arch_sp_trap(call);
        if (status != WT_FFM_SUCCESS || wt_spm_call_would_block(call) == 0) {
            break;
        }
    }
    return status;
}

int wt_spm_sp_call(struct wt_spm_call* call)
{
    return wt_spm_svc_transport(NULL, call);
}

int wt_spm_measure_read_call(unsigned int index, void* record,
                             unsigned int record_len, unsigned int* count)
{
    wt_spm_call_t call;

    (void)memset(&call, 0, sizeof(call));
    call.op = WT_SPM_OP_MEASURE_READ;
    call.vec_idx = index;
    call.buffer = record;
    call.num_bytes = record_len;
    if (wt_arch_sp_trap(&call) != WT_FFM_SUCCESS) {
        return -1;
    }
    if (count != NULL) {
        *count = (unsigned int)call.ret_size;
    }
    return call.ret_int;
}

int wt_arch_thread_unprivileged(void)
{
    unsigned int control;
    unsigned int ipsr;
    __asm volatile("mrs %0, control" : "=r"(control));
    __asm volatile("mrs %0, ipsr" : "=r"(ipsr));
    return (int)(ipsr == 0u && (control & 1u) != 0u);
}

int wt_spm_keystore_lock_call(int sub_op)
{
    wt_spm_call_t call;

    for (;;) {
        (void)memset(&call, 0, sizeof(call));
        call.op = WT_SPM_OP_KEYSTORE_LOCK;
        call.call_type = sub_op;
        if (wt_arch_sp_trap(&call) != WT_FFM_SUCCESS) {
            return -1;
        }
        if (call.ret_int != 1) {
            return call.ret_int;
        }
        /* Enqueued: the dispatcher blocked this coroutine on exception
         * return; the release hands ownership over before waking, so the
         * re-issue observes it and returns acquired. */
    }
}

/* Diagnostic trap for a scheduler livelock: pack the scheduler state into the
 * exception frame's r0-r2 (the emulator's MEMFAULT dump prints them) and
 * fault on purpose. Removed once the multi-SP dance is proven. */
__attribute__((noinline))
void wt_arch_diag_trap(uint32_t a, uint32_t b, uint32_t c)
{
    /* Pin the scheduler state into callee-saved registers the emulator's
     * fault dump prints; the 0xEFFFFFF4 read faults with a full dump. */
    register uint32_t diag_a __asm__("r4") = a;
    register uint32_t diag_b __asm__("r5") = b;
    register uint32_t diag_c __asm__("r6") = c;
    volatile uint32_t probe;

#if defined(WT_CONF_DIAG_TRAP) && (WT_CONF_DIAG_TRAP == 0)
    /* Hardware: no fault-dump printer exists, and the conformance monitor
     * answers the deliberate fault with a system reset — which can land in
     * the suite's NS-only report window and silently restart the whole run.
     * Keep the probes counting but never trap. */
    (void)diag_a; (void)diag_b; (void)diag_c; (void)probe;
    return;
#else
    __asm__ volatile("" : : "r"(diag_a), "r"(diag_b), "r"(diag_c));
    probe = *(const volatile uint32_t*)0xEFFFFFF4u;
    (void)probe;
#endif
}
