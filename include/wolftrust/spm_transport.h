/* spm_transport.h
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


#ifndef WOLFTRUST_SPM_TRANSPORT_H
#define WOLFTRUST_SPM_TRANSPORT_H

#include "wolftrust/ffm.h"
#include "wolftrust/spm_sched.h"

#include <stdint.h>

struct wt_co;
struct wt_spm_call;
struct wt_trap_frame;

/* SP-side transport: trap one wt_spm_call_t to the privileged gate,
 * re-issuing a blocking psa_wait after each wake until it completes. The
 * dispatcher stamps the caller's own partition id into the call, so callers
 * need not (and cannot usefully) set it. Only valid on a scheduled SP thread.
 * wt_spm_svc_transport is the same loop in the callback shape the service
 * loops bind. */
int wt_spm_sp_call(struct wt_spm_call* call);
int wt_spm_svc_transport(wt_ffm_runtime_t* runtime, struct wt_spm_call* call);

/* Privileged gate dispatch, run by the architecture's trap decoder with the
 * partition's call block and trap frame; returns the gate-level status. */
int wt_spm_dispatch_call(struct wt_spm_call* call, struct wt_trap_frame* frame);

/* Graceful fault recovery for a scheduled Secure Partition (WT-SYS-0008 /
 * WT-FFM-0017), split across execution modes. wt_spm_sp_fault is the
 * handler-mode half: if the faulted coroutine is a scheduled SP it is marked
 * dead and recovery is PENDED, returning WT_FFM_SUCCESS; WT_FFM_ERROR_STATE
 * means not a scheduled SP and the caller falls back to its guest-tasklet
 * path. wt_spm_recover_faulted is the bootstrap-thread half: it runs the full
 * recovery (locks dropped, pinned clients failed, stack scrubbed, partition
 * restarted under its manifest budget or escalated) for every pended fault.
 * The SPM dispatch path calls it; recovery must never run in handler mode. */
int wt_spm_sp_fault(struct wt_co* faulted_co);
void wt_spm_recover_faulted(void);

/* SERVICE_HSM's partition identity, released first on a fault so the relay
 * wake path never targets a dead server. */
void wt_spm_set_hsm_partition(int32_t partition_id);

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* Conformance-only hang tripwire: called from the secure tick; traps with
 * a scheduler-state register dump when IPC activity stalls (lost wake). */
void wt_spm_sched_hang_probe(void);

/* FLIH for a Secure Partition interrupt (P4.2c): masks the line, resolves the
 * manifest-bound partition/signal for `irq`, and asserts the signal so the
 * partition's psa_wait observes it. Called from the port's IRQ vector. */
void wt_spm_conf_irq(uint32_t irq);

/* Privileged conformance services the port provides: the flash NVM sync
 * (hsm_flash.c) and the PAL interrupt source control (platform). */
int wt_conf_nvm_flash_sync(uint8_t *buf, uint32_t len, int store);
void wt_conf_uart_irq_set(int on);
#endif

#endif /* WOLFTRUST_SPM_TRANSPORT_H */
