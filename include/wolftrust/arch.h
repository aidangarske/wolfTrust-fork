/* arch.h
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFTRUST_ARCH_H
#define WOLFTRUST_ARCH_H

/* Architecture contract: the execution mechanics the neutral core calls
 * (guest context switching, privilege transitions, protection domains,
 * interrupt delivery, timers, barriers). Implemented once per architecture
 * under src/arch/<arch>/; a SoC port implements wolftrust/platform.h only. */

#include "wolftrust/platform.h"

/* Architecture-level boot setup (fault routing, reset authority, exception
 * priorities); the port calls it once its fabric and memory windows are
 * programmed and before any guest or partition runs. */
void wt_arch_init(void);
void wt_arch_start_secure_timer(uint32_t timeslice_ms);
void wt_arch_mask_all_guest_irqs(void);
void wt_arch_apply_irq_mask(const wt_irq_mask_t* mask);
void wt_arch_quarantine_pending_irqs(const wt_irq_mask_t* allowed_mask);

/* Program the active guest's Non-secure protection domain. Only a port that
 * provides WT_PORT_CAPABILITY_NS_DOMAIN_PROGRAMMING is ever asked to. */
void wt_arch_program_guest_domain(const wt_memory_region_t* regions,
                                  size_t count);
/* Narrow Secure execution to a single Secure Partition's protection domain
 * (WT-FFM-0011): map regions 0..count-1 from the composed table and nothing
 * else, so any access outside the partition's regions faults.
 * wt_arch_restore_spm_domain reinstates the full SPM domain. */
void wt_arch_program_secure_partition_domain(
    const wt_memory_region_t* regions, size_t count);
/* Variant for an unprivileged Secure Partition thread: identical region set,
 * but the privileged gate, scheduler, and fault handlers keep default access
 * while the unprivileged thread is confined to the mapped regions. */
void wt_arch_program_sp_thread_domain(const wt_memory_region_t* regions,
                                      size_t count);
void wt_arch_restore_spm_domain(void);

void wt_arch_guest_context_prepare(wt_guest_id_t guest_id,
                                   const wt_guest_context_t* context);
void wt_arch_guest_context_capture(wt_guest_context_t* context,
                                   const wt_trap_frame_t* frame);
void wt_arch_guest_context_restore(wt_guest_context_t* context);
/* True when a guest context has been seeded with a valid entry point (the
 * port's reset path resolved the reset handler). The monitor panics at boot
 * on an unseeded context. */
bool wt_arch_guest_context_ready(const wt_guest_context_t* context);
/* Faulting program counter recorded in an opaque trap frame (fault log). */
uintptr_t wt_arch_trap_pc(const wt_trap_frame_t* frame);
/* Guest id whose context is active on the Non-secure side, or UINT32_MAX
 * when no guest is running. Gateways must use this, never a guest-supplied
 * identity. */
uint32_t wt_arch_active_guest_id(void);
void wt_arch_zero_guest_memory(uintptr_t base, size_t size);

/* Reinstate a guest's banked stack and control state before resuming its
 * blocked Secure tasklet: that path returns to the guest without the normal
 * context restore, so the previous guest's bank would leak in. */
void wt_arch_restore_guest_bank(const wt_guest_context_t* context);

bool wt_arch_in_handler_mode(void);
/* True when the trap being served interrupted a guest thread. */
bool wt_arch_trap_from_guest_thread(void);
/* True when the trap being served interrupted a Secure thread. */
bool wt_arch_trap_from_secure_thread(void);
void wt_arch_return_to_secure_thread(
    void (*entry)(void) __attribute__((noreturn)));

uintptr_t wt_arch_read_fault_address(void);

/* Enable/disable a Secure-targeted external interrupt for a Secure Partition
 * (psa_irq_enable / EOI-mask path). Enable routes the line to Secure, clears
 * any stale pending, and unmasks at the lowest priority so it never preempts
 * the SPM gate. */
void wt_arch_secure_irq_enable(uint32_t irq);
void wt_arch_secure_irq_disable(uint32_t irq);
/* Route an interrupt line to the guest world and enable it. Called once at
 * boot for each synthetic interrupt the monitor delivers to guests. */
void wt_arch_route_irq_to_guest(uint32_t irq);
/* Assert or deassert a guest-targeted interrupt. Idempotent. */
void wt_arch_set_guest_irq_pending(uint32_t irq, bool asserted);

/* Data-memory / data-synchronization barriers around a shared-memory handoff
 * (e.g. the boot handoff region). Host builds no-op. */
void wt_arch_dmb(void);
void wt_arch_dsb(void);

/* Non-zero when the calling Secure thread is unprivileged (a confined Secure
 * Partition), which reaches privileged platform services only through the
 * SPM gate. Handler context is always privileged. Host builds never are. */
#ifdef WT_TARGET_BUILD
int wt_arch_thread_unprivileged(void);
#else
static inline int wt_arch_thread_unprivileged(void)
{
    return 0;
}
#endif

#endif /* WOLFTRUST_ARCH_H */
