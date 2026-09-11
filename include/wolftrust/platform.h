/* platform.h
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

#ifndef WOLFTRUST_PLATFORM_H
#define WOLFTRUST_PLATFORM_H

/* The guest execution context and the trap frame are architecture-port types:
 * the port defines the concrete structs (Armv8-M: wolftrust/arch/armv8m/
 * context.h) and the core only ever holds pointers to them. */
struct wt_guest_context;
typedef struct wt_guest_context wt_guest_context_t;
struct wt_trap_frame;
typedef struct wt_trap_frame wt_trap_frame_t;
#include "wolftrust/types.h"

void wt_platform_init(void);
void wt_platform_start_secure_timer(uint32_t timeslice_ms);
void wt_platform_mask_all_guest_irqs(void);
void wt_platform_apply_irq_mask(const wt_irq_mask_t* mask);
void wt_platform_quarantine_pending_irqs(const wt_irq_mask_t* allowed_mask);
void wt_platform_program_memory_windows(const wt_memory_window_t* windows,
                                        size_t count);
void wt_platform_program_ns_mpu(const wt_memory_region_t* regions,
                                size_t count);
/* Narrow the secure MPU to a single Secure Partition's protection domain
 * (WT-FFM-0011): program regions 0..count-1 from the composed table and
 * disable the rest, so any access outside the partition's regions faults.
 * wt_platform_restore_spm_domain reinstates the full SPM whitelist. */
void wt_platform_program_secure_partition_domain(
    const wt_memory_region_t* regions, size_t count);
/* Variant for an unprivileged Secure Partition thread (P1t): identical
 * region set, but PRIVDEFENA stays on so the privileged SVC/PendSV/fault
 * handlers keep default-map access while the unprivileged thread is
 * confined to the mapped regions. */
void wt_platform_program_sp_thread_domain(const wt_memory_region_t* regions,
                                          size_t count);
void wt_platform_restore_spm_domain(void);
void wt_platform_prepare_guest_return(wt_guest_id_t guest_id,
                                      const wt_guest_context_t* context);
void wt_platform_capture_guest_context(wt_guest_context_t* context,
                                       const wt_trap_frame_t* frame);
/* Faulting program counter recorded in an opaque trap frame (fault log). */
uintptr_t wt_platform_trap_pc(const wt_trap_frame_t* frame);
void wt_platform_restore_guest_context(wt_guest_context_t* context);
void wt_platform_svc_guest_return(void) __attribute__((noreturn));
bool wt_platform_in_handler_mode(void);
bool wt_platform_ns_thread_mode_trap(void);
bool wt_platform_secure_psp_thread_trap(void);
void wt_platform_return_to_secure_thread(
    void (*entry)(void) __attribute__((noreturn)));
void wt_platform_zero_guest_memory(uintptr_t base, size_t size);
void wt_platform_log_fault(wt_guest_id_t guest_id,
                           wt_fault_reason_t reason,
                           uintptr_t fault_address,
                           uintptr_t pc);
/* Pinned guest measurements stamped into the signed image by the assembly
 * patcher. Returns NULL with *count zero when no patched slot exists, which
 * launch verification treats as fail-closed for required guests. */
struct wt_guest_measurement;
const struct wt_guest_measurement* wt_platform_guest_measurements(
    size_t* count);
/* Verify a guest image window is hardware write-protected (WRP) so a peer
 * Non-secure guest cannot reprogram it. Returns WT_GUEST_VERIFY_OK when every
 * sector of [window_base, window_base + window_size) is write-protected, else a
 * wt_guest_verify_result_t error. Called only under WT_GUEST_FLASH_WRP. */
int wt_platform_guest_flash_wrp_ok(uintptr_t window_base, size_t window_size);
uintptr_t wt_platform_read_fault_address(void);
void wt_platform_all_guests_faulted(void) __attribute__((noreturn));
void wt_platform_panic(void) __attribute__((noreturn));

/* Request a full SoC reset (AIRCR.SYSRESETREQ) and spin until it takes. Used
 * by the conformance panic-reset path (P5 K3) so val's boot-flag resume can run
 * after reboot; production keeps the fail-closed quarantine in wt_platform_panic. */
void wt_platform_system_reset(void) __attribute__((noreturn));

/* Reinstate a guest's NS-banked stack/control registers before resuming its
 * blocked secure tasklet: that path returns to NS via BXNS, bypassing the
 * exception-return restore, so the previous guest's bank would leak in. */
void wt_platform_restore_ns_bank(const wt_guest_context_t* context);

/* Enable/disable a Secure-targeted external interrupt for a Secure Partition
 * (psa_irq_enable / EOI-mask path). Enable routes the line to Secure, clears
 * any stale pending, and unmasks at the lowest priority so it never preempts
 * the SVC gate. */
void wt_platform_secure_irq_enable(uint32_t irq);
void wt_platform_secure_irq_disable(uint32_t irq);
#ifdef WT_ENGINE_HSM
bool wt_platform_secure_service_active(void);
void wt_platform_note_hsm_wait_skip(wt_guest_id_t guest_id);
#endif

/* Returns the guest id whose context is currently active on the NS side,
 * or UINT32_MAX if no guest is running (boot, secure service, etc.).
 * Veneers must use this — never trust a guest-supplied VM id. */
uint32_t wt_platform_active_guest_id(void);

/* Mark an NVIC IRQ as targeting the non-secure world (ITNS bit) AND
 * enable it in the NVIC. Called once at boot for each synthetic vIRQ
 * the monitor wants to be deliverable to guests. */
void wt_platform_configure_ns_irq(uint32_t irq);

/* Assert (asserted=true) or deassert (asserted=false) an NS-targeted
 * IRQ via the NS alias of NVIC ISPR/ICPR. Idempotent. */
void wt_platform_set_ns_irq_pending(uint32_t irq, bool asserted);

/* Data-memory / data-synchronization barriers around a shared-memory handoff
 * (e.g. the wolfBoot handoff region). The port supplies the real barrier;
 * host builds no-op. */
void wt_platform_dmb(void);
void wt_platform_dsb(void);

/* True when a guest context has been seeded with a valid entry point
 * (the port's reset path resolved the reset handler). The monitor panics
 * at boot on an unseeded context. */
bool wt_platform_guest_context_ready(const wt_guest_context_t* context);

#endif
