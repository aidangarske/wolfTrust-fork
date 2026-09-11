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

/* SoC and board contract: what a port under port/<soc>/ implements. The
 * architecture mechanics the core also needs live in wolftrust/arch.h and
 * are implemented once per architecture. */

/* The guest execution context and the trap frame are architecture-port types:
 * the port defines the concrete structs (Armv8-M: wolftrust/arch/armv8m/
 * context.h) and the core only ever holds pointers to them. */
struct wt_guest_context;
typedef struct wt_guest_context wt_guest_context_t;
struct wt_trap_frame;
typedef struct wt_trap_frame wt_trap_frame_t;
#include "wolftrust/types.h"

void wt_platform_init(void);
/* Program the SoC's TrustZone address filter with the active guest's memory
 * windows. Only a port that provides WT_PORT_CAPABILITY_TZ_FILTER is asked. */
void wt_platform_program_memory_windows(const wt_memory_window_t* windows,
                                        size_t count);
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
void wt_platform_all_guests_faulted(void) __attribute__((noreturn));
void wt_platform_panic(void) __attribute__((noreturn));

/* Request a full SoC reset and spin until it takes. Used by the conformance
 * panic-reset path (P5 K3) so val's boot-flag resume can run after reboot;
 * production keeps the fail-closed quarantine in wt_platform_panic. */
void wt_platform_system_reset(void) __attribute__((noreturn));

#ifdef WT_ENGINE_HSM
bool wt_platform_secure_service_active(void);
void wt_platform_note_hsm_wait_skip(wt_guest_id_t guest_id);
#endif

/* Secure RAM region the boot loader wrote its measured-boot record into.
 * Returns the region base and sets *size to its length; NULL means the port
 * has no handoff region. The core reads the record from the start of it. */
volatile void* wt_platform_boot_handoff_region(size_t* size);

#endif
