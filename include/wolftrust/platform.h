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

/* SoC contract, implemented under port/<soc>/; see wolftrust/arch.h. */

/* Opaque: the architecture defines the concrete structs. */
struct wt_guest_context;
typedef struct wt_guest_context wt_guest_context_t;
struct wt_trap_frame;
typedef struct wt_trap_frame wt_trap_frame_t;
#include "wolftrust/types.h"

void wt_platform_init(void);
/* Only asked of ports providing WT_PORT_CAPABILITY_TZ_FILTER. */
void wt_platform_program_memory_windows(const wt_memory_window_t* windows,
                                        size_t count);
void wt_platform_log_fault(wt_guest_id_t guest_id,
                           wt_fault_reason_t reason,
                           uintptr_t fault_address,
                           uintptr_t pc);
/* NULL with *count zero when no patched slot exists (fail-closed). */
struct wt_guest_measurement;
const struct wt_guest_measurement* wt_platform_guest_measurements(
    size_t* count);
int wt_platform_guest_flash_wrp_ok(uintptr_t window_base, size_t window_size);
void wt_platform_all_guests_faulted(void) __attribute__((noreturn));
void wt_platform_panic(void) __attribute__((noreturn));
void wt_platform_system_reset(void) __attribute__((noreturn));

#ifdef WT_ENGINE_HSM
bool wt_platform_secure_service_active(void);
void wt_platform_note_hsm_wait_skip(wt_guest_id_t guest_id);
#endif

/* NULL when the port has no boot-loader handoff region. */
volatile void* wt_platform_boot_handoff_region(size_t* size);

/* Returns the number of regions written (<= max). */
size_t wt_platform_sp_shared_regions(wt_memory_region_t* regions, size_t max);
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
size_t wt_platform_conf_sp_grants(int32_t partition_id,
                                  wt_memory_region_t* regions,
                                  size_t count, size_t max);
#endif
#if (defined(WT_FFM_NEGATIVE_PROBE) && (WT_FFM_NEGATIVE_PROBE == 1)) || \
    (defined(WT_VNET_NEG_PROBE) && (WT_VNET_NEG_PROBE == 1))
uintptr_t wt_platform_out_of_domain_probe_address(void);
#endif

#if defined(WT_REMEASURE_PROBE)
void wt_platform_remeasure_probe(void);
#endif
#if defined(WT_BOOTUPDATE_PROBE)
void wt_platform_bootupdate_probe(uint32_t running_version);
#endif

#endif
