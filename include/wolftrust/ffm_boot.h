/* ffm_boot.h
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

#ifndef WOLFTRUST_FFM_BOOT_H
#define WOLFTRUST_FFM_BOOT_H

#include "wolftrust/ffm.h"
#include "wolftrust/ffm_veneer.h"
#include "wolftrust/manifest.h"
#include "wolftrust/types.h"

int wt_ffm_boot_init(const wt_system_manifest_t* manifest);
/* Upgrade the crypto partition to a scheduled unprivileged coroutine (P1t).
 * Call after wt_tasklet_init; requires the coroutine scheduler, so the
 * WT_ENGINE_HSM boot path invokes it once the scheduler is up. */
int wt_ffm_boot_start_sched(void);
const wt_ffm_runtime_t* wt_ffm_boot_runtime(void);

/* NS-window memory checks are an architecture-port capability (CMSE on
 * Armv8-M). The port installs them at boot (wt_ffm_gateway_install); unset checks
 * fail closed so an unported build rejects every NS window. guest_id is the
 * resolved NS caller. */
typedef int (*wt_ffm_ns_check_read_fn)(wt_guest_id_t guest_id,
                                       const void* address, size_t size);
typedef int (*wt_ffm_ns_check_write_fn)(wt_guest_id_t guest_id,
                                        void* address, size_t size);
void wt_ffm_boot_set_memcheck(wt_ffm_ns_check_read_fn check_read,
                              wt_ffm_ns_check_write_fn check_write);

/* Mutable runtime accessor for the architecture port's NS client veneers. */
wt_ffm_runtime_t* wt_ffm_boot_runtime_mut(void);

#endif /* WOLFTRUST_FFM_BOOT_H */
