/* hsm_priv.h
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

#ifndef WOLFTRUST_HSM_PRIV_H
#define WOLFTRUST_HSM_PRIV_H

/* Privileged-side registry for the per-guest wolfHSM server tasklets: their
 * handles and SPM-private stacks (WT-FFM-0011), which the monitor and fault
 * dispatcher resume privileged and so must keep out of the keystore band.
 * These carry no wolfHSM types, so this header stays free of the wolfHSM
 * include surface and the registry can be unit-tested on the host. */

#include "wolftrust/types.h"

struct wt_co;

/* Handle registry. The monitor and the fault dispatcher resume these
 * coroutines privileged, so the handle must live in SPM-private RAM, never in
 * the keystore band the partitions can write. */
void wt_hsm_priv_register(wt_guest_id_t guest_id, struct wt_co *tasklet);
struct wt_co *wt_hsm_guest_tasklet(wt_guest_id_t guest_id);
wt_guest_id_t wt_hsm_guest_for_tasklet(const struct wt_co *tasklet);

/* The SPM-private per-guest server tasklet stack (never in the keystore band).
 * NULL for an out-of-range guest. */
unsigned char *wt_hsm_priv_stack(wt_guest_id_t guest_id);

/* Zero a faulted guest's tasklet stack and guard, keeping the canary word at
 * stack[0] for the post-fault switch check. */
void wt_hsm_priv_wipe_stack(wt_guest_id_t guest_id);

#endif /* WOLFTRUST_HSM_PRIV_H */
