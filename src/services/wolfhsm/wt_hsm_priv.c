/* wt_hsm_priv.c
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

/* Privileged-side registry of the per-guest wolfHSM server tasklets. The
 * monitor and the fault dispatcher resume these coroutines privileged, so the
 * handle they follow must not live in the shared keystore band that the
 * keystore partitions can write (WT-FFM-0011). This translation unit is
 * deliberately not claimed by any keystore-band linker rule, so its state
 * stays in SPM-private RAM. */

#include "wolftrust/types.h"
#include "wolftrust/sched/coroutine.h"
#include "wolftrust/hsm_priv.h"

#include <stdint.h>

static struct wt_co *g_wt_taskreg[WT_MAX_GUESTS];

/* Per-guest server tasklet stacks. These back PRIVILEGED coroutines, so they
 * must stay in SPM-private RAM, out of the shared keystore band; this TU is
 * not claimed by any keystore-band linker rule (WT-FFM-0011). A guard below
 * each descending stack contains an underflow before it corrupts a neighbour. */
#define WT_HSM_STACK_UNDERFLOW_GUARD_SIZE 256u

typedef struct wt_hsm_stack_slot {
    uint8_t guard[WT_HSM_STACK_UNDERFLOW_GUARD_SIZE];
    uint8_t stack[WT_CO_STACK_SIZE];
} wt_hsm_stack_slot_t;

static wt_hsm_stack_slot_t g_co_stack_slots[WT_MAX_GUESTS]
    __attribute__((aligned(8)));

uint8_t *wt_hsm_priv_stack(wt_guest_id_t guest_id)
{
    if (guest_id >= WT_MAX_GUESTS) {
        return (uint8_t *)0;
    }
    return g_co_stack_slots[guest_id].stack;
}

void wt_hsm_priv_register(wt_guest_id_t guest_id, struct wt_co *tasklet)
{
    if (guest_id < WT_MAX_GUESTS) {
        g_wt_taskreg[guest_id] = tasklet;
    }
}

struct wt_co *wt_hsm_guest_tasklet(wt_guest_id_t guest_id)
{
    if (guest_id >= WT_MAX_GUESTS) {
        return (struct wt_co *)0;
    }
    return g_wt_taskreg[guest_id];
}

wt_guest_id_t wt_hsm_guest_for_tasklet(const struct wt_co *tasklet)
{
    wt_guest_id_t gid;

    if (tasklet == (const struct wt_co *)0) {
        return WT_MAX_GUESTS;
    }
    for (gid = 0; gid < WT_MAX_GUESTS; gid++) {
        if (g_wt_taskreg[gid] == tasklet) {
            return gid;
        }
    }
    return WT_MAX_GUESTS;
}
