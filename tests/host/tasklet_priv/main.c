/* main.c
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

/* WT-FFM-0011: a coroutine is privileged until wt_co_set_domain drops it, so
 * wt_co_create must refuse a stack the platform marks partition-writable. The
 * platform hook here rejects one marker buffer and accepts the other. */

#include "wolftrust/sched/coroutine.h"
#include "wolftrust/sched/coroutine_internal.h"
#include "wolftrust/priv_stack.h"
#include "wolftrust/hsm_priv.h"

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

static unsigned char g_band_stack[WT_CO_STACK_SIZE]
    __attribute__((aligned(8)));
static unsigned char g_priv_stack[WT_CO_STACK_SIZE]
    __attribute__((aligned(8)));

/* ---- Host stubs for the coroutine arch backend -------------------------- */
void wt_co_arch_init_stack(struct wt_co *co, wt_co_entry_fn entry, void *arg)
{
    (void)co;
    (void)entry;
    (void)arg;
}
void wt_co_arch_enter(struct wt_co *to) { (void)to; }
void wt_co_arch_leave(void) {}
void wt_co_arch_request_preempt(void) {}
void wt_platform_panic(void) {}
struct wt_co *g_wt_co_pendsv_target;

/* Call the SAME decision the port validator calls (wt_priv_stack_ok), not a
 * divergent mirror (WT-FFM-0011). The SPM-private window is g_priv_stack's own
 * extent, so g_priv_stack is accepted and the disjoint g_band_stack (standing
 * in for a partition stack) is refused. */
int wt_platform_priv_stack_ok(const void *stack, size_t size)
{
    if (stack == NULL) {
        return 0;
    }
    return wt_priv_stack_ok((uintptr_t)stack, size, (uintptr_t)g_priv_stack,
                            (uintptr_t)g_priv_stack + sizeof(g_priv_stack),
                            NULL, 0u);
}

static void entry(void *arg)
{
    (void)arg;
}

static int g_failures;

static void check(int ok, const char *what)
{
    printf("  [check] %s  %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_failures++;
    }
}

int main(void)
{
    struct wt_co *co;
    wt_priv_band_t band;

    wt_co_init();

    /* Shared range arithmetic (WT-FFM-0011). */
    check(wt_priv_range_valid(0x1000u, 0x100u) == 1, "valid range accepted");
    check(wt_priv_range_valid(0x1000u, 0u) == 0, "zero-size range rejected");
    check(wt_priv_range_valid((uintptr_t)-16, 0x100u) == 0,
          "wrapping range rejected");
    check(wt_priv_range_overlaps(0x1000u, 0x100u, 0x1080u, 0x100u) == 1,
          "overlapping range detected");
    check(wt_priv_range_overlaps(0x1000u, 0x100u, 0x1100u, 0x100u) == 0,
          "adjacent range (touching upper edge) is disjoint");
    check(wt_priv_range_overlaps(0x1100u, 0x100u, 0x1000u, 0x100u) == 0,
          "adjacent range (touching lower edge) is disjoint");
    check(wt_priv_range_overlaps(0x1000u, 0x100u, 0x2000u, 0u) == 0,
          "zero-size band never overlaps");
    check(wt_priv_range_within(0x1100u, 0x100u, 0x1000u, 0x2000u) == 1,
          "range inside window accepted");
    check(wt_priv_range_within(0x1000u, 0x100u, 0x1000u, 0x2000u) == 1,
          "range at window base accepted");
    check(wt_priv_range_within(0x1F00u, 0x100u, 0x1000u, 0x2000u) == 1,
          "range at window top accepted");
    check(wt_priv_range_within(0x1000u, 0x1000u, 0x1000u, 0x2000u) == 1,
          "range filling the window accepted");
    check(wt_priv_range_within(0x0F80u, 0x100u, 0x1000u, 0x2000u) == 0,
          "range below the window base rejected");
    check(wt_priv_range_within(0x1F80u, 0x100u, 0x1000u, 0x2000u) == 0,
          "range past the window top rejected");
    check(wt_priv_range_within(0x2000u, 0x100u, 0x1000u, 0x2000u) == 0,
          "range starting at the window end rejected");

    /* The full shared decision (WT-FFM-0011). */
    band.base = 0x1400u;
    band.size = 0x100u;
    check(wt_priv_stack_ok(0x1100u, 0x100u, 0x1000u, 0x2000u, &band, 1u) == 1,
          "in-RAM range clear of the band accepted");
    check(wt_priv_stack_ok(0x1400u, 0x080u, 0x1000u, 0x2000u, &band, 1u) == 0,
          "in-RAM range overlapping the band refused");
    check(wt_priv_stack_ok(0x0F00u, 0x100u, 0x1000u, 0x2000u, &band, 1u) == 0,
          "range outside secure RAM refused");

    /* The privileged path (wt_co_create_blocked) enforces the stack check; the
     * demoted SP path (wt_co_create_blocked_ex) is exempt and accepts either. */
    co = wt_co_create_blocked(g_band_stack, sizeof(g_band_stack), entry, NULL);
    check(co == NULL,
          "WT-FFM-0011 partition stack refused for a privileged coroutine");
    co = wt_co_create_blocked(g_priv_stack, sizeof(g_priv_stack), entry, NULL);
    check(co != NULL, "WT-FFM-0011 SPM-private stack accepted");
    co = wt_co_create_blocked_ex(g_band_stack, sizeof(g_band_stack), entry, NULL);
    check(co != NULL, "WT-FFM-0011 SP coroutine keeps its partition stack");

    /* The SPM-private tasklet registry and stacks (WT-FFM-0011). */
    check(wt_hsm_priv_stack(0u) != NULL, "guest 0 has an SPM-private stack");
    check(wt_hsm_priv_stack(WT_MAX_GUESTS) == NULL,
          "out-of-range guest has no stack");
    if (WT_MAX_GUESTS > 1u) {
        check(wt_hsm_priv_stack(0u) != wt_hsm_priv_stack(1u),
              "per-guest stacks are distinct");
    }
    check(wt_hsm_guest_tasklet(0u) == NULL, "unregistered guest has no tasklet");
    check(wt_hsm_guest_tasklet(WT_MAX_GUESTS) == NULL,
          "out-of-range guest has no tasklet");
    check(wt_hsm_guest_for_tasklet(NULL) == WT_MAX_GUESTS,
          "NULL tasklet resolves to no guest");
    wt_hsm_priv_register(WT_MAX_GUESTS, co);
    check(wt_hsm_guest_for_tasklet(co) == WT_MAX_GUESTS,
          "out-of-range register is refused");
    wt_hsm_priv_register(0u, co);
    check(wt_hsm_guest_tasklet(0u) == co, "register/get round trip");
    check(wt_hsm_guest_for_tasklet(co) == 0u, "reverse lookup finds guest 0");

    if (g_failures == 0) {
        printf("PASS: tasklet_priv\n");
        return 0;
    }
    printf("FAIL: tasklet_priv (%d)\n", g_failures);
    return 1;
}
