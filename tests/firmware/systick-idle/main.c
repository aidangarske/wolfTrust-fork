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

#include "wolftrust/arch/armv8m/core_regs.h"

static volatile uint32_t g_test_csr;
static volatile uint32_t g_test_rvr;
static volatile uint32_t g_test_cvr;
static volatile uint32_t g_test_icsr;
static volatile uint32_t g_test_ticks;
static volatile uint32_t g_test_inject;
static volatile uint32_t g_test_handoff;
static volatile uint32_t g_test_mask_seen;
static volatile uint32_t g_test_bad_handoff;
static volatile uint32_t g_test_reset_owner;

static volatile uint32_t* test_reload_register(void);

#undef WT_SYST_NS_CSR
#undef WT_SYST_NS_RVR
#undef WT_SYST_NS_CVR
#undef WT_SCB_ICSR_NS
#define WT_SYST_NS_CSR g_test_csr
#define WT_SYST_NS_RVR (*test_reload_register())
#define WT_SYST_NS_CVR g_test_cvr
#define WT_SCB_ICSR_NS g_test_icsr

/* Stable NS register model; Secure SysTick and WFI execute on the Cortex-M. */
#include "../../../src/arch/armv8m/guest_context_armv8m.c"

extern uint32_t _estack;
extern uint32_t _sbss;
extern uint32_t _ebss;
void Reset_Handler(void);

__attribute__((section(".vectors")))
const uintptr_t g_test_vectors[16] = {
    [0] = (uintptr_t)&_estack,
    [1] = (uintptr_t)Reset_Handler,
    [3] = (uintptr_t)wt_platform_panic,
    [15] = (uintptr_t)SysTick_Handler
};

static volatile uint32_t* test_reload_register(void)
{
    if (g_test_inject != 0U) {
        g_test_inject = 0U;
        __asm volatile("mrs %0, primask" : "=r"(g_test_mask_seen));
        g_test_handoff = 1U;
        WT_SCB_ICSR_S = WT_SCB_ICSR_PENDSTSET;
        __asm volatile("dsb 0xF\n isb 0xF" ::: "memory");
    }
    return &g_test_rvr;
}

void wt_monitor_on_secure_timer(const wt_trap_frame_t* frame)
{
    (void)frame;
    g_test_ticks++;
    if (g_test_reset_owner != 0U) {
        g_test_reset_owner = 0U;
        wt_virtual_systick_reset(0U);
    }
    if (g_test_handoff != 0U && g_active_guest != UINT32_MAX) {
        g_test_bad_handoff++;
    }
}

void wt_platform_panic(void)
{
    __asm volatile("bkpt #0x7e");
    for (;;) {}
}

static void check(int ok)
{
    if (!ok) {
        wt_platform_panic();
    }
}

void Reset_Handler(void)
{
    uint32_t* p;
    uint32_t primask;
    wt_virtual_systick_t saved;

    for (p = &_sbss; p < &_ebss; ++p) {
        *p = 0U;
    }
    wt_arch_init();
    g_systick_reload = 100000U;
    g_secure_wall_cycles = 1000000U;
    WT_SYST_RVR = g_systick_reload - 1U;
    WT_SYST_CVR = 0U;
    WT_SYST_CSR = WT_SYST_CSR_ENABLE | WT_SYST_CSR_TICKINT |
                  WT_SYST_CSR_CLKSOURCE;

    g_active_guest = 0U;
    g_test_csr = WT_SYST_CSR_ENABLE | WT_SYST_CSR_TICKINT |
                 WT_SYST_CSR_CLKSOURCE;
    g_test_rvr = 10000U;
    g_test_cvr = 4321U;
    g_test_icsr = WT_SCB_ICSR_PENDSTSET;
    g_test_inject = 1U;
    wt_arch_wait_for_interrupt();
    g_test_handoff = 0U;
    check(g_guest_systick[0].csr == 7U &&
          g_guest_systick[0].rvr == 10000U &&
          g_guest_systick[0].cvr == 4321U &&
          g_guest_systick[0].pending == 1U &&
          g_guest_systick[0].owed_ticks == 1U);
    check(g_active_guest == UINT32_MAX && g_test_csr == 0U &&
          g_test_icsr == WT_SCB_ICSR_PENDSTCLR);
    __asm volatile("mrs %0, primask" : "=r"(primask));
    check(g_test_mask_seen == 1U && primask == 0U &&
          g_test_bad_handoff == 0U && g_test_ticks == 1U);

    saved = g_guest_systick[0];
    wt_arch_wait_for_interrupt();
    check(g_guest_systick[0].csr == saved.csr &&
          g_guest_systick[0].rvr == saved.rvr &&
          g_guest_systick[0].cvr == saved.cvr &&
          g_guest_systick[0].pending == saved.pending &&
          g_guest_systick[0].owed_ticks == saved.owed_ticks &&
          g_guest_systick[0].last_accounted_cycles ==
              saved.last_accounted_cycles);

    g_secure_wall_cycles = saved.last_accounted_cycles;
    wt_virtual_systick_restore_arriving(0U);
    check(g_arriving_systick_csr == saved.csr &&
          g_test_rvr == saved.cvr && g_arriving_systick_inject == 1U);
    wt_virtual_systick_arm_arriving();
    check(g_test_csr == saved.csr && g_test_rvr == saved.rvr &&
          g_test_icsr == WT_SCB_ICSR_PENDSTSET);

    g_active_guest = 1U;
    g_test_csr = WT_SYST_CSR_CLKSOURCE;
    g_test_rvr = 321U;
    g_test_cvr = 123U;
    g_test_icsr = 0U;
    wt_arch_wait_for_interrupt();
    check(g_guest_systick[1].csr == WT_SYST_CSR_CLKSOURCE &&
          g_guest_systick[1].rvr == 321U &&
          g_guest_systick[1].cvr == 123U &&
          g_guest_systick[1].pending == 0U &&
          g_guest_systick[1].owed_ticks == 0U);

    /* A tick before the critical section completes before ownership is read. */
    g_active_guest = 0U;
    g_test_csr = 7U;
    g_test_reset_owner = 1U;
    WT_SCB_ICSR_S = WT_SCB_ICSR_PENDSTSET;
    __asm volatile("dsb 0xF\n isb 0xF" ::: "memory");
    check(g_test_reset_owner == 0U);
    wt_arch_wait_for_interrupt();
    check(g_active_guest == UINT32_MAX &&
          g_guest_systick[0].csr == 0U &&
          g_guest_systick[0].rvr == 0U &&
          g_guest_systick[0].cvr == 0U &&
          g_guest_systick[0].pending == 0U &&
          g_guest_systick[0].owed_ticks == 0U);
    __asm volatile("bkpt #0x7f");
    for (;;) {}
}
