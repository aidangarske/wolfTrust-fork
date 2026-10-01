/* start_armv8m.c
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


/* Armv8-M reset entry: initialize the image's data and bss (including the
 * conformance, keystore, and vnet bands the secure linker script places in
 * their own MPU-granted windows), then enter the neutral boot sequence. */

#include "wolftrust/boot.h"
#include "wolftrust/platform.h"
#include "wolftrust/arch/armv8m/core_regs.h"

#include <stdint.h>

static void wt_reset_main(void) __attribute__((noreturn, used));

/* Naked so nothing is pushed before MSP is moved below the two seal words
 * and they are written; MSP moves first so an exception cannot stack over them. */
__attribute__((naked, noreturn))
void Reset_Handler(void)
{
    __asm volatile(
        "ldr  r0, =_estack       \n"
        "movw r1, #0xEDA5        \n"   /* WT_ARMV8M_STACK_SEAL low half */
        "movt r1, #0xFEF5        \n"   /* WT_ARMV8M_STACK_SEAL high half */
        "subs r0, r0, #8         \n"
        "msr  msp, r0            \n"
        "str  r1, [r0, #0]       \n"
        "str  r1, [r0, #4]       \n"
        "b    wt_reset_main      \n");
}

static void wt_reset_main(void)
{
    extern uint32_t _estack;
    extern uint32_t _sidata;
    extern uint32_t _sdata;
    extern uint32_t _edata;
    extern uint32_t _sbss;
    extern uint32_t _ebss;
    extern uint32_t _siconfdata;
    extern uint32_t _sconfdata;
    extern uint32_t _econfdata;
    extern uint32_t _sconfbss;
    extern uint32_t _econfbss;
    extern uint32_t _si_keystore;
    extern uint32_t _s_keystore;
    extern uint32_t _e_keystore_data;
    extern uint32_t _s_keystore_bss;
    extern uint32_t _e_keystore;
#if defined(CONFIG_VNET)
    extern uint32_t _si_vnet;
    extern uint32_t _s_vnet;
    extern uint32_t _e_vnet_data;
    extern uint32_t _s_vnet_bss;
    extern uint32_t _e_vnet;
#endif
    const uint32_t* seal = (const uint32_t*)((uintptr_t)&_estack - 8u);
    uint32_t* src = &_sidata;
    uint32_t* dst = &_sdata;
    uint32_t msp;

    while (dst < &_edata) {
        *dst++ = *src++;
    }

    for (dst = &_sbss; dst < &_ebss; ++dst) {
        *dst = 0u;
    }

    /* Conformance SP .data/.bss live in their own MPU-granted window; the main
     * loops above skip it, so initialize it here. Empty in production builds. */
    src = &_siconfdata;
    for (dst = &_sconfdata; dst < &_econfdata; ++dst) {
        *dst = *src++;
    }
    for (dst = &_sconfbss; dst < &_econfbss; ++dst) {
        *dst = 0u;
    }

    /* wolfHSM keystore band lives outside the general .data/.bss window, so the
     * loops above skip it; initialize its loaded .data and zero its .bss here. */
    src = &_si_keystore;
    for (dst = &_s_keystore; dst < &_e_keystore_data; ++dst) {
        *dst = *src++;
    }
    for (dst = &_s_keystore_bss; dst < &_e_keystore; ++dst) {
        *dst = 0u;
    }

#if defined(CONFIG_VNET)
    /* SERVICE_VNET data band: same treatment as the keystore band. */
    src = &_si_vnet;
    for (dst = &_s_vnet; dst < &_e_vnet_data; ++dst) {
        *dst = *src++;
    }
    for (dst = &_s_vnet_bss; dst < &_e_vnet; ++dst) {
        *dst = 0u;
    }
#endif

#if defined(WT_SEAL_NEG_PROBE) && (WT_SEAL_NEG_PROBE == 3)
    /* sealbootneg: a damaged main-stack seal must stop the boot here. The
     * store is opaque so the compiler cannot fold the check and drop the
     * boot path behind it. */
    __asm__ volatile ("str %1, [%0]" : : "r"(seal), "r"(0u) : "memory");
#endif
    /* Refuse to boot unless the reset entry sealed the main stack top and
     * moved MSP below the seal words. */
    __asm__ volatile ("mrs %0, msp" : "=r"(msp));
    if (seal[0] != WT_ARMV8M_STACK_SEAL || seal[1] != WT_ARMV8M_STACK_SEAL ||
        msp > (uint32_t)(uintptr_t)seal) {
        wt_platform_panic();
    }

    wt_boot_run();
}
