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

#include <stdint.h>

void Reset_Handler(void)
{
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
    uint32_t* src = &_sidata;
    uint32_t* dst = &_sdata;

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

    wt_boot_run();
}
