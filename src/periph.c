/* periph.c
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

#include "wolftrust/periph.h"

int wt_periph_sp_device_ok(const wt_periph_t* table, size_t count,
                           uintptr_t base, size_t size)
{
    size_t i;

    if (table == NULL || size == 0U || base > UINTPTR_MAX - size) {
        return 0;
    }
    for (i = 0U; i < count; i++) {
        if (table[i].base != base || table[i].size != size) {
            continue;
        }
        if (table[i].bus_master != 0U || table[i].is_secure == NULL) {
            return 0;
        }
        return (table[i].is_secure() == 1) ? 1 : 0;
    }
    return 0;
}

int wt_periph_sp_region_ok(const wt_periph_t* table, size_t count,
                           uintptr_t base, size_t size, int device, int mmio)
{
    if (device == 0) {
        return (mmio == 0) ? 1 : 0;
    }
    return wt_periph_sp_device_ok(table, count, base, size);
}

int wt_periph_sp_domain_ok(const wt_periph_t* table, size_t count,
                           const wt_memory_region_t* regions, size_t n,
                           int (*is_mmio)(uintptr_t base, size_t size))
{
    size_t i;

    if ((regions == NULL && n != 0U) || is_mmio == NULL) {
        return 0;
    }
    for (i = 0U; i < n; i++) {
        if (wt_periph_sp_region_ok(table, count, regions[i].base,
                regions[i].size,
                (regions[i].attributes & WT_MEM_ATTR_DEVICE) != 0U,
                is_mmio(regions[i].base, regions[i].size)) != 1) {
            return 0;
        }
    }
    return 1;
}
