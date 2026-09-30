/* mmio_map.h
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

#ifndef WOLFTRUST_ARCH_ARMV8M_MMIO_MAP_H
#define WOLFTRUST_ARCH_ARMV8M_MMIO_MAP_H

#include <stddef.h>
#include <stdint.h>

/* Nonzero when [base, base + size) overlaps the Armv8-M default map's
 * Peripheral (0x40000000-0x5FFFFFFF), Device (0xA0000000-0xDFFFFFFF), or
 * System (0xE0000000 up) ranges; an empty or wrapping range counts too. */
static inline int wt_armv8m_range_is_mmio(uintptr_t base, size_t size)
{
    uintptr_t last;

    if (size == 0u || base > UINTPTR_MAX - (size - 1u)) {
        return 1;
    }
    last = base + (size - 1u);
    if (base <= 0x5FFFFFFFu && last >= 0x40000000u) {
        return 1;
    }
    return (last >= 0xA0000000u) ? 1 : 0;
}

#endif /* WOLFTRUST_ARCH_ARMV8M_MMIO_MAP_H */
