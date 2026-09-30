/* periph.h
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

#ifndef WOLFTRUST_PERIPH_H
#define WOLFTRUST_PERIPH_H

#include <stddef.h>
#include <stdint.h>

#include "wolftrust/types.h"

/* A peripheral the port lets a Secure Partition own through a DEVICE memory
 * resource. is_secure reads back the peripheral's security attribution from
 * the fabric (TZSC, AHBSC), so a table entry the port forgot to secure cannot
 * be mapped into a partition. */
typedef struct wt_periph {
    const char* name;
    uintptr_t base;
    size_t size;
    uint32_t bus_master;
    int (*is_secure)(void);
} wt_periph_t;

/* 1 when [base, base + size) is exactly one table entry that is not a bus
 * master and reads back Secure; 0 otherwise. A partition that owns a bus
 * master could aim it at memory its MPU table does not grant. */
int wt_periph_sp_device_ok(const wt_periph_t* table, size_t count,
                           uintptr_t base, size_t size);

/* 1 when a Secure Partition may map [base, base + size). A range the
 * architecture treats as MMIO (mmio != 0) must be marked DEVICE and pass
 * wt_periph_sp_device_ok, so dropping the DEVICE bit cannot map a peripheral
 * as Normal memory; a DEVICE range must pass it wherever it lies. */
int wt_periph_sp_region_ok(const wt_periph_t* table, size_t count,
                           uintptr_t base, size_t size, int device, int mmio);

/* 1 when every region of a partition domain passes wt_periph_sp_region_ok,
 * with is_mmio classifying each range for the target architecture. */
int wt_periph_sp_domain_ok(const wt_periph_t* table, size_t count,
                           const wt_memory_region_t* regions, size_t n,
                           int (*is_mmio)(uintptr_t base, size_t size));

#endif /* WOLFTRUST_PERIPH_H */
