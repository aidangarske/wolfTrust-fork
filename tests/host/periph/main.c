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

/* WT-FFM-0068: a Secure Partition may own a peripheral only when the port
 * lists it exactly, it is not a bus master, and it reads back Secure. */

#include "wolftrust/periph.h"
#include "wolftrust/arch/armv8m/mmio_map.h"

#include <stdint.h>
#include <stdio.h>

static int checks;
static int failures;
static int g_secure = 1;

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

static int fake_secure(void)
{
    return g_secure;
}

static int armv8m_is_mmio(uintptr_t base, size_t size)
{
    return wt_armv8m_range_is_mmio(base, size);
}

static wt_memory_region_t region(uintptr_t base, size_t size, uint32_t attr)
{
    wt_memory_region_t r;

    r.base = base;
    r.size = size;
    r.attributes = attr;
    return r;
}

static const wt_periph_t g_table[] = {
    { "timer", 0x50000000u, 0x400u, 0u, fake_secure },
    { "dma", 0x50020000u, 0x1000u, 1u, fake_secure },
    { "unchecked", 0x50030000u, 0x400u, 0u, NULL },
};
#define TABLE_COUNT (sizeof(g_table) / sizeof(g_table[0]))

int main(void)
{
    wt_memory_region_t ram[2];
    wt_memory_region_t mmio_plain[2];
    wt_memory_region_t mmio_device[2];
    wt_memory_region_t dma_device[1];

    printf("WT-FFM-0068 partition peripheral ownership\n");

    check(wt_periph_sp_device_ok(g_table, TABLE_COUNT, 0x50000000u,
                                 0x400u) == 1,
          "exact Secure non-bus-master entry is accepted");
    check(wt_periph_sp_device_ok(g_table, TABLE_COUNT, 0x50000000u,
                                 0x800u) == 0,
          "region larger than the peripheral is refused");
    check(wt_periph_sp_device_ok(g_table, TABLE_COUNT, 0x50000100u,
                                 0x100u) == 0,
          "sub-range of a peripheral is refused");
    check(wt_periph_sp_device_ok(g_table, TABLE_COUNT, 0x50020000u,
                                 0x1000u) == 0,
          "bus-master peripheral is refused");
    check(wt_periph_sp_device_ok(g_table, TABLE_COUNT, 0x50030000u,
                                 0x400u) == 0,
          "entry without a security read-back is refused");
    check(wt_periph_sp_device_ok(g_table, TABLE_COUNT, 0x40000000u,
                                 0x400u) == 0,
          "unlisted peripheral is refused");
    check(wt_periph_sp_device_ok(NULL, 0u, 0x50000000u, 0x400u) == 0,
          "port without assignable peripherals refuses every region");
    check(wt_periph_sp_device_ok(g_table, TABLE_COUNT, UINTPTR_MAX - 0x10u,
                                 0x400u) == 0,
          "wrapping region is refused");
    check(wt_periph_sp_device_ok(g_table, TABLE_COUNT, 0x50000000u, 0u) == 0,
          "empty region is refused");
    check(wt_periph_sp_region_ok(g_table, TABLE_COUNT, 0x30000000u, 0x1000u,
                                 0, 0) == 1,
          "Normal-memory region outside MMIO needs no peripheral entry");
    check(wt_periph_sp_region_ok(g_table, TABLE_COUNT, 0x50000000u, 0x400u,
                                 0, 1) == 0,
          "MMIO range without the DEVICE attribute is refused");
    check(wt_periph_sp_region_ok(g_table, TABLE_COUNT, 0x50000000u, 0x400u,
                                 1, 1) == 1,
          "MMIO range marked DEVICE maps an assignable peripheral");
    check(wt_periph_sp_region_ok(g_table, TABLE_COUNT, 0x50020000u, 0x1000u,
                                 1, 1) == 0,
          "MMIO range marked DEVICE still refuses a bus master");
    check(wt_periph_sp_region_ok(g_table, TABLE_COUNT, 0x30000000u, 0x400u,
                                 1, 0) == 0,
          "DEVICE range outside MMIO still needs a peripheral entry");
    check(wt_armv8m_range_is_mmio(0x3FFFFF00u, 0x100u) == 0,
          "range ending just below the Peripheral region is Normal memory");
    check(wt_armv8m_range_is_mmio(0x3FFFFF00u, 0x101u) == 1,
          "range crossing into the Peripheral region is MMIO");
    check(wt_armv8m_range_is_mmio(0x5FFFFFFFu, 1u) == 1,
          "last Peripheral byte is MMIO");
    check(wt_armv8m_range_is_mmio(0x60000000u, 0x1000u) == 0,
          "range just above the Peripheral region is Normal memory");
    check(wt_armv8m_range_is_mmio(0x9FFFF000u, 0x1000u) == 0,
          "range ending below the Device region is Normal memory");
    check(wt_armv8m_range_is_mmio(0xA0000000u, 0x20u) == 1,
          "Device region is MMIO");
    check(wt_armv8m_range_is_mmio(0xE000E000u, 0x100u) == 1,
          "System region is MMIO");
    check(wt_armv8m_range_is_mmio(0x30000000u, 0u) == 1,
          "empty range is refused as MMIO");

    ram[0] = region(0x30020000u, 0x2000u,
                    WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE);
    ram[1] = region(0x0C060000u, 0x1000u,
                    WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC);
    mmio_plain[0] = ram[0];
    mmio_plain[1] = region(0x50000000u, 0x400u,
                           WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE);
    mmio_device[0] = ram[0];
    mmio_device[1] = region(0x50000000u, 0x400u,
                            WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE |
                            WT_MEM_ATTR_DEVICE);
    dma_device[0] = region(0x50020000u, 0x1000u,
                           WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE |
                           WT_MEM_ATTR_DEVICE);
    check(wt_periph_sp_domain_ok(NULL, 0u, ram, 2u,
                                 armv8m_is_mmio) == 1,
          "domain of plain RAM and code is admitted");
    check(wt_periph_sp_domain_ok(g_table, TABLE_COUNT, mmio_plain, 2u,
                                 armv8m_is_mmio) == 0,
          "domain mapping a peripheral without DEVICE is refused");
    check(wt_periph_sp_domain_ok(NULL, 0u, mmio_device, 2u,
                                 armv8m_is_mmio) == 0,
          "domain with a DEVICE region on a port with no table is refused");
    check(wt_periph_sp_domain_ok(g_table, TABLE_COUNT, mmio_device, 2u,
                                 armv8m_is_mmio) == 1,
          "domain owning an assignable peripheral is admitted");
    check(wt_periph_sp_domain_ok(g_table, TABLE_COUNT, dma_device, 1u,
                                 armv8m_is_mmio) == 0,
          "domain owning a bus master is refused");
    check(wt_periph_sp_domain_ok(g_table, TABLE_COUNT, NULL, 1u,
                                 armv8m_is_mmio) == 0,
          "missing region list is refused");

    g_secure = 0;
    check(wt_periph_sp_device_ok(g_table, TABLE_COUNT, 0x50000000u,
                                 0x400u) == 0,
          "entry that reads back Non-secure is refused");

    printf("%d checks, %d failures\n", checks, failures);
    if (failures != 0) {
        return 1;
    }
    printf("PASS: periph (WT-FFM-0068)\n");
    return 0;
}
