/* mpu_armv8m.c
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


/* Armv8-M PMSAv8 programming behind the architecture contract: the secure
 * MPU whitelist from a port-supplied table, the Secure Partition domains
 * composed by the core, and the per-guest Non-secure MPU. */

#include "wolftrust/arch.h"
#include "wolftrust/arch/armv8m/armv8m.h"
#include "wolftrust/arch/armv8m/core_regs.h"
#include "wolftrust/types.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* MAIR encodings: normal write-back/RA/WA inner+outer = 0xFF;
 * device-nGnRE = 0x04; normal non-cacheable inner+outer = 0x44. */
#define WT_MPU_MAIR0_NORMAL_AT_0   0x000000FFu
#define WT_MPU_MAIR0_DEVICE_AT_1   0x00000400u
#define WT_MPU_MAIR0_NOCACHE_AT_2  0x00440000u

static const wt_armv8m_mpu_region_t* g_spm_whitelist;
static size_t g_spm_whitelist_count;

/* Program one secure MPU region. base/limit are inclusive 32-byte-aligned
 * boundaries; `rbar_flags` carries XN/AP/SH, `rlar_flags` carries AttrIndx. */
static void wt_mpu_s_set_region(uint32_t rnr, uintptr_t base,
                                uintptr_t limit_inclusive,
                                uint32_t rbar_flags, uint32_t rlar_flags)
{
    WT_MPU_S_RNR  = rnr;
    WT_MPU_S_RBAR = ((uint32_t)base & 0xFFFFFFE0u) | rbar_flags;
    WT_MPU_S_RLAR = (((uint32_t)limit_inclusive & 0xFFFFFFE0u)
                    | rlar_flags | WT_MPU_RLAR_EN);
}

static void wt_mpu_s_set_mair(void)
{
    /* MAIR0[7:0]   = Normal WB/RA/WA   (AttrIndx 0)
     * MAIR0[15:8]  = Device nGnRE      (AttrIndx 1)
     * MAIR0[23:16] = Normal non-cacheable (AttrIndx 2) */
    WT_MPU_S_MAIR0 = WT_MPU_MAIR0_NORMAL_AT_0 |
                     WT_MPU_MAIR0_DEVICE_AT_1 |
                     WT_MPU_MAIR0_NOCACHE_AT_2;
    WT_MPU_S_MAIR1 = 0u;
}

/* Silicon implements TYPE.DREGION secure regions (12 on STM32H563, more
 * than WT_MAX_MEMORY_REGIONS); their reset state is UNKNOWN per PMSAv8, so
 * explicitly disable every region beyond the programmed set. */
static void wt_mpu_s_disable_from(uint32_t first)
{
    uint32_t rnr;
    uint32_t dregion = (WT_MPU_S_TYPE >> 8) & 0xFFu;

    for (rnr = first; rnr < dregion; rnr++) {
        WT_MPU_S_RNR  = rnr;
        WT_MPU_S_RBAR = 0u;
        WT_MPU_S_RLAR = 0u;
    }
}

/* Secure-side MPU whitelist. PRIVDEFENA is OFF, so any access outside
 * the listed regions traps (MemManage / SecureFault). This catches NULL
 * pointer derefs, wild pointer writes, and stray peripheral accesses
 * from inside wolfHSM / wolfCrypt coroutines. Stack overflow is caught
 * separately via PSPLIM_S -> UsageFault.STKOF. */
void wt_armv8m_mpu_s_init(const wt_armv8m_mpu_region_t* whitelist,
                          size_t count)
{
    size_t i;

    g_spm_whitelist = whitelist;
    g_spm_whitelist_count = count;

    WT_MPU_S_CTRL = 0u;
    wt_dsb();

    wt_mpu_s_set_mair();

    for (i = 0u; i < count; ++i) {
        wt_mpu_s_set_region((uint32_t)i, whitelist[i].base, whitelist[i].limit,
                            whitelist[i].rbar_flags, whitelist[i].rlar_flags);
    }
    wt_mpu_s_disable_from((uint32_t)count);

    /* Enable: PRIVDEFENA=0 (no implicit background region), HFNMIENA=1
     * so MPU stays active during HardFault/NMI (matches what we want
     * since our MemManage handler relies on the same region table). */
    wt_dsb();
    WT_MPU_S_CTRL = WT_MPU_CTRL_HFNMIENA | WT_MPU_CTRL_ENABLE;
    wt_dsb();
    wt_isb();
}

/* Encode one secure MPU region for a Secure Partition domain. Access is
 * granted at any privilege level so the unprivileged partition thread can
 * reach its own regions; isolation comes from which regions are mapped. */
static void wt_program_secure_partition_region(uint32_t rnr, uintptr_t base,
                                               size_t size, uint32_t attributes)
{
    uint32_t rbar_flags = WT_MPU_RBAR_SH_INNER;
    uint32_t rlar_flags = WT_MPU_RLAR_ATTRIDX_NORMAL;

    if ((attributes & WT_MEM_ATTR_EXEC) == 0u) {
        rbar_flags |= WT_MPU_RBAR_XN;
    }
    if ((attributes & WT_MEM_ATTR_WRITE) != 0u) {
        rbar_flags |= WT_MPU_RBAR_AP_RWRW;
    }
    else {
        rbar_flags |= WT_MPU_RBAR_AP_RORO;
    }
    if ((attributes & WT_MEM_ATTR_DEVICE) != 0u) {
        rbar_flags &= ~WT_MPU_RBAR_SH_INNER;
        rlar_flags = WT_MPU_RLAR_ATTRIDX_DEVICE;
    }
    wt_mpu_s_set_region(rnr, base, base + size - 1u, rbar_flags, rlar_flags);
}

static void wt_program_sp_domain_regions(const wt_memory_region_t* regions,
                                         size_t count, uint32_t ctrl)
{
    size_t i;

    WT_MPU_S_CTRL = 0u;
    wt_dsb();

    wt_mpu_s_set_mair();

    for (i = 0u; i < WT_MAX_MEMORY_REGIONS; ++i) {
        if (regions != NULL && i < count && regions[i].size != 0u) {
            wt_program_secure_partition_region((uint32_t)i, regions[i].base,
                                               regions[i].size,
                                               regions[i].attributes);
        }
        else {
            WT_MPU_S_RNR  = (uint32_t)i;
            WT_MPU_S_RBAR = 0u;
            WT_MPU_S_RLAR = 0u;
        }
    }
    wt_mpu_s_disable_from(WT_MAX_MEMORY_REGIONS);

    wt_dsb();
    WT_MPU_S_CTRL = ctrl;
    wt_dsb();
    wt_isb();
}

void wt_arch_program_secure_partition_domain(
    const wt_memory_region_t* regions, size_t count)
{
    wt_program_sp_domain_regions(regions, count,
                                 WT_MPU_CTRL_HFNMIENA | WT_MPU_CTRL_ENABLE);
}

void wt_arch_program_sp_thread_domain(const wt_memory_region_t* regions,
                                          size_t count)
{
    /* PRIVDEFENA: the unprivileged SP thread is confined to the mapped
     * regions while the privileged SVC/PendSV/fault handlers keep the
     * default map, so psa_* requests can reach SPM state (WT-FFM-0011). */
    wt_program_sp_domain_regions(regions, count,
                                 WT_MPU_CTRL_PRIVDEFENA |
                                 WT_MPU_CTRL_HFNMIENA | WT_MPU_CTRL_ENABLE);
}

void wt_arch_restore_spm_domain(void)
{
    wt_armv8m_mpu_s_init(g_spm_whitelist, g_spm_whitelist_count);
}

static void wt_program_ns_mpu_region(uintptr_t base, size_t size, uint32_t attributes)
{
    uint32_t rbar = (uint32_t)(base & 0xFFFFFFE0u);
    uint32_t rlar = (uint32_t)(((base + size - 1u) & 0xFFFFFFE0u) | 0x1u);
    bool allow_write = (attributes & WT_MEM_ATTR_WRITE) != 0u;
    bool allow_read = (attributes & WT_MEM_ATTR_READ) != 0u;
    bool allow_exec = (attributes & WT_MEM_ATTR_EXEC) != 0u;
    bool is_device = (attributes & WT_MEM_ATTR_DEVICE) != 0u;

    if (!allow_exec) {
        rbar |= 0x1u;
    }
    if (allow_write) {
        rbar |= (0x1u << 1);
    } else if (allow_read) {
        rbar |= (0x3u << 1);
    }
    if (is_device) {
        rlar |= (0x1u << 1);
    }

    WT_MPU_NS_RBAR = rbar;
    WT_MPU_NS_RLAR = rlar;
}

static void wt_program_ns_mpu_regions(const wt_memory_region_t* regions,
                                      size_t count)
{
    size_t i;

    WT_MPU_NS_CTRL = 0u;
    WT_MPU_NS_MAIR0 = 0x00000044u;

    for (i = 0; i < WT_MAX_MEMORY_REGIONS; ++i) {
        WT_MPU_NS_RNR = (uint32_t)i;
        if (regions != NULL && i < count && regions[i].size != 0u) {
            wt_program_ns_mpu_region(regions[i].base, regions[i].size,
                                     regions[i].attributes);
        } else {
            WT_MPU_NS_RBAR = 0u;
            WT_MPU_NS_RLAR = 0u;
        }
    }

    WT_MPU_NS_CTRL = 0x1u;
}

void wt_arch_program_guest_domain(const wt_memory_region_t* regions, size_t count)
{
    wt_program_ns_mpu_regions(regions, count);
}
