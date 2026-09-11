/* platform_stm32h563.c
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

#include "wolftrust/platform.h"
#include "wolftrust/arch.h"
#include "wolftrust/guest_verify.h"
#include "wolftrust/monitor.h"
#include "wolftrust/arch/armv8m/context.h"
#include "wolftrust/arch/armv8m/armv8m.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wolfHAL/clock/stm32h5_rcc.h>
#include <wolfHAL/platform/st/stm32h563xx.h>
#include <wolfHAL/reg.h>

#include "memory_map.h"
#include "stm32h563_regs.h"

#include "wolftrust/arch/armv8m/ffm_nsc.h"
#include "wolftrust/arch/armv8m/spm_svc.h"
#include "wolftrust/ffm.h"
#include "wolftrust/ffm_boot.h"
#include "wolftrust/ffm_domain.h"
#include "psa_manifest/pid.h"

void* memcpy(void* destination, const void* source, size_t size);
void* memset(void* destination, int value, size_t size);

#ifdef WT_ENGINE_HSM
#include "wolftrust/services/hsm.h"
#include "wolftrust/boot_handoff.h"
#include "wolftrust/services/initial_attestation.h"
#include <string.h>
#include "wolftrust/arch/armv8m/cmse.h"
#include "wolftrust/sched/tasklet.h"
#include "wolfhsm/wh_error.h"

#endif /* WT_ENGINE_HSM */

/* Secure MPU attribute encodings. MPU_RBAR[2:1] = AP (access permissions),
 * MPU_RBAR[0]  = XN (execute-never), MPU_RLAR[3:1] = AttrIndx (into MAIR). */
#define WT_MPU_RBAR_XN       (1u << 0)
#define WT_MPU_RBAR_AP_RW    (0u << 1)   /* privileged RW, no access from unpriv */
#define WT_MPU_RBAR_AP_RWRW  (1u << 1)   /* RW from any priv level */
#define WT_MPU_RBAR_AP_RO    (2u << 1)   /* privileged RO, no access from unpriv */
#define WT_MPU_RBAR_AP_RORO  (3u << 1)   /* RO from any priv level */
#define WT_MPU_RBAR_SH_INNER (3u << 3)

#define WT_MPU_RLAR_EN       (1u << 0)
#define WT_MPU_RLAR_ATTRIDX_NORMAL  (0u << 1)  /* MAIR[0] = normal memory */
#define WT_MPU_RLAR_ATTRIDX_DEVICE  (1u << 1)  /* MAIR[1] = device memory */
#define WT_MPU_RLAR_ATTRIDX_NOCACHE (2u << 1)  /* MAIR[2] = normal non-cacheable */

/* MAIR encodings: normal write-back/RA/WA inner+outer = 0xFF;
 * device-nGnRE = 0x04; normal non-cacheable inner+outer = 0x44. */
#define WT_MPU_MAIR0_NORMAL_AT_0   0x000000FFu
#define WT_MPU_MAIR0_DEVICE_AT_1   0x00000400u
#define WT_MPU_MAIR0_NOCACHE_AT_2  0x00440000u

static volatile uint32_t g_secure_service_depth;
static volatile uint32_t g_hsm_wait_skip_count;
static volatile uint32_t g_wt_attest_degraded __attribute__((used));

#ifdef WT_ENGINE_HSM
static void wt_secure_service_enter(void);
static void wt_secure_service_exit(void);
#endif

static void wt_rcc_enable_clock(uintptr_t base,
                                const whal_Stm32h5_Rcc_PeriphClk* clk)
{
    whal_Reg_Update((size_t)base, clk->regOffset, clk->enableMask,
                    clk->enableMask);
}

static void wt_sau_set_region(uint32_t rnr,
                              uint32_t base,
                              uint32_t limit_inclusive,
                              bool nsc)
{
    WT_SAU_RNR = rnr;
    WT_SAU_RBAR = base & 0xFFFFFFE0u;
    WT_SAU_RLAR = (limit_inclusive & 0xFFFFFFE0u) | (nsc ? 2u : 0u) | 1u;
}

int wt_platform_guest_flash_wrp_ok(uintptr_t window_base, size_t window_size)
{
    uint32_t wrp;
    uintptr_t bank_base;

    if (window_base >= WT_FLASH_NS_BASE + 0x00100000u) {
        wrp = WT_FLASH_WRP2R_CUR;
        bank_base = WT_FLASH_NS_BASE + 0x00100000u;
    }
    else {
        wrp = WT_FLASH_WRP1R_CUR;
        bank_base = WT_FLASH_NS_BASE;
    }

    return wt_guest_flash_wrp_covers(wrp, window_base, window_size, bank_base,
                                     WT_FLASH_SECTOR_SIZE,
                                     WT_FLASH_WRP_SECTORS_PER_GROUP);
}

static void wt_gtzc_init(void)
{
    size_t i;
    size_t nsWords = (WT_GUEST1_RAM_BASE + WT_GUEST_RAM_SIZE -
                      WT_RAM_NS_BASE) / (512u * 32u);

    WT_RCC_AHB1ENR |= WT_RCC_AHB1ENR_GTZC1EN;

    for (i = 0; i < 16u; ++i) {
        WT_GTZC1_MPCBB1_SECCFGR[i] = 0xFFFFFFFFu;
    }

    /* SRAM1 MPCBB blocks are 512 B; each SECCFGR word covers 32 blocks
     * (16 KiB). Mark the whole guest RAM extent Non-secure — derived from
     * the memory map so a layout change cannot leave a guest window
     * secure-blocked. The Secure monitor .data/.bss lives above this bank. */
    for (i = 0; i < nsWords && i < 16u; ++i) {
        WT_GTZC1_MPCBB1_SECCFGR[i] = 0x00000000u;
    }

    /* Guests own the UARTs. SAU makes the APB window non-secure, but
     * STM32H5 also gates peripheral security through GTZC/TZSC. */
    WT_GTZC1_TZSC_SECCFGR1 &= ~(WT_GTZC_SECCFGR1_USART2SEC |
                                WT_GTZC_SECCFGR1_USART3SEC);

    /* Crypto peripherals are secure-owned. Do not clear these bits when the
     * APB/AHB SAU windows are exposed to guests for other devices. STM32H563
     * has HASH, RNG and PKA in this GTZC register; AES/SAES are not present on
     * this line and future H5 derivatives should add their bits here. */
    WT_GTZC1_TZSC_SECCFGR3 |= (WT_GTZC_SECCFGR3_HASHSEC |
                               WT_GTZC_SECCFGR3_RNGSEC |
                               WT_GTZC_SECCFGR3_PKASEC);

    for (i = 0; i < 4u; ++i) {
        WT_GTZC1_MPCBB2_SECCFGR[i] = 0xFFFFFFFFu;
    }

    for (i = 0; i < 20u; ++i) {
        WT_GTZC1_MPCBB3_SECCFGR[i] = 0xFFFFFFFFu;
    }

    /* MPCBB PRIVCFGR resets to all-privileged on real silicon, which blocks
     * every unprivileged SRAM access below the MPU — the unprivileged crypto
     * SP thread faults on its first frame access no matter what the MPU
     * grants. Privilege enforcement is the secure MPU's job here, so drop the
     * GTZC privilege filter (the M33MU does not model it). */
    for (i = 0; i < 16u; ++i) {
        WT_GTZC1_MPCBB1_PRIVCFGR[i] = 0x00000000u;
    }
    for (i = 0; i < 4u; ++i) {
        WT_GTZC1_MPCBB2_PRIVCFGR[i] = 0x00000000u;
    }
    for (i = 0; i < 20u; ++i) {
        WT_GTZC1_MPCBB3_PRIVCFGR[i] = 0x00000000u;
    }
}

static void wt_sau_init(void)
{
    uint32_t region;
    uint32_t regionCount = WT_SAU_TYPE & 0xFFu;

    /* Disable the SAU before changing any region pair. Updating RBAR while
     * the previous RLAR remains enabled creates a transient region spanning
     * the new base and old limit. That can reclassify the currently executing
     * Secure image as Non-secure before the matching RLAR write completes. */
    WT_SAU_CTRL = 0u;
    wt_dsb();
    wt_isb();

    /* A preceding Secure stage may leave enabled regions behind. Clear every
     * implemented slot before installing wolfTrust's complete attribution
     * map so no higher-priority stale region can override it. */
    for (region = 0u; region < regionCount; region++) {
        WT_SAU_RNR = region;
        WT_SAU_RLAR = 0u;
    }

    wt_sau_set_region(0u, WT_GUEST0_FLASH_BASE,
                      WT_GUEST1_FLASH_BASE + WT_GUEST1_FLASH_SIZE - 1u,
                      false);
    wt_sau_set_region(1u, WT_RAM_NS_BASE, WT_RAM_NS_BASE + 0x0009FFFFu, false);
    wt_sau_set_region(2u, WT_FLASH_NSC_BASE, WT_FLASH_NSC_END, true);
    wt_sau_set_region(3u, 0x40000000u, 0x4FFFFFFFu, false);
    WT_SAU_CTRL = 1u;
    wt_dsb();
    wt_isb();
}

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

volatile void* wt_platform_boot_handoff_region(size_t* size)
{
    *size = WT_RAM_S_BASE - WT_BOOT_HANDOFF_ADDRESS;
    return (volatile void*)WT_BOOT_HANDOFF_ADDRESS;
}

#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
static void wt_clear_boot_handoff_scratch(void)
{
    volatile uint8_t* scratch =
        (volatile uint8_t*)WT_BOOT_HANDOFF_ADDRESS;
    size_t scratchSize = WT_RAM_S_BASE - WT_BOOT_HANDOFF_ADDRESS;
    size_t i;

    for (i = 0u; i < scratchSize; ++i) {
        scratch[i] = 0u;
    }
    wt_dsb();
}
#endif

/* Secure-side MPU whitelist. PRIVDEFENA is OFF, so any access outside
 * the listed regions traps (MemManage / SecureFault). This catches NULL
 * pointer derefs, wild pointer writes, and stray peripheral accesses
 * from inside wolfHSM / wolfCrypt coroutines. Stack overflow is caught
 * separately via PSPLIM_S → UsageFault.STKOF. */
static void wt_mpu_s_init(void)
{
    uint32_t rnr;
    uint32_t dregion = (WT_MPU_S_TYPE >> 8) & 0xFFu;

    WT_MPU_S_CTRL = 0u;
    wt_dsb();

    /* MAIR0[7:0]   = Normal WB/RA/WA   (AttrIndx 0)
     * MAIR0[15:8]  = Device nGnRE      (AttrIndx 1)
     * MAIR0[23:16] = Normal non-cacheable (AttrIndx 2) */
    WT_MPU_S_MAIR0 = WT_MPU_MAIR0_NORMAL_AT_0 |
                     WT_MPU_MAIR0_DEVICE_AT_1 |
                     WT_MPU_MAIR0_NOCACHE_AT_2;
    WT_MPU_S_MAIR1 = 0u;

    /* Region 0: secure flash RX (image, NSC stubs, .text). */
    wt_mpu_s_set_region(0u,
        WT_FLASH_S_BASE, WT_FLASH_S_BASE + WT_FLASH_S_SIZE - 1u,
        WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
        WT_MPU_RLAR_ATTRIDX_NORMAL);

    /* Region 1: secure flash bank 2 RW-NX. The wolfHSM NVM partition
     * lives at 0x0C1FC000..0x0C1FFFFF and STM32H5 flash programming
     * writes data words directly to the destination flash address with
     * FLASH_CR.PG set (the FLASH controller intercepts the stores).
     * The peripheral's own LOCK / PG gating is the real write barrier.
     * Keep this region non-cacheable so an immediate verify reads the flash
     * controller rather than a cache line populated before programming. */
    wt_mpu_s_set_region(1u,
        0x0C100000u, 0x0C1FFFFFu,
        WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
        WT_MPU_RLAR_ATTRIDX_NOCACHE);

    /* Region 2: secure RAM RW-NX (.data/.bss/MSP_S + coroutine stacks). */
    wt_mpu_s_set_region(2u,
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
        WT_BOOT_HANDOFF_ADDRESS,
#else
        WT_RAM_S_BASE,
#endif
        WT_RAM_S_BASE + WT_RAM_S_SIZE - 1u,
        WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
        WT_MPU_RLAR_ATTRIDX_NORMAL);

    /* Region 3: NS RAM RW-NX. Secure code touches this through the
     * 0x20000000 alias to exchange HSM transport buffers with guests
     * and to write fault-response CSRs. */
    wt_mpu_s_set_region(3u,
        WT_RAM_NS_BASE, WT_RAM_NS_BASE + 0x0001FFFFu,
        WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW | WT_MPU_RBAR_SH_INNER,
        WT_MPU_RLAR_ATTRIDX_NORMAL);

    /* Region 4: NS flash R (so secure side can read guest image
     * metadata if needed — current code does not, but the SAU window
     * exists and we keep it consistent). XN to prevent stray Secure
     * execution into NS code. */
    wt_mpu_s_set_region(4u,
        WT_FLASH_NS_BASE, WT_FLASH_NS_BASE + 0x001FFFFFu,
        WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
        WT_MPU_RLAR_ATTRIDX_NORMAL);

    /* Region 5: SoC peripheral aperture (RCC, GTZC, GPIO, USART, FLASH
     * controller, RNG, etc.) — both the 0x40000000 NS alias and the
     * 0x50000000 secure alias fall in one 256 MiB block. */
    wt_mpu_s_set_region(5u,
        0x40000000u, 0x5FFFFFFFu,
        WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW,
        WT_MPU_RLAR_ATTRIDX_DEVICE);

    /* Region 6: Cortex private peripheral bus (SCB, NVIC, SAU, MPU,
     * SysTick — everything in the 0xE0000000..0xE00FFFFF window). */
    wt_mpu_s_set_region(6u,
        0xE0000000u, 0xE00FFFFFu,
        WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RW,
        WT_MPU_RLAR_ATTRIDX_DEVICE);

    /* Region 7: Secure alias of guest flash images.
     * RO-XN — the Secure side only reads guest reset vectors and metadata
     * from here; never executes guest code in Secure state. The 0x08...
     * NS alias is reachable too (region 4), but on at least one emulator
     * the Secure-side read of that NS alias returns zero, so we keep this
     * Secure alias window for reliable access. */
    wt_mpu_s_set_region(7u,
        WT_FLASH_TO_S_ALIAS(WT_GUEST0_FLASH_BASE),
        WT_FLASH_TO_S_ALIAS(WT_GUEST1_FLASH_BASE + WT_GUEST1_FLASH_SIZE - 1u),
        WT_MPU_RBAR_XN | WT_MPU_RBAR_AP_RO | WT_MPU_RBAR_SH_INNER,
        WT_MPU_RLAR_ATTRIDX_NORMAL);

    /* Silicon implements TYPE.DREGION secure regions (12 on STM32H563, more
     * than WT_MAX_MEMORY_REGIONS); their reset state is UNKNOWN per PMSAv8, so
     * explicitly disable every region beyond the whitelist. */
    for (rnr = WT_MAX_MEMORY_REGIONS; rnr < dregion; rnr++) {
        WT_MPU_S_RNR  = rnr;
        WT_MPU_S_RBAR = 0u;
        WT_MPU_S_RLAR = 0u;
    }

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
    uint32_t rnr;
    uint32_t dregion = (WT_MPU_S_TYPE >> 8) & 0xFFu;

    WT_MPU_S_CTRL = 0u;
    wt_dsb();

    WT_MPU_S_MAIR0 = WT_MPU_MAIR0_NORMAL_AT_0 |
                     WT_MPU_MAIR0_DEVICE_AT_1 |
                     WT_MPU_MAIR0_NOCACHE_AT_2;
    WT_MPU_S_MAIR1 = 0u;

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
    for (rnr = WT_MAX_MEMORY_REGIONS; rnr < dregion; rnr++) {
        WT_MPU_S_RNR  = rnr;
        WT_MPU_S_RBAR = 0u;
        WT_MPU_S_RLAR = 0u;
    }

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
    wt_mpu_s_init();
}

static void wt_clock_init(void)
{
    uint32_t reg;

    /* Do not inherit wolfBoot's clock (250 MHz, APB1 undivided): re-establish the
     * 240 MHz APB1/2 tree the stock nucleo_h563zi NS guest was built for, else
     * its USART3 baud is ~2x off on real silicon. */

    reg = WT_PWR_VOSCR & ~WT_PWR_VOSCR_VOS_MASK;
    WT_PWR_VOSCR = reg | WT_PWR_VOSCR_SCALE0;
    while ((WT_PWR_VOSSR & WT_PWR_VOSSR_VOSRDY) == 0u) {
    }

    reg = WT_FLASH_ACR & ~(WT_FLASH_ACR_LATENCY_MASK |
                           WT_FLASH_ACR_WRHIGHFREQ_MASK);
    WT_FLASH_ACR = reg | WT_FLASH_LATENCY_5WS | WT_FLASH_WRHIGHFREQ_2;
    while ((WT_FLASH_ACR & (WT_FLASH_ACR_LATENCY_MASK |
                            WT_FLASH_ACR_WRHIGHFREQ_MASK)) !=
           (WT_FLASH_LATENCY_5WS | WT_FLASH_WRHIGHFREQ_2)) {
    }

    WT_RCC_CFGR1 = (WT_RCC_CFGR1 & ~WT_RCC_CFGR1_SW_MASK) |
                   WT_RCC_CFGR1_SW_HSI;
    while (((WT_RCC_CFGR1 >> WT_RCC_CFGR1_SWS_SHIFT) &
            WT_RCC_CFGR1_SW_MASK) != WT_RCC_CFGR1_SW_HSI) {
    }

    WT_RCC_CR &= ~WT_RCC_CR_PLL1ON;
    while ((WT_RCC_CR & WT_RCC_CR_PLL1RDY) != 0u) {
    }

    WT_RCC_CR = (WT_RCC_CR | WT_RCC_CR_HSION | WT_RCC_CR_HSEON |
                 WT_RCC_CR_HSEBYP) & ~WT_RCC_CR_HSIDIV_MASK;
    while ((WT_RCC_CR & WT_RCC_CR_HSIRDY) == 0u) {
    }
    while ((WT_RCC_CR & WT_RCC_CR_HSERDY) == 0u) {
    }
    WT_RCC_CR |= WT_RCC_CR_HSI48ON;
    while ((WT_RCC_CR & WT_RCC_CR_HSI48RDY) == 0u) {
    }

    /* NUCLEO-H563ZI HSE is the 8 MHz ST-LINK MCO. PLL1: 8 / 2 * 120 / 2
     * gives a 240 MHz core clock. APB1/APB3 are kept at 120 MHz. */
    WT_RCC_PLL1CFGR = WT_RCC_PLL1CFGR_SRC_HSE |
                      WT_RCC_PLL1CFGR_RGE_4_8 |
                      WT_RCC_PLL1CFGR_VCO_WIDE |
                      (2u << WT_RCC_PLL1CFGR_M_SHIFT);
    WT_RCC_PLL1DIVR = ((120u - 1u) << WT_RCC_PLL1DIVR_N_SHIFT) |
                      ((2u - 1u) << WT_RCC_PLL1DIVR_P_SHIFT) |
                      ((4u - 1u) << WT_RCC_PLL1DIVR_Q_SHIFT) |
                      ((2u - 1u) << WT_RCC_PLL1DIVR_R_SHIFT);
    WT_RCC_PLL1FRACR = 0u;
    WT_RCC_PLL1CFGR |= WT_RCC_PLL1CFGR_PEN |
                       WT_RCC_PLL1CFGR_QEN |
                       WT_RCC_PLL1CFGR_REN;

    WT_RCC_CFGR2 = (WT_RCC_AHB_DIV_NONE << WT_RCC_CFGR2_HPRE_SHIFT) |
                   (WT_RCC_APB_DIV_2 << WT_RCC_CFGR2_PPRE1_SHIFT) |
                   (WT_RCC_APB_DIV_NONE << WT_RCC_CFGR2_PPRE2_SHIFT) |
                   (WT_RCC_APB_DIV_2 << WT_RCC_CFGR2_PPRE3_SHIFT);

    WT_RCC_CR |= WT_RCC_CR_PLL1ON;
    while ((WT_RCC_CR & WT_RCC_CR_PLL1RDY) == 0u) {
    }

    WT_RCC_CFGR1 = (WT_RCC_CFGR1 & ~WT_RCC_CFGR1_SW_MASK) |
                   WT_RCC_CFGR1_SW_PLL1;
    while (((WT_RCC_CFGR1 >> WT_RCC_CFGR1_SWS_SHIFT) &
            WT_RCC_CFGR1_SW_MASK) != WT_RCC_CFGR1_SW_PLL1) {
    }

    /* USART2/USART3 kernel clock source 0 is PCLK1. */
    WT_RCC_CCIPR1 &= ~((WT_RCC_CCIPR_USARTSEL_MASK <<
                        WT_RCC_CCIPR1_USART2SEL_SHIFT) |
                       (WT_RCC_CCIPR_USARTSEL_MASK <<
                        WT_RCC_CCIPR1_USART3SEL_SHIFT));
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

static void wt_configure_uart_gpio_pin(uintptr_t gpio_base, uint32_t pin,
                                       uint32_t af)
{
    volatile uint32_t* afr;
    uint32_t shift;

    WT_GPIO_MODER(gpio_base) =
        (WT_GPIO_MODER(gpio_base) & ~(0x3u << (pin * 2u))) |
        (0x2u << (pin * 2u));
    WT_GPIO_OTYPER(gpio_base) &= ~(1u << pin);
    WT_GPIO_OSPEEDR(gpio_base) |= (0x3u << (pin * 2u));
    WT_GPIO_PUPDR(gpio_base) =
        (WT_GPIO_PUPDR(gpio_base) & ~(0x3u << (pin * 2u))) |
        (0x1u << (pin * 2u));
    WT_GPIO_SECCFGR(gpio_base) &= ~(1u << pin);

    if (pin < 8u) {
        afr = &WT_GPIO_AFRL(gpio_base);
        shift = pin * 4u;
    } else {
        afr = &WT_GPIO_AFRH(gpio_base);
        shift = (pin - 8u) * 4u;
    }

    *afr = (*afr & ~(0xFu << shift)) | ((af & 0xFu) << shift);
}

static void wt_uart_gpio_init(void)
{
    static const whal_Stm32h5_Rcc_PeriphClk gpio_clocks[] = {
        {WHAL_STM32H563_GPIOA_CLOCK},
        {WHAL_STM32H563_GPIOD_CLOCK},
    };

    for (size_t i = 0u; i < sizeof(gpio_clocks) / sizeof(gpio_clocks[0]); ++i) {
        wt_rcc_enable_clock(WT_RCC_BASE_S, &gpio_clocks[i]);
    }
    (void)WT_RCC_AHB2ENR;
    WT_PWR_CR2 |= WT_PWR_CR2_IOSV;

    /* USART2 on PA2/PA3, USART3 VCP on PD8/PD9. */
    wt_configure_uart_gpio_pin(WT_GPIOA_BASE_S, 2u, 7u);
    wt_configure_uart_gpio_pin(WT_GPIOA_BASE_S, 3u, 7u);
    wt_configure_uart_gpio_pin(WT_GPIOD_BASE_S, 8u, 7u);
    wt_configure_uart_gpio_pin(WT_GPIOD_BASE_S, 9u, 7u);
}

void wt_platform_init(void)
{
    static const whal_Stm32h5_Rcc_PeriphClk uart_clocks[] = {
        {WHAL_STM32H563_USART2_CLOCK},
        {WHAL_STM32H563_USART3_CLOCK},
    };
    static const whal_Stm32h5_Rcc_PeriphClk rng_clock =
        {WHAL_STM32H563_RNG_CLOCK};

    wt_clock_init();
    /* Arm the FF-M NS-window checks before any NS guest can reach the
     * WolfTrust_FFM_* veneers; the core fails closed until this runs. */
    wt_ffm_nsc_install();
    /* The signed wolfBoot handoff reserves the manifest header at the slot
     * base; the Secure vector table begins at the image base after it. */
    WT_SCB_VTOR_S = WT_FLASH_IMAGE_BASE;
    wt_gtzc_init();
    wt_sau_init();
    wt_mpu_s_init();
    wt_arch_init();
    /* Enable USART2/USART3 clocks in both security views before guests run. */
    for (size_t i = 0u; i < sizeof(uart_clocks) / sizeof(uart_clocks[0]); ++i) {
        wt_rcc_enable_clock(WT_RCC_BASE_S, &uart_clocks[i]);
        wt_rcc_enable_clock(WT_RCC_BASE_NS, &uart_clocks[i]);
    }
    wt_rcc_enable_clock(WT_RCC_BASE_S, &rng_clock);
    wt_uart_gpio_init();
    wt_arch_zero_guest_memory(WT_GUEST0_RAM_BASE, WT_GUEST_RAM_SIZE);
    wt_arch_zero_guest_memory(WT_GUEST1_RAM_BASE, WT_GUEST_RAM_SIZE);
    g_secure_service_depth = 0u;
    g_hsm_wait_skip_count = 0u;
}

/* GTZC curtain (cross-guest isolation): NS guest kernels run privileged, so
 * the per-guest NS MPU alone cannot stop a hostile guest from reprogramming
 * MPU_NS and reaching the peer's RAM. Every dispatch closes the whole shared
 * guest RAM extent at the fabric (blocks marked Secure reject Non-secure
 * transactions regardless of privilege) and reopens only the arriving
 * guest's declared writable windows. */
void wt_platform_program_memory_windows(const wt_memory_window_t* windows,
                                        size_t count)
{
    uintptr_t extent_end = WT_GUEST1_RAM_BASE + WT_GUEST_RAM_SIZE;
    size_t nsWords = (extent_end - WT_RAM_NS_BASE) / (512u * 32u);
    size_t i;
    size_t w;

    for (i = 0; i < nsWords && i < 16u; ++i) {
        WT_GTZC1_MPCBB1_SECCFGR[i] = 0xFFFFFFFFu;
    }
    for (w = 0; windows != NULL && w < count; ++w) {
        uintptr_t base = windows[w].base;
        uintptr_t end = base + windows[w].size;
        size_t block;
        size_t first;
        size_t last;

        if ((windows[w].attributes & WT_MEM_ATTR_WRITE) == 0u ||
                base < WT_RAM_NS_BASE || end > extent_end || end <= base) {
            continue;
        }
        first = (base - WT_RAM_NS_BASE) / 512u;
        last = (end - WT_RAM_NS_BASE + 511u) / 512u;
        for (block = first; block < last; ++block) {
            WT_GTZC1_MPCBB1_SECCFGR[block / 32u] &=
                ~(1u << (block % 32u));
        }
    }
    wt_dsb();
    wt_isb();
}

void wt_arch_program_guest_domain(const wt_memory_region_t* regions, size_t count)
{
    wt_program_ns_mpu_regions(regions, count);
}

void wt_platform_log_fault(wt_guest_id_t guest_id,
                           wt_fault_reason_t reason,
                           uintptr_t fault_address,
                           uintptr_t pc)
{
    (void)guest_id;
    (void)reason;
    wt_armv8m_note_fault(fault_address, pc);
}

void wt_platform_all_guests_faulted(void)
{
    __asm volatile("bkpt #0x7D");
    for (;;) {
        __asm volatile("wfi");
    }
}

void wt_platform_panic(void)
{
    __asm volatile("bkpt #0x7E");
    for (;;) {
    }
}

#ifdef WT_LAUNCH_DEBUG
/* Temporary launch-verify triage: one distinct BKPT per failure reason so the
 * emulator log names the guest and error. Never built into production. */
void wt_platform_launch_debug(int code, uint32_t guest)
{
    unsigned int index = (unsigned int)(-700 - code);

    if (index > 5u) {
        index = 6u;
    }
    switch (index + (guest * 8u)) {
        case 0u:  __asm volatile("bkpt #0x50"); break;
        case 1u:  __asm volatile("bkpt #0x51"); break;
        case 2u:  __asm volatile("bkpt #0x52"); break;
        case 3u:  __asm volatile("bkpt #0x53"); break;
        case 4u:  __asm volatile("bkpt #0x54"); break;
        case 5u:  __asm volatile("bkpt #0x55"); break;
        case 8u:  __asm volatile("bkpt #0x58"); break;
        case 9u:  __asm volatile("bkpt #0x59"); break;
        case 10u: __asm volatile("bkpt #0x5A"); break;
        case 11u: __asm volatile("bkpt #0x5B"); break;
        case 12u: __asm volatile("bkpt #0x5C"); break;
        case 13u: __asm volatile("bkpt #0x5D"); break;
        default:  __asm volatile("bkpt #0x5F"); break;
    }
}
#endif

void wt_platform_system_reset(void)
{
    uint32_t spins = 0u;

    /* A flash program issued just before this reset - the conformance boot
     * flag val resumes from, an anti-rollback arming store - must physically
     * land before SYSRESETREQ, or the reset can cut it short and the value is
     * lost (on silicon the panic test then re-runs into a reboot loop; the
     * emulator programs flash instantly and never sees it). Wait for the flash
     * controller to go idle, bounded so a wedged controller still resets. */
    while ((WT_FLASH_SR & (WT_FLASH_SR_BSY | WT_FLASH_SR_DBNE)) != 0u &&
            spins < 0x00200000u) {
        spins++;
    }
    wt_dsb();
    WT_SCB_AIRCR_S = WT_SCB_AIRCR_SYSRESETREQ;
    wt_dsb();
    for (;;) {
    }
}

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* PAL interrupt source (P4.2c): LPUART1 with TXEIE raises its NVIC line as
 * soon as the transmitter is enabled (TXE idles high), giving the DRIVER
 * partition a real peripheral interrupt to receive and acknowledge. */
void wt_conf_uart_irq_set(int on)
{
    if (on != 0) {
        WT_LPUART1_CR1 |= WT_LPUART1_CR1_UE | WT_LPUART1_CR1_TE |
                          WT_LPUART1_CR1_TXEIE;
    } else {
        WT_LPUART1_CR1 &= ~WT_LPUART1_CR1_TXEIE;
        wt_arch_secure_irq_disable(WT_LPUART1_IRQ);
    }
}

void LPUART1_IRQHandler(void)
{
    wt_spm_conf_irq(WT_LPUART1_IRQ);
}
#endif

#if defined(WT_REMEASURE_PROBE)
/* P6-S5: prove on-demand runtime re-measurement (WT-FFM-0052) on target. After
 * boot init and launch verification, an untampered re-measure of guest0 must
 * pass; a post-launch in-flash tamper (the secure MPU maps flash
 * privileged-RO, so it is dropped for the single program) must then be caught
 * and quarantine the guest. bkpt #0x6C fires only when both are correct. */
extern int wt_hsm_flash_remeasure_tamper(uintptr_t secure_base);

static void wt_platform_remeasure_probe(void)
{
    const wt_guest_config_t *configs;
    size_t cfg_count;
    const wt_memory_window_t *window = NULL;
    uint32_t mpu_ctrl;
    size_t i;
    int r1;
    int r2;

    configs = wt_partitions_config_table(&cfg_count);
    if (configs != NULL && cfg_count > 0u) {
        for (i = 0u; i < configs[0].memory_window_count; i++) {
            if ((configs[0].memory_windows[i].attributes &
                    WT_MEM_ATTR_EXEC) != 0u) {
                window = &configs[0].memory_windows[i];
                break;
            }
        }
    }
    if (window != NULL) {
        r1 = wt_runtime_verify_guest(0u);
        mpu_ctrl = WT_MPU_S_CTRL;
        WT_MPU_S_CTRL = 0u;
        wt_dsb();
        wt_isb();
        (void)wt_hsm_flash_remeasure_tamper(WT_FLASH_TO_S_ALIAS(window->base));
        WT_MPU_S_CTRL = mpu_ctrl;
        wt_dsb();
        wt_isb();
        r2 = wt_runtime_verify_guest(0u);
        /* WT_GUEST_VERIFY_OK == 0: a pass then a fail-closed is the only
         * correct outcome. */
        if (r1 == 0 && r2 != 0) {
            __asm volatile("bkpt #0x6C");
        }
    }
    for (;;) {
        __asm volatile("wfi");
    }
}
#endif

#if defined(WT_BOOTUPDATE_PROBE)
/* P6-S6: full boot-and-update gate. On the pre-update image (version 1) arm
 * wolfBoot's real update trigger for the v2 candidate pre-staged in the UPDATE
 * partition, then reboot so wolfBoot swaps it in; the swapped-in v2 (version 2)
 * skips the arm, so the swap terminates instead of looping. The secure MPU
 * maps flash privileged-RO, so it is dropped for the single trailer program
 * (as in the S5 re-measure probe). */
#include "wolftrust/services/fwu_service.h"
extern const wt_fwu_backend_t wt_fwu_flash_backend;

static void wt_platform_bootupdate_probe(uint32_t running_version)
{
    uint32_t mpu_ctrl;
    int armed = -1;

    if (running_version != 1u) {
        return;
    }
    if (wt_fwu_flash_backend.begin != NULL &&
            wt_fwu_flash_backend.begin(NULL) == 0 &&
            wt_fwu_flash_backend.arm != NULL) {
        mpu_ctrl = WT_MPU_S_CTRL;
        WT_MPU_S_CTRL = 0u;
        wt_dsb();
        wt_isb();
        armed = wt_fwu_flash_backend.arm(NULL, 0u, 2u);
        WT_MPU_S_CTRL = mpu_ctrl;
        wt_dsb();
        wt_isb();
    }
    if (armed == 0) {
        wt_platform_system_reset();
    }
    /* Arm failed: fall through to a normal boot so the miss is observable
     * (the token's v2 measurement will be absent) instead of a reboot loop. */
}
#endif

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
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    wt_boot_handoff_t bootHandoff;
    int handoffRet;
#endif

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

    wt_monitor_init();
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    handoffRet = wt_boot_handoff_consume(&bootHandoff);
    wt_clear_boot_handoff_scratch();
#endif
#ifdef WT_ENGINE_HSM
    /* Bring up the secure-side wolfHSM service before dispatching guests:
     *  1. tasklet scheduler (provides the bootstrap context)
     *  2. shared wolfCrypt + NVM + lock
     *  3. one transport + server context + tasklet per guest
     * Any failure here is fatal because guests require this engine. */
    wt_tasklet_init();
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    /* Gate vault auto-reformat on the wolfBoot-reported lifecycle before the
     * store comes up: only unlocked development states permit a foreign-pool
     * wipe (see wt_hsm_set_boot_lifecycle). */
    if (handoffRet == 0) {
        wt_hsm_set_boot_lifecycle(bootHandoff.lifecycle);
    }
#endif
    if (wt_hsm_init() != 0) wt_platform_panic();
    /* WT-FFM-0050: the vault NVM is live and no guest has dispatched, so the
     * monotonic version floors gate every domain now. A missing handoff
     * reports version zero, which fails closed once a floor is armed. */
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    (void)wt_hsm_rollback_enforce((handoffRet == 0) ?
                                  bootHandoff.image_version : 0u);
#else
    (void)wt_hsm_rollback_enforce(0u);
#endif
    /* WT-FFM-0054: every guest server binds the secure relay capture
     * transport — packets arrive only through SERVICE_HSM's mediated
     * psa_call path, never a shared NS-RAM window. */
    for (wt_guest_id_t gid = 0u; gid < WT_MAX_GUESTS; gid++) {
        const wt_guest_config_t *configs;
        size_t cfg_count;
        configs = wt_partitions_config_table(&cfg_count);
        if (configs == NULL || gid >= cfg_count) break;
        if (wt_hsm_guest_init_relay(gid) != 0) {
            wt_platform_panic();
        }
    }
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    if (wt_hsm_attest_bootstrap() != WH_ERROR_OK) {
        /* The vault could not be provisioned and auto-reformat was not
         * permitted (a foreign or corrupt pool on a SECURED device). Boot
         * degraded rather than dead-trap: attestation fails closed and the
         * condition is observable, never a mute HardFault. */
        g_wt_attest_degraded = 1u;
    }
#endif
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    if (handoffRet == 0) {
        if (wt_initial_attest_init(&bootHandoff) != WT_ATTEST_SUCCESS) {
            /* Attestation could not initialize (e.g. the IAK was unavailable on
             * a fail-closed vault). Degrade rather than dead-trap: the service
             * returns errors, the rest of the system boots. */
            g_wt_attest_degraded = 1u;
        }
    }
#endif
    if (handoffRet == 0) {
        wt_ffm_set_lifecycle(wt_ffm_boot_runtime_mut(), bootHandoff.lifecycle);
    }
    /* P1t: crypto SP becomes a scheduled unprivileged coroutine now that
     * the tasklet scheduler exists. Fail closed — guests depend on it. */
    if (wt_ffm_boot_start_sched() != WT_FFM_SUCCESS) {
        wt_platform_panic();
    }
#endif
#if defined(WT_REMEASURE_PROBE)
    wt_platform_remeasure_probe();
#endif
#if defined(WT_BOOTUPDATE_PROBE)
#if defined(WT_ATTEST_COSE) && (WT_ATTEST_COSE == 1)
    wt_platform_bootupdate_probe((handoffRet == 0) ?
                                 bootHandoff.image_version : 0u);
#else
    wt_platform_bootupdate_probe(0u);
#endif
#endif
    wt_monitor_start();
    wt_platform_panic();
}

#ifdef WT_ENGINE_HSM

static void wt_secure_service_enter(void)
{
    g_secure_service_depth++;
}

static void wt_secure_service_exit(void)
{
    if (g_secure_service_depth == 0u) {
        wt_platform_panic();
    }
    g_secure_service_depth--;
}

bool wt_platform_secure_service_active(void)
{
    return g_secure_service_depth != 0u;
}

void wt_platform_note_hsm_wait_skip(wt_guest_id_t guest_id)
{
    (void)guest_id;
    g_hsm_wait_skip_count++;
}

#endif /* WT_ENGINE_HSM */
