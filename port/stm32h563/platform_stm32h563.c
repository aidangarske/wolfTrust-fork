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
#include "wolftrust/guest_verify.h"
#include "wolftrust/monitor.h"
#include "wolftrust/arch/armv8m/context.h"

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

typedef struct wt_exception_frame {
    uint32_t r0;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint32_t r12;
    uintptr_t lr;
    uintptr_t pc;
    uint32_t xpsr;
} wt_exception_frame_t;

#define WT_ASM_STR2(x) #x
#define WT_ASM_STR(x) WT_ASM_STR2(x)

#define WT_GUEST_CONTEXT_PSP_NS_OFFSET     32U
#define WT_GUEST_CONTEXT_MSP_NS_OFFSET     36U
#define WT_GUEST_CONTEXT_CONTROL_NS_OFFSET 44U
#define WT_GUEST_CONTEXT_EXC_RETURN_OFFSET 48U
#define WT_GUEST_CONTEXT_PSPLIM_NS_OFFSET  68U
#define WT_EXC_RETURN_MODE_THREAD          0x08u
#define WT_EXC_RETURN_RETURN_TO_NONSECURE  0x00u
#define WT_EXC_RETURN_SECURITY_MASK        0x40u
#define WT_EXC_RETURN_SPSEL_PSP            0x04u

_Static_assert(WT_GUEST_CONTEXT_PSP_NS_OFFSET == 32U, "unexpected psp_ns offset");
_Static_assert(WT_GUEST_CONTEXT_MSP_NS_OFFSET == 36U, "unexpected msp_ns offset");
_Static_assert(WT_GUEST_CONTEXT_CONTROL_NS_OFFSET == 44U, "unexpected control_ns offset");
_Static_assert(WT_GUEST_CONTEXT_EXC_RETURN_OFFSET == 48U, "unexpected exc_return offset");
_Static_assert(WT_GUEST_CONTEXT_PSP_NS_OFFSET == offsetof(wt_guest_context_t, psp_ns),
               "wt_guest_context_t layout changed");
_Static_assert(WT_GUEST_CONTEXT_MSP_NS_OFFSET == offsetof(wt_guest_context_t, msp_ns),
               "wt_guest_context_t layout changed");
_Static_assert(WT_GUEST_CONTEXT_CONTROL_NS_OFFSET == offsetof(wt_guest_context_t, control_ns),
               "wt_guest_context_t layout changed");
_Static_assert(WT_GUEST_CONTEXT_EXC_RETURN_OFFSET == offsetof(wt_guest_context_t, exc_return),
               "wt_guest_context_t layout changed");
_Static_assert(WT_GUEST_CONTEXT_PSPLIM_NS_OFFSET == offsetof(wt_guest_context_t, psplim_ns),
               "wt_guest_context_t layout changed");

/* Referenced by inline asm in SysTick_Handler; mark used so -Os does
 * not DCE them since the C code only touches them by name in __asm. */
static wt_guest_context_t g_return_context __attribute__((used));
static uint32_t g_live_r4_r11[8] __attribute__((used));
static uintptr_t g_live_exc_return __attribute__((used));
static uint32_t g_systick_reload;
static uint64_t g_secure_wall_cycles;
static uintptr_t g_secure_entry_sp __attribute__((used));
static volatile uint32_t g_last_fault_address;
static volatile uint32_t g_last_fault_pc;
static volatile uint32_t g_switch_count;
static volatile uint32_t g_active_guest;
static volatile uint32_t g_secure_service_depth;
static volatile uint32_t g_hsm_wait_skip_count;
static volatile uint32_t g_tasklet_fault_count;
static volatile uint32_t g_wt_attest_degraded __attribute__((used));
static volatile uint32_t g_tasklet_fault_cfsr;
static volatile uint32_t g_tasklet_fault_pc;
static volatile uint32_t g_tasklet_fault_exc_return;
static volatile uint32_t g_tasklet_fault_frame;
static volatile uint32_t g_tasklet_fault_xpsr;
static volatile uint32_t g_tasklet_fault_psp;
static volatile uint32_t g_tasklet_fault_icsr;
static volatile uint32_t g_tasklet_fault_co;
static volatile uint32_t g_tasklet_fault_co_sp;
static void (*g_secure_thread_resume_entry)(void) __attribute__((noreturn));

typedef struct wt_virtual_systick {
    uint32_t csr;
    uint32_t rvr;
    uint32_t cvr;
    uint64_t last_accounted_cycles;
    uint32_t owed_ticks;
    uint8_t pending;
    uint32_t accrued_ticks;
    uint32_t injected_ticks;
    uint32_t coalesced_ticks;
    uint32_t max_owed_ticks;
} wt_virtual_systick_t;

static wt_virtual_systick_t g_guest_systick[WT_MAX_GUESTS];
/* Deferred SysTick arm for the arriving guest: arming/injecting before the
 * NS bank is restored lets the tick preempt the dispatch window and stack
 * through the new VTOR_NS onto the departing guest's MSP_NS. */
static volatile uint32_t g_arriving_systick_csr;
static volatile uint32_t g_arriving_systick_inject;

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

void wt_platform_program_secure_partition_domain(
    const wt_memory_region_t* regions, size_t count)
{
    wt_program_sp_domain_regions(regions, count,
                                 WT_MPU_CTRL_HFNMIENA | WT_MPU_CTRL_ENABLE);
}

void wt_platform_program_sp_thread_domain(const wt_memory_region_t* regions,
                                          size_t count)
{
    /* PRIVDEFENA: the unprivileged SP thread is confined to the mapped
     * regions while the privileged SVC/PendSV/fault handlers keep the
     * default map, so psa_* requests can reach SPM state (WT-FFM-0011). */
    wt_program_sp_domain_regions(regions, count,
                                 WT_MPU_CTRL_PRIVDEFENA |
                                 WT_MPU_CTRL_HFNMIENA | WT_MPU_CTRL_ENABLE);
}

void wt_platform_restore_spm_domain(void)
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

static uint32_t wt_read_psp_ns(void)
{
    uint32_t value;
    __asm volatile("mrs %0, psp_ns" : "=r"(value));
    return value;
}

static uint32_t wt_read_control_ns(void)
{
    uint32_t value;
    __asm volatile("mrs %0, control_ns" : "=r"(value));
    return value;
}

static uint32_t wt_read_ipsr(void)
{
    uint32_t value;
    __asm volatile("mrs %0, ipsr" : "=r"(value));
    return value;
}

__attribute__((noreturn, used))
void wt_secure_thread_resume_trampoline(void)
{
    void (*entry)(void) __attribute__((noreturn)) = g_secure_thread_resume_entry;

    if (entry == NULL) {
        wt_platform_panic();
    }

    entry();
    wt_platform_panic();
    __builtin_unreachable();
}

bool wt_platform_in_handler_mode(void)
{
    return wt_read_ipsr() != 0u;
}

bool wt_platform_ns_thread_mode_trap(void)
{
    return (g_live_exc_return &
            (WT_EXC_RETURN_MODE_THREAD | WT_EXC_RETURN_SECURITY_MASK)) ==
           (WT_EXC_RETURN_MODE_THREAD | WT_EXC_RETURN_RETURN_TO_NONSECURE);
}

bool wt_platform_secure_psp_thread_trap(void)
{
    /* True only when the tick landed on a Secure Thread running on PSP —
     * i.e. a coroutine is physically executing, not merely named current
     * inside the bootstrap's do_switch/arch_enter window. Gates the HSM
     * tasklet preempt so an async SysTick cannot corrupt a mid-switch frame. */
    return (g_live_exc_return &
            (WT_EXC_RETURN_MODE_THREAD | WT_EXC_RETURN_SPSEL_PSP |
             WT_EXC_RETURN_SECURITY_MASK)) ==
           (WT_EXC_RETURN_MODE_THREAD | WT_EXC_RETURN_SPSEL_PSP |
            WT_EXC_RETURN_SECURITY_MASK);
}

void wt_platform_return_to_secure_thread(
    void (*entry)(void) __attribute__((noreturn)))
{
    if (entry == NULL || wt_read_ipsr() == 0u) {
        wt_platform_panic();
    }

    g_secure_thread_resume_entry = entry;

    __asm volatile(
        "sub    sp, sp, #32                  \n"
        "movs   r1, #0                       \n"
        "str    r1, [sp, #0]                 \n"
        "str    r1, [sp, #4]                 \n"
        "str    r1, [sp, #8]                 \n"
        "str    r1, [sp, #12]                \n"
        "str    r1, [sp, #16]                \n"
        "str    r1, [sp, #20]                \n"
        "movw   r1, #:lower16:wt_secure_thread_resume_trampoline \n"
        "movt   r1, #:upper16:wt_secure_thread_resume_trampoline \n"
        "str    r1, [sp, #24]                \n"
        "movw   r1, #0x0000                  \n"
        "movt   r1, #0x0100                  \n"
        "str    r1, [sp, #28]                \n"
        "mvn    lr, #6                       \n"
        "bx     lr                           \n"
        :
        : "r"(entry)
        : "memory", "r1");

    __builtin_unreachable();
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

static void wt_exception_return_ns_msp(void) __attribute__((naked, noreturn));

static void wt_exception_return_ns_msp(void)
{
    __asm volatile(
        "ldr r2, =g_secure_entry_sp     \n"
        "ldr r2, [r2]                   \n"
        "mov sp, r2                     \n"
        "ldr r0, =g_return_context      \n"
        "ldr r1, [r0, #" WT_ASM_STR(WT_GUEST_CONTEXT_PSP_NS_OFFSET) "] \n"
        "msr psp_ns, r1                 \n"
        "ldr r1, [r0, #" WT_ASM_STR(WT_GUEST_CONTEXT_MSP_NS_OFFSET) "] \n"
        "msr msp_ns, r1                 \n"
        "ldr r1, [r0, #" WT_ASM_STR(WT_GUEST_CONTEXT_PSPLIM_NS_OFFSET) "] \n"
        "msr psplim_ns, r1              \n"
        /* MSP_NS is the exception stack shared with the secure transition;
         * keep its limit disabled until the port has a dedicated exception
         * stack. Restoring an RTOS task limit here can block the next secure
         * timer frame before the scheduler can switch guests. */
        "mov r1, #0                     \n"
        "msr msplim_ns, r1              \n"
        "ldr r1, [r0, #" WT_ASM_STR(WT_GUEST_CONTEXT_CONTROL_NS_OFFSET) "] \n"
        "msr control_ns, r1             \n"
        /* NS bank is now consistent: arm/inject the guest's SysTick here,
         * never earlier in the dispatch window. */
        "bl wt_virtual_systick_arm_arriving \n"
        "ldr r0, =g_return_context      \n"
        "ldmia r0, {r4-r11}             \n"
        "ldr lr, [r0, #" WT_ASM_STR(WT_GUEST_CONTEXT_EXC_RETURN_OFFSET) "] \n"
        "bx lr                          \n"
    );
}

__attribute__((naked, noreturn))
void wt_platform_svc_guest_return(void)
{
    __asm volatile(
        "mrs r2, msp                    \n"
        "ldr r1, =g_secure_entry_sp    \n"
        "str r2, [r1]                  \n"
        "b wt_exception_return_ns_msp  \n"
    );
}

static void wt_jump_to_ns(uint32_t msp_ns, uint32_t reset_addr)
    __attribute__((naked, noreturn));

static void wt_jump_to_ns(uint32_t msp_ns __attribute__((unused)),
                          uint32_t reset_addr __attribute__((unused)))
{
    __asm volatile(
        "msr msp_ns, r0     \n"
        "bics r1, r1, #1    \n"
        "mov r4, r1         \n"
        "movs r2, #0        \n"
        "msr control_ns, r2 \n"
        /* See wt_exception_return_ns_msp — clear PSPLIM_NS / MSPLIM_NS
         * before the first BXNS so a guest that programs them later
         * doesn't inherit a stale value from the previous guest. */
        "msr psplim_ns, r2  \n"
        "msr msplim_ns, r2  \n"
        "bl wt_virtual_systick_arm_arriving \n"
        "isb 0xF            \n"
        "bxns r4            \n"
    );
}

static void wt_secure_systick_dispatch(const wt_trap_frame_t* frame)
    __attribute__((used));
static void wt_secure_fault_dispatch(const wt_trap_frame_t* frame)
    __attribute__((noreturn, used));

static void wt_secure_systick_dispatch(const wt_trap_frame_t* frame)
{
    g_secure_wall_cycles += g_systick_reload;
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    wt_spm_sched_hang_probe();
#endif
    wt_monitor_on_secure_timer(frame);
}

static void wt_secure_fault_dispatch(const wt_trap_frame_t* frame)
{
    g_last_fault_address = WT_SAU_SFAR;
    wt_monitor_on_guest_fault(frame, WT_FAULT_SECURE_ESCALATION);
    wt_platform_panic();
    __builtin_unreachable();
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
    /* Route MemManage and UsageFault to their own handlers (otherwise
     * they escalate to HardFault and we lose the fault-status registers
     * by the time we get the trap). STKOF on PSPLIM_S overflow surfaces
     * as a UsageFault. */
    WT_SCB_SHCSR_S |= WT_SCB_SHCSR_MEMFAULTENA | WT_SCB_SHCSR_USGFAULTENA;
    /* Reset authority belongs to the Secure world. With SYSRESETREQS set, a
     * Non-secure SYSRESETREQ (e.g. a guest RTOS calling sys_reboot on a fault)
     * no longer resets the SoC — only Secure code can. This is the correct
     * Secure-Manager policy and stops a rogue NS reboot from tearing the whole
     * system down. Read-modify-write with VECTKEY, preserving the TrustZone
     * config bits (PRIS/BFHFNMINS/PRIGROUP). */
    WT_SCB_AIRCR_S = WT_SCB_AIRCR_VECTKEY |
                     (WT_SCB_AIRCR_S & WT_SCB_AIRCR_CFG_MASK) |
                     WT_SCB_AIRCR_SYSRESETREQS;
#ifdef WT_ENGINE_HSM
    /* PendSV and the secure SysTick must share the lowest priority: SysTick at
     * the reset default (0, highest) would preempt PendSV mid-coroutine switch,
     * and a nested exception return off the half-saved frame faults INVPC.
     * Equal priority makes the context switch atomic against the timer. */
    WT_SCB_SHPR3_S |= (0xFFu << WT_SCB_SHPR3_PENDSV_SHIFT) |
                      (0xFFu << WT_SCB_SHPR3_SYSTICK_SHIFT);
    WT_SCB_ICSR_S = WT_SCB_ICSR_PENDSVCLR;
#endif
    /* Enable USART2/USART3 clocks in both security views before guests run. */
    for (size_t i = 0u; i < sizeof(uart_clocks) / sizeof(uart_clocks[0]); ++i) {
        wt_rcc_enable_clock(WT_RCC_BASE_S, &uart_clocks[i]);
        wt_rcc_enable_clock(WT_RCC_BASE_NS, &uart_clocks[i]);
    }
    wt_rcc_enable_clock(WT_RCC_BASE_S, &rng_clock);
    wt_uart_gpio_init();
    wt_platform_zero_guest_memory(WT_GUEST0_RAM_BASE, WT_GUEST_RAM_SIZE);
    wt_platform_zero_guest_memory(WT_GUEST1_RAM_BASE, WT_GUEST_RAM_SIZE);
    g_switch_count = 0u;
    g_active_guest = UINT32_MAX;
    g_secure_service_depth = 0u;
    g_hsm_wait_skip_count = 0u;
    g_tasklet_fault_count = 0u;
}

void wt_platform_start_secure_timer(uint32_t timeslice_ms)
{
    uint32_t reload;

    if (timeslice_ms == 0u) {
        wt_platform_panic();
    }

    reload = timeslice_ms * (WT_STM32H563_CORE_CLOCK_HZ / 1000u);
    g_systick_reload = reload;
}

static void wt_arm_secure_timer(void)
{
    WT_SYST_CSR = 0u;
    WT_SYST_RVR = g_systick_reload - 1u;
    WT_SYST_CVR = 0u;
    WT_SYST_CSR = WT_SYST_CSR_CLKSOURCE |
                  WT_SYST_CSR_TICKINT |
                  WT_SYST_CSR_ENABLE;
}

void wt_platform_mask_all_guest_irqs(void)
{
    volatile uint32_t* icer = (volatile uint32_t*)0xE000E180u;
    size_t i;

    for (i = 0; i < WT_MAX_IRQ_WORDS; ++i) {
        icer[i] = 0xFFFFFFFFu;
    }
}

void wt_platform_apply_irq_mask(const wt_irq_mask_t* mask)
{
    volatile uint32_t* iser = (volatile uint32_t*)0xE000E100u;
    size_t i;

    if (mask == NULL) {
        return;
    }

    for (i = 0; i < WT_MAX_IRQ_WORDS; ++i) {
        iser[i] = mask->words[i];
    }
}

void wt_platform_quarantine_pending_irqs(const wt_irq_mask_t* allowed_mask)
{
    volatile uint32_t* icpr = (volatile uint32_t*)0xE000E280u;
    size_t i;

    if (allowed_mask == NULL) {
        return;
    }

    for (i = 0; i < WT_MAX_IRQ_WORDS; ++i) {
        icpr[i] = ~allowed_mask->words[i];
    }
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

void wt_platform_program_ns_mpu(const wt_memory_region_t* regions, size_t count)
{
    wt_program_ns_mpu_regions(regions, count);
}

static uint32_t wt_virtual_systick_period(const wt_virtual_systick_t* systick)
{
    return (systick->rvr & 0x00FFFFFFu) + 1u;
}

static bool wt_virtual_systick_active(const wt_virtual_systick_t* systick)
{
    return (systick->csr & WT_SYST_CSR_ENABLE) != 0u;
}

static bool wt_virtual_systick_irq_enabled(const wt_virtual_systick_t* systick)
{
    return (systick->csr & (WT_SYST_CSR_ENABLE | WT_SYST_CSR_TICKINT)) ==
           (WT_SYST_CSR_ENABLE | WT_SYST_CSR_TICKINT);
}

static void wt_virtual_systick_note_consumed(wt_virtual_systick_t* systick,
                                             bool hw_pending)
{
    if (systick->pending && !hw_pending) {
        if (systick->owed_ticks > 0u) {
            systick->owed_ticks--;
        }
        systick->pending = 0u;
    }
}

static void wt_virtual_systick_save_departing(void)
{
    wt_virtual_systick_t* systick;
    uint32_t csr;
    bool hw_pending;

    if (g_active_guest >= WT_MAX_GUESTS) {
        WT_SYST_NS_CSR = 0u;
        WT_SCB_ICSR_NS = WT_SCB_ICSR_PENDSTCLR;
        return;
    }

    systick = &g_guest_systick[g_active_guest];
    csr = WT_SYST_NS_CSR;
    hw_pending = (WT_SCB_ICSR_NS & WT_SCB_ICSR_PENDSTSET) != 0u;

    wt_virtual_systick_note_consumed(systick, hw_pending);
    systick->csr = csr;
    systick->rvr = WT_SYST_NS_RVR;
    systick->cvr = WT_SYST_NS_CVR;
    systick->last_accounted_cycles = g_secure_wall_cycles;

    if (!systick->pending && hw_pending && wt_virtual_systick_irq_enabled(systick)) {
        systick->owed_ticks++;
        systick->pending = 1u;
        systick->accrued_ticks++;
        if (systick->owed_ticks > systick->max_owed_ticks) {
            systick->max_owed_ticks = systick->owed_ticks;
        }
    }

    WT_SYST_NS_CSR = 0u;
    WT_SCB_ICSR_NS = WT_SCB_ICSR_PENDSTCLR;
}

static void wt_virtual_systick_account_elapsed(wt_virtual_systick_t* systick)
{
    uint64_t elapsed;
    uint32_t period;
    uint32_t remaining;
    uint64_t ticks;
    uint64_t rem;

    if (systick->last_accounted_cycles == 0u) {
        systick->last_accounted_cycles = g_secure_wall_cycles;
        return;
    }

    elapsed = g_secure_wall_cycles - systick->last_accounted_cycles;
    systick->last_accounted_cycles = g_secure_wall_cycles;
    if (!wt_virtual_systick_active(systick) || elapsed == 0u) {
        return;
    }

    period = wt_virtual_systick_period(systick);
    remaining = (systick->cvr == 0u || systick->cvr >= period) ? period :
                (systick->cvr + 1u);

    if (elapsed < remaining) {
        systick->cvr = remaining - (uint32_t)elapsed - 1u;
        return;
    }

    elapsed -= remaining;
    ticks = 1u + (elapsed / period);
    rem = elapsed % period;
    systick->cvr = (uint32_t)(period - rem - 1u);

    if (ticks > (uint64_t)(UINT32_MAX - systick->owed_ticks)) {
        systick->owed_ticks = UINT32_MAX;
    }
    else {
        systick->owed_ticks += (uint32_t)ticks;
    }

    if (ticks > (uint64_t)(UINT32_MAX - systick->accrued_ticks)) {
        systick->accrued_ticks = UINT32_MAX;
    }
    else {
        systick->accrued_ticks += (uint32_t)ticks;
    }

    if (systick->owed_ticks > systick->max_owed_ticks) {
        systick->max_owed_ticks = systick->owed_ticks;
    }
}

static void wt_virtual_systick_restore_arriving(wt_guest_id_t guest_id)
{
    wt_virtual_systick_t* systick;

    WT_SCB_ICSR_NS = WT_SCB_ICSR_PENDSTCLR;
    if (guest_id >= WT_MAX_GUESTS) {
        return;
    }

    systick = &g_guest_systick[guest_id];
    wt_virtual_systick_account_elapsed(systick);

    WT_SYST_NS_CSR = 0u;
    WT_SYST_NS_RVR = systick->rvr;
    WT_SYST_NS_CVR = 0u;
    g_arriving_systick_csr = 0u;
    g_arriving_systick_inject = 0u;
    if (wt_virtual_systick_active(systick)) {
        g_arriving_systick_csr = systick->csr & ~WT_SYST_CSR_COUNTFLAG;
    }

    if (systick->owed_ticks > 0u && wt_virtual_systick_irq_enabled(systick)) {
        if (!systick->pending) {
            systick->pending = 1u;
            systick->injected_ticks++;
        }
        else {
            systick->coalesced_ticks++;
        }
        g_arriving_systick_inject = 1u;
    }
}

/* Called from the NS-entry asm once MSP/PSP/CONTROL_NS are restored, so a
 * tick taken here stacks on the arriving guest's own stack. */
static void wt_virtual_systick_arm_arriving(void) __attribute__((used));
static void wt_virtual_systick_arm_arriving(void)
{
    uint32_t csr = g_arriving_systick_csr;

    g_arriving_systick_csr = 0u;
    if (csr != 0u) {
        WT_SYST_NS_CSR = csr;
    }
    if (g_arriving_systick_inject != 0u) {
        g_arriving_systick_inject = 0u;
        WT_SCB_ICSR_NS = WT_SCB_ICSR_PENDSTSET;
    }
}

static void wt_virtual_systick_reset(wt_guest_id_t guest_id)
{
    wt_virtual_systick_t* systick;

    if (guest_id >= WT_MAX_GUESTS) {
        return;
    }
    systick = &g_guest_systick[guest_id];
    systick->csr = 0u;
    systick->rvr = 0u;
    systick->cvr = 0u;
    systick->last_accounted_cycles = g_secure_wall_cycles;
    systick->owed_ticks = 0u;
    systick->pending = 0u;
    systick->accrued_ticks = 0u;
    systick->injected_ticks = 0u;
    systick->coalesced_ticks = 0u;
    systick->max_owed_ticks = 0u;
}

void wt_platform_prepare_guest_return(wt_guest_id_t guest_id,
                                      const wt_guest_context_t* context)
{
    if (context == NULL) {
        return;
    }

    /* A non-secure RTOS must not be able to redirect Secure exception
     * dispatch through the shared PPB alias. Reassert wolfTrust's vector
     * table before every guest handoff so the next CMSE/HSM transition
     * always enters the relocated secure runtime. */
    WT_SCB_VTOR_S = WT_FLASH_IMAGE_BASE;
    wt_dsb();
    wt_isb();
    wt_virtual_systick_save_departing();

    WT_SCB_VTOR_NS = (uint32_t)context->vector_table_ns;
    g_active_guest = guest_id;
    wt_virtual_systick_restore_arriving(guest_id);
}

void wt_platform_capture_guest_context(wt_guest_context_t* context,
                                       const wt_trap_frame_t* frame)
{
    wt_exception_frame_t* stacked;
    uintptr_t stacked_addr;

    if (context == NULL || frame == NULL) {
        wt_platform_panic();
    }

    stacked = (wt_exception_frame_t*)frame;
    context->psp_ns = wt_read_psp_ns();
    stacked_addr = (uintptr_t)stacked;
    /* A SecureFault can be raised before the NS exception frame exists (for
     * example, on a failed first BXNS). Preserve the configured guest MSP
     * in that case; replacing it with zero would make the recovery path
     * fabricate a frame at 0xffffffe0 and fault recursively. */
    if (stacked_addr >= WT_RAM_NS_BASE &&
        stacked_addr <= (WT_RAM_NS_BASE + 0x00020000u -
                         sizeof(wt_exception_frame_t))) {
        context->msp_ns = stacked_addr;
    }
    context->control_ns = wt_read_control_ns();
    __asm volatile("mrs %0, psplim_ns" : "=r"(context->psplim_ns));
    context->exc_return = g_live_exc_return;
    context->r4_r11[0] = g_live_r4_r11[0];
    context->r4_r11[1] = g_live_r4_r11[1];
    context->r4_r11[2] = g_live_r4_r11[2];
    context->r4_r11[3] = g_live_r4_r11[3];
    context->r4_r11[4] = g_live_r4_r11[4];
    context->r4_r11[5] = g_live_r4_r11[5];
    context->r4_r11[6] = g_live_r4_r11[6];
    context->r4_r11[7] = g_live_r4_r11[7];
    context->pc = stacked->pc;
    context->lr = stacked->lr;
    context->xpsr = stacked->xpsr;
    context->frame_stacked = true;
}

void wt_platform_restore_guest_context(wt_guest_context_t* context)
{
    g_switch_count++;

    if (!context->frame_stacked) {
        if (wt_read_ipsr() == 0u) {
            wt_arm_secure_timer();
            wt_jump_to_ns((uint32_t)context->msp_ns, (uint32_t)context->pc);
        } else {
            wt_exception_frame_t* stacked;

            context->lr = 0u;
            context->xpsr = 0x01000000u;
            stacked = (wt_exception_frame_t*)(context->msp_ns - sizeof(wt_exception_frame_t));
            stacked->r0 = 0u;
            stacked->r1 = 0u;
            stacked->r2 = 0u;
            stacked->r3 = 0u;
            stacked->r12 = 0u;
            stacked->lr = context->lr;
            /* Vector-table reset handlers carry the Thumb marker in bit 0,
             * but an exception frame carries the aligned PC and restores
             * Thumb state from xPSR.T. Leaving bit 0 set causes INVEP on
             * STM32H563 during the first exception-based guest dispatch. */
            stacked->pc = context->pc & ~(uintptr_t)1u;
            stacked->xpsr = context->xpsr;
            context->msp_ns = (uintptr_t)stacked;
            context->frame_stacked = true;
        }
    }

    g_return_context = *context;
    wt_arm_secure_timer();
    if (wt_read_ipsr() == 0u) {
        __asm volatile("svc #0x7F");
        wt_platform_panic();
    }
    wt_exception_return_ns_msp();
}

void wt_platform_zero_guest_memory(uintptr_t base, size_t size)
{
    volatile uint32_t* ptr = (volatile uint32_t*)base;
    size_t words = size / sizeof(uint32_t);
    size_t i;

    for (i = 0; i < words; ++i) {
        ptr[i] = 0u;
    }
    if (base == WT_GUEST0_RAM_BASE && size >= WT_GUEST_RAM_SIZE) {
        wt_virtual_systick_reset(0u);
    }
    else if (base == WT_GUEST1_RAM_BASE && size >= WT_GUEST_RAM_SIZE) {
        wt_virtual_systick_reset(1u);
    }
}

void wt_platform_log_fault(wt_guest_id_t guest_id,
                           wt_fault_reason_t reason,
                           uintptr_t fault_address,
                           uintptr_t pc)
{
    (void)guest_id;
    (void)reason;
    g_last_fault_address = (uint32_t)fault_address;
    g_last_fault_pc = (uint32_t)pc;
}

uintptr_t wt_platform_read_fault_address(void)
{
    return g_last_fault_address;
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

void wt_platform_dmb(void)
{
    wt_dmb();
}

void wt_platform_dsb(void)
{
    wt_dsb();
}

bool wt_platform_guest_context_ready(const wt_guest_context_t* context)
{
    return (context != NULL) && (context->pc != 0u);
}

/* Rewrite the NS-banked stack/control registers from a guest's saved context.
 * A guest resumed through its blocked secure tasklet returns to NS via BXNS,
 * not the exception-return path, so nothing else reinstates its NS bank — the
 * previous guest's CONTROL_NS/MSP_NS would leak in and the thread resumes on
 * the wrong stack. Mirrors wt_exception_return_ns_msp (MSPLIM_NS stays 0). */
void wt_platform_restore_ns_bank(const wt_guest_context_t* context)
{
    uint32_t zero = 0u;

    __asm volatile(
        "msr psp_ns, %0     \n"
        "msr msp_ns, %1     \n"
        "msr psplim_ns, %2  \n"
        "msr msplim_ns, %3  \n"
        "msr control_ns, %4 \n"
        "isb                \n"
        :
        : "r"(context->psp_ns), "r"(context->msp_ns),
          "r"(context->psplim_ns), "r"(zero), "r"(context->control_ns));
}

void wt_platform_secure_irq_enable(uint32_t irq)
{
    uint32_t word = irq >> 5;
    uint32_t bit = irq & 31u;

    if (word > 1u)
        return;
    /* Route to Secure, drop any stale pending, lowest priority so the line
     * never preempts the active SVC gate, then unmask. */
    if (word == 0u) {
        WT_NVIC_ITNS0 &= ~(1u << bit);
        WT_NVIC_ICPR0 = (1u << bit);
    } else {
        WT_NVIC_ITNS1 &= ~(1u << bit);
        WT_NVIC_ICPR1 = (1u << bit);
    }
    WT_NVIC_IPR_BASE[irq] = 0xFFu;
    __asm volatile("dsb\nisb" ::: "memory");
    if (word == 0u)
        WT_NVIC_ISER0 = (1u << bit);
    else
        WT_NVIC_ISER1 = (1u << bit);
}

void wt_platform_secure_irq_disable(uint32_t irq)
{
    uint32_t word = irq >> 5;
    uint32_t bit = irq & 31u;

    if (word > 1u)
        return;
    if (word == 0u) {
        WT_NVIC_ICER0 = (1u << bit);
        WT_NVIC_ICPR0 = (1u << bit);
    } else {
        WT_NVIC_ICER1 = (1u << bit);
        WT_NVIC_ICPR1 = (1u << bit);
    }
    __asm volatile("dsb\nisb" ::: "memory");
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
        wt_platform_secure_irq_disable(WT_LPUART1_IRQ);
    }
}

void LPUART1_IRQHandler(void)
{
    wt_spm_conf_irq(WT_LPUART1_IRQ);
}
#endif

uint32_t wt_platform_active_guest_id(void)
{
    return g_active_guest;
}

void wt_platform_configure_ns_irq(uint32_t irq)
{
    volatile uint32_t *itns = (volatile uint32_t *)0xE000E380u;
    uint32_t word = irq >> 5;
    uint32_t bit  = irq & 31u;

    if (word >= WT_MAX_IRQ_WORDS) return;
    /* ITNS only has a secure alias; mark this IRQ as NS-targeted.
     * Do NOT enable in NVIC ISER here — that comes from the per-guest
     * partition irq_mask when the monitor dispatches a guest that
     * actually wants to receive this IRQ. */
    itns[word] |= (1u << bit);
}

void wt_platform_set_ns_irq_pending(uint32_t irq, bool asserted)
{
    uint32_t word = irq >> 5;
    uint32_t bit  = irq & 31u;
    if (word >= WT_MAX_IRQ_WORDS) return;
    if (asserted) {
        volatile uint32_t *ispr_ns = (volatile uint32_t *)0xE002E200u;
        ispr_ns[word] = (1u << bit);
    } else {
        volatile uint32_t *icpr_ns = (volatile uint32_t *)0xE002E280u;
        icpr_ns[word] = (1u << bit);
    }
}

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

__attribute__((naked)) void SecureFault_Handler(void)
{
    __asm volatile(
#ifdef WT_ENGINE_HSM
        /* EXC_RETURN bit6 = secure frame, bit3 = Thread. A fault from Secure
         * Thread with a live tasklet is a Secure Partition/tasklet fault, not
         * a guest escalation: blaming the scheduled NS guest would restart an
         * innocent domain and leave the SP's CPU state live. Route it to the
         * tasklet recovery entry, which self-derives everything from its own
         * EXC_RETURN. (The M33MU can deliver a secure MPU violation through
         * this vector; silicon MemManage takes the direct handler.) */
        "tst lr, #0x40                  \n"
        "beq 1f                         \n"
        "tst lr, #0x08                  \n"
        "beq 1f                         \n"
        "ldr r0, =g_wt_co_current       \n"
        "ldr r0, [r0]                   \n"
        "ldr r1, =g_wt_co_bootstrap     \n"
        "cmp r0, r1                     \n"
        "beq 1f                         \n"
        "b wt_secure_tasklet_fault_entry \n"
        "1:                             \n"
#endif
        "mov r2, sp                     \n"
        "ldr r1, =g_secure_entry_sp     \n"
        "str r2, [r1]                   \n"
        "ldr r1, =g_live_r4_r11         \n"
        "stmia r1!, {r4-r11}            \n"
        "ldr r1, =g_live_exc_return     \n"
        "str lr, [r1]                   \n"
        "mrs r0, msp_ns                 \n"
        "b wt_secure_fault_dispatch     \n"
    );
}

#ifdef WT_ENGINE_HSM
/* -----------------------------------------------------------------------
 * Secure-side tasklet fault path.
 *
 * MemManage and UsageFault can fire from within a wolfHSM tasklet when:
 *   - PSPLIM_S is hit (UsageFault.STKOF) — tasklet stack overflow,
 *   - MPU_S blocks a wild read/write (MemManage IACCVIOL/DACCVIOL),
 *   - the tasklet executes an illegal instruction (UsageFault).
 *
 * Recovery model:
 *   1. C dispatcher logs the fault, identifies the running tasklet
 *      (g_tasklet_current via wt_tasklet_current), maps it back to a guest_id,
 *      hands the NS client a WH_ERROR_ABORTED via wt_hsm_signal_fault,
 *      drops any mutex held by the dying tasklet, and marks the
 *      tasklet WT_TASKLET_FAULTED.
 *   2. The naked handler asm restores MSP_S to the bootstrap SP that
 *      PendSV saved (r4-r11 push + preserved exception frame), pops
 *      r4-r11, and EXC_RETURNs through the preserved bootstrap frame —
 *      all in Handler mode, mirroring PendSV's bootstrap-resume path.
 *      Execution resumes inside wt_tasklet_run as if the tasklet had
 *      switched back; the scheduler picks up the next runnable tasklet —
 *      the faulted one is no longer on the runqueue. (An earlier design
 *      EXC_RETURNed into a Thread-mode thunk that then tried a second
 *      exception return; only Handler mode can exception-return on real
 *      silicon, so that worked on the M33MU and IACCVIOL-faulted on H5.)
 *
 * If the fault fires while bootstrap (monitor) is running there is no
 * tasklet to abandon and no saved frame to unwind to, so the C
 * dispatcher panics.
 * ----------------------------------------------------------------------- */
static void wt_secure_tasklet_fault_dispatch(uint32_t *frame,
                                             uint32_t exc_return)
    __attribute__((used));
static void wt_secure_tasklet_fault_dispatch(uint32_t *frame,
                                             uint32_t exc_return)
{
    uint32_t cfsr = WT_SCB_CFSR_S;

    /* First-wins forensic record: the first tasklet fault's CFSR, stacked PC
     * and EXC_RETURN survive any later cascade so a debugger post-mortem can
     * tell what faulted (MMFSR/UFSR bits), where (PC), and from which mode
     * (EXC_RETURN bit 3). g_last_fault_address below adds the data address. */
    if (g_tasklet_fault_cfsr == 0u) {
        uint32_t psp_now;

        g_tasklet_fault_cfsr = cfsr;
        g_tasklet_fault_pc = frame[6];
        g_tasklet_fault_exc_return = exc_return;
        /* Frame position vs the coroutine stack identifies which pusher
         * built it (SVC/tick 8-word vs NS-preempt callee+signature). */
        g_tasklet_fault_frame = (uint32_t)(uintptr_t)frame;
        g_tasklet_fault_xpsr = frame[7];
        __asm volatile("mrs %0, psp" : "=r"(psp_now));
        g_tasklet_fault_psp = psp_now;
        g_tasklet_fault_icsr = WT_SCB_ICSR_S;
        g_tasklet_fault_co = (uint32_t)(uintptr_t)wt_co_current();
        if (wt_co_current() != NULL) {
            g_tasklet_fault_co_sp = *(const uint32_t*)(const void*)
                                        wt_co_current();
        }
    }
    if ((cfsr & WT_SCB_CFSR_MMFSR_MMARVALID) != 0u) {
        g_last_fault_address = WT_SCB_MMFAR_S;
    }
    /* Write-1-to-clear so the next fault is observable. */
    WT_SCB_CFSR_S = cfsr;

    wt_tasklet_t *tasklet = wt_tasklet_current();
    if (tasklet == NULL) {
        /* Bootstrap took the fault — no tasklet to abandon. */
        wt_platform_panic();
    }

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    /* The Arm isolation tests (i068+) fault inside a Secure Partition on
     * purpose and expect a system restart so val resumes off its flash boot
     * flag; the graceful quarantine below would leave the server partition
     * dead for every later test. Production keeps the quarantine (task #26). */
    wt_platform_system_reset();
#endif

    g_tasklet_fault_count++;

    /* Graceful recovery for a scheduled Secure Partition (WT-SYS-0008 /
     * WT-FFM-0017): mark it dead and pend the recovery; the SPM dispatch path
     * restarts it on the bootstrap thread under its manifest policy without
     * resetting the world. If the coroutine is not a scheduled SP this returns
     * an error and the guest-tasklet teardown below runs instead. */
    if (wt_spm_sp_fault(tasklet) == WT_FFM_SUCCESS) {
        return;
    }

    wt_guest_id_t gid = wt_hsm_guest_for_tasklet(tasklet);
    if (gid < WT_MAX_GUESTS) {
        (void)wt_hsm_signal_fault(gid);
    }

    wt_tasklet_mark_faulted(tasklet);
}

/* Shared tail for MemManage_Handler and UsageFault_Handler. Naked so
 * we control the stack layout the EXC_RETURN unwinds through. */
__attribute__((naked, used))
static void wt_secure_tasklet_fault_entry(void)
{
    __asm volatile(
        /* r0 = the faulting context's stacked exception frame (EXC_RETURN
         * bit 2 selects the stack it was pushed to), r1 = EXC_RETURN. */
        "tst    lr, #4                              \n"
        "ite    eq                                  \n"
        "mrseq  r0, msp                             \n"
        "mrsne  r0, psp                             \n"
        "mov    r1, lr                              \n"
        "bl     wt_secure_tasklet_fault_dispatch    \n"
        /* Resume the bootstrap exactly like PendSV's bootstrap path:
         * g_wt_co_bootstrap.sp points at the r4-r11 PendSV pushed with the
         * preserved bootstrap exception frame above it. This is Handler
         * mode, so the final bx is a real exception return — a Thread-mode
         * thunk cannot exception-return on hardware (M33MU accepted it,
         * H5 silicon IACCVIOL-faults at 0xFFFFFFF8). */
        "ldr    r0, =g_wt_co_bootstrap              \n"
        "ldr    lr, [r0, #44]                       \n"
        "ldr    r0, [r0, #0]                        \n"
        "msr    msp, r0                             \n"
        "pop    {r4-r11}                            \n"
        /* Drop PSPLIM_S — wt_co_arch_switch reinstalls it for the next
         * tasklet. PSP_S itself is left pointing into the dead
         * tasklet's stack; harmless because CONTROL.SPSEL=0 on
         * return-to-Thread-MSP and arch_switch will overwrite PSP_S
         * before re-enabling PSP. */
        "movs   r0, #0                              \n"
        "msr    psplim, r0                          \n"
        /* An unprivileged Secure Partition coroutine dies here without
         * passing through PendSV's bootstrap path, so clear CONTROL.nPRIV
         * or the resumed bootstrap would run unprivileged. */
        "mrs    r0, control                         \n"
        "bic    r0, r0, #1                          \n"
        "msr    control, r0                         \n"
        /* EXC_RETURN = 0xFFFFFFF9: Secure Thread mode using MSP_S, no
         * FP context. mvn of 6 builds the value with no literal pool. */
        "mvn    lr, #6                              \n"
        "bx     lr                                  \n"
    );
}

__attribute__((naked)) void MemManage_Handler(void)
{
    __asm volatile("b wt_secure_tasklet_fault_entry \n");
}

__attribute__((naked)) void UsageFault_Handler(void)
{
    __asm volatile("b wt_secure_tasklet_fault_entry \n");
}
#endif /* WT_ENGINE_HSM */

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

__attribute__((naked)) void SysTick_Handler(void)
{
    __asm volatile(
        "mov r2, sp                     \n"
        "ldr r1, =g_secure_entry_sp     \n"
        "str r2, [r1]                   \n"
        "ldr r1, =g_live_r4_r11         \n"
        "stmia r1!, {r4-r11}            \n"
        "ldr r1, =g_live_exc_return     \n"
        "str lr, [r1]                   \n"
        "mrs r0, msp_ns                 \n"
        "b wt_secure_systick_dispatch   \n"
    );
}
