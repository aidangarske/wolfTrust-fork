/* nvm_store.c
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

/*
 * Engine-independent secure NVM store: the vault partition's flash-backed
 * object store. Linked in both crypto engines. Everything the SPM itself
 * consumes (the lock, the lifecycle latch, the rollback floors) lives in
 * nvm_boot.c, outside the vault's band.
 */

/* wolfCrypt settings must come first. */
#include "wolfssl/wolfcrypt/settings.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_lock.h"
#if defined(WT_NVM_STORE_NATIVE)
#include "wolftrust/nvm_native.h"
#else
#include "wolfhsm/wh_nvm_flash.h"
#endif

#include "wolftrust/types.h"
#include "wolftrust/sync/mutex.h"
#include "wolftrust/nvm_store.h"
#include "wolftrust/services/hsm.h"

#include "wolftrust/port_nvm.h"

#include <string.h>
#include <stdint.h>

#ifndef WOLFHSM_CFG_THREADSAFE
#error "wolfTrust requires WOLFHSM_CFG_THREADSAFE for the shared NVM store"
#endif

/* -------------------------------------------------------------------------
 * The vault's NVM state (one instance, serialised by g_wt_nvm_lock_mutex).
 * ---------------------------------------------------------------------- */
whNvmContext             g_wt_nvm_ctx;
#if defined(WT_NVM_STORE_NATIVE)
static wt_nvs_context_t  g_nvm_flash_ctx;
static const whNvmCb     g_nvm_flash_cb[1] = {WT_NVS_CB};
typedef wt_nvs_config_t  wt_nvm_backend_config_t;
#else
static whNvmFlashContext g_nvm_flash_ctx;
static const whNvmCb     g_nvm_flash_cb[1] = {WH_NVM_FLASH_CB};
typedef whNvmFlashConfig wt_nvm_backend_config_t;
#endif

#if !defined(WT_NVM_STORE_NATIVE)
/* g_wt_hsm_lock_cb (wt_hsm_lock.c) dispatches acquire/release to the
 * SPM-owned g_wt_nvm_lock_mutex (nvm_boot.c). */
static whLockConfig g_nvm_lock_cfg;
extern const whLockCb g_wt_hsm_lock_cb; /* defined in wt_hsm_lock.c */
#endif

#if defined(WT_NVM_STORE_NATIVE)
/* Called only just before the store reformats itself, so it also flags it. */
static int wt_nvm_store_may_format(void)
{
    if (wt_nvm_reformat_allowed() == 0) {
        return 0;
    }
    wt_nvm_mark_reformatted();
    return 1;
}
#endif

int wt_nvm_store_bind(void)
{
    wt_nvm_backend_config_t nvm_flash_cfg;
#if !defined(WT_NVM_STORE_NATIVE)
    whNvmConfig             nvm_cfg;
#endif

    (void)memset(&g_nvm_flash_ctx, 0, sizeof(g_nvm_flash_ctx));
    (void)memset(&nvm_flash_cfg, 0, sizeof(nvm_flash_cfg));
    nvm_flash_cfg.cb      = &g_wt_hsm_flash_cb;
    nvm_flash_cfg.context = wt_hsm_flash_context();
    nvm_flash_cfg.config  = wt_hsm_flash_config();
#if defined(WT_NVM_STORE_NATIVE)
    nvm_flash_cfg.may_format = wt_nvm_store_may_format;

    /* The vault calls the native store directly (vault_store.h): no lock. */
    (void)memset(&g_wt_nvm_ctx, 0, sizeof(g_wt_nvm_ctx));
    g_wt_nvm_ctx.cb      = (whNvmCb *)g_nvm_flash_cb;
    g_wt_nvm_ctx.context = &g_nvm_flash_ctx;
    return wt_nvs_init(&g_nvm_flash_ctx, &nvm_flash_cfg);
#else
    g_nvm_lock_cfg.cb      = &g_wt_hsm_lock_cb;
    g_nvm_lock_cfg.context = &g_wt_nvm_lock_mutex;
    g_nvm_lock_cfg.config  = NULL;

    (void)memset(&g_wt_nvm_ctx, 0, sizeof(g_wt_nvm_ctx));
    (void)memset(&nvm_cfg, 0, sizeof(nvm_cfg));
    nvm_cfg.cb         = (whNvmCb *)g_nvm_flash_cb;
    nvm_cfg.context    = &g_nvm_flash_ctx;
    nvm_cfg.config     = &nvm_flash_cfg;
    nvm_cfg.lockConfig = &g_nvm_lock_cfg;

    return wh_Nvm_Init(&g_wt_nvm_ctx, &nvm_cfg);
#endif
}

void wt_nvm_store_pin(void)
{
    /* The store lives in the vault's band. Re-assert every pointer in the
     * chain from link-time constants so a forged value is never dereferenced
     * (WT-FFM-0011); data fields (directory, state) stay partition-owned. */
    g_wt_nvm_ctx.cb           = (whNvmCb *)g_nvm_flash_cb;
    g_wt_nvm_ctx.context      = &g_nvm_flash_ctx;
#if !defined(WT_NVM_STORE_NATIVE)
    g_wt_nvm_ctx.lock.cb      = &g_wt_hsm_lock_cb;
    g_wt_nvm_ctx.lock.context = &g_wt_nvm_lock_mutex;
#endif
    g_nvm_flash_ctx.cb    = &g_wt_hsm_flash_cb;
    g_nvm_flash_ctx.flash = wt_hsm_flash_context();
}

#if defined(WT_HSM_PIN_NEG_PROBE) && (WT_HSM_PIN_NEG_PROBE == 1)
int wt_nvm_store_pin_probe(void)
{
    void *sentinel = (void *)0x30028001u;

    /* Forge every pointer wt_nvm_store_pin repairs, heal them, and confirm
     * each holds its exact canonical address. Synchronous: the store is left
     * correct with no yield (WT-FFM-0011). */
    g_wt_nvm_ctx.cb           = (whNvmCb *)sentinel;
    g_wt_nvm_ctx.context      = sentinel;
#if !defined(WT_NVM_STORE_NATIVE)
    g_wt_nvm_ctx.lock.cb      = (const whLockCb *)sentinel;
    g_wt_nvm_ctx.lock.context = sentinel;
#endif
    g_nvm_flash_ctx.cb        = (const whFlashCb *)sentinel;
    g_nvm_flash_ctx.flash     = sentinel;

    wt_nvm_store_pin();

    if (g_wt_nvm_ctx.cb != (whNvmCb *)g_nvm_flash_cb ||
            g_wt_nvm_ctx.context != (void *)&g_nvm_flash_ctx ||
#if !defined(WT_NVM_STORE_NATIVE)
            g_wt_nvm_ctx.lock.cb != &g_wt_hsm_lock_cb ||
            g_wt_nvm_ctx.lock.context != (void *)&g_wt_nvm_lock_mutex ||
#endif
            g_nvm_flash_ctx.cb != &g_wt_hsm_flash_cb ||
            g_nvm_flash_ctx.flash != wt_hsm_flash_context()) {
        return 0;
    }
    return 1;
}
#endif
