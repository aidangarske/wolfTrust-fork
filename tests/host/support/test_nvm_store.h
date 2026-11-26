/* test_nvm_store.h
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

/* Host suites set up the NVM store through the wolfHSM names; built with
 * NVM_STORE=native the same suites run over the native store instead. */

#ifndef WOLFTRUST_TEST_NVM_STORE_H
#define WOLFTRUST_TEST_NVM_STORE_H

#include "wolfhsm/wh_nvm_flash.h"

#if defined(WT_NVM_STORE_NATIVE)
#include "wolftrust/nvm_native.h"

#define whNvmFlashConfig           wt_nvs_config_t
#define whNvmFlashContext          wt_nvs_context_t
#undef  WH_NVM_FLASH_CB
#define WH_NVM_FLASH_CB            WT_NVS_CB
#define wh_NvmFlash_Init           wt_nvs_init
#define wh_NvmFlash_Cleanup        wt_nvs_cleanup
#define wh_NvmFlash_GetAvailable   wt_nvs_get_available
#define wh_NvmFlash_AddObject      wt_nvs_add_object
#define wh_NvmFlash_GetMetadata    wt_nvs_get_metadata
#define wh_NvmFlash_DestroyObjects wt_nvs_destroy_objects
#define wh_NvmFlash_Read           wt_nvs_read
#endif

#if defined(WT_NVM_STORE_NATIVE)
#include "wolftrust/services/hsm.h"

#include <string.h>

/* The native store creates the vault's counter table with the seal key, so a
 * suite that binds the vault without the real sealer adds a stand-in key. */
static inline int test_vault_store_ready(whNvmContext* nvm)
{
    whNvmMetadata meta;
    uint8_t key[32];

    (void)memset(&meta, 0, sizeof(meta));
    (void)memset(key, 0x5A, sizeof(key));
    meta.id = WT_HSM_SEAL_KEY_ID;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags = WH_NVM_FLAGS_SENSITIVE | WH_NVM_FLAGS_NONEXPORTABLE |
                 WH_NVM_FLAGS_NONMODIFIABLE | WH_NVM_FLAGS_NONDESTROYABLE;
    meta.len = (whNvmSize)sizeof(key);
    return wt_hsm_vault_seal_key_add(nvm, &meta, key);
}
#else
static inline int test_vault_store_ready(whNvmContext* nvm)
{
    (void)nvm;
    return 0;
}
#endif

#endif /* WOLFTRUST_TEST_NVM_STORE_H */
