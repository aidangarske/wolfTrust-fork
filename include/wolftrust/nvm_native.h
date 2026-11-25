/* nvm_native.h
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

#ifndef WOLFTRUST_NVM_NATIVE_H
#define WOLFTRUST_NVM_NATIVE_H

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_flash.h"
#include "wolfhsm/wh_nvm.h"

/* Directory slots per partition. */
#ifndef WT_NVS_SLOTS
#define WT_NVS_SLOTS 32u
#endif

/* On-flash record unit: one STM32H5 quadword, a whole number of every port's
 * program unit. */
#define WT_NVS_UNIT 16u

typedef struct wt_nvs_config {
    /* With no Verify callback, Program must verify what it wrote. */
    const whFlashCb* cb;
    void*            context;
    const void*      config;
    /* Nonzero when a store that is neither blank nor readable may be erased
     * and reformatted; NULL refuses it. */
    int (*may_format)(void);
} wt_nvs_config_t;

/* Data is allocated in slot order, so a slot's data offset is the padded
 * length of the slots before it. */
typedef struct wt_nvs_slot {
    whNvmId  id;      /* WH_NVM_ID_INVALID once superseded */
    whNvmSize len;
} wt_nvs_slot_t;

typedef struct wt_nvs_context {
    const whFlashCb* cb;
    void*            flash;
    uint32_t         part_size;
    uint32_t         epoch;
    uint32_t         next_data;
    uint32_t         dead_data;
    uint16_t         used;
    uint16_t         dead;
    uint8_t          active;
    uint8_t          torn;
    uint8_t          bad;
    uint8_t          ready;
    wt_nvs_slot_t    slot[WT_NVS_SLOTS];
} wt_nvs_context_t;

int wt_nvs_init(void* c, const void* cf);
int wt_nvs_cleanup(void* c);
int wt_nvs_get_available(void* c, uint32_t* out_avail_size,
                         whNvmId* out_avail_objects,
                         uint32_t* out_reclaim_size,
                         whNvmId* out_reclaim_objects);
int wt_nvs_add_object(void* c, whNvmMetadata* meta, whNvmSize data_len,
                      const uint8_t* data);
int wt_nvs_get_metadata(void* c, whNvmId id, whNvmMetadata* meta);
int wt_nvs_destroy_objects(void* c, whNvmId list_count,
                           const whNvmId* id_list);
int wt_nvs_read(void* c, whNvmId id, whNvmSize offset, whNvmSize data_len,
                uint8_t* data);

#define WT_NVS_CB {                                   \
        .Init = wt_nvs_init,                            \
        .Cleanup = wt_nvs_cleanup,                      \
        .GetAvailable = wt_nvs_get_available,           \
        .AddObject = wt_nvs_add_object,                 \
        .List = NULL,                                   \
        .GetMetadata = wt_nvs_get_metadata,             \
        .DestroyObjects = wt_nvs_destroy_objects,       \
        .Read = wt_nvs_read,                            \
    }

#endif /* WOLFTRUST_NVM_NATIVE_H */
