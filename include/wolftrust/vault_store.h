/* vault_store.h
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

/* The vault's object store calls. On the native store they dispatch through
 * the pinned callback table themselves: only the vault partition reaches the
 * store at runtime and nothing takes the wolfHSM NVM lock, so wh_nvm.c adds
 * nothing there. */

#ifndef WOLFTRUST_VAULT_STORE_H
#define WOLFTRUST_VAULT_STORE_H

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"

#if defined(WT_NVM_STORE_NATIVE)
static inline const whNvmCb* wt_vstore_cb(const whNvmContext* nvm)
{
    return (nvm != NULL) ? nvm->cb : NULL;
}

static inline int wt_vstore_available(whNvmContext* nvm, uint32_t* size,
                                      whNvmId* objects, uint32_t* reclaim,
                                      whNvmId* reclaim_objects)
{
    const whNvmCb* cb = wt_vstore_cb(nvm);

    if (cb == NULL || cb->GetAvailable == NULL) {
        return WH_ERROR_BADARGS;
    }
    return cb->GetAvailable(nvm->context, size, objects, reclaim,
                            reclaim_objects);
}

static inline int wt_vstore_add(whNvmContext* nvm, whNvmMetadata* meta,
                                whNvmSize len, const uint8_t* data)
{
    const whNvmCb* cb = wt_vstore_cb(nvm);

    if (cb == NULL || cb->AddObject == NULL) {
        return WH_ERROR_BADARGS;
    }
    return cb->AddObject(nvm->context, meta, len, data);
}

static inline int wt_vstore_metadata(whNvmContext* nvm, whNvmId id,
                                     whNvmMetadata* meta)
{
    const whNvmCb* cb = wt_vstore_cb(nvm);

    if (cb == NULL || cb->GetMetadata == NULL) {
        return WH_ERROR_BADARGS;
    }
    return cb->GetMetadata(nvm->context, id, meta);
}

static inline int wt_vstore_destroy(whNvmContext* nvm, whNvmId count,
                                    const whNvmId* ids)
{
    const whNvmCb* cb = wt_vstore_cb(nvm);

    if (cb == NULL || cb->DestroyObjects == NULL) {
        return WH_ERROR_BADARGS;
    }
    return cb->DestroyObjects(nvm->context, count, ids);
}

static inline int wt_vstore_read(whNvmContext* nvm, whNvmId id,
                                 whNvmSize offset, whNvmSize len,
                                 uint8_t* data)
{
    const whNvmCb* cb = wt_vstore_cb(nvm);

    if (cb == NULL || cb->Read == NULL) {
        return WH_ERROR_BADARGS;
    }
    return cb->Read(nvm->context, id, offset, len, data);
}

/* The metadata-flag policy of wolfHSM's *Checked calls: WH_ERROR_ACCESS when
 * the stored object carries a denied flag or is server-only trusted. */
static inline int wt_vstore_policy(whNvmContext* nvm, whNvmId id,
                                   whNvmFlags deny)
{
    whNvmMetadata meta;
    int rc = wt_vstore_metadata(nvm, id, &meta);

    if (rc == WH_ERROR_OK &&
            (meta.flags & (deny | WH_NVM_FLAGS_TRUSTED)) != 0U) {
        rc = WH_ERROR_ACCESS;
    }
    return rc;
}

static inline int wt_vstore_add_checked(whNvmContext* nvm,
                                        const whNvmMetadata* meta,
                                        whNvmSize len, const uint8_t* data)
{
    whNvmMetadata clean;
    int rc;

    if (meta == NULL) {
        return WH_ERROR_BADARGS;
    }
    rc = wt_vstore_policy(nvm, meta->id, WH_NVM_FLAGS_NONMODIFIABLE);
    if (rc != WH_ERROR_OK && rc != WH_ERROR_NOTFOUND) {
        return rc;
    }
    clean = *meta;
    clean.flags &= (whNvmFlags)~WH_NVM_FLAGS_SERVER_ONLY;
    return wt_vstore_add(nvm, &clean, len, data);
}

static inline int wt_vstore_destroy_checked(whNvmContext* nvm, whNvmId count,
                                            const whNvmId* ids)
{
    whNvmId i;
    int rc = WH_ERROR_OK;

    if (ids == NULL && count != 0U) {
        return WH_ERROR_BADARGS;
    }
    for (i = 0U; i < count && (rc == WH_ERROR_OK || rc == WH_ERROR_NOTFOUND);
            i++) {
        rc = wt_vstore_policy(nvm, ids[i], WH_NVM_FLAGS_NONMODIFIABLE |
                                           WH_NVM_FLAGS_NONDESTROYABLE);
    }
    if (rc != WH_ERROR_OK && rc != WH_ERROR_NOTFOUND) {
        return rc;
    }
    return wt_vstore_destroy(nvm, count, ids);
}

static inline int wt_vstore_read_checked(whNvmContext* nvm, whNvmId id,
                                         whNvmSize offset, whNvmSize len,
                                         uint8_t* data)
{
    int rc = wt_vstore_policy(nvm, id, WH_NVM_FLAGS_NONEXPORTABLE);

    if (rc == WH_ERROR_OK) {
        rc = wt_vstore_read(nvm, id, offset, len, data);
    }
    return rc;
}
#else
#define wt_vstore_available       wh_Nvm_GetAvailable
#define wt_vstore_add             wh_Nvm_AddObject
#define wt_vstore_metadata        wh_Nvm_GetMetadata
#define wt_vstore_destroy         wh_Nvm_DestroyObjects
#define wt_vstore_read            wh_Nvm_Read
#define wt_vstore_add_checked     wh_Nvm_AddObjectChecked
#define wt_vstore_destroy_checked wh_Nvm_DestroyObjectsChecked
#define wt_vstore_read_checked    wh_Nvm_ReadChecked
#endif

#endif /* WOLFTRUST_VAULT_STORE_H */
