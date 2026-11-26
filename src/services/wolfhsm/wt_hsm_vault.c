/* wt_hsm_vault.c
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

/* Gated wolfHSM vault backing (WT-FFM-0044/0045/0047): PSA storage objects
 * live as wolfHSM NVM objects keyed by the SPM-stamped owner identity plus
 * the caller's 64-bit uid, recorded in the object label. Only the *Checked
 * NVM entry points are used so the immutable-object flags are enforced by
 * the vault, not by caller convention. Ops run to completion on the single
 * cooperative core without yielding, matching the per-guest HSM server
 * tasklets' serialisation of the shared NVM context. */

#include "wolftrust/services/vault_service.h"
#include "wolftrust/services/hsm.h"

#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_keyid.h"
#include "wolftrust/rollback.h"
#include "wolftrust/static_assert.h"
#include "wolftrust/vault_store.h"
#include "wolfhsm/wh_nvm.h"
#if defined(WT_NVM_STORE_NATIVE)
#include "wolftrust/nvm_native.h"
#define WT_VAULT_STORE_AVAILABLE wt_nvs_get_available
#define WT_VAULT_STORE_DESTROY   wt_nvs_destroy_objects
#define WT_VAULT_STORE_UNIT      WT_NVS_UNIT
#else
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_unit.h"
#define WT_VAULT_STORE_AVAILABLE wh_NvmFlash_GetAvailable
#define WT_VAULT_STORE_DESTROY   wh_NvmFlash_DestroyObjects
#define WT_VAULT_STORE_UNIT      WHFU_BYTES_PER_UNIT
#endif

/* Vault NVM id window: plain-NVM id space (type nibble 0), disjoint from the
 * keystore's composed ids (type nibble >= 1, e.g. the attestation IAK). */
#define WT_HSM_VAULT_ID_BASE  0x0100U
#define WT_HSM_VAULT_ID_COUNT 32U

#define WT_HSM_VAULT_LABEL_MAGIC 0x31565457UL /* "WTV1" little-endian */
#if defined(WT_NVM_STORE_NATIVE)
#define WT_HSM_VAULT_TABLE_MAGIC 0x32565457UL /* "WTV2" little-endian */
#ifndef WT_VAULT_COUNTER_RANGE
#define WT_VAULT_COUNTER_RANGE   8U
#endif
WT_STATIC_ASSERT(WT_VAULT_COUNTER_RANGE >= 1U,
                 "a pair must cover the counter it seals under");
#else
#define WT_HSM_VAULT_TABLE_MAGIC 0x43565457UL /* "WTVC" little-endian */
#endif
#define WT_HSM_VAULT_STAGE_ID    0x0123U
#define WT_HSM_VAULT_DELETE_MARKER_BASE WT_HSM_VAULT_ID_COUNT

#define WT_HSM_VAULT_FLAG_MASK \
    (WT_VAULT_FLAG_WRITE_ONCE | WT_VAULT_FLAG_NO_CONFIDENTIALITY | \
     WT_VAULT_FLAG_NO_REPLAY | WT_VAULT_FLAG_SEALED)

/* Rollback counter table (WT-FFM-0048), persisted at WT_HSM_VAULT_TABLE_ID.
 * global increments on every sealed write and is persisted BEFORE the sealed
 * object, so a power loss can never make a GCM nonce repeat; slot[] holds the
 * counter each in-window object was sealed under, so a replayed (rolled-back)
 * ciphertext fails tag authentication on the next read. reserved holds the
 * slot plus one while its prior object is staged for rollback, or the
 * delete marker base plus slot plus one while deletion is in progress. On the
 * native store (WTV2) global is the highest counter issued, the table commits
 * together with the object it covers, and reserved only records whether the
 * rollback floors were provisioned. */
typedef struct wt_hsm_vault_table {
    uint32_t magic;
    uint32_t reserved;
    uint64_t global;
    uint64_t slot[WT_HSM_VAULT_ID_COUNT];
} wt_hsm_vault_table_t;

static whNvmContext* g_vault_nvm;
static const wt_vault_sealer_t* g_vault_sealer;
#if defined(WT_NVM_STORE_NATIVE)
/* Next counter to seal under; valid only while g_vault_counted is set, and
 * re-derived from the committed table after every bind or failed write. */
static uint64_t g_vault_next;
static uint8_t g_vault_counted;
#endif

/* Sealed-object staging in the shared keystore trust band. */
/* Sealed objects are unsealed in place; a path that writes the ciphertext
 * back re-reads it from flash first. */
static uint8_t g_vault_ct[WT_VAULT_OBJECT_MAX + WT_VAULT_SEAL_TAG_LEN];

int wt_hsm_vault_init(whNvmContext* nvm)
{
    /* Reservations require physical append slots and flash compaction. */
    if (nvm == NULL || nvm->cb == NULL ||
            nvm->cb->GetAvailable != WT_VAULT_STORE_AVAILABLE ||
            nvm->cb->DestroyObjects != WT_VAULT_STORE_DESTROY) {
        g_vault_nvm = NULL;
        return -1;
    }
    g_vault_nvm = nvm;
#if defined(WT_NVM_STORE_NATIVE)
    g_vault_counted = 0U;
#endif
    return 0;
}

void wt_hsm_vault_set_sealer(const wt_vault_sealer_t* sealer)
{
    g_vault_sealer = sealer;
}

static void wt_hsm_vault_zeroize(uint8_t* buf, size_t len)
{
    volatile uint8_t* p = buf;
    size_t i;

    for (i = 0U; i < len; i++) {
        p[i] = 0U;
    }
}

static psa_status_t wt_hsm_vault_map_err(int rc);
#if defined(WT_NVM_STORE_NATIVE)
#define WT_HSM_VAULT_FLOORS_SET  1U

/* WH_ERROR_OK with a table of the given magic, WH_ERROR_NOTFOUND, or an
 * error for anything else. */
static int wt_hsm_vault_table_read(whNvmContext* nvm,
                                   wt_hsm_vault_table_t* table,
                                   uint32_t magic)
{
    whNvmMetadata meta;
    uint32_t i;
    int rc;

    rc = wt_vstore_metadata(nvm, WT_HSM_VAULT_TABLE_ID, &meta);
    if (rc == WH_ERROR_OK && meta.len != sizeof(*table)) {
        rc = WH_ERROR_ABORTED;
    }
    if (rc == WH_ERROR_OK) {
        rc = wt_vstore_read(nvm, WT_HSM_VAULT_TABLE_ID, 0U,
                            (whNvmSize)sizeof(*table), (uint8_t*)table);
    }
    if (rc == WH_ERROR_OK && (table->magic != magic ||
            (magic == WT_HSM_VAULT_TABLE_MAGIC &&
             (table->reserved & ~WT_HSM_VAULT_FLOORS_SET) != 0U))) {
        rc = WH_ERROR_ABORTED;
    }
    /* A slot above global would let a later seal reuse its counter. */
    for (i = 0U; rc == WH_ERROR_OK && i < WT_HSM_VAULT_ID_COUNT; i++) {
        if (table->slot[i] > table->global) {
            rc = WH_ERROR_ABORTED;
        }
    }
    return rc;
}

static psa_status_t wt_hsm_vault_table_load(wt_hsm_vault_table_t* table)
{
    /* The table is written with the seal key, so it is never absent. */
    return (wt_hsm_vault_table_read(g_vault_nvm, table,
                                    WT_HSM_VAULT_TABLE_MAGIC) == WH_ERROR_OK) ?
           PSA_SUCCESS : PSA_ERROR_STORAGE_FAILURE;
}
#else
static psa_status_t wt_hsm_vault_recover(wt_hsm_vault_table_t* table);

static psa_status_t wt_hsm_vault_table_load(wt_hsm_vault_table_t* table)
{
    whNvmMetadata meta;
    int rc;

    rc = wt_vstore_metadata(g_vault_nvm, WT_HSM_VAULT_TABLE_ID, &meta);
    if (rc == WH_ERROR_NOTFOUND) {
        (void)memset(table, 0, sizeof(*table));
        table->magic = WT_HSM_VAULT_TABLE_MAGIC;
        return wt_hsm_vault_recover(table);
    }
    if (rc != WH_ERROR_OK || meta.len != sizeof(*table)) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    rc = wt_vstore_read(g_vault_nvm, WT_HSM_VAULT_TABLE_ID, 0U,
                        (whNvmSize)sizeof(*table), (uint8_t*)table);
    if (rc != WH_ERROR_OK || table->magic != WT_HSM_VAULT_TABLE_MAGIC ||
            table->reserved >
                WT_HSM_VAULT_DELETE_MARKER_BASE + WT_HSM_VAULT_ID_COUNT) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    return wt_hsm_vault_recover(table);
}

#endif

/* Gate every pool write: a doomed add on a full data pool fails mid-write
 * with NOTBLANK and poisons later adds, so compact reclaimable space when
 * that frees enough and otherwise report INSUFFICIENT_STORAGE before any
 * write starts. Transaction callers include every write needed to commit or
 * roll back so recovery cannot run out of space. */
static uint32_t wt_hsm_vault_storage_size(size_t len)
{
    return (uint32_t)(((len + WT_VAULT_STORE_UNIT - 1u) /
                       WT_VAULT_STORE_UNIT) * WT_VAULT_STORE_UNIT);
}

static psa_status_t wt_hsm_vault_reserve_in(whNvmContext* nvm,
                                            uint32_t need_size,
                                            uint16_t need_objects)
{
    uint32_t avail_size;
    uint32_t reclaim_size;
    uint16_t avail_objects;
    uint16_t reclaim_objects;
    int rc;

    rc = wt_vstore_available(nvm, &avail_size, &avail_objects,
                             &reclaim_size, &reclaim_objects);
    if (rc != WH_ERROR_OK) {
        return wt_hsm_vault_map_err(rc);
    }
    if (avail_size < need_size || avail_objects < need_objects) {
        if (avail_size + reclaim_size >= need_size &&
                (uint32_t)avail_objects + (uint32_t)reclaim_objects >=
                    need_objects) {
            rc = wt_vstore_destroy(nvm, 0U, NULL);
            if (rc != WH_ERROR_OK) {
                return wt_hsm_vault_map_err(rc);
            }
        }
        else {
            return PSA_ERROR_INSUFFICIENT_STORAGE;
        }
    }
    return PSA_SUCCESS;
}

#if defined(WT_NVM_STORE_NATIVE)
/* Kept free on every vault write so the boot-time floor rewrite in
 * nvm_boot.c always has its slot and bytes. */
#define WT_HSM_VAULT_FLOOR_SIZE \
    wt_hsm_vault_storage_size(sizeof(wt_rollback_table_t))

static psa_status_t wt_hsm_vault_admit(uint32_t need_size,
                                       uint16_t need_objects)
{
    return wt_hsm_vault_reserve_in(g_vault_nvm,
                                   need_size + WT_HSM_VAULT_FLOOR_SIZE,
                                   (uint16_t)(need_objects + 1U));
}
#else
static psa_status_t wt_hsm_vault_reserve(uint32_t need_size,
                                         uint16_t need_objects)
{
    return wt_hsm_vault_reserve_in(g_vault_nvm, need_size, need_objects);
}
#endif

/* Object-add reservation for the native key backend: reserve the object's
 * bytes plus the counter-table headroom, and two directory entries (the add
 * plus one kept free) so a later sealed write's counter-table create always
 * has a slot (WT-FFM-0048). Exported for keyvault.c. */
psa_status_t wt_hsm_vault_reserve_object_in(whNvmContext* nvm, whNvmSize len)
{
    if (nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#if defined(WT_NVM_STORE_NATIVE)
    /* Same headroom as a storage create: a later sealed pair still fits. */
    return wt_hsm_vault_reserve_in(nvm, wt_hsm_vault_storage_size(len) +
        wt_hsm_vault_storage_size(sizeof(wt_hsm_vault_table_t)) +
        WT_HSM_VAULT_FLOOR_SIZE, 3U);
#else
    return wt_hsm_vault_reserve_in(nvm,
        wt_hsm_vault_storage_size(len) +
            wt_hsm_vault_storage_size(sizeof(wt_hsm_vault_table_t)), 2U);
#endif
}

psa_status_t wt_hsm_vault_reserve_object(whNvmSize len)
{
    return wt_hsm_vault_reserve_object_in(g_vault_nvm, len);
}

psa_status_t wt_hsm_vault_reserve_table_in(whNvmContext* nvm, whNvmId id,
                                           whNvmSize len)
{
    whNvmMetadata meta;
    int rc;

    if (nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    rc = wt_vstore_metadata(nvm, id, &meta);
    if (rc != WH_ERROR_OK && rc != WH_ERROR_NOTFOUND) {
        return wt_hsm_vault_map_err(rc);
    }
    /* A first create keeps room for one more copy so the next supersede can
     * land before the old copy becomes reclaimable. */
    return wt_hsm_vault_reserve_in(nvm,
        wt_hsm_vault_storage_size(len) * ((rc == WH_ERROR_NOTFOUND) ? 2U : 1U),
        (rc == WH_ERROR_NOTFOUND) ? 2U : 1U);
}

#if !defined(WT_NVM_STORE_NATIVE)
static psa_status_t wt_hsm_vault_table_store(const wt_hsm_vault_table_t* table)
{
    whNvmMetadata meta;
    psa_status_t status;
    int rc;

    status = wt_hsm_vault_reserve(
        wt_hsm_vault_storage_size(sizeof(*table)), 1U);
    if (status != PSA_SUCCESS) {
        return status;
    }
    (void)memset(&meta, 0, sizeof(meta));
    meta.id = WT_HSM_VAULT_TABLE_ID;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags = 0U;
    meta.len = (whNvmSize)sizeof(*table);
    rc = wt_vstore_add(g_vault_nvm, &meta, (whNvmSize)sizeof(*table),
                       (const uint8_t*)table);
    return (rc == WH_ERROR_OK) ? PSA_SUCCESS : PSA_ERROR_STORAGE_FAILURE;
}
#endif

void wt_hsm_vault_make_label(uint8_t* label, int32_t owner, int32_t sub,
                             uint64_t uid, uint32_t flags)
{
    uint32_t magic = WT_HSM_VAULT_LABEL_MAGIC;

    (void)memset(label, 0, WH_NVM_LABEL_LEN);
    (void)memcpy(label, &magic, sizeof(magic));
    (void)memcpy(label + 4, &owner, sizeof(owner));
    (void)memcpy(label + 8, &uid, sizeof(uid));
    (void)memcpy(label + 16, &flags, sizeof(flags));
    (void)memcpy(label + 20, &sub, sizeof(sub));
}

/* key selects the namespace: WT_VAULT_FLAG_KEY for key objects, 0 for
 * storage objects, so neither face can see or squat the other's triples. */
static int wt_hsm_vault_label_match(const uint8_t* label, uint32_t key,
                                    int32_t owner, int32_t sub, uint64_t uid)
{
    uint32_t magic;
    uint32_t flags;
    int32_t l_owner;
    int32_t l_sub;
    uint64_t l_uid;

    (void)memcpy(&magic, label, sizeof(magic));
    (void)memcpy(&l_owner, label + 4, sizeof(l_owner));
    (void)memcpy(&l_uid, label + 8, sizeof(l_uid));
    (void)memcpy(&flags, label + 16, sizeof(flags));
    (void)memcpy(&l_sub, label + 20, sizeof(l_sub));
    return magic == WT_HSM_VAULT_LABEL_MAGIC &&
           (flags & WT_VAULT_FLAG_KEY) == key && l_owner == owner &&
           l_sub == sub && l_uid == uid;
}

uint32_t wt_hsm_vault_flags_of(const uint8_t* label)
{
    uint32_t flags;

    (void)memcpy(&flags, label + 16, sizeof(flags));
    return flags;
}

static psa_status_t wt_hsm_vault_read_sealed(whNvmId id,
                                              const whNvmMetadata* meta,
                                              uint64_t counter)
{
    size_t pt_len;
    psa_status_t status;

    if (g_vault_sealer == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (counter == 0U ||
            (wt_hsm_vault_flags_of(meta->label) &
             WT_VAULT_FLAG_SEALED) == 0U ||
            meta->len < WT_VAULT_SEAL_TAG_LEN ||
            meta->len > sizeof(g_vault_ct)) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    status = wt_hsm_vault_map_err(
        wt_vstore_read_checked(g_vault_nvm, id, 0U, meta->len, g_vault_ct));
    if (status != PSA_SUCCESS) {
        return status;
    }
    pt_len = (size_t)meta->len - WT_VAULT_SEAL_TAG_LEN;
    status = g_vault_sealer->unseal(meta->label, WH_NVM_LABEL_LEN, counter,
                                    g_vault_ct, meta->len, g_vault_ct);
    if (status != PSA_SUCCESS) {
        wt_hsm_vault_zeroize(g_vault_ct, pt_len);
    }
    return status;
}

#if !defined(WT_NVM_STORE_NATIVE)
static psa_status_t wt_hsm_vault_destroy_stage(void)
{
    whNvmMetadata meta;
    whNvmId id = WT_HSM_VAULT_STAGE_ID;
    int rc;

    rc = wt_vstore_metadata(g_vault_nvm, id, &meta);
    if (rc == WH_ERROR_NOTFOUND) {
        return PSA_SUCCESS;
    }
    if (rc != WH_ERROR_OK) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    return wt_hsm_vault_map_err(
        wt_vstore_destroy(g_vault_nvm, 1U, &id));
}

static psa_status_t wt_hsm_vault_recover_live(wt_hsm_vault_table_t* table)
{
    whNvmMetadata meta;
    uint32_t slot = table->reserved - 1U;
    whNvmId id = (whNvmId)(WT_HSM_VAULT_ID_BASE + slot);
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;
    int rc;

    rc = wt_vstore_metadata(g_vault_nvm, id, &meta);
    if (rc == WH_ERROR_OK) {
        status = wt_hsm_vault_read_sealed(id, &meta, table->slot[slot]);
    }
    else if (rc != WH_ERROR_NOTFOUND) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    if (status == PSA_SUCCESS) {
        wt_hsm_vault_zeroize(g_vault_ct,
                            (size_t)meta.len - WT_VAULT_SEAL_TAG_LEN);
    }
    else if (status == PSA_ERROR_INVALID_SIGNATURE ||
             status == PSA_ERROR_NOT_PERMITTED ||
             status == PSA_ERROR_DOES_NOT_EXIST) {
        if (rc == WH_ERROR_OK) {
            /* The uncommitted replacement may carry WRITE_ONCE. */
            status = wt_hsm_vault_map_err(
                wt_vstore_destroy(g_vault_nvm, 1U, &id));
            if (status != PSA_SUCCESS) {
                return status;
            }
        }
        table->slot[slot] = 0U;
    }
    else {
        return status;
    }
    table->reserved = 0U;
    status = wt_hsm_vault_table_store(table);
    if (status != PSA_SUCCESS) {
        return status;
    }
    return wt_hsm_vault_destroy_stage();
}

static psa_status_t wt_hsm_vault_recover(wt_hsm_vault_table_t* table)
{
    whNvmMetadata meta;
    whNvmMetadata stage_meta;
    whNvmId id;
    uint32_t slot;
    uint32_t label_magic;
    size_t pt_len;
    psa_status_t status;

    if (table->reserved > WT_HSM_VAULT_DELETE_MARKER_BASE) {
        slot = table->reserved - WT_HSM_VAULT_DELETE_MARKER_BASE - 1U;
        id = (whNvmId)(WT_HSM_VAULT_ID_BASE + slot);
        status = wt_hsm_vault_map_err(
            wt_vstore_metadata(g_vault_nvm, id, &meta));
        if (status == PSA_SUCCESS) {
            (void)memcpy(&label_magic, meta.label, sizeof(label_magic));
            /* Only the key writer bypasses table recovery. Preserve a key
             * that reused the slot; reclaim the old sealed object even if
             * its ciphertext is corrupt and cannot be authenticated. */
            if (label_magic != WT_HSM_VAULT_LABEL_MAGIC ||
                    (wt_hsm_vault_flags_of(meta.label) &
                     WT_VAULT_FLAG_KEY) == 0U ||
                    (wt_hsm_vault_flags_of(meta.label) &
                     WT_VAULT_FLAG_SEALED) != 0U ||
                    (meta.flags & WH_NVM_FLAGS_NONEXPORTABLE) == 0U) {
                status = wt_hsm_vault_map_err(
                    wt_vstore_destroy_checked(g_vault_nvm, 1U, &id));
                if (status != PSA_SUCCESS &&
                        status != PSA_ERROR_DOES_NOT_EXIST) {
                    return status;
                }
            }
        }
        else if (status != PSA_SUCCESS &&
                 status != PSA_ERROR_DOES_NOT_EXIST) {
            return status;
        }
        table->slot[slot] = 0U;
        table->reserved = 0U;
        return wt_hsm_vault_table_store(table);
    }
    if (table->reserved == 0U) {
        return wt_hsm_vault_destroy_stage();
    }
    slot = table->reserved - 1U;
    id = (whNvmId)(WT_HSM_VAULT_ID_BASE + slot);
    status = wt_hsm_vault_map_err(
        wt_vstore_metadata(g_vault_nvm, WT_HSM_VAULT_STAGE_ID, &stage_meta));
    if (status == PSA_SUCCESS) {
        /* Live metadata may be torn; the committed counter binds the stage. */
        status = wt_hsm_vault_read_sealed(WT_HSM_VAULT_STAGE_ID,
                                           &stage_meta, table->slot[slot]);
    }
    if (status == PSA_ERROR_DOES_NOT_EXIST ||
            status == PSA_ERROR_NOT_PERMITTED ||
            status == PSA_ERROR_INVALID_SIGNATURE) {
        return wt_hsm_vault_recover_live(table);
    }
    if (status != PSA_SUCCESS) {
        return status;
    }
    pt_len = (size_t)stage_meta.len - WT_VAULT_SEAL_TAG_LEN;
    wt_hsm_vault_zeroize(g_vault_ct, pt_len);
    meta = stage_meta;
    meta.id = id;
    meta.flags = WH_NVM_FLAGS_SENSITIVE;
    status = wt_hsm_vault_reserve(
        wt_hsm_vault_storage_size(meta.len) +
            wt_hsm_vault_storage_size(sizeof(*table)),
        2U);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = wt_hsm_vault_map_err(
        wt_vstore_read_checked(g_vault_nvm, WT_HSM_VAULT_STAGE_ID, 0U, meta.len,
                               g_vault_ct));
    /* The uncommitted replacement may already carry WRITE_ONCE. */
    if (status == PSA_SUCCESS) {
        status = wt_hsm_vault_map_err(
            wt_vstore_add(g_vault_nvm, &meta, meta.len, g_vault_ct));
    }
    wt_hsm_vault_zeroize(g_vault_ct, sizeof(g_vault_ct));
    if (status != PSA_SUCCESS) {
        return status;
    }
    table->reserved = 0U;
    status = wt_hsm_vault_table_store(table);
    if (status != PSA_SUCCESS) {
        return status;
    }
    return wt_hsm_vault_destroy_stage();
}
#endif

/* Shared directory lookup for confined vault backends: find the
 * (owner, sub, uid) object in the vault id window. Returns PSA_SUCCESS
 * with the id + metadata, or PSA_ERROR_DOES_NOT_EXIST. out_free_id receives
 * the lowest unused id in the window (WH_NVM_ID_INVALID when full). */
static psa_status_t wt_hsm_vault_find_in(whNvmContext* nvm, uint32_t key,
                                         int32_t owner, int32_t sub,
                                         uint64_t uid, whNvmId* out_id,
                                         whNvmMetadata* out_meta,
                                         whNvmId* out_free_id)
{
    whNvmMetadata meta;
    whNvmId id;
    whNvmId free_id = WH_NVM_ID_INVALID;
    uint32_t i;
    int rc;
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    if (nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    for (i = 0U; i < WT_HSM_VAULT_ID_COUNT; i++) {
        id = (whNvmId)(WT_HSM_VAULT_ID_BASE + i);
        rc = wt_vstore_metadata(nvm, id, &meta);
        if (rc == WH_ERROR_NOTFOUND) {
            if (free_id == WH_NVM_ID_INVALID) {
                free_id = id;
            }
        }
        else if (rc == WH_ERROR_OK) {
            if (wt_hsm_vault_label_match(meta.label, key, owner, sub,
                                         uid)) {
                if (out_id != NULL) {
                    *out_id = id;
                }
                if (out_meta != NULL) {
                    *out_meta = meta;
                }
                status = PSA_SUCCESS;
                break;
            }
        }
        else {
            status = PSA_ERROR_STORAGE_FAILURE;
            break;
        }
    }
    if (out_free_id != NULL) {
        *out_free_id = free_id;
    }
    return status;
}

psa_status_t wt_hsm_vault_lookup_in(whNvmContext* nvm, int32_t owner,
                                    int32_t sub, uint64_t uid,
                                    whNvmId* out_id, whNvmMetadata* out_meta,
                                    whNvmId* out_free_id)
{
    return wt_hsm_vault_find_in(nvm, 0U, owner, sub, uid, out_id, out_meta,
                                out_free_id);
}

psa_status_t wt_hsm_vault_lookup(int32_t owner, int32_t sub, uint64_t uid,
                                 whNvmId* out_id, whNvmMetadata* out_meta,
                                 whNvmId* out_free_id)
{
    return wt_hsm_vault_lookup_in(g_vault_nvm, owner, sub, uid, out_id,
                                  out_meta, out_free_id);
}

static psa_status_t wt_hsm_vault_map_err(int rc)
{
    psa_status_t status;

    switch (rc) {
    case WH_ERROR_OK:
        status = PSA_SUCCESS;
        break;
    case WH_ERROR_ACCESS:
        status = PSA_ERROR_NOT_PERMITTED;
        break;
    case WH_ERROR_NOSPACE:
        status = PSA_ERROR_INSUFFICIENT_STORAGE;
        break;
    case WH_ERROR_NOTFOUND:
        status = PSA_ERROR_DOES_NOT_EXIST;
        break;
    default:
        status = PSA_ERROR_STORAGE_FAILURE;
        break;
    }
    return status;
}

/* Load the counter table (running recovery) and find the caller's object. */
static psa_status_t wt_hsm_vault_open(wt_hsm_vault_table_t* table,
                                      int32_t owner, int32_t sub,
                                      uint64_t uid, whNvmId* id,
                                      whNvmMetadata* meta, whNvmId* free_id)
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    if (g_vault_nvm != NULL) {
        status = wt_hsm_vault_table_load(table);
        if (status == PSA_SUCCESS) {
            status = wt_hsm_vault_lookup(owner, sub, uid, id, meta, free_id);
        }
    }
    return status;
}

#if !defined(WT_NVM_STORE_NATIVE)
static psa_status_t wt_hsm_vault_set(int32_t owner, int32_t sub,
                                     uint64_t uid, uint32_t flags,
                                     const uint8_t* data, size_t len)
{
    whNvmMetadata meta;
    whNvmMetadata stage_meta;
    wt_hsm_vault_table_t table;
    whNvmId id = WH_NVM_ID_INVALID;
    whNvmId free_id = WH_NVM_ID_INVALID;
    uint32_t slot = 0U;
    uint32_t need_size;
    uint64_t counter = 0U;
    whNvmSize store_len;
    const uint8_t* store_data;
    psa_status_t status;
    int replacement = 0;
    int created = 0;

    if (g_vault_nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (len > WT_VAULT_OBJECT_MAX ||
            (flags & ~(uint32_t)WT_HSM_VAULT_FLAG_MASK) != 0U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((flags & WT_VAULT_FLAG_SEALED) != 0U && g_vault_sealer == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    status = wt_hsm_vault_open(&table, owner, sub, uid, &id, &meta, &free_id);
    if (status == PSA_SUCCESS) {
        /* A storage SET must never overwrite a key object (WT-FFM-0046),
         * and honours WRITE_ONCE before any backend write; the *Checked add
         * enforces the same policy at the NVM layer. */
        if ((wt_hsm_vault_flags_of(meta.label) &
                (WT_VAULT_FLAG_KEY | WT_VAULT_FLAG_WRITE_ONCE)) != 0U) {
            return PSA_ERROR_NOT_PERMITTED;
        }
        replacement =
            (wt_hsm_vault_flags_of(meta.label) &
             WT_VAULT_FLAG_SEALED) != 0U;
    }
    else if (status == PSA_ERROR_DOES_NOT_EXIST) {
        if (free_id == WH_NVM_ID_INVALID) {
            return PSA_ERROR_INSUFFICIENT_STORAGE;
        }
        id = free_id;
        created = 1;
    }
    else {
        return status;
    }

    slot = id - WT_HSM_VAULT_ID_BASE;
    store_data = data;
    store_len = (whNvmSize)len;
    if ((flags & WT_VAULT_FLAG_SEALED) != 0U) {
        store_len = (whNvmSize)(len + WT_VAULT_SEAL_TAG_LEN);
    }
    if (replacement != 0) {
        status = wt_hsm_vault_read_sealed(id, &meta, table.slot[slot]);
        if (status == PSA_ERROR_INVALID_SIGNATURE) {
            replacement = 0;
        }
        else if (status != PSA_SUCCESS) {
            return status;
        }
        else {
            wt_hsm_vault_zeroize(
                g_vault_ct, (size_t)meta.len - WT_VAULT_SEAL_TAG_LEN);
        }
    }
    need_size = wt_hsm_vault_storage_size(store_len) +
                wt_hsm_vault_storage_size(sizeof(table));
    if (replacement != 0) {
        need_size += 2U * wt_hsm_vault_storage_size(meta.len) +
                     wt_hsm_vault_storage_size(sizeof(table));
        status = wt_hsm_vault_reserve(need_size, 4U);
    }
    else {
        /* A new object keeps one entry free, as the object reservation does,
         * so a later sealed remove can still update the table; an unsealed
         * overwrite needs only the append, its old copy becomes reclaimable. */
        status = wt_hsm_vault_reserve(
            need_size,
            (uint16_t)(((flags & WT_VAULT_FLAG_SEALED) != 0U ||
                        table.slot[slot] != 0U || created != 0) ? 2U : 1U));
    }
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (replacement != 0) {
        stage_meta = meta;
        stage_meta.id = WT_HSM_VAULT_STAGE_ID;
        stage_meta.flags = WH_NVM_FLAGS_SENSITIVE;
    }
    (void)memset(&meta, 0, sizeof(meta));
    meta.id = id;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags = WH_NVM_FLAGS_SENSITIVE;
    if ((flags & WT_VAULT_FLAG_WRITE_ONCE) != 0U) {
        meta.flags |= WH_NVM_FLAGS_NONMODIFIABLE |
                      WH_NVM_FLAGS_NONDESTROYABLE;
    }
    wt_hsm_vault_make_label(meta.label, owner, sub, uid, flags);
    if ((flags & WT_VAULT_FLAG_SEALED) != 0U) {
        /* Persist the bumped counter before any ciphertext exists so a power
         * loss can never repeat a GCM nonce (WT-FFM-0048). */
        table.global++;
        counter = table.global;
    }
    if (replacement != 0 || (flags & WT_VAULT_FLAG_SEALED) != 0U ||
            table.slot[slot] != 0U) {
        if (replacement != 0) {
            table.reserved = slot + 1U;
        }
        else {
            table.slot[slot] = counter;
        }
        status = wt_hsm_vault_table_store(&table);
        if (status != PSA_SUCCESS) {
            return status;
        }
    }
    if (replacement != 0) {
        status = wt_hsm_vault_map_err(
            wt_vstore_read_checked(g_vault_nvm, id, 0U, stage_meta.len,
                                   g_vault_ct));
        if (status == PSA_SUCCESS) {
            status = wt_hsm_vault_map_err(
                wt_vstore_add(g_vault_nvm, &stage_meta, stage_meta.len,
                              g_vault_ct));
        }
        wt_hsm_vault_zeroize(g_vault_ct, sizeof(g_vault_ct));
        if (status != PSA_SUCCESS) {
            return status;
        }
    }
    if ((flags & WT_VAULT_FLAG_SEALED) != 0U) {
        status = g_vault_sealer->seal(meta.label, WH_NVM_LABEL_LEN,
                                      counter, data, len, g_vault_ct);
        if (status != PSA_SUCCESS) {
            return status;
        }
        store_data = g_vault_ct;
    }
    meta.len = store_len;
    status = wt_hsm_vault_map_err(
        wt_vstore_add_checked(g_vault_nvm, &meta, store_len, store_data));
    if (store_data == g_vault_ct) {
        wt_hsm_vault_zeroize(g_vault_ct, sizeof(g_vault_ct));
    }
    if (status != PSA_SUCCESS || replacement == 0) {
        return status;
    }
    table.slot[slot] = counter;
    table.reserved = 0U;
    status = wt_hsm_vault_table_store(&table);
    if (status != PSA_SUCCESS) {
        return status;
    }
    return wt_hsm_vault_destroy_stage();
}
#endif

static psa_status_t wt_hsm_vault_get(int32_t owner, int32_t sub,
                                     uint64_t uid, uint32_t offset,
                                     uint8_t* data, size_t size,
                                     size_t* out_len)
{
    whNvmMetadata meta;
    wt_hsm_vault_table_t table;
    whNvmId id = WH_NVM_ID_INVALID;
    size_t n;
    size_t pt_len;
    psa_status_t status;

    status = wt_hsm_vault_open(&table, owner, sub, uid, &id, &meta, NULL);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if ((wt_hsm_vault_flags_of(meta.label) & WT_VAULT_FLAG_KEY) != 0U) {
        /* Key material is never readable through the storage face
         * (WT-FFM-0046); the NVM NONEXPORTABLE flag enforces the same at
         * the *Checked layer. */
        return PSA_ERROR_NOT_PERMITTED;
    }
    if ((wt_hsm_vault_flags_of(meta.label) & WT_VAULT_FLAG_SEALED) != 0U) {
        if (table.slot[id - WT_HSM_VAULT_ID_BASE] == 0U) {
            /* A sealed object with no live counter is a rolled-back or
             * resurrected ciphertext — fail closed. */
            return PSA_ERROR_INVALID_SIGNATURE;
        }
        status = wt_hsm_vault_read_sealed(
            id, &meta, table.slot[id - WT_HSM_VAULT_ID_BASE]);
        if (status != PSA_SUCCESS) {
            return status;
        }
        pt_len = (size_t)meta.len - WT_VAULT_SEAL_TAG_LEN;
        if (offset > pt_len) {
            wt_hsm_vault_zeroize(g_vault_ct, pt_len);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        n = pt_len - offset;
        if (n > size) {
            n = size;
        }
        if (n > 0U) {
            (void)memcpy(data, g_vault_ct + offset, n);
        }
        wt_hsm_vault_zeroize(g_vault_ct, pt_len);
        *out_len = n;
        return PSA_SUCCESS;
    }
    if (offset > meta.len) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    n = (size_t)meta.len - offset;
    if (n > size) {
        n = size;
    }
    if (n > 0U) {
        status = wt_hsm_vault_map_err(
            wt_vstore_read_checked(g_vault_nvm, id, (whNvmSize)offset,
                                   (whNvmSize)n, data));
        if (status != PSA_SUCCESS) {
            return status;
        }
    }
    *out_len = n;
    return PSA_SUCCESS;
}

static psa_status_t wt_hsm_vault_get_info(int32_t owner, int32_t sub,
                                          uint64_t uid, wt_vault_info_t* info)
{
    whNvmMetadata meta;
    wt_hsm_vault_table_t table;
    psa_status_t status;

    status = wt_hsm_vault_open(&table, owner, sub, uid, NULL, &meta, NULL);
    if (status != PSA_SUCCESS) {
        return status;
    }
    info->capacity = meta.len;
    info->size = meta.len;
    info->flags = wt_hsm_vault_flags_of(meta.label);
    if ((info->flags & WT_VAULT_FLAG_SEALED) != 0U) {
        if (meta.len < WT_VAULT_SEAL_TAG_LEN) {
            return PSA_ERROR_STORAGE_FAILURE;
        }
        info->capacity = meta.len - WT_VAULT_SEAL_TAG_LEN;
        info->size = info->capacity;
    }
    info->reserved = 0U;
    return PSA_SUCCESS;
}

#if !defined(WT_NVM_STORE_NATIVE)
static psa_status_t wt_hsm_vault_remove(int32_t owner, int32_t sub,
                                        uint64_t uid)
{
    whNvmMetadata meta;
    wt_hsm_vault_table_t table;
    whNvmId id = WH_NVM_ID_INVALID;
    uint32_t flags;
    psa_status_t status;

    status = wt_hsm_vault_open(&table, owner, sub, uid, &id, &meta, NULL);
    if (status != PSA_SUCCESS) {
        return status;
    }
    flags = wt_hsm_vault_flags_of(meta.label);
    if ((flags & WT_VAULT_FLAG_KEY) != 0U ||
            (flags & WT_VAULT_FLAG_WRITE_ONCE) != 0U) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if ((flags & WT_VAULT_FLAG_SEALED) != 0U) {
        /* No extra reservation: removal must work on a full store, and the
         * compacting destroy frees room for the final table update. */
        table.reserved = WT_HSM_VAULT_DELETE_MARKER_BASE +
                         (id - WT_HSM_VAULT_ID_BASE) + 1U;
        status = wt_hsm_vault_table_store(&table);
        if (status != PSA_SUCCESS) {
            return status;
        }
    }
    status = wt_hsm_vault_map_err(
        wt_vstore_destroy_checked(g_vault_nvm, 1U, &id));
    if (status != PSA_SUCCESS) {
        if ((flags & WT_VAULT_FLAG_SEALED) != 0U &&
                wt_vstore_metadata(g_vault_nvm, id, &meta) == WH_ERROR_OK &&
                wt_hsm_vault_label_match(meta.label, 0U, owner, sub, uid) !=
                    0 &&
                wt_hsm_vault_read_sealed(
                    id, &meta, table.slot[id - WT_HSM_VAULT_ID_BASE]) ==
                    PSA_SUCCESS) {
            /* The original object survived intact, so cancel the deletion. */
            wt_hsm_vault_zeroize(
                g_vault_ct, (size_t)meta.len - WT_VAULT_SEAL_TAG_LEN);
            table.reserved = 0U;
            if (wt_hsm_vault_table_store(&table) != PSA_SUCCESS) {
                return PSA_ERROR_STORAGE_FAILURE;
            }
        }
        return status;
    }
    if ((flags & WT_VAULT_FLAG_SEALED) != 0U) {
        table.slot[id - WT_HSM_VAULT_ID_BASE] = 0U;
        table.reserved = 0U;
        return wt_hsm_vault_table_store(&table);
    }
    return PSA_SUCCESS;
}
#endif

#if defined(WT_NVM_STORE_NATIVE)
static void wt_hsm_vault_table_meta(whNvmMetadata* meta)
{
    (void)memset(meta, 0, sizeof(*meta));
    meta->id = WT_HSM_VAULT_TABLE_ID;
    meta->access = WH_NVM_ACCESS_ANY;
    meta->len = (whNvmSize)sizeof(wt_hsm_vault_table_t);
}

/* Commit a table: alone, paired with obj (both visible or neither), or in the
 * compaction that drops drop. issued never goes down. */
static psa_status_t wt_hsm_vault_commit(whNvmMetadata* obj,
                                        const uint8_t* data,
                                        wt_hsm_vault_table_t* table,
                                        whNvmId drop)
{
    whNvmMetadata meta;
    uint64_t issued = 0U;
    int rc;

    rc = wt_vstore_read(g_vault_nvm, WT_HSM_VAULT_TABLE_ID,
                        (whNvmSize)offsetof(wt_hsm_vault_table_t, global),
                        (whNvmSize)sizeof(issued), (uint8_t*)&issued);
    if (rc == WH_ERROR_OK && table->global < issued) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    if (rc == WH_ERROR_NOTFOUND) {
        rc = WH_ERROR_OK;
    }
    if (rc == WH_ERROR_OK && obj != NULL) {
        rc = wt_vstore_policy(g_vault_nvm, obj->id,
                              WH_NVM_FLAGS_NONMODIFIABLE);
        rc = (rc == WH_ERROR_NOTFOUND) ? WH_ERROR_OK : rc;
    }
    if (rc == WH_ERROR_OK && drop != WH_NVM_ID_INVALID) {
        rc = wt_vstore_policy(g_vault_nvm, drop, WH_NVM_FLAGS_NONMODIFIABLE |
                                                 WH_NVM_FLAGS_NONDESTROYABLE);
    }
    if (rc != WH_ERROR_OK) {
        return wt_hsm_vault_map_err(rc);
    }
    wt_hsm_vault_table_meta(&meta);
    if (drop != WH_NVM_ID_INVALID) {
        rc = wt_vstore_compact_with(g_vault_nvm, drop, &meta,
                                    (const uint8_t*)table);
    }
    else if (obj != NULL) {
        rc = wt_vstore_add_pair(g_vault_nvm, obj, data, &meta,
                                (const uint8_t*)table);
    }
    else {
        rc = wt_vstore_add(g_vault_nvm, &meta, meta.len,
                           (const uint8_t*)table);
    }
    return wt_hsm_vault_map_err(rc);
}

static psa_status_t wt_hsm_vault_set(int32_t owner, int32_t sub,
                                     uint64_t uid, uint32_t flags,
                                     const uint8_t* data, size_t len)
{
    whNvmMetadata meta;
    wt_hsm_vault_table_t table;
    whNvmId id = WH_NVM_ID_INVALID;
    whNvmId free_id = WH_NVM_ID_INVALID;
    uint32_t slot;
    uint32_t need_size;
    uint16_t need_objects = 1U;
    uint64_t counter;
    int sealed = (flags & WT_VAULT_FLAG_SEALED) != 0U;
    int created = 0;
    int reserve = 0;
    psa_status_t status;

    if (g_vault_nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (len > WT_VAULT_OBJECT_MAX ||
            (flags & ~(uint32_t)WT_HSM_VAULT_FLAG_MASK) != 0U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (sealed != 0 && g_vault_sealer == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    status = wt_hsm_vault_open(&table, owner, sub, uid, &id, &meta, &free_id);
    if (status == PSA_SUCCESS) {
        /* A storage SET must never overwrite a key object (WT-FFM-0046),
         * and honours WRITE_ONCE before any backend write. */
        if ((wt_hsm_vault_flags_of(meta.label) &
                (WT_VAULT_FLAG_KEY | WT_VAULT_FLAG_WRITE_ONCE)) != 0U) {
            return PSA_ERROR_NOT_PERMITTED;
        }
    }
    else if (status == PSA_ERROR_DOES_NOT_EXIST &&
             free_id != WH_NVM_ID_INVALID) {
        id = free_id;
        created = 1;
    }
    else {
        return (status == PSA_ERROR_DOES_NOT_EXIST) ?
               PSA_ERROR_INSUFFICIENT_STORAGE : status;
    }
    slot = id - WT_HSM_VAULT_ID_BASE;
    (void)memset(&meta, 0, sizeof(meta));
    meta.id = id;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags = WH_NVM_FLAGS_SENSITIVE;
    if ((flags & WT_VAULT_FLAG_WRITE_ONCE) != 0U) {
        meta.flags |= WH_NVM_FLAGS_NONMODIFIABLE |
                      WH_NVM_FLAGS_NONDESTROYABLE;
    }
    meta.len = (whNvmSize)(len + ((sealed != 0) ? WT_VAULT_SEAL_TAG_LEN : 0U));
    wt_hsm_vault_make_label(meta.label, owner, sub, uid, flags);

    need_size = wt_hsm_vault_storage_size(meta.len);
    /* A new object leaves a table's worth of room, so on a full store an
     * object stays overwritable with a value of up to its stored size. */
    if (sealed != 0 || table.slot[slot] != 0U || created != 0) {
        need_size += wt_hsm_vault_storage_size(sizeof(table));
        need_objects = 2U;
    }
    if (sealed != 0) {
        if (table.global > UINT64_MAX - 2U * WT_VAULT_COUNTER_RANGE) {
            return PSA_ERROR_INSUFFICIENT_STORAGE;
        }
        /* The first seal after a bind or a failure reserves a fresh range
         * from the committed table: counters up to global may be used. */
        reserve = (g_vault_counted == 0U || g_vault_next > table.global);
        if (reserve != 0) {
            need_size += wt_hsm_vault_storage_size(sizeof(table));
            need_objects++;
        }
    }
    status = wt_hsm_vault_admit(need_size, need_objects);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (reserve != 0) {
        /* Never restart below a counter this bind already handed out. */
        if (g_vault_counted != 0U && g_vault_next > table.global + 1U) {
            table.global = g_vault_next - 1U;
        }
        g_vault_counted = 0U;
        counter = table.global + 1U;
        table.global += WT_VAULT_COUNTER_RANGE;
        status = wt_hsm_vault_commit(NULL, NULL, &table, WH_NVM_ID_INVALID);
        if (status != PSA_SUCCESS) {
            return status;
        }
        g_vault_next = counter;
        g_vault_counted = 1U;
    }
    if (sealed == 0) {
        if (table.slot[slot] == 0U) {
            return wt_hsm_vault_map_err(
                wt_vstore_add_checked(g_vault_nvm, &meta, meta.len, data));
        }
        table.slot[slot] = 0U;
        return wt_hsm_vault_commit(&meta, data, &table, WH_NVM_ID_INVALID);
    }
    counter = g_vault_next++;
    status = g_vault_sealer->seal(meta.label, WH_NVM_LABEL_LEN, counter,
                                  data, len, g_vault_ct);
    if (status == PSA_SUCCESS) {
        table.slot[slot] = counter;
        if (table.global < counter + WT_VAULT_COUNTER_RANGE) {
            table.global = counter + WT_VAULT_COUNTER_RANGE;
        }
        status = wt_hsm_vault_commit(&meta, g_vault_ct, &table,
                                     WH_NVM_ID_INVALID);
    }
    wt_hsm_vault_zeroize(g_vault_ct, sizeof(g_vault_ct));
    if (status != PSA_SUCCESS) {
        g_vault_counted = 0U;
    }
    return status;
}

static psa_status_t wt_hsm_vault_remove(int32_t owner, int32_t sub,
                                        uint64_t uid)
{
    whNvmMetadata meta;
    wt_hsm_vault_table_t table;
    whNvmId id = WH_NVM_ID_INVALID;
    uint32_t slot;
    psa_status_t status;

    status = wt_hsm_vault_open(&table, owner, sub, uid, &id, &meta, NULL);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if ((wt_hsm_vault_flags_of(meta.label) &
            (WT_VAULT_FLAG_KEY | WT_VAULT_FLAG_WRITE_ONCE)) != 0U) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    slot = id - WT_HSM_VAULT_ID_BASE;
    if (table.slot[slot] == 0U &&
            (wt_hsm_vault_flags_of(meta.label) & WT_VAULT_FLAG_SEALED) == 0U) {
        return wt_hsm_vault_map_err(
            wt_vstore_destroy_checked(g_vault_nvm, 1U, &id));
    }
    /* One compaction drops the object and clears its counter, so it needs no
     * space beyond the live set and a full store can still delete. */
    table.slot[slot] = 0U;
    return wt_hsm_vault_commit(NULL, NULL, &table, id);
}


int wt_hsm_vault_seal_key_add(whNvmContext* nvm, whNvmMetadata* meta,
                              const uint8_t* key)
{
    wt_hsm_vault_table_t table;
    whNvmMetadata table_meta;
    whNvmId objects = 0U;
    whNvmId reclaim = 0U;
    int rc;

    if (nvm == NULL || meta == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* The key is only ever created on a store with no live record (a torn
     * first-boot pair counts as none); a populated store missing it is not
     * given a new one. */
    rc = wt_vstore_available(nvm, NULL, &objects, NULL, &reclaim);
    if (rc == WH_ERROR_OK &&
            (uint32_t)objects + (uint32_t)reclaim != WT_NVS_SLOTS) {
        rc = WH_ERROR_ABORTED;
    }
    if (rc == WH_ERROR_OK) {
        (void)memset(&table, 0, sizeof(table));
        table.magic = WT_HSM_VAULT_TABLE_MAGIC;
        wt_hsm_vault_table_meta(&table_meta);
        rc = wt_vstore_add_pair(nvm, meta, key, &table_meta,
                                (const uint8_t*)&table);
    }
    return rc;
}

int wt_hsm_vault_table_check(whNvmContext* nvm)
{
    wt_hsm_vault_table_t table;

    return wt_hsm_vault_table_read(nvm, &table, WT_HSM_VAULT_TABLE_MAGIC);
}

int wt_hsm_vault_floors_provisioned(void)
{
    wt_hsm_vault_table_t table;

    if (wt_hsm_vault_table_load(&table) != PSA_SUCCESS) {
        return -1;
    }
    return ((table.reserved & WT_HSM_VAULT_FLOORS_SET) != 0U) ? 1 : 0;
}

int wt_hsm_vault_floors_mark(void)
{
    wt_hsm_vault_table_t table;

    if (wt_vstore_metadata(g_vault_nvm, WT_HSM_ROLLBACK_TABLE_ID, NULL) !=
            WH_ERROR_OK) {
        return 0;
    }
    if (wt_hsm_vault_table_load(&table) != PSA_SUCCESS) {
        return -1;
    }
    if ((table.reserved & WT_HSM_VAULT_FLOORS_SET) != 0U) {
        return 0;
    }
    table.reserved |= WT_HSM_VAULT_FLOORS_SET;
    return (wt_hsm_vault_commit(NULL, NULL, &table, WH_NVM_ID_INVALID) ==
            PSA_SUCCESS) ? 0 : -1;
}
#endif

const wt_vault_backend_t wt_hsm_vault_backend = {
    wt_hsm_vault_set,
    wt_hsm_vault_get,
    wt_hsm_vault_get_info,
    wt_hsm_vault_remove
};

#if !defined(WT_ENGINE_NATIVE)
/* Keystore object door (isolation level 3). The crypto partition's wolfHSM
 * keystore ids carry a non-zero type nibble and never collide with the
 * vault window; its native key objects live in the window under the key
 * flag. Everything else in the store (storage front-end objects, the
 * directory table, the seal key, the rollback table, the stage object) is
 * invisible through the door. */
static int wt_hsm_vault_nvm_label_is_key(const uint8_t* label)
{
    uint32_t magic;

    (void)memcpy(&magic, label, sizeof(magic));
    return magic == WT_HSM_VAULT_LABEL_MAGIC &&
           (wt_hsm_vault_flags_of(label) & WT_VAULT_FLAG_KEY) != 0U;
}

/* 2 = keystore namespace, 1 = vault window (key objects only), 0 = never. */
static int wt_hsm_vault_nvm_id_class(whNvmId id)
{
    if ((id & (whNvmId)WH_KEYTYPE_MASK) != 0U) {
        return 2;
    }
    if (id >= WT_HSM_VAULT_ID_BASE &&
            id < (whNvmId)(WT_HSM_VAULT_ID_BASE + WT_HSM_VAULT_ID_COUNT)) {
        return 1;
    }
    return 0;
}

static void wt_hsm_vault_nvm_meta_out(const whNvmMetadata* meta,
                                      wt_vault_nvm_meta_t* out)
{
    (void)memset(out, 0, sizeof(*out));
    out->id = meta->id;
    out->access = meta->access;
    out->flags = meta->flags;
    out->len = meta->len;
    (void)memcpy(out->label, meta->label, WT_VAULT_NVM_LABEL_LEN);
}

/* Fetch an existing object's metadata if the door may see it. */
static psa_status_t wt_hsm_vault_nvm_visible(whNvmId id, whNvmMetadata* meta)
{
    int cls = wt_hsm_vault_nvm_id_class(id);
    int rc;

    if (g_vault_nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (cls == 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    rc = wt_vstore_metadata(g_vault_nvm, id, meta);
    if (rc != WH_ERROR_OK) {
        return wt_hsm_vault_map_err(rc);
    }
    if (cls == 1 && !wt_hsm_vault_nvm_label_is_key(meta->label)) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    return PSA_SUCCESS;
}

static psa_status_t wt_hsm_vault_nvm_get_available(wt_vault_nvm_avail_t* avail)
{
    int rc;

    if (g_vault_nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    rc = wt_vstore_available(g_vault_nvm, &avail->avail_size,
                             &avail->avail_objects, &avail->reclaim_size,
                             &avail->reclaim_objects);
    return wt_hsm_vault_map_err(rc);
}

static psa_status_t wt_hsm_vault_nvm_get_metadata(uint16_t id,
                                                  wt_vault_nvm_meta_t* out)
{
    whNvmMetadata meta;
    psa_status_t status;

    status = wt_hsm_vault_nvm_visible((whNvmId)id, &meta);
    if (status == PSA_ERROR_NOT_PERMITTED &&
            wt_hsm_vault_nvm_id_class((whNvmId)id) == 1) {
        /* A storage object occupies this window slot: report it taken
         * without its label so a key lookup neither matches nor reuses it. */
        (void)memset(out, 0, sizeof(*out));
        out->id = id;
        return PSA_SUCCESS;
    }
    if (status != PSA_SUCCESS) {
        return status;
    }
    wt_hsm_vault_nvm_meta_out(&meta, out);
    return PSA_SUCCESS;
}

static psa_status_t wt_hsm_vault_nvm_add_object(const wt_vault_nvm_meta_t* in,
                                                const uint8_t* data,
                                                size_t len)
{
    whNvmMetadata meta;
    whNvmMetadata occupant;
    psa_status_t status;
    int cls = wt_hsm_vault_nvm_id_class((whNvmId)in->id);
    int rc;

    if (g_vault_nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (cls == 0 || (cls == 1 && !wt_hsm_vault_nvm_label_is_key(in->label))) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (len > WT_VAULT_OBJECT_MAX || in->len != len) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    /* Replacing an object the door cannot see would overwrite a storage
     * front end's data through the keystore namespace. */
    status = wt_hsm_vault_nvm_visible((whNvmId)in->id, &occupant);
    if (status != PSA_SUCCESS && status != PSA_ERROR_DOES_NOT_EXIST) {
        return status;
    }
    status = wt_hsm_vault_reserve_object((whNvmSize)len);
    if (status != PSA_SUCCESS) {
        return status;
    }
    (void)memset(&meta, 0, sizeof(meta));
    meta.id = in->id;
    meta.access = in->access;
    meta.flags = in->flags;
    meta.len = (whNvmSize)len;
    (void)memcpy(meta.label, in->label, WH_NVM_LABEL_LEN);
    rc = wt_vstore_add(g_vault_nvm, &meta, (whNvmSize)len, data);
    return wt_hsm_vault_map_err(rc);
}

static psa_status_t wt_hsm_vault_nvm_destroy(const uint16_t* ids,
                                             size_t count)
{
    whNvmMetadata meta;
    whNvmId list[WT_VAULT_NVM_DESTROY_MAX];
    psa_status_t status;
    size_t i;
    int rc;

    if (g_vault_nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (count > WT_VAULT_NVM_DESTROY_MAX) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    for (i = 0U; i < count; i++) {
        status = wt_hsm_vault_nvm_visible((whNvmId)ids[i], &meta);
        if (status != PSA_SUCCESS && status != PSA_ERROR_DOES_NOT_EXIST) {
            return status;
        }
        list[i] = (whNvmId)ids[i];
    }
    rc = wt_vstore_destroy_checked(g_vault_nvm, (whNvmId)count,
                                   (count != 0U) ? list : NULL);
    return wt_hsm_vault_map_err(rc);
}

static psa_status_t wt_hsm_vault_nvm_read(uint16_t id, uint32_t offset,
                                          uint8_t* data, size_t len)
{
    whNvmMetadata meta;
    psa_status_t status;
    int rc;

    status = wt_hsm_vault_nvm_visible((whNvmId)id, &meta);
    if (status != PSA_SUCCESS) {
        return status;
    }
    /* Same bounds as the flash backend: the offset must fall inside the
     * object, even for a zero-length read. */
    if (len > WT_VAULT_OBJECT_MAX || offset >= meta.len ||
            len > (size_t)meta.len - offset) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    rc = wt_vstore_read(g_vault_nvm, (whNvmId)id, (whNvmSize)offset,
                        (whNvmSize)len, data);
    return wt_hsm_vault_map_err(rc);
}

const wt_vault_nvm_backend_t wt_hsm_vault_nvm_backend = {
    wt_hsm_vault_nvm_get_available,
    wt_hsm_vault_nvm_get_metadata,
    wt_hsm_vault_nvm_add_object,
    wt_hsm_vault_nvm_destroy,
    wt_hsm_vault_nvm_read
};
#else
/* Key face (native engine). Only key-namespace labels match, the stored
 * flags carry nothing but the key label, and the length fits the type. */
static int wt_hsm_vault_key_label_ok(uint32_t label, size_t len)
{
    uint32_t type = WT_VAULT_KEY_TYPE_OF(label);

    if (label != WT_VAULT_KEY_LABEL(label, type)) {
        return 0;
    }
    if (type == WT_VAULT_KEY_P256) {
        return len == (size_t)WT_VAULT_KEY_MATERIAL_LEN + WT_VAULT_KEY_PUB_LEN;
    }
    if (type == WT_VAULT_KEY_AES256) {
        return len == WT_VAULT_KEY_MATERIAL_LEN;
    }
    return type == WT_VAULT_KEY_PSA_RECORD && len != 0U &&
           len <= WT_VAULT_OBJECT_MAX;
}

static psa_status_t wt_hsm_vault_key_put(int32_t owner, int32_t sub,
                                         uint64_t uid, uint32_t label,
                                         const uint8_t* data, size_t len)
{
    whNvmMetadata meta;
    whNvmId free_id = WH_NVM_ID_INVALID;
    psa_status_t status;
    int rc;

    if (g_vault_nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (data == NULL || wt_hsm_vault_key_label_ok(label, len) == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    status = wt_hsm_vault_find_in(g_vault_nvm, WT_VAULT_FLAG_KEY, owner, sub,
                                  uid, NULL, NULL, &free_id);
    if (status == PSA_SUCCESS) {
        return PSA_ERROR_ALREADY_EXISTS;
    }
    if (status != PSA_ERROR_DOES_NOT_EXIST) {
        return status;
    }
    if (free_id == WH_NVM_ID_INVALID) {
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }
    status = wt_hsm_vault_reserve_object((whNvmSize)len);
    if (status != PSA_SUCCESS) {
        return status;
    }
    (void)memset(&meta, 0, sizeof(meta));
    meta.id = free_id;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags = WH_NVM_FLAGS_SENSITIVE | WH_NVM_FLAGS_NONEXPORTABLE;
    meta.len = (whNvmSize)len;
    wt_hsm_vault_make_label(meta.label, owner, sub, uid, label);
    rc = wt_vstore_add(g_vault_nvm, &meta, (whNvmSize)len, data);
    return (rc == WH_ERROR_OK) ? PSA_SUCCESS : PSA_ERROR_STORAGE_FAILURE;
}

/* The internal read of NONEXPORTABLE key material, served on this face only. */
static psa_status_t wt_hsm_vault_key_get(int32_t owner, int32_t sub,
                                         uint64_t uid, uint32_t want,
                                         uint32_t select, uint32_t offset,
                                         uint8_t* data, size_t len)
{
    whNvmMetadata meta;
    whNvmId id = WH_NVM_ID_INVALID;
    uint32_t flags;
    uint32_t usage = want & WT_VAULT_KEY_USAGE_MASK;
    psa_status_t status;

    if (g_vault_nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    status = wt_hsm_vault_find_in(g_vault_nvm, WT_VAULT_FLAG_KEY, owner, sub,
                                  uid, &id, &meta, NULL);
    if (status != PSA_SUCCESS) {
        return status;
    }
    flags = wt_hsm_vault_flags_of(meta.label);
    if (WT_VAULT_KEY_TYPE_OF(flags) != WT_VAULT_KEY_TYPE_OF(want) ||
            (flags & usage) != usage) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if ((select & WT_VAULT_KEY_SEL_WHOLE) != 0U) {
        if (offset != 0U || len != meta.len) {
            return PSA_ERROR_STORAGE_FAILURE;
        }
    }
    else if (offset > meta.len || len > (size_t)meta.len - offset) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (len != 0U && (data == NULL ||
            wt_vstore_read(g_vault_nvm, id, (whNvmSize)offset, (whNvmSize)len,
                           data) != WH_ERROR_OK)) {
        return PSA_ERROR_STORAGE_FAILURE;
    }
    return PSA_SUCCESS;
}

static psa_status_t wt_hsm_vault_key_del(int32_t owner, int32_t sub,
                                         uint64_t uid)
{
    whNvmId id = WH_NVM_ID_INVALID;
    psa_status_t status;

    if (g_vault_nvm == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    status = wt_hsm_vault_find_in(g_vault_nvm, WT_VAULT_FLAG_KEY, owner, sub,
                                  uid, &id, NULL, NULL);
    if (status == PSA_SUCCESS) {
        status = wt_hsm_vault_map_err(
            wt_vstore_destroy_checked(g_vault_nvm, 1U, &id));
    }
    return status;
}

const wt_vault_keystore_t wt_hsm_vault_keystore = {
    wt_hsm_vault_key_put,
    wt_hsm_vault_key_get,
    wt_hsm_vault_key_del
};
#endif
