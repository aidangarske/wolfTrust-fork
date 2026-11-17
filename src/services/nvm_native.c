/* nvm_native.c
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

/* Native-engine NVM object store behind the wolfHSM whNvmCb table. Each of
 * two flash partitions holds a header unit, a directory of slots (metadata
 * then a commit unit) and a data area. A slot counts only once its commit
 * unit is programmed, after its metadata and data; compaction copies the
 * live objects to the other partition and programs its header last, so a
 * power cut leaves either the old or the new state. Records are units the
 * flash programs once; a torn tail is compacted away before the next write. */

#include "wolfhsm/wh_error.h"

#include "wolftrust/nvm_native.h"
#include "wolftrust/static_assert.h"

#include <stddef.h>
#include <string.h>

#define WT_NVS_MAGIC        0x31564E57u /* "WNV1" */
#define WT_NVS_META_UNITS   2u
#define WT_NVS_SLOT_UNITS   (WT_NVS_META_UNITS + 1u)
#define WT_NVS_DIR_OFF      WT_NVS_UNIT
#define WT_NVS_DATA_OFF     (WT_NVS_UNIT * (1u + WT_NVS_SLOT_UNITS * WT_NVS_SLOTS))
#define WT_NVS_COPY_LEN     (4u * WT_NVS_UNIT)

WT_STATIC_ASSERT(sizeof(whNvmMetadata) == WT_NVS_META_UNITS * WT_NVS_UNIT,
                 "metadata fills its units exactly");
WT_STATIC_ASSERT(WT_NVS_SLOTS > 0u && WT_NVS_SLOTS < 0xFFFFu,
                 "slot count fits the 16-bit counters");

static uint32_t wt_nvs_pad(uint32_t len)
{
    return (len + (WT_NVS_UNIT - 1u)) & ~(WT_NVS_UNIT - 1u);
}

static uint32_t wt_nvs_base(const wt_nvs_context_t* ctx, uint32_t part)
{
    return (part != 0u) ? ctx->part_size : 0u;
}

static uint32_t wt_nvs_slot_off(const wt_nvs_context_t* ctx, uint32_t part,
                                uint32_t slot)
{
    return wt_nvs_base(ctx, part) + WT_NVS_DIR_OFF +
           (WT_NVS_UNIT * WT_NVS_SLOT_UNITS * slot);
}

static uint32_t wt_nvs_data_off(const wt_nvs_context_t* ctx, uint32_t part)
{
    return wt_nvs_base(ctx, part) + WT_NVS_DATA_OFF;
}

static uint32_t wt_nvs_data_size(const wt_nvs_context_t* ctx)
{
    return ctx->part_size - WT_NVS_DATA_OFF;
}

static int wt_nvs_program(const wt_nvs_context_t* ctx, uint32_t off,
                          uint32_t size, const uint8_t* data)
{
    int rc = ctx->cb->Program(ctx->flash, off, size, data);

    if (rc == WH_ERROR_OK && ctx->cb->Verify != NULL) {
        rc = ctx->cb->Verify(ctx->flash, off, size, data);
    }
    return rc;
}

static int wt_nvs_erase(const wt_nvs_context_t* ctx, uint32_t part)
{
    uint32_t off = wt_nvs_base(ctx, part);
    uint32_t size = ctx->part_size;
    int rc = ctx->cb->BlankCheck(ctx->flash, off, size);

    if (rc == WH_ERROR_NOTBLANK) {
        rc = ctx->cb->Erase(ctx->flash, off, size);
        if (rc == WH_ERROR_OK) {
            rc = ctx->cb->BlankCheck(ctx->flash, off, size);
        }
    }
    return rc;
}

/* A record is a value and a check word, each also stored inverted, so a torn
 * program (some bits left at their erased value) never reads as valid. */
static void wt_nvs_rec_make(uint32_t* rec, uint32_t a, uint32_t b)
{
    rec[0] = a;
    rec[1] = b;
    rec[2] = ~a;
    rec[3] = ~b;
}

static int wt_nvs_rec_read(const wt_nvs_context_t* ctx, uint32_t off,
                           uint32_t* a, uint32_t* b)
{
    uint32_t rec[WT_NVS_UNIT / sizeof(uint32_t)];
    int rc = ctx->cb->Read(ctx->flash, off, WT_NVS_UNIT, (uint8_t*)rec);

    if (rc == WH_ERROR_OK && (rec[2] != ~rec[0] || rec[3] != ~rec[1])) {
        rc = WH_ERROR_ABORTED;
    }
    if (rc == WH_ERROR_OK) {
        *a = rec[0];
        *b = rec[1];
    }
    return rc;
}

static int wt_nvs_rec_write(const wt_nvs_context_t* ctx, uint32_t off,
                            uint32_t a, uint32_t b)
{
    uint32_t rec[WT_NVS_UNIT / sizeof(uint32_t)];

    wt_nvs_rec_make(rec, a, b);
    return wt_nvs_program(ctx, off, WT_NVS_UNIT, (const uint8_t*)rec);
}

/* 0 with the epoch, WH_ERROR_NOTFOUND for a blank header, else an error. */
static int wt_nvs_header(const wt_nvs_context_t* ctx, uint32_t part,
                         uint32_t* epoch)
{
    uint32_t magic = 0u;
    uint32_t off = wt_nvs_base(ctx, part);
    int rc = ctx->cb->BlankCheck(ctx->flash, off, WT_NVS_UNIT);

    if (rc == WH_ERROR_OK) {
        return WH_ERROR_NOTFOUND;
    }
    if (rc == WH_ERROR_NOTBLANK) {
        rc = wt_nvs_rec_read(ctx, off, &magic, epoch);
    }
    if (rc == WH_ERROR_OK && magic != WT_NVS_MAGIC) {
        rc = WH_ERROR_ABORTED;
    }
    return rc;
}

static int wt_nvs_meta_read(const wt_nvs_context_t* ctx, uint32_t part,
                            uint32_t slot, whNvmMetadata* meta)
{
    return ctx->cb->Read(ctx->flash, wt_nvs_slot_off(ctx, part, slot),
                         (uint32_t)sizeof(*meta), (uint8_t*)meta);
}

static void wt_nvs_supersede(wt_nvs_context_t* ctx, whNvmId id)
{
    uint32_t i;

    for (i = 0u; i < ctx->used; i++) {
        if (ctx->slot[i].id == id) {
            ctx->slot[i].id = WH_NVM_ID_INVALID;
            ctx->dead++;
            ctx->dead_data += wt_nvs_pad(ctx->slot[i].len);
        }
    }
}

static void wt_nvs_append(wt_nvs_context_t* ctx, whNvmId id, whNvmSize len)
{
    wt_nvs_supersede(ctx, id);
    ctx->slot[ctx->used].id = id;
    ctx->slot[ctx->used].len = len;
    ctx->used++;
    ctx->next_data += wt_nvs_pad(len);
}

static uint32_t wt_nvs_start(const wt_nvs_context_t* ctx, uint32_t slot)
{
    uint32_t i;
    uint32_t start = 0u;

    for (i = 0u; i < slot; i++) {
        start += wt_nvs_pad(ctx->slot[i].len);
    }
    return start;
}

/* Rebuild the index from a partition. Committed slots must be contiguous,
 * allocated in order and agree with their metadata; anything else is
 * corruption. Only the last written slot may be torn. */
static int wt_nvs_scan(wt_nvs_context_t* ctx, uint32_t part)
{
    whNvmMetadata meta;
    uint32_t data_size = wt_nvs_data_size(ctx);
    uint32_t slot_bytes = WT_NVS_UNIT * WT_NVS_SLOT_UNITS;
    uint32_t i;
    uint32_t off;
    uint32_t key = 0u;
    uint32_t start = 0u;
    whNvmId id;
    whNvmSize len;
    uint32_t rest;
    int rc = WH_ERROR_OK;

    ctx->used = 0u;
    ctx->dead = 0u;
    ctx->next_data = 0u;
    ctx->dead_data = 0u;
    ctx->torn = 0u;
    for (i = 0u; i < WT_NVS_SLOTS && rc == WH_ERROR_OK; i++) {
        off = wt_nvs_slot_off(ctx, part, i);
        if (wt_nvs_rec_read(ctx, off + WT_NVS_UNIT * WT_NVS_META_UNITS,
                            &key, &start) != WH_ERROR_OK) {
            /* The directory ends here: this slot is blank or torn, and every
             * later one must be blank. */
            rest = slot_bytes * (WT_NVS_SLOTS - i);
            if (ctx->cb->BlankCheck(ctx->flash, off, rest) != WH_ERROR_OK) {
                ctx->torn = 1u;
                if (ctx->cb->BlankCheck(ctx->flash, off + slot_bytes,
                                        rest - slot_bytes) != WH_ERROR_OK) {
                    rc = WH_ERROR_ABORTED;
                }
            }
            break;
        }
        id = (whNvmId)(key & 0xFFFFu);
        len = (whNvmSize)(key >> 16);
        if (id == WH_NVM_ID_INVALID || start != ctx->next_data ||
                wt_nvs_pad(len) > data_size - ctx->next_data) {
            rc = WH_ERROR_ABORTED;
        }
        if (rc == WH_ERROR_OK) {
            rc = wt_nvs_meta_read(ctx, part, i, &meta);
        }
        if (rc == WH_ERROR_OK && (meta.id != id || meta.len != len)) {
            rc = WH_ERROR_ABORTED;
        }
        if (rc == WH_ERROR_OK) {
            wt_nvs_append(ctx, id, len);
        }
    }
    return rc;
}

static int wt_nvs_format(wt_nvs_context_t* ctx)
{
    int rc = wt_nvs_erase(ctx, 0u);

    if (rc == WH_ERROR_OK) {
        rc = wt_nvs_erase(ctx, 1u);
    }
    if (rc == WH_ERROR_OK) {
        rc = wt_nvs_rec_write(ctx, wt_nvs_base(ctx, 0u), WT_NVS_MAGIC, 0u);
    }
    if (rc == WH_ERROR_OK) {
        ctx->active = 0u;
        ctx->epoch = 0u;
        rc = wt_nvs_scan(ctx, 0u);
    }
    return rc;
}

static int wt_nvs_listed(whNvmId count, const whNvmId* list, whNvmId id)
{
    whNvmId i;

    for (i = 0u; i < count; i++) {
        if (list[i] == id) {
            return 1;
        }
    }
    return 0;
}

static int wt_nvs_copy(wt_nvs_context_t* ctx, uint32_t slot, uint32_t src,
                       uint32_t dst, uint32_t pos, uint32_t next)
{
    uint32_t buf[WT_NVS_COPY_LEN / sizeof(uint32_t)];
    whNvmMetadata meta;
    const wt_nvs_slot_t* s = &ctx->slot[slot];
    uint32_t done = 0u;
    uint32_t n;
    int rc = wt_nvs_meta_read(ctx, ctx->active, slot, &meta);

    if (rc == WH_ERROR_OK && (meta.id != s->id || meta.len != s->len)) {
        rc = WH_ERROR_ABORTED;
    }
    if (rc == WH_ERROR_OK) {
        (void)memcpy(buf, &meta, sizeof(meta));
        rc = wt_nvs_program(ctx, wt_nvs_slot_off(ctx, dst, pos),
                            (uint32_t)sizeof(meta), (const uint8_t*)buf);
    }
    while (rc == WH_ERROR_OK && done < s->len) {
        n = (uint32_t)s->len - done;
        if (n > WT_NVS_COPY_LEN) {
            n = WT_NVS_COPY_LEN;
        }
        (void)memset(buf, 0, sizeof(buf));
        rc = ctx->cb->Read(ctx->flash, wt_nvs_data_off(ctx, ctx->active) +
                           src + done, n, (uint8_t*)buf);
        if (rc == WH_ERROR_OK) {
            rc = wt_nvs_program(ctx, wt_nvs_data_off(ctx, dst) + next + done,
                                wt_nvs_pad(n), (const uint8_t*)buf);
        }
        done += n;
    }
    if (rc == WH_ERROR_OK) {
        rc = wt_nvs_rec_write(ctx, wt_nvs_slot_off(ctx, dst, pos) +
                              WT_NVS_UNIT * WT_NVS_META_UNITS,
                              (uint32_t)s->id | ((uint32_t)s->len << 16),
                              next);
    }
    return rc;
}

static int wt_nvs_compact(wt_nvs_context_t* ctx, whNvmId count,
                          const whNvmId* list)
{
    uint32_t src = ctx->active;
    uint32_t dst = src ^ 1u;
    uint32_t i;
    uint32_t pos = 0u;
    uint32_t from = 0u;
    uint32_t next = 0u;
    int rc = wt_nvs_erase(ctx, dst);

    for (i = 0u; i < ctx->used && rc == WH_ERROR_OK; i++) {
        if (ctx->slot[i].id != WH_NVM_ID_INVALID &&
                wt_nvs_listed(count, list, ctx->slot[i].id) == 0) {
            rc = wt_nvs_copy(ctx, i, from, dst, pos, next);
            pos++;
            next += wt_nvs_pad(ctx->slot[i].len);
        }
        from += wt_nvs_pad(ctx->slot[i].len);
    }
    if (rc == WH_ERROR_OK) {
        rc = wt_nvs_rec_write(ctx, wt_nvs_base(ctx, dst), WT_NVS_MAGIC,
                              ctx->epoch + 1u);
    }
    if (rc != WH_ERROR_OK) {
        return rc;
    }
    /* The new copy is now the newest, so boot would pick it too: a copy that
     * does not read back leaves the store unusable rather than stale. */
    rc = wt_nvs_scan(ctx, dst);
    if (rc != WH_ERROR_OK) {
        ctx->bad = 1u;
        return rc;
    }
    ctx->active = (uint8_t)dst;
    ctx->epoch++;
    return wt_nvs_erase(ctx, src);
}

static int wt_nvs_find(const wt_nvs_context_t* ctx, whNvmId id)
{
    uint32_t i;

    for (i = 0u; id != WH_NVM_ID_INVALID && i < ctx->used; i++) {
        if (ctx->slot[i].id == id) {
            return (int)i;
        }
    }
    return -1;
}

static int wt_nvs_usable(const wt_nvs_context_t* ctx)
{
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (ctx->ready == 0u || ctx->bad != 0u) {
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

int wt_nvs_init(void* c, const void* cf)
{
    wt_nvs_context_t* ctx = (wt_nvs_context_t*)c;
    const wt_nvs_config_t* cfg = (const wt_nvs_config_t*)cf;
    const whFlashCb* cb;
    uint32_t epoch[2] = {0u, 0u};
    uint32_t size;
    int hdr[2];
    int rc = WH_ERROR_OK;

    if (ctx == NULL || cfg == NULL || cfg->cb == NULL) {
        return WH_ERROR_BADARGS;
    }
    cb = cfg->cb;
    if (cb->PartitionSize == NULL || cb->Read == NULL ||
            cb->Program == NULL || cb->Erase == NULL ||
            cb->BlankCheck == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (cb->Init != NULL) {
        rc = cb->Init(cfg->context, cfg->config);
    }
    if (rc != WH_ERROR_OK) {
        return rc;
    }
    (void)memset(ctx, 0, sizeof(*ctx));
    ctx->cb = cb;
    ctx->flash = cfg->context;
    size = cb->PartitionSize(ctx->flash);
    ctx->part_size = size;
    if ((size % WT_NVS_UNIT) != 0u || size <= WT_NVS_DATA_OFF ||
            size > 0x7FFFFFFFu) {
        rc = WH_ERROR_BADARGS;
    }
    if (rc == WH_ERROR_OK) {
        if (cb->WriteUnlock != NULL) {
            (void)cb->WriteUnlock(ctx->flash, 0u, 2u * size);
        }
        hdr[0] = wt_nvs_header(ctx, 0u, &epoch[0]);
        hdr[1] = wt_nvs_header(ctx, 1u, &epoch[1]);
        if (hdr[0] == WH_ERROR_OK || hdr[1] == WH_ERROR_OK) {
            ctx->active = (hdr[0] != WH_ERROR_OK ||
                           (hdr[1] == WH_ERROR_OK && epoch[1] > epoch[0]))
                          ? 1u : 0u;
            ctx->epoch = epoch[ctx->active];
            rc = WH_ERROR_ABORTED;
            if (hdr[0] != WH_ERROR_OK || hdr[1] != WH_ERROR_OK ||
                    epoch[0] != epoch[1]) {
                rc = wt_nvs_scan(ctx, ctx->active);
            }
        }
        else if (cb->BlankCheck(ctx->flash, 0u, 2u * size) == WH_ERROR_OK) {
            rc = wt_nvs_format(ctx);
        }
        else {
            rc = WH_ERROR_ABORTED;
        }
        /* Never fall back to an older copy: only an explicit reformat
         * recovers a store whose newest state cannot be read. */
        if (rc != WH_ERROR_OK && cfg->may_format != NULL &&
                cfg->may_format() != 0) {
            rc = wt_nvs_format(ctx);
        }
    }
    if (rc == WH_ERROR_OK) {
        ctx->ready = 1u;
    }
    else if (cb->Cleanup != NULL) {
        (void)cb->Cleanup(cfg->context);
    }
    return rc;
}

int wt_nvs_cleanup(void* c)
{
    wt_nvs_context_t* ctx = (wt_nvs_context_t*)c;
    int rc = WH_ERROR_OK;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (ctx->ready != 0u) {
        ctx->ready = 0u;
        if (ctx->cb->WriteLock != NULL) {
            (void)ctx->cb->WriteLock(ctx->flash, 0u, 2u * ctx->part_size);
        }
        if (ctx->cb->Cleanup != NULL) {
            rc = ctx->cb->Cleanup(ctx->flash);
        }
    }
    return rc;
}

int wt_nvs_get_available(void* c, uint32_t* out_avail_size,
                         whNvmId* out_avail_objects,
                         uint32_t* out_reclaim_size,
                         whNvmId* out_reclaim_objects)
{
    wt_nvs_context_t* ctx = (wt_nvs_context_t*)c;
    uint32_t size;
    uint32_t objects;
    uint32_t reclaim_size;
    uint32_t reclaim_objects;
    int rc = wt_nvs_usable(ctx);

    if (rc != WH_ERROR_OK) {
        return rc;
    }
    size = wt_nvs_data_size(ctx) - ctx->next_data;
    objects = WT_NVS_SLOTS - ctx->used;
    reclaim_size = ctx->dead_data;
    reclaim_objects = ctx->dead;
    if (ctx->torn != 0u) {
        /* Nothing appends past a torn slot; compaction frees it all. */
        reclaim_size += size;
        reclaim_objects += objects;
        size = 0u;
        objects = 0u;
    }
    if (out_avail_size != NULL) {
        *out_avail_size = size;
    }
    if (out_avail_objects != NULL) {
        *out_avail_objects = (whNvmId)objects;
    }
    if (out_reclaim_size != NULL) {
        *out_reclaim_size = reclaim_size;
    }
    if (out_reclaim_objects != NULL) {
        *out_reclaim_objects = (whNvmId)reclaim_objects;
    }
    return WH_ERROR_OK;
}

int wt_nvs_add_object(void* c, whNvmMetadata* meta, whNvmSize data_len,
                      const uint8_t* data)
{
    wt_nvs_context_t* ctx = (wt_nvs_context_t*)c;
    uint32_t buf[sizeof(whNvmMetadata) / sizeof(uint32_t)];
    uint32_t off;
    uint32_t dst;
    uint32_t full = (uint32_t)data_len & ~(WT_NVS_UNIT - 1u);
    int rc;

    rc = wt_nvs_usable(ctx);
    if (rc == WH_ERROR_OK && (meta == NULL ||
            (data_len > 0u && data == NULL) ||
            meta->id == WH_NVM_ID_INVALID)) {
        return WH_ERROR_BADARGS;
    }
    if (rc == WH_ERROR_OK && ctx->torn != 0u) {
        rc = wt_nvs_compact(ctx, 0u, NULL);
    }
    if (rc == WH_ERROR_OK && (ctx->used >= WT_NVS_SLOTS ||
            wt_nvs_pad(data_len) > wt_nvs_data_size(ctx) - ctx->next_data)) {
        rc = WH_ERROR_NOSPACE;
    }
    if (rc != WH_ERROR_OK) {
        return rc;
    }
    meta->len = data_len;
    off = wt_nvs_slot_off(ctx, ctx->active, ctx->used);
    dst = wt_nvs_data_off(ctx, ctx->active) + ctx->next_data;
    (void)memcpy(buf, meta, sizeof(*meta));
    rc = wt_nvs_program(ctx, off, (uint32_t)sizeof(*meta),
                        (const uint8_t*)buf);
    if (rc == WH_ERROR_OK && full != 0u) {
        rc = wt_nvs_program(ctx, dst, full, data);
    }
    if (rc == WH_ERROR_OK && full != (uint32_t)data_len) {
        (void)memset(buf, 0, WT_NVS_UNIT);
        (void)memcpy(buf, data + full, (uint32_t)data_len - full);
        rc = wt_nvs_program(ctx, dst + full, WT_NVS_UNIT,
                            (const uint8_t*)buf);
    }
    if (rc == WH_ERROR_OK) {
        rc = wt_nvs_rec_write(ctx, off + WT_NVS_UNIT * WT_NVS_META_UNITS,
                              (uint32_t)meta->id | ((uint32_t)data_len << 16),
                              ctx->next_data);
    }
    if (rc == WH_ERROR_OK) {
        wt_nvs_append(ctx, meta->id, data_len);
    }
    else {
        ctx->torn = 1u;
    }
    return rc;
}

int wt_nvs_get_metadata(void* c, whNvmId id, whNvmMetadata* meta)
{
    wt_nvs_context_t* ctx = (wt_nvs_context_t*)c;
    whNvmMetadata stored;
    int slot;
    int rc = wt_nvs_usable(ctx);

    if (rc != WH_ERROR_OK) {
        return rc;
    }
    slot = wt_nvs_find(ctx, id);
    if (slot < 0) {
        return WH_ERROR_NOTFOUND;
    }
    rc = wt_nvs_meta_read(ctx, ctx->active, (uint32_t)slot, &stored);
    if (rc == WH_ERROR_OK && (stored.id != id ||
            stored.len != ctx->slot[slot].len)) {
        rc = WH_ERROR_ABORTED;
    }
    if (rc == WH_ERROR_OK && meta != NULL) {
        *meta = stored;
    }
    return rc;
}

int wt_nvs_destroy_objects(void* c, whNvmId list_count,
                           const whNvmId* id_list)
{
    wt_nvs_context_t* ctx = (wt_nvs_context_t*)c;
    whNvmId i;
    int matched = 0;
    int rc;

    rc = wt_nvs_usable(ctx);
    if (rc == WH_ERROR_OK && list_count > 0u && id_list == NULL) {
        rc = WH_ERROR_BADARGS;
    }
    if (rc != WH_ERROR_OK) {
        return rc;
    }
    for (i = 0u; i < list_count && matched == 0; i++) {
        matched = (wt_nvs_find(ctx, id_list[i]) >= 0);
    }
    /* A list that names nothing present needs no rewrite; an empty list is
     * a compaction request. */
    if (list_count > 0u && matched == 0) {
        return WH_ERROR_OK;
    }
    return wt_nvs_compact(ctx, list_count, id_list);
}

int wt_nvs_read(void* c, whNvmId id, whNvmSize offset, whNvmSize data_len,
                uint8_t* data)
{
    wt_nvs_context_t* ctx = (wt_nvs_context_t*)c;
    whNvmSize len;
    uint32_t start;
    int slot;
    int rc = wt_nvs_usable(ctx);

    if (rc == WH_ERROR_OK && data_len > 0u && data == NULL) {
        rc = WH_ERROR_BADARGS;
    }
    if (rc != WH_ERROR_OK) {
        return rc;
    }
    slot = wt_nvs_find(ctx, id);
    if (slot < 0) {
        return WH_ERROR_NOTFOUND;
    }
    len = ctx->slot[slot].len;
    if (offset >= len || data_len > (whNvmSize)(len - offset)) {
        return WH_ERROR_BADARGS;
    }
    start = wt_nvs_start(ctx, (uint32_t)slot);
    if (start > wt_nvs_data_size(ctx) ||
            len > wt_nvs_data_size(ctx) - start) {
        return WH_ERROR_ABORTED;
    }
    return ctx->cb->Read(ctx->flash, wt_nvs_data_off(ctx, ctx->active) +
                         start + offset, data_len, data);
}
