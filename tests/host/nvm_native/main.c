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

/* Host proof of the native NVM store over the RAM flash simulator: object
 * semantics, the wh_Nvm policy flags, corruption refusal, and recovery from
 * a power cut at every program and erase step. */

#include "wolftrust/nvm_native.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_nvm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECTOR    4096u
#define FLASH_SZ  (2u * SECTOR)
#define PAGE      8u
#define MAX_OBJS  8u

static int g_failures;
static uint8_t g_mem[FLASH_SZ];
static whFlashRamsimCtx g_sim;

/* Power model: -1 runs forever; otherwise the op that brings it to zero is
 * torn and every later op fails, as if power dropped. */
static int g_ops_left = -1;
static int g_dead;
static int g_misaligned;
static int g_allow_format;
/* ECC model: a torn unit that reads as an uncorrectable error until erased. */
static int g_ecc;
static uint32_t g_ecc_off;
/* Lie model: the program that brings it to zero lands but reports failure. */
static int g_lie_left = -1;

static void check(int cond, const char* what)
{
    if (!cond) {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
}

static int cut_now(void)
{
    if (g_dead) {
        return 1;
    }
    if (g_ops_left > 0) {
        g_ops_left--;
        if (g_ops_left == 0) {
            g_dead = 1;
            return 2;
        }
    }
    return 0;
}

static int ecc_hit(uint32_t off, uint32_t size)
{
    return g_ecc != 0 && off < g_ecc_off + WT_NVS_UNIT &&
           g_ecc_off < off + size;
}

static uint32_t f_size(void* c)
{
    (void)c;
    return SECTOR;
}

static int f_read(void* c, uint32_t off, uint32_t size, uint8_t* data)
{
    if (g_dead || ecc_hit(off, size)) {
        return WH_ERROR_ABORTED;
    }
    return whFlashRamsim_Read(c, off, size, data);
}

static int f_program(void* c, uint32_t off, uint32_t size,
                     const uint8_t* data)
{
    int cut = cut_now();

    if ((off % WT_NVS_UNIT) != 0u || (size % WT_NVS_UNIT) != 0u) {
        g_misaligned++;
    }
    if (g_lie_left > 0 && --g_lie_left == 0) {
        (void)whFlashRamsim_Program(c, off, size, data);
        return WH_ERROR_ABORTED;
    }
    if (cut == 1) {
        return WH_ERROR_ABORTED;
    }
    if (cut == 2) {
        /* Torn: only the first half of the bytes reach the flash. */
        (void)whFlashRamsim_Program(c, off, (size / 2u) & ~(PAGE - 1u), data);
        return WH_ERROR_ABORTED;
    }
    return whFlashRamsim_Program(c, off, size, data);
}

static int f_erase(void* c, uint32_t off, uint32_t size)
{
    int cut = cut_now();

    if (cut == 1) {
        return WH_ERROR_ABORTED;
    }
    if (cut == 2) {
        (void)memset(g_mem + off, 0xFF, size / 2u);
        return WH_ERROR_ABORTED;
    }
    if (ecc_hit(off, size)) {
        g_ecc = 0;
    }
    return whFlashRamsim_Erase(c, off, size);
}

static int f_verify(void* c, uint32_t off, uint32_t size, const uint8_t* d)
{
    if (g_dead) {
        return WH_ERROR_ABORTED;
    }
    return whFlashRamsim_Verify(c, off, size, d);
}

static int f_blank(void* c, uint32_t off, uint32_t size)
{
    if (g_dead || ecc_hit(off, size)) {
        return WH_ERROR_ABORTED;
    }
    return whFlashRamsim_BlankCheck(c, off, size);
}

static const whFlashCb g_cb[1] = {{
    .Init = NULL,
    .Cleanup = NULL,
    .PartitionSize = f_size,
    .WriteLock = NULL,
    .WriteUnlock = NULL,
    .Read = f_read,
    .Program = f_program,
    .Erase = f_erase,
    .Verify = f_verify,
    .BlankCheck = f_blank,
}};

static int may_format(void)
{
    return g_allow_format;
}

static const whNvmCb g_nvs_cb[1] = {WT_NVS_CB};
static wt_nvs_context_t g_nvs;
static whNvmContext g_nvm;

static void sim_reset(void)
{
    whFlashRamsimCfg cfg;

    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.memory = g_mem;
    cfg.size = FLASH_SZ;
    cfg.sectorSize = SECTOR;
    cfg.pageSize = PAGE;
    cfg.erasedByte = 0xFF;
    (void)whFlashRamsim_Init(&g_sim, &cfg);
}

static int store_open(void)
{
    wt_nvs_config_t ncfg;
    whNvmConfig cfg;

    (void)memset(&ncfg, 0, sizeof(ncfg));
    ncfg.cb = g_cb;
    ncfg.context = &g_sim;
    ncfg.may_format = may_format;
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.cb = (whNvmCb*)g_nvs_cb;
    cfg.context = &g_nvs;
    cfg.config = &ncfg;
    (void)memset(&g_nvm, 0, sizeof(g_nvm));
    return wh_Nvm_Init(&g_nvm, &cfg);
}

static int add(whNvmId id, whNvmFlags flags, const uint8_t* data,
               whNvmSize len)
{
    whNvmMetadata meta;

    (void)memset(&meta, 0, sizeof(meta));
    meta.id = id;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags = flags;
    (void)snprintf((char*)meta.label, sizeof(meta.label), "obj-%u",
                   (unsigned)id);
    return wh_Nvm_AddObject(&g_nvm, &meta, len, data);
}

/* Expected contents: id and fill byte per object (len 0 = absent). */
typedef struct {
    whNvmId   id[MAX_OBJS];
    whNvmSize len[MAX_OBJS];
    uint8_t   fill[MAX_OBJS];
    uint32_t  n;
} model_t;

static void model_set(model_t* m, whNvmId id, whNvmSize len, uint8_t fill)
{
    uint32_t i;

    for (i = 0u; i < m->n; i++) {
        if (m->id[i] == id) {
            m->len[i] = len;
            m->fill[i] = fill;
            return;
        }
    }
    m->id[m->n] = id;
    m->len[m->n] = len;
    m->fill[m->n] = fill;
    m->n++;
}

static int model_matches(const model_t* m)
{
    whNvmMetadata meta;
    uint8_t buf[256];
    uint32_t i;
    uint32_t j;
    int rc;

    for (i = 0u; i < m->n; i++) {
        rc = wh_Nvm_GetMetadata(&g_nvm, m->id[i], &meta);
        if (m->len[i] == 0u) {
            if (rc != WH_ERROR_NOTFOUND) {
                return 0;
            }
            continue;
        }
        if (rc != WH_ERROR_OK || meta.len != m->len[i] ||
                wh_Nvm_Read(&g_nvm, m->id[i], 0u, m->len[i], buf) !=
                WH_ERROR_OK) {
            return 0;
        }
        for (j = 0u; j < m->len[i]; j++) {
            if (buf[j] != m->fill[i]) {
                return 0;
            }
        }
    }
    return 1;
}

static int put(whNvmId id, whNvmSize len, uint8_t fill)
{
    uint8_t buf[256];

    (void)memset(buf, fill, sizeof(buf));
    return add(id, 0u, buf, len);
}

static void test_basic(void)
{
    static const uint8_t a[] = "alpha";
    static const uint8_t b[] = "bravo-bravo-bravo-bravo";
    whNvmMetadata meta;
    uint8_t buf[64];
    uint32_t avail;
    uint32_t reclaim;
    whNvmId objs;
    whNvmId reclaim_objs;
    whNvmId ids[1];
    whNvmId fill;
    whNvmId count;
    whNvmId id;

    sim_reset();
    check(store_open() == WH_ERROR_OK, "blank flash formats on init");
    check(wh_Nvm_GetAvailable(&g_nvm, &avail, &objs, &reclaim,
                              &reclaim_objs) == WH_ERROR_OK &&
          objs == WT_NVS_SLOTS && reclaim == 0u && reclaim_objs == 0u,
          "fresh store reports every slot free");
    check(add(0u, 0u, a, sizeof(a)) == WH_ERROR_BADARGS,
          "id 0 is refused");
    check(add(1u, 0u, a, sizeof(a)) == WH_ERROR_OK, "add object");
    check(wh_Nvm_GetMetadata(&g_nvm, 1u, &meta) == WH_ERROR_OK &&
          meta.len == sizeof(a) && strcmp((char*)meta.label, "obj-1") == 0,
          "metadata round trips");
    check(wh_Nvm_Read(&g_nvm, 1u, 0u, sizeof(a), buf) == WH_ERROR_OK &&
          memcmp(buf, a, sizeof(a)) == 0, "data round trips");
    check(wh_Nvm_Read(&g_nvm, 1u, 2u, 3u, buf) == WH_ERROR_OK &&
          memcmp(buf, a + 2, 3u) == 0, "offset read");
    check(wh_Nvm_Read(&g_nvm, 1u, sizeof(a), 0u, buf) == WH_ERROR_BADARGS,
          "read at end is refused");
    check(wh_Nvm_Read(&g_nvm, 1u, 1u, sizeof(a), buf) == WH_ERROR_BADARGS,
          "read past end is refused");
    check(wh_Nvm_Read(&g_nvm, 7u, 0u, 1u, buf) == WH_ERROR_NOTFOUND,
          "absent id reads NOTFOUND");
    check(wh_Nvm_List(&g_nvm, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_ANY, 0u,
                      &count, &id) == WH_ERROR_ABORTED,
          "listing is refused");

    check(add(1u, 0u, b, sizeof(b)) == WH_ERROR_OK, "replace object");
    check(wh_Nvm_Read(&g_nvm, 1u, 0u, sizeof(b), buf) == WH_ERROR_OK &&
          memcmp(buf, b, sizeof(b)) == 0, "replacement wins");
    check(wh_Nvm_GetAvailable(&g_nvm, NULL, NULL, &reclaim,
                              &reclaim_objs) == WH_ERROR_OK &&
          reclaim_objs == 1u && reclaim == 16u,
          "superseded copy is reclaimable");

    check(store_open() == WH_ERROR_OK &&
          wh_Nvm_Read(&g_nvm, 1u, 0u, sizeof(b), buf) == WH_ERROR_OK &&
          memcmp(buf, b, sizeof(b)) == 0, "contents persist across init");

    ids[0] = 9u;
    check(wh_Nvm_DestroyObjects(&g_nvm, 1u, ids) == WH_ERROR_OK &&
          g_nvs.epoch == 0u, "destroying an absent id rewrites nothing");
    ids[0] = 1u;
    check(wh_Nvm_DestroyObjects(&g_nvm, 1u, ids) == WH_ERROR_OK &&
          wh_Nvm_GetMetadata(&g_nvm, 1u, NULL) == WH_ERROR_NOTFOUND &&
          g_nvs.epoch == 1u && g_nvs.active == 1u,
          "destroy compacts into the other partition");
    check(store_open() == WH_ERROR_OK && g_nvs.active == 1u &&
          wh_Nvm_GetMetadata(&g_nvm, 1u, NULL) == WH_ERROR_NOTFOUND,
          "newer partition wins on init");

    for (fill = 1u; fill <= WT_NVS_SLOTS; fill++) {
        if (put(fill, 4u, (uint8_t)fill) != WH_ERROR_OK) {
            break;
        }
    }
    check(fill == WT_NVS_SLOTS + 1u &&
          put(100u, 4u, 0x11u) == WH_ERROR_NOSPACE,
          "a full directory reports NOSPACE");
    check(put(200u, 3000u, 0x22u) == WH_ERROR_NOSPACE ||
          put(200u, 3000u, 0x22u) == WH_ERROR_BADARGS,
          "an oversized object is refused");
    check(g_misaligned == 0, "every program is whole units");
}

static void test_policy(void)
{
    static const uint8_t k[] = "key";
    uint8_t buf[8];
    whNvmMetadata meta;
    whNvmId ids[1];

    sim_reset();
    check(store_open() == WH_ERROR_OK, "policy store opens");
    check(add(1u, WH_NVM_FLAGS_NONMODIFIABLE, k, sizeof(k)) == WH_ERROR_OK &&
          add(2u, WH_NVM_FLAGS_NONDESTROYABLE, k, sizeof(k)) == WH_ERROR_OK &&
          add(3u, WH_NVM_FLAGS_NONEXPORTABLE, k, sizeof(k)) == WH_ERROR_OK &&
          add(4u, WH_NVM_FLAGS_TRUSTED, k, sizeof(k)) == WH_ERROR_OK,
          "flagged objects stored");
    (void)memset(&meta, 0, sizeof(meta));
    meta.id = 1u;
    check(wh_Nvm_AddObjectChecked(&g_nvm, &meta, sizeof(k), k) ==
          WH_ERROR_ACCESS, "NONMODIFIABLE refuses a checked replace");
    ids[0] = 1u;
    check(wh_Nvm_DestroyObjectsChecked(&g_nvm, 1u, ids) == WH_ERROR_ACCESS,
          "NONMODIFIABLE refuses a checked destroy");
    ids[0] = 2u;
    check(wh_Nvm_DestroyObjectsChecked(&g_nvm, 1u, ids) == WH_ERROR_ACCESS,
          "NONDESTROYABLE refuses a checked destroy");
    check(wh_Nvm_ReadChecked(&g_nvm, 3u, 0u, sizeof(k), buf) ==
          WH_ERROR_ACCESS, "NONEXPORTABLE refuses a checked read");
    check(wh_Nvm_ReadChecked(&g_nvm, 4u, 0u, sizeof(k), buf) ==
          WH_ERROR_ACCESS, "TRUSTED refuses a checked read");
    meta.id = 5u;
    meta.flags = WH_NVM_FLAGS_TRUSTED;
    check(wh_Nvm_AddObjectChecked(&g_nvm, &meta, sizeof(k), k) ==
              WH_ERROR_OK &&
          wh_Nvm_GetMetadata(&g_nvm, 5u, &meta) == WH_ERROR_OK &&
          (meta.flags & WH_NVM_FLAGS_TRUSTED) == 0u,
          "a checked add strips TRUSTED");
}

static void test_corruption(void)
{
    static const uint8_t d[] = "data";
    uint32_t commit0 = WT_NVS_UNIT + 2u * WT_NVS_UNIT;

    sim_reset();
    check(store_open() == WH_ERROR_OK && put(1u, 8u, 0xA1u) == WH_ERROR_OK &&
          put(2u, 8u, 0xA2u) == WH_ERROR_OK, "corruption store seeded");
    g_mem[commit0 + 4u] ^= 0x01u;
    check(store_open() == WH_ERROR_ABORTED,
          "a damaged committed slot before a live one is refused");
    g_allow_format = 1;
    check(store_open() == WH_ERROR_OK &&
          wh_Nvm_GetMetadata(&g_nvm, 2u, NULL) == WH_ERROR_NOTFOUND,
          "only an allowed reformat recovers it");
    g_allow_format = 0;

    check(add(1u, 0u, d, sizeof(d)) == WH_ERROR_OK, "reseeded");
    g_mem[WT_NVS_UNIT] ^= 0x01u;
    check(store_open() == WH_ERROR_ABORTED,
          "metadata that disagrees with its commit is refused");

    sim_reset();
    (void)memset(g_mem, 0x5A, 64u);
    check(store_open() == WH_ERROR_ABORTED,
          "an unrecognized store is refused, not wiped");
    check(g_mem[0] == 0x5Au, "refused store left untouched");

    sim_reset();
    check(store_open() == WH_ERROR_OK && put(1u, 8u, 0xB1u) == WH_ERROR_OK,
          "slot bounds store seeded");
    g_nvs.slot[0].len = 0xFFF0u;
    check(wh_Nvm_Read(&g_nvm, 1u, 0u, 8u, (uint8_t[8]){0}) ==
          WH_ERROR_ABORTED, "a forged index entry never reads out of range");
}

typedef int (*op_fn)(void);

static int op_add_new(void)
{
    return put(3u, 40u, 0xC3u);
}

static int op_replace(void)
{
    return put(1u, 70u, 0xD1u);
}

static int op_destroy(void)
{
    whNvmId ids[1] = {2u};

    return wh_Nvm_DestroyObjects(&g_nvm, 1u, ids);
}

static int op_compact(void)
{
    return wh_Nvm_DestroyObjects(&g_nvm, 0u, NULL);
}

static void seed(model_t* m)
{
    (void)memset(m, 0, sizeof(*m));
    sim_reset();
    (void)store_open();
    (void)put(1u, 33u, 0xA1u);
    (void)put(2u, 20u, 0xA2u);
    (void)put(2u, 21u, 0xB2u);
    model_set(m, 1u, 33u, 0xA1u);
    model_set(m, 2u, 21u, 0xB2u);
    model_set(m, 3u, 0u, 0u);
}

static void sweep(const char* name, op_fn op, whNvmId id, whNvmSize len,
                  uint8_t fill)
{
    model_t before;
    model_t after;
    int k;
    int rc = WH_ERROR_ABORTED;
    int ok = 1;
    int cuts = 0;
    char what[96];

    for (k = 1; k < 200 && rc != WH_ERROR_OK; k++) {
        seed(&before);
        after = before;
        model_set(&after, id, len, fill);
        g_ops_left = k;
        g_dead = 0;
        rc = op();
        g_ops_left = -1;
        g_dead = 0;
        if (store_open() != WH_ERROR_OK) {
            ok = 0;
            break;
        }
        if (!model_matches(&before) && !model_matches(&after)) {
            ok = 0;
            break;
        }
        if (put(9u, 17u, 0xE9u) != WH_ERROR_OK || store_open() != 0 ||
                wh_Nvm_Read(&g_nvm, 9u, 0u, 1u, (uint8_t[1]){0}) !=
                WH_ERROR_OK || op_compact() != WH_ERROR_OK) {
            ok = 0;
            break;
        }
        cuts++;
    }
    (void)snprintf(what, sizeof(what),
                   "%s: old or new state after a cut at each of %d steps",
                   name, cuts);
    check(ok && rc == WH_ERROR_OK && cuts > 1, what);
}

static void test_power_cut(void)
{
    sweep("add", op_add_new, 3u, 40u, 0xC3u);
    sweep("replace", op_replace, 1u, 70u, 0xD1u);
    sweep("destroy", op_destroy, 2u, 0u, 0u);
    sweep("compact", op_compact, 1u, 33u, 0xA1u);
    check(g_misaligned == 0, "power-cut runs program whole units only");
}

static void test_runtime_fault(void)
{
    uint8_t buf[40];
    uint32_t avail;
    whNvmId objs;

    sim_reset();
    check(store_open() == WH_ERROR_OK && put(1u, 40u, 0x31u) == WH_ERROR_OK,
          "runtime fault store seeded");
    g_ops_left = 2;
    check(put(2u, 40u, 0x32u) != WH_ERROR_OK, "a failed write reports it");
    g_ops_left = -1;
    g_dead = 0;
    check(wh_Nvm_GetAvailable(&g_nvm, &avail, &objs, NULL, NULL) ==
              WH_ERROR_OK && avail == 0u && objs == 0u,
          "a torn tail offers no append space");
    check(put(3u, 40u, 0x33u) == WH_ERROR_OK &&
          wh_Nvm_Read(&g_nvm, 1u, 0u, 40u, buf) == WH_ERROR_OK &&
          buf[39] == 0x31u && wh_Nvm_GetMetadata(&g_nvm, 2u, NULL) ==
          WH_ERROR_NOTFOUND, "the next write compacts past the torn slot");
}

/* A cut after compaction commits but before it erases the older copy leaves
 * two valid copies; boot must erase the older one, not keep it as a fallback. */
static void test_stale_copy(void)
{
    static uint8_t saved[SECTOR];
    uint32_t i;
    int blank = 1;

    sim_reset();
    check(store_open() == WH_ERROR_OK && put(1u, 8u, 0xA1u) == WH_ERROR_OK,
          "stale copy store seeded");
    (void)memcpy(saved, g_mem, SECTOR);
    check(put(1u, 8u, 0xB1u) == WH_ERROR_OK && op_compact() == WH_ERROR_OK &&
          g_mem[0] == 0xFFu, "compaction moves to the second copy");
    (void)memcpy(g_mem, saved, SECTOR);
    check(store_open() == WH_ERROR_OK &&
          wh_Nvm_Read(&g_nvm, 1u, 0u, 1u, saved) == WH_ERROR_OK &&
          saved[0] == 0xB1u, "two valid copies open on the newer one");
    for (i = 0u; i < SECTOR; i++) {
        if (g_mem[i] != 0xFFu) {
            blank = 0;
        }
    }
    check(blank, "boot erases the older copy");
    g_mem[SECTOR] ^= 0x01u;
    check(store_open() == WH_ERROR_ABORTED,
          "a damaged newest copy never falls back to an older one");
}

/* The compaction that would wrap the epoch is refused, not taken. */
static void test_epoch_wrap(void)
{
    uint8_t b = 0u;

    sim_reset();
    check(store_open() == WH_ERROR_OK && put(1u, 8u, 0xA1u) == WH_ERROR_OK,
          "epoch wrap store seeded");
    g_nvs.epoch = UINT32_MAX;
    check(op_compact() != WH_ERROR_OK && store_open() == WH_ERROR_OK &&
          wh_Nvm_Read(&g_nvm, 1u, 0u, 1u, &b) == WH_ERROR_OK && b == 0xA1u,
          "a compaction that would wrap the epoch fails and keeps the data");
}

static int part_blank(uint32_t part)
{
    uint32_t i;

    for (i = 0u; i < SECTOR; i++) {
        if (g_mem[part * SECTOR + i] != 0xFFu) {
            return 0;
        }
    }
    return 1;
}

/* A cut while programming the new copy's header leaves a full older copy with
 * a higher epoch; if its marginal header later read valid, it would win. */
static void test_torn_header_copy(void)
{
    uint32_t word;

    sim_reset();
    check(store_open() == WH_ERROR_OK && put(1u, 8u, 0xA1u) == WH_ERROR_OK &&
          op_compact() == WH_ERROR_OK && part_blank(0u),
          "torn header store seeded on the second copy");
    (void)memcpy(g_mem, g_mem + SECTOR, SECTOR);
    word = 2u;
    (void)memcpy(g_mem + 4u, &word, sizeof(word));
    check(store_open() == WH_ERROR_OK,
          "a torn newer header opens the committed copy");
    check(part_blank(0u), "boot erases a copy whose header is torn");
}

/* On ECC flash a torn unit fails the blank check instead of reading as data. */
static void test_ecc_blank(void)
{
    uint8_t buf[8];

    sim_reset();
    check(store_open() == WH_ERROR_OK && put(1u, 8u, 0xA1u) == WH_ERROR_OK,
          "ECC store seeded");
    g_mem[SECTOR + WT_NVS_UNIT] = 0x00u;
    g_ecc_off = SECTOR + WT_NVS_UNIT;
    g_ecc = 1;
    check(op_compact() == WH_ERROR_OK &&
          wh_Nvm_Read(&g_nvm, 1u, 0u, 8u, buf) == WH_ERROR_OK &&
          buf[7] == 0xA1u,
          "compaction erases a copy whose torn unit reads as an ECC error");
    g_ecc = 0;
}

static int pair(whNvmId a, whNvmSize alen, uint8_t afill, whNvmId b,
                whNvmSize blen, uint8_t bfill)
{
    whNvmMetadata ma;
    whNvmMetadata mb;
    uint8_t da[256];
    uint8_t db[256];

    (void)memset(&ma, 0, sizeof(ma));
    (void)memset(&mb, 0, sizeof(mb));
    ma.id = a;
    mb.id = b;
    (void)memset(da, afill, sizeof(da));
    (void)memset(db, bfill, sizeof(db));
    return wt_nvs_add_pair(&g_nvs, &ma, alen, da, &mb, blen, db);
}

static int op_pair(void)
{
    return pair(3u, 40u, 0xC3u, 1u, 70u, 0xD1u);
}

static void pair_after(model_t* m)
{
    model_set(m, 3u, 40u, 0xC3u);
    model_set(m, 1u, 70u, 0xD1u);
}

/* A cut or a lying program at every step of a pair leaves both old objects
 * or both new ones, never one of each. */
static void test_pair(void)
{
    model_t before;
    model_t after;
    int k;
    int rc = WH_ERROR_ABORTED;
    int ok = 1;
    int cuts = 0;
    char what[96];

    for (k = 1; k < 200 && rc != WH_ERROR_OK; k++) {
        seed(&before);
        after = before;
        pair_after(&after);
        g_ops_left = k;
        g_dead = 0;
        rc = op_pair();
        g_ops_left = -1;
        g_dead = 0;
        if (store_open() != WH_ERROR_OK ||
                (!model_matches(&before) && !model_matches(&after)) ||
                put(9u, 17u, 0xE9u) != WH_ERROR_OK) {
            ok = 0;
            break;
        }
        cuts++;
    }
    (void)snprintf(what, sizeof(what),
                   "pair: both old or both new after a cut at each of %d "
                   "steps", cuts);
    check(ok && rc == WH_ERROR_OK && cuts > 4, what);

    rc = WH_ERROR_ABORTED;
    ok = 1;
    cuts = 0;
    for (k = 1; k < 200 && rc != WH_ERROR_OK; k++) {
        seed(&before);
        g_lie_left = k;
        rc = op_pair();
        g_lie_left = -1;
        if (rc != WH_ERROR_OK && (g_nvs.torn != 0u ||
                !model_matches(&before) || store_open() != WH_ERROR_OK ||
                !model_matches(&before))) {
            ok = 0;
            break;
        }
        cuts++;
    }
    (void)snprintf(what, sizeof(what),
                   "pair: a failed step at each of %d is compacted away now",
                   cuts - 1);
    check(ok && rc == WH_ERROR_OK && cuts > 4, what);

    rc = WH_ERROR_ABORTED;
    ok = 1;
    for (k = 1; k < 200 && rc != WH_ERROR_OK; k++) {
        seed(&before);
        g_lie_left = k;
        rc = op_add_new();
        g_lie_left = -1;
        if (rc != WH_ERROR_OK && (store_open() != WH_ERROR_OK ||
                !model_matches(&before))) {
            ok = 0;
        }
    }
    check(ok && rc == WH_ERROR_OK,
          "a single-slot commit that reported failure never becomes visible");
}

static int with(whNvmId drop, whNvmId id, whNvmSize len, uint8_t fill)
{
    whNvmMetadata meta;
    uint8_t buf[256];

    (void)memset(&meta, 0, sizeof(meta));
    meta.id = id;
    (void)memset(buf, fill, sizeof(buf));
    return wt_nvs_compact_with(&g_nvs, drop, &meta, len, buf);
}

static int op_with(void)
{
    return with(2u, 1u, 50u, 0xF1u);
}

static int op_with_new(void)
{
    return with(2u, 4u, 30u, 0xF4u);
}

static void with_sweep(const char* name, op_fn op, whNvmId id, whNvmSize len,
                       uint8_t fill)
{
    model_t before;
    model_t after;
    int k;
    int rc = WH_ERROR_ABORTED;
    int ok = 1;
    int cuts = 0;
    char what[96];

    for (k = 1; k < 200 && rc != WH_ERROR_OK; k++) {
        seed(&before);
        after = before;
        model_set(&after, 2u, 0u, 0u);
        model_set(&after, id, len, fill);
        g_ops_left = k;
        g_dead = 0;
        rc = op();
        g_ops_left = -1;
        g_dead = 0;
        if (store_open() != WH_ERROR_OK ||
                (!model_matches(&before) && !model_matches(&after))) {
            ok = 0;
            break;
        }
        cuts++;
    }
    (void)snprintf(what, sizeof(what),
                   "%s: old or new state after a cut at each of %d steps",
                   name, cuts);
    check(ok && rc == WH_ERROR_OK && cuts > 4 && model_matches(&after), what);
}

static void test_compact_with(void)
{
    model_t m;

    with_sweep("compact_with substitute", op_with, 1u, 50u, 0xF1u);
    with_sweep("compact_with append", op_with_new, 4u, 30u, 0xF4u);
    seed(&m);
    check(with(2u, 2u, 8u, 0x11u) == WH_ERROR_BADARGS &&
          model_matches(&m), "compact_with refuses to drop its own record");
}

/* A compaction header that lands but reports failure must not win a later
 * boot over the writes made after it. */
static void test_header_lie(void)
{
    model_t before;
    int k;
    int ok = 1;
    int rc = WH_ERROR_ABORTED;

    for (k = 1; k < 200 && rc != WH_ERROR_OK; k++) {
        seed(&before);
        g_lie_left = k;
        rc = op_compact();
        g_lie_left = -1;
        if (rc != WH_ERROR_OK && (put(5u, 12u, 0xE5u) != WH_ERROR_OK ||
                store_open() != WH_ERROR_OK || !model_matches(&before) ||
                wh_Nvm_GetMetadata(&g_nvm, 5u, NULL) != WH_ERROR_OK)) {
            ok = 0;
        }
    }
    check(ok && rc == WH_ERROR_OK,
          "a failed compaction never outranks the writes after it");
}

static void set_magic(uint32_t part, uint32_t magic)
{
    uint32_t rec[4];

    (void)memcpy(rec, g_mem + part * SECTOR, sizeof(rec));
    rec[0] = magic;
    rec[2] = ~magic;
    (void)memcpy(g_mem + part * SECTOR, rec, sizeof(rec));
}

/* Commit word of directory slot i in partition 0. */
static uint32_t commit_off(uint32_t i)
{
    return WT_NVS_UNIT + 3u * WT_NVS_UNIT * i + 2u * WT_NVS_UNIT;
}

static void test_provisional(void)
{
    model_t before;
    uint32_t rec[4];

    seed(&before);
    check(op_pair() == WH_ERROR_OK && store_open() == WH_ERROR_OK,
          "provisional store seeded");
    (void)memset(g_mem + commit_off(4u), 0xFF, WT_NVS_UNIT);
    check(store_open() == WH_ERROR_OK && model_matches(&before) &&
          g_nvs.torn != 0u,
          "a provisional slot without its partner is a torn tail");

    seed(&before);
    check(op_pair() == WH_ERROR_OK, "second provisional store seeded");
    (void)memcpy(rec, g_mem + commit_off(4u), sizeof(rec));
    rec[1] |= 0x80000000u;
    rec[3] = ~rec[1];
    (void)memcpy(g_mem + commit_off(4u), rec, sizeof(rec));
    check(store_open() == WH_ERROR_ABORTED,
          "two provisional slots in a row are corruption");

    seed(&before);
    check(op_pair() == WH_ERROR_OK, "ECC provisional store seeded");
    g_ecc_off = commit_off(4u);
    g_ecc = 1;
    check(store_open() == WH_ERROR_OK && model_matches(&before),
          "an ECC error on the partner's commit is a torn tail");
    g_ecc = 0;

    seed(&before);
    set_magic(0u, 0x31564E57u);
    check(store_open() == WH_ERROR_ABORTED,
          "a store with the WNV1 magic is refused");
    g_allow_format = 1;
    check(store_open() == WH_ERROR_OK && g_nvs.used == 0u,
          "a refused WNV1 store reformats only where allowed");
    g_allow_format = 0;
}

int main(void)
{
    test_basic();
    test_policy();
    test_corruption();
    test_power_cut();
    test_runtime_fault();
    test_stale_copy();
    test_epoch_wrap();
    test_torn_header_copy();
    test_ecc_blank();
    test_pair();
    test_provisional();
    test_compact_with();
    test_header_lie();
    if (g_failures != 0) {
        (void)printf("FAIL: nvm_native (%d)\n", g_failures);
        return EXIT_FAILURE;
    }
    (void)printf("PASS: nvm_native\n");
    return EXIT_SUCCESS;
}
