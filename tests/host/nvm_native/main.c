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

static uint32_t f_size(void* c)
{
    (void)c;
    return SECTOR;
}

static int f_read(void* c, uint32_t off, uint32_t size, uint8_t* data)
{
    if (g_dead) {
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
    if (g_dead) {
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
    g_nvs.slot[0].start = 0xFFFF0000u;
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

int main(void)
{
    test_basic();
    test_policy();
    test_corruption();
    test_power_cut();
    test_runtime_fault();
    if (g_failures != 0) {
        (void)printf("FAIL: nvm_native (%d)\n", g_failures);
        return EXIT_FAILURE;
    }
    (void)printf("PASS: nvm_native\n");
    return EXIT_SUCCESS;
}
