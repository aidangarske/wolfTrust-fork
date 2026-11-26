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

/* Native-store vault transactions under a power cut, or a program that lands
 * but reports failure, at every flash step: each object reads its old or new
 * value, and no seal counter is ever used twice under one key. */

#include "wolftrust/nvm_native.h"
#include "wolftrust/services/hsm.h"
#include "wolftrust/services/vault_service.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECTOR     4096u
#define FLASH_SZ   (2u * SECTOR)
#define PAGE       8u
#define OWNER      5
#define SUB        (-1)
#define MAX_USED   1024u
#define STAGE_ID   0x0123u

typedef struct {
    uint32_t magic;
    uint32_t reserved;
    uint64_t global;
    uint64_t slot[32];
} table_t;

static int g_failures;
static uint8_t g_mem[FLASH_SZ];
static whFlashRamsimCtx g_sim;
static int g_ops_left = -1;
static int g_dead;
static int g_lie_left = -1;
static int g_erase_fail;

static uint64_t g_used[MAX_USED];
static uint32_t g_used_n;
static int g_reuse;

static const whNvmCb g_nvs_cb[1] = {WT_NVS_CB};
static wt_nvs_context_t g_nvs;
static whNvmContext g_nvm;

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
    if (g_ops_left > 0 && --g_ops_left == 0) {
        g_dead = 1;
        return 2;
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
    return g_dead ? WH_ERROR_ABORTED : whFlashRamsim_Read(c, off, size, data);
}

static int f_program(void* c, uint32_t off, uint32_t size,
                     const uint8_t* data)
{
    int cut = cut_now();

    if (g_lie_left > 0 && --g_lie_left == 0) {
        (void)whFlashRamsim_Program(c, off, size, data);
        return WH_ERROR_ABORTED;
    }
    if (cut == 1) {
        return WH_ERROR_ABORTED;
    }
    if (cut == 2) {
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
    if (g_erase_fail != 0) {
        g_erase_fail = 0;
        return WH_ERROR_ABORTED;
    }
    return whFlashRamsim_Erase(c, off, size);
}

static int f_verify(void* c, uint32_t off, uint32_t size, const uint8_t* d)
{
    return g_dead ? WH_ERROR_ABORTED : whFlashRamsim_Verify(c, off, size, d);
}

static int f_blank(void* c, uint32_t off, uint32_t size)
{
    return g_dead ? WH_ERROR_ABORTED :
           whFlashRamsim_BlankCheck(c, off, size);
}

static const whFlashCb g_cb[1] = {{
    .PartitionSize = f_size,
    .Read = f_read,
    .Program = f_program,
    .Erase = f_erase,
    .Verify = f_verify,
    .BlankCheck = f_blank,
}};

/* Every counter sealed under the current key; a repeat is nonce reuse. */
static psa_status_t rec_seal(const uint8_t* aad, size_t aad_len,
                             uint64_t counter, const uint8_t* pt,
                             size_t pt_len, uint8_t* ct)
{
    uint32_t i;

    for (i = 0u; i < g_used_n; i++) {
        if (g_used[i] == counter) {
            g_reuse = 1;
        }
    }
    if (g_used_n < MAX_USED) {
        g_used[g_used_n++] = counter;
    }
    return wt_hsm_sealer.seal(aad, aad_len, counter, pt, pt_len, ct);
}

static psa_status_t rec_unseal(const uint8_t* aad, size_t aad_len,
                               uint64_t counter, const uint8_t* ct,
                               size_t ct_len, uint8_t* pt)
{
    return wt_hsm_sealer.unseal(aad, aad_len, counter, ct, ct_len, pt);
}

static const wt_vault_sealer_t g_rec = {rec_seal, rec_unseal};

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
    g_used_n = 0u;
    g_reuse = 0;
}

static int store_only(void)
{
    wt_nvs_config_t cfg;

    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.cb = g_cb;
    cfg.context = &g_sim;
    (void)memset(&g_nvm, 0, sizeof(g_nvm));
    g_nvm.cb = (whNvmCb*)g_nvs_cb;
    g_nvm.context = &g_nvs;
    return wt_nvs_init(&g_nvs, &cfg);
}

/* One boot: the store, the vault bind and the seal key, as nvm_boot does. */
static int boot(void)
{
    if (store_only() != WH_ERROR_OK || wt_hsm_vault_init(&g_nvm) != 0 ||
            wt_hsm_seal_init(&g_nvm) != 0) {
        return -1;
    }
    wt_hsm_vault_set_sealer(&g_rec);
    return 0;
}

static psa_status_t put(uint64_t uid, uint32_t flags, const char* v)
{
    return wt_hsm_vault_backend.set(OWNER, SUB, uid, flags,
                                    (const uint8_t*)v, strlen(v) + 1u);
}

/* 1 when uid reads v, or is absent and v is NULL. */
static int holds(uint64_t uid, const char* v)
{
    uint8_t buf[64];
    size_t got = 0u;
    psa_status_t st = wt_hsm_vault_backend.get(OWNER, SUB, uid, 0u, buf,
                                               sizeof(buf), &got);

    if (v == NULL) {
        return st == PSA_ERROR_DOES_NOT_EXIST;
    }
    return st == PSA_SUCCESS && got == strlen(v) + 1u &&
           memcmp(buf, v, got) == 0;
}

typedef struct {
    psa_status_t (*run)(void);
    uint64_t uid;
    const char* before;
    const char* after;
    const char* name;
} txn_t;

static psa_status_t op_seal_new(void)
{
    return put(3u, WT_VAULT_FLAG_SEALED, "three");
}

static psa_status_t op_seal_replace(void)
{
    return put(1u, WT_VAULT_FLAG_SEALED, "one-v2");
}

static psa_status_t op_plain_over_sealed(void)
{
    return put(1u, 0u, "one-plain");
}

static psa_status_t op_seal_over_plain(void)
{
    return put(2u, WT_VAULT_FLAG_SEALED, "two-sealed");
}

static psa_status_t op_seal_remove(void)
{
    return wt_hsm_vault_backend.remove(OWNER, SUB, 1u);
}

static psa_status_t op_plain_remove(void)
{
    return wt_hsm_vault_backend.remove(OWNER, SUB, 2u);
}

static const txn_t g_txns[] = {
    {op_seal_new, 3u, NULL, "three", "sealed create"},
    {op_seal_replace, 1u, "one-v1", "one-v2", "sealed replace"},
    {op_plain_over_sealed, 1u, "one-v1", "one-plain", "plain over sealed"},
    {op_seal_over_plain, 2u, "two-plain", "two-sealed", "sealed over plain"},
    {op_seal_remove, 1u, "one-v1", NULL, "sealed remove"},
    {op_plain_remove, 2u, "two-plain", NULL, "plain remove"},
};

static int seed(int rebind)
{
    sim_reset();
    if (boot() != 0 || put(1u, WT_VAULT_FLAG_SEALED, "one-v1") != 0 ||
            put(2u, 0u, "two-plain") != 0) {
        return -1;
    }
    /* A rebind forgets the RAM counter, so the next seal reserves first. */
    return (rebind != 0) ? boot() : 0;
}

/* The untouched objects, and a fresh seal that must use a new counter. */
static int survives(const txn_t* t)
{
    if ((t->uid != 1u && !holds(1u, "one-v1")) ||
            (t->uid != 2u && !holds(2u, "two-plain"))) {
        return 0;
    }
    return put(4u, WT_VAULT_FLAG_SEALED, "retry") == PSA_SUCCESS &&
           holds(4u, "retry") && boot() == 0 && holds(4u, "retry") &&
           g_reuse == 0;
}

static void sweep(const txn_t* t, int rebind, int lie)
{
    int k;
    int ok = 1;
    int steps = 0;
    psa_status_t st = PSA_ERROR_STORAGE_FAILURE;
    char what[128];

    for (k = 1; k < 400 && st != PSA_SUCCESS && ok; k++) {
        if (seed(rebind) != 0) {
            ok = 0;
            break;
        }
        if (lie != 0) {
            g_lie_left = k;
        }
        else {
            g_ops_left = k;
            g_dead = 0;
        }
        st = t->run();
        g_ops_left = -1;
        g_lie_left = -1;
        g_dead = 0;
        /* A reported failure must leave the old value, before a reboot. */
        if (lie != 0 && st != PSA_SUCCESS && !holds(t->uid, t->before)) {
            ok = 0;
        }
        if (ok && boot() != 0) {
            ok = 0;
        }
        if (ok && st == PSA_SUCCESS && !holds(t->uid, t->after)) {
            ok = 0;
        }
        if (ok && st != PSA_SUCCESS && !holds(t->uid, t->before) &&
                (lie != 0 || !holds(t->uid, t->after))) {
            ok = 0;
        }
        if (ok && !survives(t)) {
            ok = 0;
        }
        steps++;
    }
    (void)snprintf(what, sizeof(what), "%s (%s, %s): old or new at each of "
                   "%d steps, no counter reused", t->name,
                   rebind ? "after a rebind" : "warm",
                   lie ? "failed program" : "power cut", steps);
    check(ok && st == PSA_SUCCESS && steps > 3, what);
}

static void test_transactions(void)
{
    uint32_t i;
    int rebind;
    int lie;

    for (i = 0u; i < sizeof(g_txns) / sizeof(g_txns[0]); i++) {
        for (rebind = 0; rebind < 2; rebind++) {
            for (lie = 0; lie < 2; lie++) {
                sweep(&g_txns[i], rebind, lie);
            }
        }
    }
}

/* Many seals across range boundaries and rebinds never repeat a counter. */
static void test_counter_ranges(void)
{
    char v[16];
    int i;
    int ok = (seed(0) == 0);

    for (i = 0; i < 60 && ok; i++) {
        (void)snprintf(v, sizeof(v), "gen-%d", i);
        ok = put(1u + (uint64_t)(i % 3), WT_VAULT_FLAG_SEALED, v) ==
             PSA_SUCCESS && holds(1u + (uint64_t)(i % 3), v);
        if (ok && (i % 4) == 3) {
            ok = (boot() == 0);
        }
        if (ok && (i % 7) == 6) {
            g_ops_left = 3;
            (void)put(9u, WT_VAULT_FLAG_SEALED, "cut");
            g_ops_left = -1;
            g_dead = 0;
            ok = (boot() == 0);
        }
    }
    check(ok && g_reuse == 0 && g_used_n > 60u,
          "60 seals across ranges, rebinds and cuts never reuse a counter");
}

/* Write-once objects refuse the pair and compaction paths too. */
static void test_write_once(void)
{
    uint32_t once = WT_VAULT_FLAG_SEALED | WT_VAULT_FLAG_WRITE_ONCE;

    check(seed(0) == 0 && put(5u, once, "once") == PSA_SUCCESS,
          "sealed write-once object stored");
    check(put(5u, WT_VAULT_FLAG_SEALED, "again") != PSA_SUCCESS &&
          put(5u, 0u, "plain") != PSA_SUCCESS && holds(5u, "once"),
          "a sealed or plain overwrite of a write-once object is refused");
    check(wt_hsm_vault_backend.remove(OWNER, SUB, 5u) != PSA_SUCCESS &&
          boot() == 0 && holds(5u, "once"),
          "a sealed write-once object cannot be removed");
}

/* The seal key and the table exist together on a WNV2 store. */
static void test_key_table_pair(void)
{
    whNvmMetadata meta;

    sim_reset();
    check(boot() == 0 &&
          g_nvs_cb[0].GetMetadata(&g_nvs, WT_HSM_VAULT_TABLE_ID, &meta) ==
              WH_ERROR_OK, "a blank store gets the seal key and table");
    check(wt_nvs_destroy_objects(&g_nvs, 1u,
              (const whNvmId[]){WT_HSM_VAULT_TABLE_ID}) == WH_ERROR_OK &&
          boot() != 0, "a seal key without its table fails the bind");
    sim_reset();
    check(store_only() == WH_ERROR_OK && wt_hsm_vault_init(&g_nvm) == 0,
          "bare store bound");
    (void)memset(&meta, 0, sizeof(meta));
    meta.id = 0x0200u;
    check(wt_nvs_add_object(&g_nvs, &meta, 4u, (const uint8_t*)"abc") ==
              WH_ERROR_OK && wt_hsm_seal_init(&g_nvm) != 0,
          "a populated store with neither is not given a new seal key");
}

/* A cut anywhere in the first boot's seal key and table pair must leave a
 * store the next boot provisions, not one it refuses forever. */
static void test_first_boot_cut(void)
{
    int k;
    int ok = 1;
    int steps = 0;
    int rc = -1;

    for (k = 1; k < 100 && rc != 0 && ok; k++) {
        sim_reset();
        g_ops_left = k;
        g_dead = 0;
        rc = boot();
        g_ops_left = -1;
        g_dead = 0;
        ok = (boot() == 0) && put(1u, WT_VAULT_FLAG_SEALED, "first") == 0 &&
             holds(1u, "first");
        steps++;
    }
    check(ok && rc == 0 && steps > 3,
          "a cut at every first-boot step still provisions on the next boot");
}

/* Moves the committed table's global counter, as a long-lived device has. */
static int set_global(uint64_t global)
{
    table_t t;
    whNvmMetadata meta;

    if (wt_nvs_get_metadata(&g_nvs, WT_HSM_VAULT_TABLE_ID, &meta) !=
            WH_ERROR_OK || meta.len != sizeof(t) ||
            wt_nvs_read(&g_nvs, WT_HSM_VAULT_TABLE_ID, 0u, sizeof(t),
                        (uint8_t*)&t) != WH_ERROR_OK) {
        return -1;
    }
    t.global = global;
    return wt_nvs_compact_with(&g_nvs, STAGE_ID, &meta, meta.len,
                               (const uint8_t*)&t);
}

/* Issued counters stop short of the 64-bit limit instead of wrapping. */
static void test_counter_limit(void)
{
    sim_reset();
    check(boot() == 0 && set_global(UINT64_MAX - 8u) == WH_ERROR_OK &&
          boot() == 0 &&
          put(6u, WT_VAULT_FLAG_SEALED, "max") ==
              PSA_ERROR_INSUFFICIENT_STORAGE && holds(6u, NULL) &&
          g_reuse == 0, "a table near the counter limit refuses new seals");
}

int main(void)
{
    test_transactions();
    test_counter_ranges();
    test_key_table_pair();
    test_first_boot_cut();
    test_write_once();
    test_counter_limit();
    if (g_failures != 0) {
        (void)printf("FAIL: vault_txn (%d)\n", g_failures);
        return EXIT_FAILURE;
    }
    (void)printf("PASS: vault_txn\n");
    return EXIT_SUCCESS;
}
