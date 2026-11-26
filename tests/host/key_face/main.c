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

/* The vault's key face (native engine) over real FF-M round trips: the
 * crypto partition's key client, forged requests from that partition, and a
 * rogue partition that is not the registered keystore client. */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_nvm.h"
#include "test_nvm_store.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "spm_host.h"
#include "wolftrust/ffm.h"
#include "wolftrust/services/hsm.h"
#include "wolftrust/services/vault_ipc.h"
#include "wolftrust/services/vault_service.h"
#include "wolftrust/services/crypto_native.h"

#include <stdio.h>
#include <string.h>

#define TEST_HSM_PARTITION    4
#define TEST_VAULT_PARTITION  5
#define TEST_ROGUE_PARTITION  6
#define TEST_VAULT_SID        4098U
#define TEST_HSM_SID          4102U
#define TEST_ROGUE_SID        4200U

#define TEST_P256_LEN (WT_VAULT_KEY_MATERIAL_LEN + WT_VAULT_KEY_PUB_LEN)
#define TEST_SIGN_P256 \
    WT_VAULT_KEY_LABEL(WT_VAULT_KEY_USAGE_SIGN | WT_VAULT_KEY_USAGE_VERIFY, \
                       WT_VAULT_KEY_P256)
#define TEST_RECORD WT_VAULT_KEY_LABEL(0U, WT_VAULT_KEY_PSA_RECORD)

#define RAMSIM_SIZE   (64 * 1024)
#define RAMSIM_SECTOR 4096
#define RAMSIM_PAGE   8

static uint8_t g_flash_memory[RAMSIM_SIZE];
static whFlashRamsimCfg g_ramsim_cfg;
static whFlashRamsimCtx g_ramsim_ctx;
static const whFlashCb g_ramsim_cb[1] = {WH_FLASH_RAMSIM_CB};
static whNvmFlashConfig g_nvm_flash_cfg;
static whNvmFlashContext g_nvm_flash_ctx;
static const whNvmCb g_nvm_cb[1] = {WH_NVM_FLASH_CB};
static whNvmConfig g_nvm_cfg;
static whNvmContext g_store;

static const wt_vault_keystore_t* g_client;
static wt_svc_client_t g_raw_hsm;
static wt_svc_client_t g_raw_rogue;
static int g_failures;
static unsigned int g_wipe_checks;
static unsigned int g_wipe_dirty;

void wt_vault_wipe_probe(const uint8_t* buf, size_t len)
{
    size_t i;
    uint8_t acc = 0U;

    for (i = 0U; i < len; i++) {
        acc |= buf[i];
    }
    g_wipe_checks++;
    if (acc != 0U) {
        g_wipe_dirty++;
    }
}

/* key_client.c hands its IPC face to the keyvault; capture it here. */
int wt_hsm_keyvault_init(const wt_vault_keystore_t* store)
{
    g_client = store;
    return (store != NULL) ? 0 : -1;
}

static void check(int ok, const char* what)
{
    if (ok) {
        (void)printf("PASS: %s\n", what);
    } else {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
}

static int test_check_read(void* context, psa_client_id_t caller,
                           const void* address, size_t size)
{
    (void)context;
    (void)caller;
    return size == 0U || address != NULL;
}

static int test_check_write(void* context, psa_client_id_t caller,
                            void* address, size_t size)
{
    (void)context;
    (void)caller;
    return size == 0U || address != NULL;
}

static void test_panic(void* context, int32_t partition_id)
{
    (void)context;
    (void)partition_id;
}

static int idle_dispatch(void* context, wt_ffm_runtime_t* runtime,
                         int32_t partition_id)
{
    (void)context;
    (void)runtime;
    (void)partition_id;
    return WT_FFM_ERROR_STATE;
}

static const wt_spm_host_ops_t g_port_ops = {
    test_check_read,
    test_check_write,
    idle_dispatch,
    test_panic
};

/* wt_spm_transport_direct plus running the vault for each pending call. */
static int test_transport(wt_ffm_runtime_t* runtime, wt_spm_call_t* call)
{
    int status = wt_spm_gate(runtime, NULL, call);
    unsigned int guard = 0U;

    while (status == WT_FFM_SUCCESS && call->pending_valid != 0U &&
            call->ret_int == WT_FFM_ERROR_NOT_READY && guard < 8U) {
        wt_spm_run();
        status = wt_spm_gate(runtime, NULL, call);
        guard++;
    }
    return status;
}

static const wt_service_descriptor_t g_vault_services[] = {
    { "SERVICE_VAULT", TEST_VAULT_SID, 1U, WT_SERVICE_VERSION_RELAXED,
      0x10U, 0U, 0U, 1U }
};
static const wt_service_descriptor_t g_hsm_services[] = {
    { "SERVICE_HSM", TEST_HSM_SID, 1U, WT_SERVICE_VERSION_RELAXED,
      0x20U, 0U, 1U, 1U }
};
static const wt_service_descriptor_t g_rogue_services[] = {
    { "SERVICE_ROGUE", TEST_ROGUE_SID, 1U, WT_SERVICE_VERSION_RELAXED,
      0x10U, 0U, 1U, 1U }
};
static const uint32_t g_vault_deps[] = { TEST_VAULT_SID };

static const wt_partition_manifest_t g_partitions[] = {
    {
        "PARTITION_VAULT", TEST_VAULT_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_vault_services, 1U, NULL, 0U, NULL, 0U
    },
    {
        "PARTITION_HSM", TEST_HSM_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_hsm_services, 1U, g_vault_deps, 1U, NULL, 0U
    },
    {
        "PARTITION_ROGUE", TEST_ROGUE_PARTITION, WT_FFM_VERSION_1_0,
        WT_PARTITION_MODEL_IPC, WT_PARTITION_PRIORITY_NORMAL,
        g_rogue_services, 1U, g_vault_deps, 1U, NULL, 0U
    }
};

static const wt_system_manifest_t g_manifest = {
    .format_version = WT_MANIFEST_FORMAT_VERSION,
    .generator_version = "key-face-test",
    .features = WT_MANIFEST_FEATURE_IPC,
    .partitions = g_partitions,
    .partition_count = sizeof(g_partitions) / sizeof(g_partitions[0])
};

static int store_up(void)
{
    (void)memset(g_flash_memory, 0xFF, sizeof(g_flash_memory));
    (void)memset(&g_ramsim_cfg, 0, sizeof(g_ramsim_cfg));
    g_ramsim_cfg.memory = g_flash_memory;
    g_ramsim_cfg.size = RAMSIM_SIZE;
    g_ramsim_cfg.sectorSize = RAMSIM_SECTOR;
    g_ramsim_cfg.pageSize = RAMSIM_PAGE;
    g_ramsim_cfg.erasedByte = 0xFF;
    (void)memset(&g_ramsim_ctx, 0, sizeof(g_ramsim_ctx));
    (void)memset(&g_nvm_flash_cfg, 0, sizeof(g_nvm_flash_cfg));
    g_nvm_flash_cfg.cb = g_ramsim_cb;
    g_nvm_flash_cfg.context = &g_ramsim_ctx;
    g_nvm_flash_cfg.config = &g_ramsim_cfg;
    (void)memset(&g_nvm_flash_ctx, 0, sizeof(g_nvm_flash_ctx));
    (void)memset(&g_nvm_cfg, 0, sizeof(g_nvm_cfg));
    g_nvm_cfg.cb = (whNvmCb*)g_nvm_cb;
    g_nvm_cfg.context = &g_nvm_flash_ctx;
    g_nvm_cfg.config = &g_nvm_flash_cfg;
    (void)memset(&g_store, 0, sizeof(g_store));
    if (wh_Nvm_Init(&g_store, &g_nvm_cfg) != WH_ERROR_OK ||
            wt_hsm_vault_init(&g_store) != 0 ||
            test_vault_store_ready(&g_store) != 0) {
        return -1;
    }
    wt_vault_service_set_backend(&wt_hsm_vault_backend);
    wt_vault_service_set_keystore(&wt_hsm_vault_keystore);
    wt_vault_service_set_keystore_client(TEST_HSM_PARTITION);
    return 0;
}

static int runtime_up(void)
{
    if (wt_spm_host_init(&g_manifest, &g_port_ops, NULL) !=
            WT_FFM_SUCCESS ||
            wt_spm_host_bind(TEST_VAULT_PARTITION, wt_vault_service_dispatch,
                             NULL) != WT_FFM_SUCCESS ||
            wt_spm_host_bind(TEST_HSM_PARTITION, idle_dispatch, NULL) !=
                WT_FFM_SUCCESS ||
            wt_spm_host_bind(TEST_ROGUE_PARTITION, idle_dispatch, NULL) !=
                WT_FFM_SUCCESS) {
        return -1;
    }
    return 0;
}

static void raw_bind(wt_svc_client_t* c, int32_t partition_id)
{
    (void)memset(c, 0, sizeof(*c));
    c->transport = test_transport;
    c->runtime = wt_spm_host_runtime();
    c->partition_id = partition_id;
    c->sid = TEST_VAULT_SID;
}

/* A forged key-face request, exactly as a compromised partition can send. */
static psa_status_t raw(wt_svc_client_t* c, int32_t type, int32_t sub,
                        uint64_t uid, uint32_t label, uint32_t select,
                        const uint8_t* in, size_t in_len, uint8_t* out,
                        size_t out_len)
{
    wt_vault_req_t req;
    size_t got = out_len;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    (void)memset(&req, 0, sizeof(req));
    req.uid = uid;
    req.flags = label;
    req.sub_owner = sub;
    req.select = select;
    if (wt_svc_client_call(c, type, &req, sizeof(req), in, in_len, out, &got,
                           &status) != WT_FFM_SUCCESS) {
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }
    return status;
}

static void fill(uint8_t* buf, size_t len, uint8_t seed)
{
    size_t i;

    for (i = 0U; i < len; i++) {
        buf[i] = (uint8_t)(seed + i);
    }
}

static void test_client_round_trip(void)
{
    uint8_t obj[TEST_P256_LEN];
    uint8_t out[TEST_P256_LEN];

    fill(obj, sizeof(obj), 0x10U);
    check(g_client != NULL && g_client != &wt_hsm_vault_keystore,
          "K1 the bound keyvault uses the IPC key face");
    check(g_client->put(TEST_HSM_PARTITION, -1, 0x10ULL, TEST_SIGN_P256, obj,
                        sizeof(obj)) == PSA_SUCCESS,
          "K1 a P-256 key is stored through the key face");
    (void)memset(out, 0, sizeof(out));
    check(g_client->get(TEST_HSM_PARTITION, -1, 0x10ULL,
                        WT_VAULT_KEY_LABEL(WT_VAULT_KEY_USAGE_SIGN,
                                           WT_VAULT_KEY_P256),
                        WT_VAULT_KEY_SEL_WHOLE, 0U, out, sizeof(out)) ==
              PSA_SUCCESS && memcmp(out, obj, sizeof(obj)) == 0,
          "K1 it reads back whole with the usage it carries");
    check(g_client->get(TEST_HSM_PARTITION, -1, 0x10ULL,
                        WT_VAULT_KEY_LABEL(WT_VAULT_KEY_USAGE_ENCRYPT,
                                           WT_VAULT_KEY_P256),
                        WT_VAULT_KEY_SEL_WHOLE, 0U, out, sizeof(out)) ==
              PSA_ERROR_NOT_PERMITTED,
          "K1 a usage the key lacks is refused by the vault");
    check(g_client->get(TEST_HSM_PARTITION, -1, 0x10ULL,
                        WT_VAULT_KEY_LABEL(0U, WT_VAULT_KEY_AES256),
                        WT_VAULT_KEY_SEL_WHOLE, 0U, out,
                        WT_VAULT_KEY_MATERIAL_LEN) == PSA_ERROR_NOT_PERMITTED,
          "K1 the wrong key type is refused by the vault");
    check(g_client->get(TEST_HSM_PARTITION, -1, 0x10ULL, TEST_SIGN_P256,
                        WT_VAULT_KEY_SEL_WHOLE, 0U, out, 32U) ==
              PSA_ERROR_STORAGE_FAILURE,
          "K1 a whole read of the wrong length fails");
    check(g_client->put(TEST_HSM_PARTITION, -1, 0x10ULL, TEST_SIGN_P256, obj,
                        sizeof(obj)) == PSA_ERROR_ALREADY_EXISTS,
          "K1 put is create-only");
    check(g_client->del(TEST_HSM_PARTITION, -1, 0x10ULL) == PSA_SUCCESS &&
              g_client->get(TEST_HSM_PARTITION, -1, 0x10ULL, TEST_SIGN_P256,
                            WT_VAULT_KEY_SEL_WHOLE, 0U, out, sizeof(out)) ==
                  PSA_ERROR_DOES_NOT_EXIST &&
              g_client->del(TEST_HSM_PARTITION, -1, 0x10ULL) ==
                  PSA_ERROR_DOES_NOT_EXIST,
          "K1 delete removes it, and a second delete finds nothing");
}

static void test_owner_stamping(void)
{
    uint8_t obj[TEST_P256_LEN];
    uint8_t out[TEST_P256_LEN];

    fill(obj, sizeof(obj), 0x20U);
    check(g_client->put(99, -2, 0x20ULL, TEST_SIGN_P256, obj, sizeof(obj)) ==
              PSA_SUCCESS,
          "K2 a put naming another owner is accepted");
    check(wt_hsm_vault_keystore.get(TEST_HSM_PARTITION, -2, 0x20ULL,
                                    TEST_SIGN_P256, WT_VAULT_KEY_SEL_WHOLE,
                                    0U, out, sizeof(out)) == PSA_SUCCESS &&
              wt_hsm_vault_keystore.get(99, -2, 0x20ULL, TEST_SIGN_P256,
                                        WT_VAULT_KEY_SEL_WHOLE, 0U, out,
                                        sizeof(out)) ==
                  PSA_ERROR_DOES_NOT_EXIST,
          "K2 the vault stored it under the caller's own id");
    check(wt_hsm_vault_keystore.put(7, -2, 0x21ULL, TEST_SIGN_P256, obj,
                                    sizeof(obj)) == PSA_SUCCESS &&
              raw(&g_raw_hsm, WT_VAULT_OP_KEY_GET, -2, 0x21ULL,
                  TEST_SIGN_P256, WT_VAULT_KEY_SEL_WHOLE, NULL, 0U, out,
                  sizeof(out)) == PSA_ERROR_DOES_NOT_EXIST &&
              raw(&g_raw_hsm, WT_VAULT_OP_KEY_DEL, -2, 0x21ULL, 0U, 0U, NULL,
                  0U, NULL, 0U) == PSA_ERROR_DOES_NOT_EXIST,
          "K2 another owner's key is unreachable by sub and uid");
}

static void test_iak(void)
{
    uint8_t iak[TEST_P256_LEN];
    uint8_t obj[TEST_P256_LEN];
    uint8_t out[TEST_P256_LEN];

    fill(iak, sizeof(iak), 0x30U);
    fill(obj, sizeof(obj), 0x40U);
    check(wt_hsm_vault_keystore.put(WT_VAULT_IAK_OWNER, WT_VAULT_IAK_SUB,
                                    WT_VAULT_IAK_UID, TEST_SIGN_P256, iak,
                                    sizeof(iak)) == PSA_SUCCESS,
          "K3 boot provisions the IAK on the direct face");
    (void)memset(out, 0, sizeof(out));
    check(g_client->get(WT_VAULT_IAK_OWNER, WT_VAULT_IAK_SUB,
                        WT_VAULT_IAK_UID, TEST_SIGN_P256,
                        WT_VAULT_KEY_SEL_WHOLE, 0U, out, sizeof(out)) ==
              PSA_SUCCESS && memcmp(out, iak, sizeof(iak)) == 0,
          "K3 attestation reads the IAK at runtime");
    check(g_client->put(WT_VAULT_IAK_OWNER, WT_VAULT_IAK_SUB,
                        WT_VAULT_IAK_UID, TEST_SIGN_P256, obj, sizeof(obj)) ==
              PSA_ERROR_NOT_PERMITTED &&
              g_client->del(WT_VAULT_IAK_OWNER, WT_VAULT_IAK_SUB,
                            WT_VAULT_IAK_UID) == PSA_ERROR_NOT_PERMITTED &&
              g_client->get(WT_VAULT_IAK_OWNER, -1, 0x30ULL, TEST_SIGN_P256,
                            WT_VAULT_KEY_SEL_WHOLE, 0U, out, sizeof(out)) ==
                  PSA_ERROR_NOT_PERMITTED,
          "K3 the client only reads the IAK triple as owner 0");
    (void)memset(out, 0, sizeof(out));
    check(raw(&g_raw_hsm, WT_VAULT_OP_KEY_GET, -1, 0x77ULL, TEST_SIGN_P256,
              WT_VAULT_KEY_SEL_IAK | WT_VAULT_KEY_SEL_WHOLE, NULL, 0U, out,
              sizeof(out)) == PSA_SUCCESS &&
              memcmp(out, iak, sizeof(iak)) == 0,
          "K3 the IAK selector pins the whole triple");
    check(raw(&g_raw_hsm, WT_VAULT_OP_KEY_PUT, WT_VAULT_IAK_SUB,
              WT_VAULT_IAK_UID, TEST_SIGN_P256, WT_VAULT_KEY_SEL_IAK, obj,
              sizeof(obj), NULL, 0U) == PSA_SUCCESS &&
              raw(&g_raw_hsm, WT_VAULT_OP_KEY_DEL, WT_VAULT_IAK_SUB,
                  WT_VAULT_IAK_UID, 0U, WT_VAULT_KEY_SEL_IAK, NULL, 0U, NULL,
                  0U) == PSA_SUCCESS &&
              wt_hsm_vault_keystore.get(WT_VAULT_IAK_OWNER, WT_VAULT_IAK_SUB,
                                        WT_VAULT_IAK_UID, TEST_SIGN_P256,
                                        WT_VAULT_KEY_SEL_WHOLE, 0U, out,
                                        sizeof(out)) == PSA_SUCCESS &&
              memcmp(out, iak, sizeof(iak)) == 0,
          "K3 put and delete ignore the selector and never touch the IAK");
}

static void test_rogue(void)
{
    uint8_t obj[TEST_P256_LEN];
    uint8_t out[TEST_P256_LEN];

    fill(obj, sizeof(obj), 0x50U);
    check(raw(&g_raw_rogue, WT_VAULT_OP_KEY_PUT, 0, 0x50ULL, TEST_SIGN_P256,
              0U, obj, sizeof(obj), NULL, 0U) == PSA_ERROR_NOT_PERMITTED &&
              raw(&g_raw_rogue, WT_VAULT_OP_KEY_GET, WT_VAULT_IAK_SUB,
                  WT_VAULT_IAK_UID, TEST_SIGN_P256,
                  WT_VAULT_KEY_SEL_IAK | WT_VAULT_KEY_SEL_WHOLE, NULL, 0U,
                  out, sizeof(out)) == PSA_ERROR_NOT_PERMITTED &&
              raw(&g_raw_rogue, WT_VAULT_OP_KEY_DEL, WT_VAULT_IAK_SUB,
                  WT_VAULT_IAK_UID, 0U, WT_VAULT_KEY_SEL_IAK, NULL, 0U, NULL,
                  0U) == PSA_ERROR_NOT_PERMITTED,
          "K4 a partition other than the keystore client is refused");
    check(raw(&g_raw_hsm, WT_VAULT_OP_NVM_READ, 0, 0ULL, 0U, 0U, NULL, 0U,
              out, sizeof(out)) == PSA_ERROR_NOT_SUPPORTED &&
              raw(&g_raw_hsm, WT_VAULT_OP_NVM_ADD_OBJECT, 0, 0ULL, 0U, 0U,
                  obj, sizeof(obj), NULL, 0U) == PSA_ERROR_NOT_SUPPORTED,
          "K4 the raw NVM door is gone");
}

static void test_labels(void)
{
    uint8_t obj[WT_VAULT_OBJECT_MAX + 1U];

    fill(obj, sizeof(obj), 0x60U);
    check(raw(&g_raw_hsm, WT_VAULT_OP_KEY_PUT, 0, 0x60ULL,
              TEST_SIGN_P256 | WT_VAULT_FLAG_SEALED, 0U, obj, TEST_P256_LEN,
              NULL, 0U) == PSA_ERROR_INVALID_ARGUMENT &&
              raw(&g_raw_hsm, WT_VAULT_OP_KEY_PUT, 0, 0x60ULL,
                  TEST_SIGN_P256 & ~WT_VAULT_FLAG_KEY, 0U, obj,
                  TEST_P256_LEN, NULL, 0U) == PSA_ERROR_INVALID_ARGUMENT &&
              raw(&g_raw_hsm, WT_VAULT_OP_KEY_PUT, 0, 0x60ULL,
                  WT_VAULT_KEY_LABEL(WT_VAULT_KEY_USAGE_SIGN, 0U), 0U, obj,
                  TEST_P256_LEN, NULL, 0U) == PSA_ERROR_INVALID_ARGUMENT,
          "K5 a label with storage bits, no key flag, or no type is refused");
    check(raw(&g_raw_hsm, WT_VAULT_OP_KEY_PUT, 0, 0x61ULL,
              WT_VAULT_KEY_LABEL(WT_VAULT_KEY_USAGE_ENCRYPT,
                                 WT_VAULT_KEY_AES256), 0U, obj,
              WT_VAULT_KEY_MATERIAL_LEN + 1U, NULL, 0U) ==
              PSA_ERROR_INVALID_ARGUMENT &&
              raw(&g_raw_hsm, WT_VAULT_OP_KEY_PUT, 0, 0x61ULL,
                  TEST_SIGN_P256, 0U, obj, TEST_P256_LEN - 1U, NULL, 0U) ==
                  PSA_ERROR_INVALID_ARGUMENT &&
              raw(&g_raw_hsm, WT_VAULT_OP_KEY_PUT, 0, 0x61ULL, TEST_RECORD,
                  0U, obj, sizeof(obj), NULL, 0U) ==
                  PSA_ERROR_INVALID_ARGUMENT,
          "K5 a length that does not fit the key type is refused");
}

static void test_namespace(void)
{
    uint8_t data[16];
    uint8_t obj[TEST_P256_LEN];
    uint8_t out[TEST_P256_LEN];
    size_t got = 0U;

    fill(data, sizeof(data), 0x70U);
    fill(obj, sizeof(obj), 0x80U);
    check(wt_hsm_vault_backend.set(TEST_HSM_PARTITION, -3, 0x70ULL, 0U, data,
                                   sizeof(data)) == PSA_SUCCESS,
          "K6 a storage object under the keystore client's own ids");
    check(g_client->get(TEST_HSM_PARTITION, -3, 0x70ULL, TEST_RECORD, 0U, 0U,
                        NULL, 0U) == PSA_ERROR_DOES_NOT_EXIST &&
              g_client->del(TEST_HSM_PARTITION, -3, 0x70ULL) ==
                  PSA_ERROR_DOES_NOT_EXIST,
          "K6 the key face neither sees nor deletes it");
    check(g_client->put(TEST_HSM_PARTITION, -3, 0x70ULL, TEST_SIGN_P256, obj,
                        sizeof(obj)) == PSA_SUCCESS &&
              wt_hsm_vault_backend.get(TEST_HSM_PARTITION, -3, 0x70ULL, 0U,
                                       out, sizeof(out), &got) ==
                  PSA_SUCCESS && got == sizeof(data) &&
              memcmp(out, data, sizeof(data)) == 0,
          "K6 a key at the same triple leaves the storage object intact");
}

static void test_record_reads(void)
{
    uint8_t rec[40];
    uint8_t out[40];

    fill(rec, sizeof(rec), 0x90U);
    check(g_client->put(TEST_HSM_PARTITION, -4, 0x90ULL, TEST_RECORD, rec,
                        sizeof(rec)) == PSA_SUCCESS,
          "K7 a PSA record is stored");
    (void)memset(out, 0, sizeof(out));
    check(g_client->get(TEST_HSM_PARTITION, -4, 0x90ULL, TEST_RECORD, 0U,
                        10U, out, 20U) == PSA_SUCCESS &&
              memcmp(out, rec + 10, 20U) == 0,
          "K7 a partial read at an offset returns that range");
    check(g_client->get(TEST_HSM_PARTITION, -4, 0x90ULL, TEST_RECORD, 0U,
                        30U, out, 20U) == PSA_ERROR_INVALID_ARGUMENT &&
              g_client->get(TEST_HSM_PARTITION, -4, 0x90ULL, TEST_RECORD,
                            0U, 41U, NULL, 0U) ==
                  PSA_ERROR_INVALID_ARGUMENT,
          "K7 a read past the end is refused");
    check(g_client->get(TEST_HSM_PARTITION, -4, 0x90ULL, TEST_RECORD, 0U,
                        0U, NULL, 0U) == PSA_SUCCESS &&
              g_client->get(TEST_HSM_PARTITION, -4, 0x90ULL, TEST_SIGN_P256,
                            0U, 0U, NULL, 0U) == PSA_ERROR_NOT_PERMITTED,
          "K7 an existence check still checks the type");
}

static int add_raw(whNvmId id, whNvmFlags flags, int32_t sub, uint64_t uid,
                   uint32_t label, size_t len)
{
    whNvmMetadata meta;
    uint8_t data[TEST_P256_LEN];

    fill(data, sizeof(data), 0xA0U);
    (void)memset(&meta, 0, sizeof(meta));
    meta.id = id;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags = flags;
    meta.len = (whNvmSize)len;
    wt_hsm_vault_make_label(meta.label, TEST_HSM_PARTITION, sub, uid, label);
    return wh_Nvm_AddObject(&g_store, &meta, meta.len, data);
}

/* The metadata-flag policy wolfHSM's *Checked calls enforced, now applied by
 * the vault on the native store too. */
static void test_metadata_policy(void)
{
    uint8_t out[16];
    size_t got = 0U;
    whNvmMetadata meta;

    check(add_raw(0x011FU, WH_NVM_FLAGS_SENSITIVE | WH_NVM_FLAGS_NONEXPORTABLE |
                      WH_NVM_FLAGS_NONDESTROYABLE, -5, 0xA0ULL,
                  TEST_SIGN_P256, TEST_P256_LEN) == WH_ERROR_OK &&
              g_client->del(TEST_HSM_PARTITION, -5, 0xA0ULL) ==
                  PSA_ERROR_NOT_PERMITTED &&
              wh_Nvm_GetMetadata(&g_store, 0x011FU, &meta) == WH_ERROR_OK,
          "K10 a NONDESTROYABLE key survives a key-face delete");
    check(add_raw(0x011EU, WH_NVM_FLAGS_NONEXPORTABLE, -6, 0xB0ULL, 0U,
                  sizeof(out)) == WH_ERROR_OK &&
              wt_hsm_vault_backend.get(TEST_HSM_PARTITION, -6, 0xB0ULL, 0U,
                                       out, sizeof(out), &got) ==
                  PSA_ERROR_NOT_PERMITTED,
          "K10 the storage face refuses to read a NONEXPORTABLE object");
    check(add_raw(0x011DU, WH_NVM_FLAGS_NONDESTROYABLE, -7, 0xC0ULL, 0U,
                  sizeof(out)) == WH_ERROR_OK &&
              wt_hsm_vault_backend.remove(TEST_HSM_PARTITION, -7, 0xC0ULL) ==
                  PSA_ERROR_NOT_PERMITTED &&
              wh_Nvm_GetMetadata(&g_store, 0x011DU, &meta) == WH_ERROR_OK,
          "K10 the storage face cannot remove a NONDESTROYABLE object");
}

static void test_restart(void)
{
    uint8_t out[TEST_P256_LEN];

    (void)wt_spm_host_restarted(TEST_VAULT_PARTITION,
                                PSA_ERROR_COMMUNICATION_FAILURE);
    wt_hsm_keyvault_vault_restarted();
    check(g_client->get(WT_VAULT_IAK_OWNER, WT_VAULT_IAK_SUB,
                        WT_VAULT_IAK_UID, TEST_SIGN_P256,
                        WT_VAULT_KEY_SEL_WHOLE, 0U, out, sizeof(out)) ==
              PSA_SUCCESS,
          "K8 the client reconnects after a vault restart");
}

int main(void)
{
    if (store_up() != 0 || runtime_up() != 0 ||
            wt_hsm_keyvault_bind_client(test_transport, wt_spm_host_runtime(),
                                        TEST_HSM_PARTITION,
                                        TEST_VAULT_SID) != 0) {
        (void)printf("FAIL: key_face setup\n");
        return 1;
    }
    raw_bind(&g_raw_hsm, TEST_HSM_PARTITION);
    raw_bind(&g_raw_rogue, TEST_ROGUE_PARTITION);
    test_client_round_trip();
    test_owner_stamping();
    test_iak();
    test_rogue();
    test_labels();
    test_namespace();
    test_record_reads();
    test_metadata_policy();
    test_restart();
    check(g_wipe_checks != 0U && g_wipe_dirty == 0U,
          "K9 every key-face transfer buffer is wiped");
    if (g_failures != 0) {
        (void)printf("FAIL: key_face (%d)\n", g_failures);
        return 1;
    }
    (void)printf("PASS: key_face\n");
    return 0;
}
