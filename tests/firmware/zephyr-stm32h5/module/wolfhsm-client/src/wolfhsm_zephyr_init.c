/* wolfhsm_zephyr_init.c
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

/* Register the wolfHSM client at POST_KERNEL before wolfPSA or app startup.
 * A failed early connection is retried on demand through the callback. */

#include <zephyr/init.h>
#include <zephyr/logging/log.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_cryptocb.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

LOG_MODULE_REGISTER(wolftrust_wolfhsm_client, LOG_LEVEL_INF);

int  wolfhsm_guest_init(void);
whClientContext *wolfhsm_guest_client(void);

static int wolftrust_wolfhsm_retry(int devId, wc_CryptoInfo *info, void *ctx)
{
    (void)ctx;
#ifdef WOLF_CRYPTO_CB_CMD
    if (info != NULL && info->algo_type == WC_ALGO_TYPE_NONE) {
        return CRYPTOCB_UNAVAILABLE;
    }
#endif
    if (wolfhsm_guest_init() != WH_ERROR_OK) {
        if (wc_CryptoCb_IsDeviceRegistered(WH_DEV_ID) == 0 &&
                wc_CryptoCb_RegisterDevice(WH_DEV_ID,
                    wolftrust_wolfhsm_retry, NULL) != 0) {
            LOG_ERR("failed to restore wolfHSM retry callback");
        }
        return WC_HW_E;
    }
    /* Successful initialization replaces this bootstrap callback. */
    return wh_Client_CryptoCb(devId, info, wolfhsm_guest_client());
}

static int wolftrust_wolfhsm_client_sys_init(void)
{
    int rc;

    rc = wolfhsm_guest_init();
    if (rc != WH_ERROR_OK) {
        LOG_WRN("wolfhsm_guest_init rc=%d (will retry on demand)", rc);
        /* Transport failure can precede wolfHSM's wolfCrypt_Init(). */
        rc = wolfCrypt_Init();
        if (rc != 0) {
            return rc;
        }
        rc = wc_CryptoCb_RegisterDevice(WH_DEV_ID, wolftrust_wolfhsm_retry,
                                        NULL);
        if (rc != 0) {
            (void)wolfCrypt_Cleanup();
            LOG_ERR("wc_CryptoCb_RegisterDevice failed rc=%d", rc);
        }
        return rc;
    }

    /* wh_Client_Init() registers the crypto callback. */
    /* wolfCrypt's "default devId" (wc_CryptoCb_DefaultDevID) returns the
     * first registered crypto_cb device; with WH_DEV_ID being the only
     * device wolfHSM registers, that's already WH_DEV_ID. wolfPSA threads its
     * own runtime-settable devId via wolfPSA_SetDefaultDevID() — done in
     * the wolfpsa module's SYS_INIT hook. */

    LOG_INF("wolfHSM client up; devId=0x%08x registered", (unsigned)WH_DEV_ID);
    return 0;
}

SYS_INIT(wolftrust_wolfhsm_client_sys_init, POST_KERNEL,
         CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
