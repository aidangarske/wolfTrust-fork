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

#include <stdio.h>
#include "psa_crypto_checks.h"

static int check(psa_status_t status, const char* property)
{
    printf("%s: WT-FFM-0054 shared PSA client %s (status %ld)\n",
        (status == PSA_SUCCESS) ? "PASS" : "FAIL", property, (long)status);
    return status != PSA_SUCCESS;
}

int main(void)
{
    uint8_t random[32];
    int failed = 0;

    if (check(psa_crypto_init(), "initialization") != 0) {
        return 1;
    }
    failed |= check(wt_guest_psa_rng_check(random, sizeof(random)), "RNG");
    failed |= check(wt_guest_psa_sha256_check(), "SHA-256 known answer");
    failed |= check(wt_guest_psa_ctr_check(), "AES-128 CTR encrypt/decrypt known answers");
    return failed;
}
