/* psa_crypto_checks.h
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

#ifndef WOLFTRUST_GUEST_PSA_CRYPTO_CHECKS_H
#define WOLFTRUST_GUEST_PSA_CRYPTO_CHECKS_H

#include <stdint.h>
#include <stddef.h>
#include <psa/crypto.h>

psa_status_t wt_guest_psa_rng_check(uint8_t* output, size_t size);
psa_status_t wt_guest_psa_sha256_check(void);
psa_status_t wt_guest_psa_ctr_check(void);

#endif /* WOLFTRUST_GUEST_PSA_CRYPTO_CHECKS_H */
