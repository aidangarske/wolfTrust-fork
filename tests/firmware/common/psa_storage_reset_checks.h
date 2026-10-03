/* psa_storage_reset_checks.h
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

#ifndef WOLFTRUST_PSA_STORAGE_RESET_CHECKS_H
#define WOLFTRUST_PSA_STORAGE_RESET_CHECKS_H

#include <stdint.h>
#include "psa/error.h"

#define WT_STORAGE_RESET_SIGNATURE 0x57545352U
#define WT_STORAGE_RESET_SEEDED    1U
#define WT_STORAGE_RESET_VERIFIED  2U
#define WT_STORAGE_RESET_FAILED    0xEU
#define WT_STORAGE_RESET_ALL       0x3FFU

typedef struct wt_storage_reset_result {
    uint32_t signature;
    uint32_t phase;
    uint32_t passed;
    int32_t status;
    uint32_t its_flags;
    uint32_t ps_flags;
} wt_storage_reset_result_t;

psa_status_t wt_guest_storage_reset_check(wt_storage_reset_result_t* result);

#endif /* WOLFTRUST_PSA_STORAGE_RESET_CHECKS_H */
