/* boot_handoff.h
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

#ifndef WOLFTRUST_BOOT_HANDOFF_H
#define WOLFTRUST_BOOT_HANDOFF_H

#include <stdint.h>

#define WT_BOOT_HANDOFF_MAGIC        0x5742484Fu
#define WT_BOOT_HANDOFF_VERSION      1u
#define WT_BOOT_HANDOFF_HASH_SHA256  1u
#define WT_BOOT_HANDOFF_DIGEST_SIZE  32u

typedef struct wt_boot_handoff {
    uint32_t magic;
    uint32_t magic_inverse;
    uint16_t version;
    uint16_t size;
    uint32_t lifecycle;
    uint32_t image_version;
    uint16_t hash_algorithm;
    uint16_t measurement_size;
    uint8_t measurement[WT_BOOT_HANDOFF_DIGEST_SIZE];
} wt_boot_handoff_t;

/* Consume the wolfBoot record from Secure RAM. The source record is cleared
 * before return so it cannot be replayed by a later service request. */
int wt_boot_handoff_consume(wt_boot_handoff_t* handoff);

#endif /* WOLFTRUST_BOOT_HANDOFF_H */
