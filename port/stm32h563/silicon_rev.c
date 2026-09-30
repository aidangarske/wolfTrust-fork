/* silicon_rev.c
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <stddef.h>
#include <stdint.h>

#include "silicon_rev.h"

typedef struct {
    uint16_t revId;
    int verdict;
} wt_h563_revision_t;

/* ES0565 Table 2 silicon revisions, REV_ID A 0x1000, Z 0x1001, X 0x1007,
 * W 0x100F; A and Z need more flash wait states during read-while-write than
 * this port programs (2.2.9). */
static const wt_h563_revision_t g_wt_h563_revisions[] = {
    { 0x1000u, WT_H563_SILICON_ERRATA },
    { 0x1001u, WT_H563_SILICON_ERRATA },
    { 0x1007u, WT_H563_SILICON_OK },
    { 0x100Fu, WT_H563_SILICON_OK },
};

int wt_h563_silicon_check(uint32_t idcode)
{
    uint32_t revId = idcode >> WT_H563_IDCODE_REV_ID_SHIFT;
    int verdict = WT_H563_SILICON_UNKNOWN;
    size_t i;

    if ((idcode & WT_H563_IDCODE_DEV_ID_MASK) == WT_H563_DEV_ID) {
        for (i = 0; i < sizeof(g_wt_h563_revisions) /
                        sizeof(g_wt_h563_revisions[0]); i++) {
            if (g_wt_h563_revisions[i].revId == revId) {
                verdict = g_wt_h563_revisions[i].verdict;
            }
        }
    }

    return verdict;
}
