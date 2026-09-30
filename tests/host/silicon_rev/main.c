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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* STM32H563 silicon-revision guard: only production revisions X and W boot;
 * ES0565 2.2.9 engineering samples A and Z and any other IDCODE are refused. */

#include "silicon_rev.h"

#include <stdint.h>
#include <stdio.h>

static int checks;
static int failures;

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

int main(void)
{
    check(wt_h563_silicon_check(0x10070484u) == WT_H563_SILICON_OK,
          "revision X (0x1007) boots");
    check(wt_h563_silicon_check(0x100F0484u) == WT_H563_SILICON_OK,
          "revision W (0x100F) boots");
    check(wt_h563_silicon_check(0x10076484u) == WT_H563_SILICON_OK,
          "reserved IDCODE bits 15:12 do not change the verdict");
    check(wt_h563_silicon_check(0x10000484u) == WT_H563_SILICON_ERRATA,
          "revision A (0x1000) refused as ES0565 2.2.9 errata");
    check(wt_h563_silicon_check(0x10010484u) == WT_H563_SILICON_ERRATA,
          "revision Z (0x1001) refused as ES0565 2.2.9 errata");
    check(wt_h563_silicon_check(0x10030484u) == WT_H563_SILICON_UNKNOWN,
          "unlisted revision of DEV_ID 0x484 refused");
    check(wt_h563_silicon_check(0x100F0474u) == WT_H563_SILICON_UNKNOWN,
          "revision W code on another DEV_ID refused");
    check(wt_h563_silicon_check(0x00000000u) == WT_H563_SILICON_UNKNOWN,
          "all-zero IDCODE refused");
    check(wt_h563_silicon_check(0xFFFFFFFFu) == WT_H563_SILICON_UNKNOWN,
          "all-ones IDCODE refused");

    printf("silicon_rev: %d checks, %d failures\n", checks, failures);
    if (failures != 0) {
        return 1;
    }
    printf("PASS: silicon_rev\n");
    return 0;
}
