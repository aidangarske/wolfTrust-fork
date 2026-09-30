/* silicon_rev.h
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

#ifndef WOLFTRUST_STM32H563_SILICON_REV_H
#define WOLFTRUST_STM32H563_SILICON_REV_H

#include <stdint.h>

/* DBGMCU_IDCODE DEV_ID shared by STM32H562/H563/H573 (ES0565 Table 2 part set). */
#define WT_H563_DEV_ID              0x484u
#define WT_H563_IDCODE_DEV_ID_MASK  0x00000FFFu
#define WT_H563_IDCODE_REV_ID_SHIFT 16u

#define WT_H563_SILICON_OK          0
#define WT_H563_SILICON_ERRATA      (-1)
#define WT_H563_SILICON_UNKNOWN     (-2)

/* Returns WT_H563_SILICON_OK only for a production revision this port
 * supports; ERRATA for an engineering sample ES0565 2.2.9 affects; UNKNOWN
 * for any other device or revision. */
int wt_h563_silicon_check(uint32_t idcode);

/* Reads DBGMCU_IDCODE and panics with a console line unless it passes. */
void wt_h563_silicon_guard(void);

#endif /* WOLFTRUST_STM32H563_SILICON_REV_H */
