/* armv8m.h
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

#ifndef WOLFTRUST_ARCH_ARMV8M_ARMV8M_H
#define WOLFTRUST_ARCH_ARMV8M_ARMV8M_H

/* Armv8-M-private entry points shared between the architecture layer and
 * the Cortex-M ports; never part of the neutral core contract. */

/* Exception-return path back to the Non-secure guest after an SVC. */
void wt_armv8m_svc_guest_return(void) __attribute__((noreturn));

#endif /* WOLFTRUST_ARCH_ARMV8M_ARMV8M_H */
