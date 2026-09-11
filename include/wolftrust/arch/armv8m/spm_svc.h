/* spm_svc.h
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


#ifndef WOLFTRUST_ARCH_ARMV8M_SPM_SVC_H
#define WOLFTRUST_ARCH_ARMV8M_SPM_SVC_H

#include <stdint.h>

/* SVC immediate for a Secure Partition psa_* request. 0x7F is the NS-guest
 * return path; anything else falls through to the PendSV scheduler pend. */
#define WT_SVC_SPM_CALL 0x01

/* Privileged SVC #1 decoder. Tail-called from SVC_Handler asm with
 * r0 = the exception frame; not for direct C callers. */
void wt_spm_svc_entry(uint32_t* frame);

#endif /* WOLFTRUST_ARCH_ARMV8M_SPM_SVC_H */
