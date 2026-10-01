/* irq_claim.h
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

#ifndef WOLFTRUST_IRQ_CLAIM_H
#define WOLFTRUST_IRQ_CLAIM_H

#include <stdint.h>

/* Interrupt-controller access for wt_irq_claim, one 32-line word at a time:
 * the arch layer binds the real NVIC, host tests bind a model. */
typedef struct wt_nvic_ops {
    void (*disable)(uint32_t word, uint32_t mask);
    void (*clear_pending)(uint32_t word, uint32_t mask);
    void (*route_secure)(uint32_t word, uint32_t mask);
    uint32_t (*enabled)(uint32_t word);
    uint32_t (*non_secure)(uint32_t word);
    void (*barrier)(void);
} wt_nvic_ops_t;

/* WT-FFM-0069: disable irq, route it Secure, and drop a stale pending, then
 * read back that it is disabled and Secure-routed. Returns 0, or -1 when irq
 * is beyond words * 32 lines or the controller did not take the state. */
int wt_irq_claim(const wt_nvic_ops_t* ops, uint32_t irq, uint32_t words);

#endif /* WOLFTRUST_IRQ_CLAIM_H */
