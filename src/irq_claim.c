/* irq_claim.c
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

#include <stddef.h>

#include "wolftrust/irq_claim.h"

int wt_irq_claim(const wt_nvic_ops_t* ops, uint32_t irq, uint32_t words)
{
    uint32_t word = irq >> 5;
    uint32_t mask = 1u << (irq & 31u);

    if (ops == NULL || ops->disable == NULL || ops->clear_pending == NULL ||
            ops->route_secure == NULL || ops->enabled == NULL ||
            ops->non_secure == NULL || ops->barrier == NULL ||
            word >= words) {
        return -1;
    }
    ops->disable(word, mask);
    ops->barrier();
    ops->route_secure(word, mask);
    ops->clear_pending(word, mask);
    ops->barrier();
    if ((ops->non_secure(word) & mask) != 0u ||
            (ops->enabled(word) & mask) != 0u) {
        return -1;
    }
    return 0;
}
