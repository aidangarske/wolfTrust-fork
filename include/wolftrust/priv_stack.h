/* priv_stack.h
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

#ifndef WOLFTRUST_PRIV_STACK_H
#define WOLFTRUST_PRIV_STACK_H

#include <stdint.h>
#include <stddef.h>

/* Pure address-range helpers shared by the per-port privileged-stack validator
 * and its host test, so both judge the same arithmetic (WT-FFM-0011). A
 * privileged coroutine stack must be a valid range that does not intersect any
 * partition-writable band. */

/* Nonzero when [start, start+size) is a usable range: non-empty and not
 * wrapping past the end of the address space. */
static inline int wt_priv_range_valid(uintptr_t start, size_t size)
{
    return (size != 0u) && ((start + size) > start);
}

/* Nonzero when a valid range [start, start+size) intersects the band
 * [base, base+bsize). Assumes both ranges are valid (see wt_priv_range_valid).
 * A band of size zero never intersects. */
static inline int wt_priv_range_overlaps(uintptr_t start, size_t size,
                                         uintptr_t base, size_t bsize)
{
    if (bsize == 0u) {
        return 0;
    }
    return (start < base + bsize) && (start + size > base);
}

/* Nonzero when a valid range [start, start+size) lies wholly within the window
 * [base, end). Assumes the range is valid (see wt_priv_range_valid) and that
 * end >= base. A privileged stack must sit inside SPM-private RAM, so the
 * validator accepts only ranges this contains. */
static inline int wt_priv_range_within(uintptr_t start, size_t size,
                                       uintptr_t base, uintptr_t end)
{
    return (start >= base) && (start + size <= end);
}

/* A partition-writable band [base, base+size) a privileged stack must avoid. */
typedef struct {
    uintptr_t base;
    size_t    size;
} wt_priv_band_t;

/* The full privileged-stack decision, shared verbatim by the per-port validator
 * and its host test so both judge identical logic (WT-FFM-0011): a usable range
 * that lies wholly within secure RAM [ram_base, ram_end) and overlaps none of
 * the partition-writable bands. */
static inline int wt_priv_stack_ok(uintptr_t start, size_t size,
                                   uintptr_t ram_base, uintptr_t ram_end,
                                   const wt_priv_band_t *bands, size_t nbands)
{
    size_t i;

    if (!wt_priv_range_valid(start, size)) {
        return 0;
    }
    if (!wt_priv_range_within(start, size, ram_base, ram_end)) {
        return 0;
    }
    for (i = 0u; i < nbands; i++) {
        if (wt_priv_range_overlaps(start, size, bands[i].base, bands[i].size)) {
            return 0;
        }
    }
    return 1;
}

#endif /* WOLFTRUST_PRIV_STACK_H */
