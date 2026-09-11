/* wt_hsm_lock.c
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

/*
 * wolfHSM lock vtable backed by the wolfTrust coroutine mutex.
 *
 * The lock context is a caller-allocated wt_mutex_t embedded in whatever
 * shared resource (e.g. NVM) needs protection.  The init config is unused.
 *
 * Per wh_lock.h: "Lock initialization and cleanup must be performed in a
 * single-threaded context before any threads attempt to use the lock."
 * Therefore init/cleanup never call acquire/release and the bootstrap-context
 * restriction on wt_mutex_acquire does not apply to them.
 */

#include <stddef.h>                    /* NULL */

#include "wolfhsm/wh_error.h"          /* WH_ERROR_OK, WH_ERROR_BADARGS, WH_ERROR_ABORTED */
#include "wolfhsm/wh_lock.h"           /* whLockCb */
#include "wolftrust/spm_gate.h"        /* wt_arch_thread_unprivileged, lock gate */
#include "wolftrust/arch.h"
#include "wolftrust/sync/mutex.h"      /* wt_mutex_t, wt_mutex_init/acquire/release */

static int wt_hsm_lock_init(void *context, const void *config)
{
    if (context == NULL) return WH_ERROR_BADARGS;
    (void)config;
    wt_mutex_init((wt_mutex_t *)context);
    return WH_ERROR_OK;
}

static int wt_hsm_lock_cleanup(void *context)
{
    if (context == NULL) return WH_ERROR_BADARGS;
    /* Mutex has no resources to free; re-init for safety. */
    wt_mutex_init((wt_mutex_t *)context);
    return WH_ERROR_OK;
}

/* NOTE: wt_mutex_acquire returns negative if called from bootstrap (monitor)
 * context.  This is intentional — acquire must only be called from a running
 * coroutine, which is guaranteed by the wolfHSM threading model above. */
static int wt_hsm_lock_acquire(void *context)
{
    if (context == NULL) return WH_ERROR_BADARGS;
#if defined(WT_TARGET_BUILD)
    /* A confined keystore partition cannot touch the scheduler state the
     * blocking path needs; the SVC gate acquires on its behalf. */
    if (wt_arch_thread_unprivileged()) {
        if (wt_spm_keystore_lock_call(WT_SPM_KS_LOCK_ACQUIRE) != 0) {
            return WH_ERROR_ABORTED;
        }
        return WH_ERROR_OK;
    }
#endif
    if (wt_mutex_acquire((wt_mutex_t *)context) != 0) {
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

static int wt_hsm_lock_release(void *context)
{
    if (context == NULL) return WH_ERROR_BADARGS;
#if defined(WT_TARGET_BUILD)
    if (wt_arch_thread_unprivileged()) {
        if (wt_spm_keystore_lock_call(WT_SPM_KS_LOCK_RELEASE) != 0) {
            return WH_ERROR_ABORTED;
        }
        return WH_ERROR_OK;
    }
#endif
    if (wt_mutex_release((wt_mutex_t *)context) != 0) {
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

/* The vtable instance that wt_hsm.c references via extern.
 * Declared const so it resides in .rodata (read-only after link). */
const whLockCb g_wt_hsm_lock_cb = {
    .init    = wt_hsm_lock_init,
    .cleanup = wt_hsm_lock_cleanup,
    .acquire = wt_hsm_lock_acquire,
    .release = wt_hsm_lock_release,
};
