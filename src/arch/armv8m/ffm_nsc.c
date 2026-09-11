/* ffm_nsc.c
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

/* Armv8-M NS-client gateway for the FF-M API: the cmse_nonsecure_entry
 * veneers plus the CMSE NS-window checks, extracted from the neutral core
 * (src/ffm_boot.c) so the core carries no CMSE dependency. The Zephyr
 * wolftrust-tee driver's tee_invoke_func dispatches into these veneers. */

#include "wolftrust/arch/armv8m/ffm_nsc.h"

#include "wolftrust/arch/armv8m/cmse.h"
#include "wolftrust/ffm_boot.h"
#include "wolftrust/platform.h"
#include "wolftrust/arch.h"
#include "wolftrust/types.h"

extern volatile uint32_t g_wt_ffm_call_trace;

static int wt_ffm_nsc_check_read(wt_guest_id_t guest_id,
                                 const void* address, size_t size)
{
    return wt_cmse_check_ns_ro(address, size) &&
           wt_cmse_check_in_guest_ns_addr(guest_id, address, size);
}

static int wt_ffm_nsc_check_write(wt_guest_id_t guest_id,
                                  void* address, size_t size)
{
    return wt_cmse_check_ns_rw(address, size) &&
           wt_cmse_check_in_guest_ns_ram(guest_id, address, size);
}

void wt_ffm_nsc_install(void)
{
    wt_ffm_boot_set_memcheck(wt_ffm_nsc_check_read, wt_ffm_nsc_check_write);
}

/* Caller identity and CMSE/window validation follow the same pattern as the
 * vnet NS veneers. Never trust a guest-supplied VM id. */
static int wt_ffm_veneer_caller(psa_client_id_t* caller)
{
    uint32_t guest_id = wt_arch_active_guest_id();

    if (guest_id >= (uint32_t)WT_MAX_GUESTS) {
        return 0;
    }
    *caller = -(psa_client_id_t)(guest_id + 1U);
    return 1;
}

__attribute__((cmse_nonsecure_entry))
int32_t WolfTrust_FFM_Connect(uint32_t sid, uint32_t version)
{
    psa_client_id_t caller;

    if (!wt_ffm_veneer_caller(&caller)) {
        return (int32_t)PSA_NULL_HANDLE;
    }
    return (int32_t)wt_ffm_connect(wt_ffm_boot_runtime_mut(), caller, sid,
                                   version);
}

__attribute__((cmse_nonsecure_entry))
int32_t WolfTrust_FFM_Call(int32_t handle, int32_t type,
                          wt_ffm_veneer_iovec_t* ns_iovec)
{
    psa_client_id_t caller;
    wt_ffm_veneer_iovec_t iovec;
    psa_invec in_vec[WT_FFM_VENEER_IOVEC_MAX];
    psa_outvec out_vec[WT_FFM_VENEER_IOVEC_MAX];
    int32_t status;
    uint32_t i;

    if (!wt_ffm_veneer_caller(&caller)) {
        g_wt_ffm_call_trace = 1UL << 28;
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    if (ns_iovec == NULL ||
            !wt_cmse_check_ns_rw(ns_iovec, sizeof(*ns_iovec))) {
        g_wt_ffm_call_trace = (2UL << 28) |
            ((uint32_t)(uintptr_t)ns_iovec & 0x0FFFFFFFUL);
        wt_ffm_call_refuse(wt_ffm_boot_runtime_mut(), caller,
                           (psa_handle_t)handle);
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    /* Single read into a local copy: the struct's own fields are not
     * re-read after this, so a racing NS write cannot change the vector
     * base/length wt_ffm_call validates and copies from. */
    iovec = *ns_iovec;
    if (iovec.in_count > WT_FFM_VENEER_IOVEC_MAX ||
            iovec.out_count > WT_FFM_VENEER_IOVEC_MAX) {
        wt_ffm_call_refuse(wt_ffm_boot_runtime_mut(), caller,
                           (psa_handle_t)handle);
        return (int32_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    for (i = 0U; i < iovec.in_count; i++) {
        in_vec[i].base = iovec.in[i].base;
        in_vec[i].len = iovec.in[i].len;
    }
    for (i = 0U; i < iovec.out_count; i++) {
        out_vec[i].base = iovec.out[i].base;
        out_vec[i].len = iovec.out[i].len;
    }
    status = (int32_t)wt_ffm_call(wt_ffm_boot_runtime_mut(), caller,
                                  (psa_handle_t)handle,
                                  type, in_vec, iovec.in_count,
                                  out_vec, iovec.out_count);
    for (i = 0U; i < iovec.out_count; i++) {
        ns_iovec->out[i].len = (uint32_t)out_vec[i].len;
    }
    return status;
}

__attribute__((cmse_nonsecure_entry))
void WolfTrust_FFM_Close(int32_t handle)
{
    psa_client_id_t caller;

    if (!wt_ffm_veneer_caller(&caller)) {
        return;
    }
    (void)wt_ffm_close(wt_ffm_boot_runtime_mut(), caller,
                       (psa_handle_t)handle);
}

__attribute__((cmse_nonsecure_entry))
uint32_t WolfTrust_FFM_FrameworkVersion(void)
{
    return wt_ffm_framework_version(wt_ffm_boot_runtime_mut());
}

__attribute__((cmse_nonsecure_entry))
uint32_t WolfTrust_FFM_ServiceVersion(uint32_t sid)
{
    psa_client_id_t caller;

    if (!wt_ffm_veneer_caller(&caller)) {
        return PSA_VERSION_NONE;
    }
    return wt_ffm_service_version(wt_ffm_boot_runtime_mut(), caller, sid);
}
