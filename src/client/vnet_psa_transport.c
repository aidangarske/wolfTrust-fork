/* vnet_psa_transport.c
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

#include "wolftrust/vnet_psa_transport.h"
#include "wolftrust/vnet/vnet_errors.h"

#include "psa/client.h"

/* A service restart fails a pinned call with COMMUNICATION_FAILURE and leaves
 * every connection to it dead (BAD_STATE or PROGRAMMER_ERROR), so the client
 * heals by reconnecting and re-binding its port. */
static int wt_vnet_psa_healable(psa_status_t status)
{
    return status == PSA_ERROR_COMMUNICATION_FAILURE ||
           status == PSA_ERROR_BAD_STATE ||
           status == PSA_ERROR_PROGRAMMER_ERROR;
}

static psa_status_t wt_vnet_psa_do_open(wt_vnet_psa_ctx_t* ctx,
                                        vnet_info_t* info)
{
    psa_handle_t handle;
    psa_outvec out_vec;
    psa_status_t status;

    handle = psa_connect(ctx->sid, ctx->version);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return (psa_status_t)WT_VNET_E_NOTREADY;
    }
    ctx->handle = (int32_t)handle;
    out_vec.base = info;
    out_vec.len = sizeof(*info);
    status = psa_call(handle, WT_VNET_OP_OPEN, NULL, 0U, &out_vec, 1U);
    if (status != PSA_SUCCESS) {
        psa_close(handle);
        ctx->handle = (int32_t)PSA_NULL_HANDLE;
    }
    return status;
}

static int wt_vnet_psa_heal(wt_vnet_psa_ctx_t* ctx)
{
    vnet_info_t info;
    psa_invec in_vec;
    psa_status_t status;

    if (ctx->active == 0U) {
        return WT_VNET_E_NOT_OPEN;
    }
    if (ctx->handle != (int32_t)PSA_NULL_HANDLE) {
        psa_close((psa_handle_t)ctx->handle);
        ctx->handle = (int32_t)PSA_NULL_HANDLE;
    }
    status = wt_vnet_psa_do_open(ctx, &info);
    if (status != PSA_SUCCESS) {
        return (int)status;
    }
    if (ctx->mac_set != 0U) {
        in_vec.base = ctx->mac;
        in_vec.len = VNET_MAC_LEN;
        status = psa_call((psa_handle_t)ctx->handle, WT_VNET_OP_SET_MAC,
                          &in_vec, 1U, NULL, 0U);
        if (status != PSA_SUCCESS) {
            return (int)status;
        }
    }
    return 0;
}

int wt_vnet_psa_open(wt_vnet_psa_ctx_t* ctx, uint32_t sid, uint32_t version,
                     vnet_info_t* info)
{
    psa_status_t status;

    if (ctx == NULL || info == NULL) {
        return WT_VNET_E_BADARG;
    }
    ctx->handle = (int32_t)PSA_NULL_HANDLE;
    ctx->sid = sid;
    ctx->version = version;
    ctx->mac_set = 0U;
    ctx->active = 0U;
    status = wt_vnet_psa_do_open(ctx, info);
    if (status != PSA_SUCCESS) {
        return (int)status;
    }
    ctx->active = 1U;
    return 0;
}

int wt_vnet_psa_set_mac(wt_vnet_psa_ctx_t* ctx, const uint8_t* mac6)
{
    psa_invec in_vec;
    psa_status_t status;
    uint32_t i;

    if (ctx == NULL || mac6 == NULL) {
        return WT_VNET_E_BADARG;
    }
    in_vec.base = mac6;
    in_vec.len = VNET_MAC_LEN;
    status = psa_call((psa_handle_t)ctx->handle, WT_VNET_OP_SET_MAC,
                      &in_vec, 1U, NULL, 0U);
    if (status == PSA_SUCCESS) {
        for (i = 0U; i < VNET_MAC_LEN; i++) {
            ctx->mac[i] = mac6[i];
        }
        ctx->mac_set = 1U;
    }
    return (status != PSA_SUCCESS) ? (int)status : 0;
}

int wt_vnet_psa_tx(wt_vnet_psa_ctx_t* ctx, const void* frame, uint16_t len)
{
    psa_invec in_vec;
    psa_status_t status;

    if (ctx == NULL || frame == NULL || len == 0U) {
        return WT_VNET_E_BADARG;
    }
    in_vec.base = frame;
    in_vec.len = len;
    status = psa_call((psa_handle_t)ctx->handle, WT_VNET_OP_TX,
                      &in_vec, 1U, NULL, 0U);
    if (wt_vnet_psa_healable(status) && wt_vnet_psa_heal(ctx) == 0) {
        status = psa_call((psa_handle_t)ctx->handle, WT_VNET_OP_TX,
                          &in_vec, 1U, NULL, 0U);
    }
    return (status != PSA_SUCCESS) ? (int)status : 0;
}

int wt_vnet_psa_rx_fetch(wt_vnet_psa_ctx_t* ctx, vnet_rx_meta_t* meta,
                         void* dst, uint16_t dst_len)
{
    psa_outvec out_vec[2];
    psa_status_t status;

    if (ctx == NULL || meta == NULL || dst == NULL || dst_len == 0U) {
        return WT_VNET_E_BADARG;
    }
    out_vec[0].base = meta;
    out_vec[0].len = sizeof(*meta);
    out_vec[1].base = dst;
    out_vec[1].len = dst_len;
    status = psa_call((psa_handle_t)ctx->handle, WT_VNET_OP_RX_FETCH,
                      NULL, 0U, out_vec, 2U);
    if (wt_vnet_psa_healable(status) && wt_vnet_psa_heal(ctx) == 0) {
        out_vec[0].base = meta;
        out_vec[0].len = sizeof(*meta);
        out_vec[1].base = dst;
        out_vec[1].len = dst_len;
        status = psa_call((psa_handle_t)ctx->handle, WT_VNET_OP_RX_FETCH,
                          NULL, 0U, out_vec, 2U);
    }
    if (status != PSA_SUCCESS) {
        return (int)status;
    }
    return (int)meta->len;
}

void wt_vnet_psa_close(wt_vnet_psa_ctx_t* ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->active = 0U;
    if (ctx->handle != (int32_t)PSA_NULL_HANDLE) {
        psa_close((psa_handle_t)ctx->handle);
        ctx->handle = (int32_t)PSA_NULL_HANDLE;
    }
}
