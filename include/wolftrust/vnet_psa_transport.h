/* vnet_psa_transport.h
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

#ifndef WOLFTRUST_VNET_PSA_TRANSPORT_H
#define WOLFTRUST_VNET_PSA_TRANSPORT_H

#include <stdint.h>

#include "wolftrust/vnet/vnet_abi.h"

/* SPM-mediated virtual network client (WT-FFM-0056): every switch
 * operation crosses to the secure side as one synchronous psa_call to
 * SERVICE_VNET - no direct-CMSE veneer. Returns 0 on success or the
 * secure side's WT_VNET_E_* refusal unchanged; RX_FETCH returns the
 * received frame length, WT_VNET_E_EMPTY when nothing is queued. After a
 * SERVICE_VNET restart a context re-registers its port and MAC on its next
 * TX or RX_FETCH; frames sent to a port before its guest re-registers are
 * dropped, so a receiver must keep polling RX_FETCH. */

typedef struct wt_vnet_psa_ctx {
    int32_t handle;
    uint32_t sid;
    uint32_t version;
    uint8_t mac[6];
    uint8_t mac_set;
    uint8_t active;
} wt_vnet_psa_ctx_t;

int wt_vnet_psa_open(wt_vnet_psa_ctx_t* ctx, uint32_t sid, uint32_t version,
                     vnet_info_t* info);
int wt_vnet_psa_set_mac(wt_vnet_psa_ctx_t* ctx, const uint8_t* mac6);
int wt_vnet_psa_tx(wt_vnet_psa_ctx_t* ctx, const void* frame, uint16_t len);
int wt_vnet_psa_rx_fetch(wt_vnet_psa_ctx_t* ctx, vnet_rx_meta_t* meta,
                         void* dst, uint16_t dst_len);
void wt_vnet_psa_close(wt_vnet_psa_ctx_t* ctx);

#endif /* WOLFTRUST_VNET_PSA_TRANSPORT_H */
