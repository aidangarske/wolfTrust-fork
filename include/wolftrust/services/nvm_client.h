/* nvm_client.h
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

#ifndef WOLFTRUST_SERVICES_NVM_CLIENT_H
#define WOLFTRUST_SERVICES_NVM_CLIENT_H

#include "wolftrust/ffm.h"
#include "wolftrust/spm_gate.h"

#include "wolfhsm/wh_nvm.h"

/* The crypto partition's view of the vault's NVM store (isolation level 3):
 * a wolfHSM NVM callback table whose every operation is an FF-M call to
 * SERVICE_VAULT's keystore object door. The partition keeps only this
 * context, its connection handle, and the wolfHSM contexts layered on top;
 * the store memory itself belongs to the vault partition alone. */
typedef struct wt_nvm_client {
    wt_spm_transport_fn transport;
    wt_ffm_runtime_t* runtime;
    int32_t partition_id;
    uint32_t vault_sid;
    psa_handle_t vault_handle;
    uint8_t vault_restarted;
} wt_nvm_client_t;

/* The forwarding callback table (context = a bound wt_nvm_client_t). */
extern const whNvmCb wt_nvm_client_cb;

/* Fill client with the partition's transport (and the runtime the direct
 * host transport needs; NULL behind the SVC transport), identity, and the
 * vault's SID, then initialise nvm on top of it (wh_Nvm_Init with a no-op
 * lock: the door serialises inside the vault). The connection is opened
 * lazily on the first operation. Returns 0 on success. */
int wt_nvm_client_bind(wt_nvm_client_t* client, whNvmContext* nvm,
                       wt_spm_transport_fn transport,
                       wt_ffm_runtime_t* runtime, int32_t partition_id,
                       uint32_t vault_sid);

/* The SPM's recovery path reports a SERVICE_VAULT restart here: the cached
 * connection is in the error state (WT-FFM-0017), so the next operation
 * closes it and reconnects instead of calling a dead handle, which is a
 * PROGRAMMER ERROR the SPM would panic the crypto partition for. */
void wt_nvm_client_vault_restarted(wt_nvm_client_t* client);

/* The crypto partition's own client and NVM context (this module's data,
 * placed in that partition's band): bind them, then hand the context to the
 * engine (wt_hsm_bind_nvm / wt_native_bind_nvm). */
int wt_nvm_client_bind_partition(wt_spm_transport_fn transport,
                                 wt_ffm_runtime_t* runtime,
                                 int32_t partition_id, uint32_t vault_sid);
whNvmContext* wt_nvm_client_partition_nvm(void);
/* Re-assert the view's callback and lock pointers from link-time constants
 * (WT-FFM-0011). Its routing state (transport, SID, handle) is followed only by
 * the owning partition's unprivileged code; privileged restart rebinds it. */
void wt_nvm_client_partition_pin(void);
#if defined(WT_HSM_PIN_NEG_PROBE) && (WT_HSM_PIN_NEG_PROBE == 1)
/* Test builds only: forge those pointers, heal them, and return 1 only if
 * each one holds its exact canonical address again. */
int wt_nvm_client_partition_pin_probe(void);
#endif
void wt_nvm_client_partition_vault_restarted(void);

#endif /* WOLFTRUST_SERVICES_NVM_CLIENT_H */
