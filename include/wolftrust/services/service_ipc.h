/* service_ipc.h
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

#ifndef WOLFTRUST_SERVICE_IPC_H
#define WOLFTRUST_SERVICE_IPC_H

#include <stddef.h>
#include <stdint.h>

#include "psa/service.h"
#include "wolftrust/spm_gate.h"

/* The message a Secure Partition service is serving. */
typedef struct wt_svc {
    wt_spm_transport_fn transport;
    wt_ffm_runtime_t*   runtime;
    int32_t             partition_id;
    psa_handle_t        handle;
} wt_svc_t;

typedef psa_status_t (*wt_svc_handler_fn)(void* ctx, const wt_svc_t* svc,
                                          const psa_msg_t* msg);

/* Copy invec[idx] into buffer, up to capacity bytes. */
int wt_svc_read(const wt_svc_t* svc, uint32_t idx, void* buffer,
                size_t capacity, size_t* out_len);
int wt_svc_write(const wt_svc_t* svc, uint32_t idx, const void* data,
                 size_t len);

/* A Secure Partition's connection to another partition's service. Set
 * restarted when the server restarts; the next call reconnects. */
typedef struct wt_svc_client {
    wt_spm_transport_fn transport;
    wt_ffm_runtime_t*   runtime;
    int32_t             partition_id;
    uint32_t            sid;
    psa_handle_t        handle;
    uint8_t             restarted;
} wt_svc_client_t;

/* Connect if needed and call: in0 and in1 are optional invecs, out is an
 * optional outvec of *out_len bytes, updated to the bytes written. Returns
 * WT_FFM_SUCCESS with the service status in *status. */
int wt_svc_client_call(wt_svc_client_t* client, int32_t type,
                       const void* in0, size_t in0_len,
                       const void* in1, size_t in1_len,
                       void* out, size_t* out_len, psa_status_t* status);
void wt_svc_client_close(wt_svc_client_t* client);

/* Serve one message: wait, get, run handler, reply with its status. */
int wt_svc_dispatch(wt_spm_transport_fn transport, wt_ffm_runtime_t* runtime,
                    int32_t partition_id, wt_svc_handler_fn handler,
                    void* ctx);

#endif /* WOLFTRUST_SERVICE_IPC_H */
