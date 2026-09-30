/* spm_sched.h
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

#ifndef WOLFTRUST_SPM_SCHED_H
#define WOLFTRUST_SPM_SCHED_H

#include "wolftrust/ffm.h"

/* Neutral Secure-Partition scheduler contract. The core boot path schedules
 * partitions through these; the architecture port implements them (Armv8-M:
 * src/arch/armv8m/spm_svc.c). */

/* A scheduled Secure Partition's thread entry: the partition's service loop,
 * unprivileged on its own stack, reaching the SPM only through the port
 * transport. arg is the partition id passed to wt_spm_sched_add. */
typedef void (*wt_spm_sp_entry_fn)(void* arg);

/* Schedule one Secure Partition (P3a): resolve its manifest protection domain,
 * build the unprivileged thread isolation table, create the coroutine on the
 * manifest stack running `entry`, and register the partition's dispatch as
 * wake-and-run. Call after wt_tasklet_init and wt_ffm_boot_init. Fails closed. */
int wt_spm_sched_add(wt_ffm_runtime_t* runtime, int32_t partition_id,
                     wt_spm_sp_entry_fn entry, void* arg);

/* Start the SERVICE_HSM relay partition (WT-FFM-0054) as a scheduled
 * UNPRIVILEGED SP confined to its manifest domain: its loop reaches the
 * wolfHSM server state through the shared keystore band, and flash, entropy,
 * and the NVM lock trap to the SVC gate. */
int wt_spm_hsm_start(wt_ffm_runtime_t* runtime, int32_t partition_id);

/* Start the SERVICE_ATTEST partition as a scheduled UNPRIVILEGED SP: its
 * dispatch loop runs on its own stack and reaches the attestation server state
 * through the shared keystore band its manifest domain grants. Defined only
 * in attestation-enabled builds. */
int wt_spm_attest_start(wt_ffm_runtime_t* runtime, int32_t partition_id);

/* Start the vault partition (WT-FFM-0047) as a scheduled UNPRIVILEGED SP:
 * the loop reaches the wolfHSM NVM state through the shared keystore band, and
 * the NVM lock traps to the SVC gate. Clients still cross the gate; the
 * manifest's dependencies[] authorizes them. */
int wt_spm_vault_start(wt_ffm_runtime_t* runtime, int32_t partition_id);

/* Start the ITS partition as a normal UNPRIVILEGED scheduled SP whose service
 * loop reaches SERVICE_VAULT over SP-to-SP IPC through the SVC gate. */
int wt_spm_its_start(wt_ffm_runtime_t* runtime, int32_t partition_id);

/* Schedule the PS partition: the storage loop with sealing forced on. */
int wt_spm_ps_start(wt_ffm_runtime_t* runtime, int32_t partition_id);

/* Start the Firmware Update partition (WT-FWU-0001) as a scheduled
 * UNPRIVILEGED SP: it stages a candidate in the wolfBoot update partition
 * through the FWU-pinned SVC gate, which programs the flash. */
int wt_spm_fwu_start(wt_ffm_runtime_t* runtime, int32_t partition_id);

int wt_spm_vnet_start(wt_ffm_runtime_t* runtime, int32_t partition_id);

#endif /* WOLFTRUST_SPM_SCHED_H */
