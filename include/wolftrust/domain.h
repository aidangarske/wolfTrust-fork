/* domain.h
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

#ifndef WOLFTRUST_DOMAIN_H
#define WOLFTRUST_DOMAIN_H

#include <stddef.h>
#include <stdint.h>

#define WT_DOMAIN_ID_INVALID UINT32_MAX
#define WT_RESOURCE_SHARE_NONE 0U

#define WT_MEMORY_ATTR_READ          (1U << 0)
#define WT_MEMORY_ATTR_WRITE         (1U << 1)
#define WT_MEMORY_ATTR_EXECUTE       (1U << 2)
#define WT_MEMORY_ATTR_DEVICE        (1U << 3)
#define WT_MEMORY_ATTR_RESTART_CLEAR (1U << 4)
#define WT_MEMORY_ATTR_SHARED        (1U << 5)

#define WT_INTERRUPT_ATTR_SHARED     (1U << 0)

#define WT_CAPABILITY_SECURITY_STATE      (1U << 0)
#define WT_CAPABILITY_PRIVILEGE_STATE     (1U << 1)
#define WT_CAPABILITY_ROT_ISOLATION       (1U << 2)
#define WT_CAPABILITY_DOMAIN_ISOLATION    (1U << 3)
#define WT_CAPABILITY_MEMORY_PROTECTION   (1U << 4)
#define WT_CAPABILITY_INTERRUPT_ISOLATION (1U << 5)
#define WT_CAPABILITY_RESTART             (1U << 6)

typedef uint32_t wt_domain_id_t;

typedef enum wt_domain_class {
    WT_DOMAIN_CLASS_SPM = 0,
    WT_DOMAIN_CLASS_SECURE_PARTITION,
    WT_DOMAIN_CLASS_NONSECURE_APPLICATION
} wt_domain_class_t;

typedef enum wt_rot_role {
    WT_ROT_ROLE_NONE = 0,
    WT_ROT_ROLE_SPM,
    WT_ROT_ROLE_PROT,
    WT_ROT_ROLE_AROT
} wt_rot_role_t;

typedef enum wt_security_state {
    WT_SECURITY_STATE_SECURE = 0,
    WT_SECURITY_STATE_NONSECURE
} wt_security_state_t;

typedef enum wt_privilege_state {
    WT_PRIVILEGE_STATE_PRIVILEGED = 0,
    WT_PRIVILEGE_STATE_UNPRIVILEGED
} wt_privilege_state_t;

typedef enum wt_domain_lifecycle {
    WT_DOMAIN_LIFECYCLE_STOPPED = 0,
    WT_DOMAIN_LIFECYCLE_READY,
    WT_DOMAIN_LIFECYCLE_RUNNING,
    WT_DOMAIN_LIFECYCLE_BLOCKED,
    WT_DOMAIN_LIFECYCLE_FAULTED,
    WT_DOMAIN_LIFECYCLE_RESTARTING
} wt_domain_lifecycle_t;

typedef enum wt_restart_action {
    WT_RESTART_ACTION_NEVER = 0,
    WT_RESTART_ACTION_DOMAIN,
    WT_RESTART_ACTION_PLATFORM
} wt_restart_action_t;

typedef enum wt_isolation_profile {
    WT_ISOLATION_PROFILE_SERVICE_ONLY = 0,
    WT_ISOLATION_PROFILE_LEVEL_1,
    WT_ISOLATION_PROFILE_LEVEL_2,
    WT_ISOLATION_PROFILE_LEVEL_3
} wt_isolation_profile_t;

typedef struct wt_memory_resource {
    uintptr_t base;
    size_t size;
    uint32_t attributes;
    uint32_t share_id;
} wt_memory_resource_t;

typedef struct wt_interrupt_resource {
    uint32_t interrupt;
    uint32_t attributes;
    uint32_t share_id;
} wt_interrupt_resource_t;

typedef struct wt_domain_restart_policy {
    wt_restart_action_t action;
    uint32_t restart_limit;
    uint32_t restart_window_ticks;
    uint32_t initial_delay_ticks;
} wt_domain_restart_policy_t;

typedef struct wt_domain_descriptor {
    wt_domain_id_t id;
    wt_domain_class_t domain_class;
    wt_rot_role_t rot_role;
    wt_security_state_t security_state;
    wt_privilege_state_t privilege_state;
    wt_domain_lifecycle_t initial_lifecycle;
    uintptr_t entry_point;
    uintptr_t stack_base;
    size_t stack_size;
    const wt_memory_resource_t* memory_resources;
    size_t memory_resource_count;
    const wt_interrupt_resource_t* interrupt_resources;
    size_t interrupt_resource_count;
    wt_domain_restart_policy_t restart_policy;
    uint32_t required_capabilities;
    uint32_t launch_required;
    uint32_t launch_min_version;
} wt_domain_descriptor_t;

typedef struct wt_profile_capabilities {
    uint32_t capabilities;
    size_t max_domains;
    size_t max_memory_resources_per_domain;
    size_t max_interrupts_per_domain;
} wt_profile_capabilities_t;

typedef enum wt_domain_validation_result {
    WT_DOMAIN_VALID = 0,
    WT_DOMAIN_ERROR_ARGUMENT = -1,
    WT_DOMAIN_ERROR_COUNT = -2,
    WT_DOMAIN_ERROR_PROFILE = -3,
    WT_DOMAIN_ERROR_CAPABILITY = -4,
    WT_DOMAIN_ERROR_ID = -5,
    WT_DOMAIN_ERROR_CLASS = -6,
    WT_DOMAIN_ERROR_ROT_ROLE = -7,
    WT_DOMAIN_ERROR_SECURITY_STATE = -8,
    WT_DOMAIN_ERROR_PRIVILEGE_STATE = -9,
    WT_DOMAIN_ERROR_LIFECYCLE = -10,
    WT_DOMAIN_ERROR_RESTART_POLICY = -11,
    WT_DOMAIN_ERROR_MEMORY_COUNT = -12,
    WT_DOMAIN_ERROR_EMPTY_REGION = -13,
    WT_DOMAIN_ERROR_ADDRESS_OVERFLOW = -14,
    WT_DOMAIN_ERROR_MEMORY_ATTRIBUTES = -15,
    WT_DOMAIN_ERROR_WRITE_EXECUTE = -16,
    WT_DOMAIN_ERROR_ENTRY_POINT = -17,
    WT_DOMAIN_ERROR_STACK = -18,
    WT_DOMAIN_ERROR_OVERLAP = -19,
    WT_DOMAIN_ERROR_SHARING = -20,
    WT_DOMAIN_ERROR_INTERRUPT_COUNT = -21,
    WT_DOMAIN_ERROR_INTERRUPT = -22,
    WT_DOMAIN_ERROR_INTERRUPT_OWNERSHIP = -23,
    WT_DOMAIN_ERROR_SPM_COUNT = -24,
    WT_DOMAIN_ERROR_LAUNCH_POLICY = -25,
    WT_DOMAIN_ERROR_ISOLATION = -26
} wt_domain_validation_result_t;

/* Phase 3 must call this on generated manifests before runtime scheduling. */
int wt_domain_validate_set(const wt_domain_descriptor_t* domains,
                           size_t domain_count,
                           wt_isolation_profile_t profile,
                           const wt_profile_capabilities_t* capabilities);

#endif
