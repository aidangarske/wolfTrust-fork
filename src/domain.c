/* domain.c
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

#include "wolftrust/domain.h"

#define WT_MEMORY_ATTR_MASK \
    (WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_WRITE | \
     WT_MEMORY_ATTR_EXECUTE | WT_MEMORY_ATTR_DEVICE | \
     WT_MEMORY_ATTR_RESTART_CLEAR | WT_MEMORY_ATTR_SHARED)

#define WT_INTERRUPT_ATTR_MASK WT_INTERRUPT_ATTR_SHARED

#define WT_CAPABILITY_MASK \
    (WT_CAPABILITY_SECURITY_STATE | WT_CAPABILITY_PRIVILEGE_STATE | \
     WT_CAPABILITY_ROT_ISOLATION | WT_CAPABILITY_DOMAIN_ISOLATION | \
     WT_CAPABILITY_MEMORY_PROTECTION | \
     WT_CAPABILITY_INTERRUPT_ISOLATION | WT_CAPABILITY_RESTART)

static int wt_range_end(uintptr_t base, size_t size, uintptr_t* end)
{
    if (end == NULL)
        return WT_DOMAIN_ERROR_ARGUMENT;

    if (size == 0U)
        return WT_DOMAIN_ERROR_EMPTY_REGION;

    if (size > (size_t)(UINTPTR_MAX - base))
        return WT_DOMAIN_ERROR_ADDRESS_OVERFLOW;

    *end = base + (uintptr_t)size;
    return WT_DOMAIN_VALID;
}

static int wt_profile_required_capabilities(wt_isolation_profile_t profile,
                                            uint32_t* required)
{
    if (required == NULL)
        return WT_DOMAIN_ERROR_ARGUMENT;

    switch (profile) {
        case WT_ISOLATION_PROFILE_SERVICE_ONLY:
            *required = 0U;
            break;

        case WT_ISOLATION_PROFILE_LEVEL_3:
            *required = WT_CAPABILITY_SECURITY_STATE |
                        WT_CAPABILITY_PRIVILEGE_STATE |
                        WT_CAPABILITY_ROT_ISOLATION |
                        WT_CAPABILITY_DOMAIN_ISOLATION |
                        WT_CAPABILITY_MEMORY_PROTECTION |
                        WT_CAPABILITY_INTERRUPT_ISOLATION;
            break;

        /* Only isolation level 3 is implemented; a level 1 or 2
         * declaration would silently receive level 3 enforcement. */
        default:
            return WT_DOMAIN_ERROR_PROFILE;
    }

    return WT_DOMAIN_VALID;
}

static int wt_domain_validate_identity(const wt_domain_descriptor_t* domain)
{
    if (domain->id == WT_DOMAIN_ID_INVALID)
        return WT_DOMAIN_ERROR_ID;

    if ((unsigned int)domain->domain_class >
            (unsigned int)WT_DOMAIN_CLASS_NONSECURE_APPLICATION) {
        return WT_DOMAIN_ERROR_CLASS;
    }

    if ((unsigned int)domain->rot_role > (unsigned int)WT_ROT_ROLE_AROT) {
        return WT_DOMAIN_ERROR_ROT_ROLE;
    }

    if ((unsigned int)domain->security_state >
            (unsigned int)WT_SECURITY_STATE_NONSECURE) {
        return WT_DOMAIN_ERROR_SECURITY_STATE;
    }

    if ((unsigned int)domain->privilege_state >
            (unsigned int)WT_PRIVILEGE_STATE_UNPRIVILEGED) {
        return WT_DOMAIN_ERROR_PRIVILEGE_STATE;
    }

    if ((unsigned int)domain->initial_lifecycle >
            (unsigned int)WT_DOMAIN_LIFECYCLE_READY) {
        return WT_DOMAIN_ERROR_LIFECYCLE;
    }

    if (domain->domain_class == WT_DOMAIN_CLASS_SPM) {
        if (domain->rot_role != WT_ROT_ROLE_SPM)
            return WT_DOMAIN_ERROR_ROT_ROLE;
        if (domain->security_state != WT_SECURITY_STATE_SECURE)
            return WT_DOMAIN_ERROR_SECURITY_STATE;
        if (domain->privilege_state != WT_PRIVILEGE_STATE_PRIVILEGED)
            return WT_DOMAIN_ERROR_PRIVILEGE_STATE;
    }
    else if (domain->domain_class == WT_DOMAIN_CLASS_SECURE_PARTITION) {
        if (domain->rot_role != WT_ROT_ROLE_PROT &&
                domain->rot_role != WT_ROT_ROLE_AROT) {
            return WT_DOMAIN_ERROR_ROT_ROLE;
        }
        if (domain->security_state != WT_SECURITY_STATE_SECURE)
            return WT_DOMAIN_ERROR_SECURITY_STATE;
        if (domain->privilege_state != WT_PRIVILEGE_STATE_UNPRIVILEGED)
            return WT_DOMAIN_ERROR_PRIVILEGE_STATE;
    }
    else {
        if (domain->rot_role != WT_ROT_ROLE_NONE)
            return WT_DOMAIN_ERROR_ROT_ROLE;
        if (domain->security_state != WT_SECURITY_STATE_NONSECURE)
            return WT_DOMAIN_ERROR_SECURITY_STATE;
    }

    return WT_DOMAIN_VALID;
}

static int wt_domain_validate_launch(const wt_domain_descriptor_t* domain)
{
    if (domain->launch_required > 1U)
        return WT_DOMAIN_ERROR_LAUNCH_POLICY;

    if (domain->launch_required == 1U &&
            domain->domain_class != WT_DOMAIN_CLASS_NONSECURE_APPLICATION) {
        return WT_DOMAIN_ERROR_LAUNCH_POLICY;
    }

    return WT_DOMAIN_VALID;
}

static int wt_domain_validate_restart(const wt_domain_descriptor_t* domain)
{
    const wt_domain_restart_policy_t* policy = &domain->restart_policy;

    if ((unsigned int)policy->action >
            (unsigned int)WT_RESTART_ACTION_PLATFORM) {
        return WT_DOMAIN_ERROR_RESTART_POLICY;
    }

    if (policy->action == WT_RESTART_ACTION_DOMAIN) {
        if (policy->restart_limit == 0U ||
                policy->restart_window_ticks == 0U) {
            return WT_DOMAIN_ERROR_RESTART_POLICY;
        }
    }
    else if (policy->restart_limit != 0U ||
            policy->restart_window_ticks != 0U ||
            policy->initial_delay_ticks != 0U) {
        return WT_DOMAIN_ERROR_RESTART_POLICY;
    }

    return WT_DOMAIN_VALID;
}

/* Armv8-M MPU regions are 32-byte granules; an unaligned resource would be
 * silently broadened by the encoder, so it is rejected here instead. */
#define WT_MPU_GRANULE 32U

static int wt_memory_resource_validate(const wt_memory_resource_t* resource)
{
    uintptr_t end;
    int ret;

    ret = wt_range_end(resource->base, resource->size, &end);
    if (ret != WT_DOMAIN_VALID)
        return ret;

    if (((resource->base % WT_MPU_GRANULE) != 0U) ||
            ((resource->size % WT_MPU_GRANULE) != 0U)) {
        return WT_DOMAIN_ERROR_MEMORY_ATTRIBUTES;
    }

    if ((resource->attributes & ~WT_MEMORY_ATTR_MASK) != 0U)
        return WT_DOMAIN_ERROR_MEMORY_ATTRIBUTES;

    if ((resource->attributes & (WT_MEMORY_ATTR_READ |
            WT_MEMORY_ATTR_WRITE | WT_MEMORY_ATTR_EXECUTE)) == 0U) {
        return WT_DOMAIN_ERROR_MEMORY_ATTRIBUTES;
    }

    if ((resource->attributes & WT_MEMORY_ATTR_DEVICE) != 0U &&
            (resource->attributes & WT_MEMORY_ATTR_EXECUTE) != 0U) {
        return WT_DOMAIN_ERROR_MEMORY_ATTRIBUTES;
    }

    if ((resource->attributes & WT_MEMORY_ATTR_RESTART_CLEAR) != 0U &&
            (resource->attributes & WT_MEMORY_ATTR_WRITE) == 0U) {
        return WT_DOMAIN_ERROR_MEMORY_ATTRIBUTES;
    }

    if ((resource->attributes & (WT_MEMORY_ATTR_WRITE |
            WT_MEMORY_ATTR_EXECUTE)) == (WT_MEMORY_ATTR_WRITE |
            WT_MEMORY_ATTR_EXECUTE)) {
        return WT_DOMAIN_ERROR_WRITE_EXECUTE;
    }

    if ((resource->attributes & WT_MEMORY_ATTR_SHARED) != 0U) {
        if (resource->share_id == WT_RESOURCE_SHARE_NONE)
            return WT_DOMAIN_ERROR_SHARING;
    }
    else if (resource->share_id != WT_RESOURCE_SHARE_NONE) {
        return WT_DOMAIN_ERROR_SHARING;
    }

    return WT_DOMAIN_VALID;
}

static int wt_domain_validate_entry_and_stack(
    const wt_domain_descriptor_t* domain)
{
    uintptr_t stack_end;
    int entry_found = 0;
    int stack_found = 0;
    size_t i;
    int ret;

    ret = wt_range_end(domain->stack_base, domain->stack_size, &stack_end);
    if (ret == WT_DOMAIN_ERROR_EMPTY_REGION)
        return WT_DOMAIN_ERROR_STACK;
    if (ret != WT_DOMAIN_VALID)
        return ret;

    for (i = 0U; i < domain->memory_resource_count; i++) {
        const wt_memory_resource_t* resource = &domain->memory_resources[i];
        uintptr_t end = resource->base + (uintptr_t)resource->size;

        if ((resource->attributes & WT_MEMORY_ATTR_EXECUTE) != 0U &&
                domain->entry_point >= resource->base &&
                domain->entry_point < end) {
            entry_found = 1;
        }

        if ((resource->attributes &
                (WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_WRITE)) ==
                (WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_WRITE) &&
                (resource->attributes &
                (WT_MEMORY_ATTR_EXECUTE | WT_MEMORY_ATTR_DEVICE |
                 WT_MEMORY_ATTR_SHARED)) == 0U &&
                domain->stack_base >= resource->base &&
                stack_end <= end) {
            stack_found = 1;
        }
    }

    if (entry_found == 0)
        return WT_DOMAIN_ERROR_ENTRY_POINT;
    if (stack_found == 0)
        return WT_DOMAIN_ERROR_STACK;

    return WT_DOMAIN_VALID;
}

static int wt_memory_resources_overlap(const wt_memory_resource_t* first,
                                       const wt_memory_resource_t* second)
{
    uintptr_t first_end = first->base + (uintptr_t)first->size;
    uintptr_t second_end = second->base + (uintptr_t)second->size;

    return first->base < second_end && second->base < first_end;
}

static int wt_memory_resources_shared(const wt_memory_resource_t* first,
                                      const wt_memory_resource_t* second)
{
    return (first->attributes & WT_MEMORY_ATTR_SHARED) != 0U &&
           (second->attributes & WT_MEMORY_ATTR_SHARED) != 0U &&
           first->share_id == second->share_id &&
           first->share_id != WT_RESOURCE_SHARE_NONE &&
           first->base == second->base && first->size == second->size &&
           first->attributes == second->attributes;
}

static int wt_domain_validate_resources(const wt_domain_descriptor_t* domain,
                                        const wt_profile_capabilities_t* caps)
{
    size_t i;
    size_t j;
    int ret;

    if (domain->memory_resource_count == 0U ||
            domain->memory_resources == NULL ||
            domain->memory_resource_count >
                caps->max_memory_resources_per_domain) {
        return WT_DOMAIN_ERROR_MEMORY_COUNT;
    }

    if (domain->interrupt_resource_count > caps->max_interrupts_per_domain ||
            (domain->interrupt_resource_count != 0U &&
             domain->interrupt_resources == NULL)) {
        return WT_DOMAIN_ERROR_INTERRUPT_COUNT;
    }

    for (i = 0U; i < domain->memory_resource_count; i++) {
        ret = wt_memory_resource_validate(&domain->memory_resources[i]);
        if (ret != WT_DOMAIN_VALID)
            return ret;

        for (j = 0U; j < i; j++) {
            if (wt_memory_resources_overlap(&domain->memory_resources[i],
                                            &domain->memory_resources[j])) {
                return WT_DOMAIN_ERROR_OVERLAP;
            }
        }
    }

    for (i = 0U; i < domain->interrupt_resource_count; i++) {
        const wt_interrupt_resource_t* interrupt =
            &domain->interrupt_resources[i];

        if (interrupt->interrupt == UINT32_MAX ||
                (interrupt->attributes & ~WT_INTERRUPT_ATTR_MASK) != 0U) {
            return WT_DOMAIN_ERROR_INTERRUPT;
        }

        if ((interrupt->attributes & WT_INTERRUPT_ATTR_SHARED) != 0U) {
            if (interrupt->share_id == WT_RESOURCE_SHARE_NONE)
                return WT_DOMAIN_ERROR_INTERRUPT_OWNERSHIP;
        }
        else if (interrupt->share_id != WT_RESOURCE_SHARE_NONE) {
            return WT_DOMAIN_ERROR_INTERRUPT_OWNERSHIP;
        }

        for (j = 0U; j < i; j++) {
            if (interrupt->interrupt ==
                    domain->interrupt_resources[j].interrupt) {
                return WT_DOMAIN_ERROR_INTERRUPT_OWNERSHIP;
            }
        }
    }

    return wt_domain_validate_entry_and_stack(domain);
}

static int wt_domain_validate_pair(const wt_domain_descriptor_t* first,
                                   const wt_domain_descriptor_t* second)
{
    size_t i;
    size_t j;

    if (first->id == second->id)
        return WT_DOMAIN_ERROR_ID;

    for (i = 0U; i < first->memory_resource_count; i++) {
        for (j = 0U; j < second->memory_resource_count; j++) {
            const wt_memory_resource_t* first_resource =
                &first->memory_resources[i];
            const wt_memory_resource_t* second_resource =
                &second->memory_resources[j];

            if (wt_memory_resources_overlap(first_resource, second_resource) &&
                    !wt_memory_resources_shared(first_resource,
                                                second_resource)) {
                if ((first_resource->attributes & WT_MEMORY_ATTR_SHARED) != 0U ||
                        (second_resource->attributes &
                         WT_MEMORY_ATTR_SHARED) != 0U) {
                    return WT_DOMAIN_ERROR_SHARING;
                }
                return WT_DOMAIN_ERROR_OVERLAP;
            }
        }
    }

    for (i = 0U; i < first->interrupt_resource_count; i++) {
        for (j = 0U; j < second->interrupt_resource_count; j++) {
            const wt_interrupt_resource_t* first_interrupt =
                &first->interrupt_resources[i];
            const wt_interrupt_resource_t* second_interrupt =
                &second->interrupt_resources[j];

            if (first_interrupt->interrupt == second_interrupt->interrupt &&
                    (!((first_interrupt->attributes &
                        WT_INTERRUPT_ATTR_SHARED) != 0U &&
                       (second_interrupt->attributes &
                        WT_INTERRUPT_ATTR_SHARED) != 0U &&
                       first_interrupt->share_id == second_interrupt->share_id &&
                       first_interrupt->share_id != WT_RESOURCE_SHARE_NONE))) {
                return WT_DOMAIN_ERROR_INTERRUPT_OWNERSHIP;
            }
        }
    }

    return WT_DOMAIN_VALID;
}

int wt_domain_validate_set(const wt_domain_descriptor_t* domains,
                           size_t domain_count,
                           wt_isolation_profile_t profile,
                           const wt_profile_capabilities_t* capabilities)
{
    uint32_t profile_required;
    size_t spm_count = 0U;
    size_t i;
    size_t j;
    int ret;

    if (domains == NULL || capabilities == NULL)
        return WT_DOMAIN_ERROR_ARGUMENT;

    if (domain_count == 0U || domain_count > capabilities->max_domains)
        return WT_DOMAIN_ERROR_COUNT;

    if ((capabilities->capabilities & ~WT_CAPABILITY_MASK) != 0U)
        return WT_DOMAIN_ERROR_CAPABILITY;

    ret = wt_profile_required_capabilities(profile, &profile_required);
    if (ret != WT_DOMAIN_VALID)
        return ret;

    if ((capabilities->capabilities & profile_required) != profile_required)
        return WT_DOMAIN_ERROR_CAPABILITY;

    for (i = 0U; i < domain_count; i++) {
        ret = wt_domain_validate_identity(&domains[i]);
        if (ret != WT_DOMAIN_VALID)
            return ret;

        if (domains[i].domain_class == WT_DOMAIN_CLASS_SPM)
            spm_count++;
    }

    if (profile != WT_ISOLATION_PROFILE_SERVICE_ONLY && spm_count != 1U)
        return WT_DOMAIN_ERROR_SPM_COUNT;

    for (i = 0U; i < domain_count; i++) {
        ret = wt_domain_validate_restart(&domains[i]);
        if (ret != WT_DOMAIN_VALID)
            return ret;

        ret = wt_domain_validate_launch(&domains[i]);
        if (ret != WT_DOMAIN_VALID)
            return ret;

        if ((domains[i].required_capabilities & ~WT_CAPABILITY_MASK) != 0U ||
                (capabilities->capabilities &
                 domains[i].required_capabilities) !=
                domains[i].required_capabilities) {
            return WT_DOMAIN_ERROR_CAPABILITY;
        }

        if (domains[i].restart_policy.action == WT_RESTART_ACTION_DOMAIN &&
                (capabilities->capabilities & WT_CAPABILITY_RESTART) == 0U) {
            return WT_DOMAIN_ERROR_CAPABILITY;
        }

        if (domains[i].memory_resource_count != 0U &&
                (capabilities->capabilities &
                 WT_CAPABILITY_MEMORY_PROTECTION) == 0U) {
            return WT_DOMAIN_ERROR_CAPABILITY;
        }

        if (domains[i].interrupt_resource_count != 0U &&
                (capabilities->capabilities &
                 WT_CAPABILITY_INTERRUPT_ISOLATION) == 0U) {
            return WT_DOMAIN_ERROR_CAPABILITY;
        }

        ret = wt_domain_validate_resources(&domains[i], capabilities);
        if (ret != WT_DOMAIN_VALID)
            return ret;

        for (j = 0U; j < i; j++) {
            ret = wt_domain_validate_pair(&domains[i], &domains[j]);
            if (ret != WT_DOMAIN_VALID)
                return ret;
        }
    }

    return WT_DOMAIN_VALID;
}
