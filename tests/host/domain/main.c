/* main.c
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

#include <stdio.h>
#include <string.h>

typedef struct wt_domain_fixture {
    wt_memory_resource_t memory[2][3];
    wt_interrupt_resource_t interrupts[2][2];
    wt_domain_descriptor_t domains[2];
    wt_profile_capabilities_t capabilities;
} wt_domain_fixture_t;

static unsigned int g_checks;
static unsigned int g_failures;

#define EXPECT_RESULT(actual, expected) \
    do { \
        int actual_result = (actual); \
        int expected_result = (expected); \
        g_checks++; \
        if (actual_result != expected_result) { \
            (void)fprintf(stderr, \
                "line %d: expected %d, received %d\n", \
                __LINE__, expected_result, actual_result); \
            g_failures++; \
        } \
    } while (0)

static void wt_fixture_init(wt_domain_fixture_t* fixture)
{
    (void)memset(fixture, 0, sizeof(*fixture));

    fixture->memory[0][0].base = 0x00001000U;
    fixture->memory[0][0].size = 0x00001000U;
    fixture->memory[0][0].attributes =
        WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_EXECUTE;
    fixture->memory[0][1].base = 0x00003000U;
    fixture->memory[0][1].size = 0x00001000U;
    fixture->memory[0][1].attributes =
        WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_WRITE |
        WT_MEMORY_ATTR_RESTART_CLEAR;

    fixture->memory[1][0].base = 0x00005000U;
    fixture->memory[1][0].size = 0x00001000U;
    fixture->memory[1][0].attributes =
        WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_EXECUTE;
    fixture->memory[1][1].base = 0x00007000U;
    fixture->memory[1][1].size = 0x00001000U;
    fixture->memory[1][1].attributes =
        WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_WRITE |
        WT_MEMORY_ATTR_RESTART_CLEAR;

    fixture->interrupts[0][0].interrupt = 10U;
    fixture->interrupts[1][0].interrupt = 11U;

    fixture->domains[0].id = 0U;
    fixture->domains[0].domain_class = WT_DOMAIN_CLASS_SPM;
    fixture->domains[0].rot_role = WT_ROT_ROLE_SPM;
    fixture->domains[0].security_state = WT_SECURITY_STATE_SECURE;
    fixture->domains[0].privilege_state =
        WT_PRIVILEGE_STATE_PRIVILEGED;
    fixture->domains[0].initial_lifecycle = WT_DOMAIN_LIFECYCLE_READY;
    fixture->domains[0].entry_point = 0x00001100U;
    fixture->domains[0].stack_base = 0x00003800U;
    fixture->domains[0].stack_size = 0x00000400U;
    fixture->domains[0].memory_resources = fixture->memory[0];
    fixture->domains[0].memory_resource_count = 2U;
    fixture->domains[0].interrupt_resources = fixture->interrupts[0];
    fixture->domains[0].interrupt_resource_count = 1U;
    fixture->domains[0].restart_policy.action = WT_RESTART_ACTION_PLATFORM;

    fixture->domains[1].id = 1U;
    fixture->domains[1].domain_class =
        WT_DOMAIN_CLASS_SECURE_PARTITION;
    fixture->domains[1].rot_role = WT_ROT_ROLE_AROT;
    fixture->domains[1].security_state = WT_SECURITY_STATE_SECURE;
    fixture->domains[1].privilege_state =
        WT_PRIVILEGE_STATE_UNPRIVILEGED;
    fixture->domains[1].initial_lifecycle = WT_DOMAIN_LIFECYCLE_STOPPED;
    fixture->domains[1].entry_point = 0x00005100U;
    fixture->domains[1].stack_base = 0x00007800U;
    fixture->domains[1].stack_size = 0x00000400U;
    fixture->domains[1].memory_resources = fixture->memory[1];
    fixture->domains[1].memory_resource_count = 2U;
    fixture->domains[1].interrupt_resources = fixture->interrupts[1];
    fixture->domains[1].interrupt_resource_count = 1U;
    fixture->domains[1].restart_policy.action = WT_RESTART_ACTION_DOMAIN;
    fixture->domains[1].restart_policy.restart_limit = 3U;
    fixture->domains[1].restart_policy.restart_window_ticks = 64U;
    fixture->domains[1].restart_policy.initial_delay_ticks = 1U;

    fixture->capabilities.capabilities =
        WT_CAPABILITY_SECURITY_STATE |
        WT_CAPABILITY_PRIVILEGE_STATE |
        WT_CAPABILITY_ROT_ISOLATION |
        WT_CAPABILITY_DOMAIN_ISOLATION |
        WT_CAPABILITY_MEMORY_PROTECTION |
        WT_CAPABILITY_INTERRUPT_ISOLATION |
        WT_CAPABILITY_RESTART;
    fixture->capabilities.max_domains = 2U;
    fixture->capabilities.max_memory_resources_per_domain = 3U;
    fixture->capabilities.max_interrupts_per_domain = 2U;
}

static int wt_validate(const wt_domain_fixture_t* fixture)
{
    return wt_domain_validate_set(fixture->domains, 2U,
                                   WT_ISOLATION_PROFILE_LEVEL_3,
                                   &fixture->capabilities);
}

static void wt_test_valid_contracts(void)
{
    wt_domain_fixture_t fixture;

    wt_fixture_init(&fixture);
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_VALID);

    fixture.domains[1].domain_class =
        WT_DOMAIN_CLASS_NONSECURE_APPLICATION;
    fixture.domains[1].rot_role = WT_ROT_ROLE_NONE;
    fixture.domains[1].security_state = WT_SECURITY_STATE_NONSECURE;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_VALID);

    wt_fixture_init(&fixture);
    fixture.domains[0].interrupt_resource_count = 0U;
    fixture.domains[0].interrupt_resources = NULL;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_VALID);
}

static void wt_test_arguments_and_ids(void)
{
    wt_domain_fixture_t fixture;

    wt_fixture_init(&fixture);
    EXPECT_RESULT(wt_domain_validate_set(NULL, 2U,
        WT_ISOLATION_PROFILE_LEVEL_3, &fixture.capabilities),
        WT_DOMAIN_ERROR_ARGUMENT);
    EXPECT_RESULT(wt_domain_validate_set(fixture.domains, 2U,
        WT_ISOLATION_PROFILE_LEVEL_3, NULL), WT_DOMAIN_ERROR_ARGUMENT);
    EXPECT_RESULT(wt_domain_validate_set(fixture.domains, 0U,
        WT_ISOLATION_PROFILE_LEVEL_3, &fixture.capabilities),
        WT_DOMAIN_ERROR_COUNT);

    fixture.domains[0].id = WT_DOMAIN_ID_INVALID;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_ID);

    wt_fixture_init(&fixture);
    fixture.domains[1].id = fixture.domains[0].id;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_ID);
}

static void wt_test_spm_count(void)
{
    wt_domain_fixture_t fixture;

    wt_fixture_init(&fixture);
    fixture.domains[0].domain_class = WT_DOMAIN_CLASS_SECURE_PARTITION;
    fixture.domains[0].rot_role = WT_ROT_ROLE_PROT;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_SPM_COUNT);

    wt_fixture_init(&fixture);
    fixture.domains[1].domain_class = WT_DOMAIN_CLASS_SPM;
    fixture.domains[1].rot_role = WT_ROT_ROLE_SPM;
    fixture.domains[1].privilege_state = WT_PRIVILEGE_STATE_PRIVILEGED;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_SPM_COUNT);
}

static void wt_test_domain_metadata(void)
{
    wt_domain_fixture_t fixture;

    wt_fixture_init(&fixture);
    fixture.domains[0].domain_class = (wt_domain_class_t)99;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_CLASS);

    wt_fixture_init(&fixture);
    fixture.domains[0].rot_role = WT_ROT_ROLE_AROT;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_ROT_ROLE);

    wt_fixture_init(&fixture);
    fixture.domains[1].security_state = WT_SECURITY_STATE_NONSECURE;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_SECURITY_STATE);

    wt_fixture_init(&fixture);
    fixture.domains[0].privilege_state =
        WT_PRIVILEGE_STATE_UNPRIVILEGED;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_PRIVILEGE_STATE);

    wt_fixture_init(&fixture);
    fixture.domains[0].initial_lifecycle = WT_DOMAIN_LIFECYCLE_RUNNING;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_LIFECYCLE);
}

static void wt_test_restart_policy(void)
{
    wt_domain_fixture_t fixture;

    wt_fixture_init(&fixture);
    fixture.domains[1].restart_policy.restart_limit = 0U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_RESTART_POLICY);

    wt_fixture_init(&fixture);
    fixture.domains[1].restart_policy.restart_window_ticks = 0U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_RESTART_POLICY);

    wt_fixture_init(&fixture);
    fixture.domains[0].restart_policy.restart_limit = 1U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_RESTART_POLICY);

    wt_fixture_init(&fixture);
    fixture.domains[0].restart_policy.action = (wt_restart_action_t)99;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_RESTART_POLICY);
}

static void wt_test_memory_regions(void)
{
    wt_domain_fixture_t fixture;

    wt_fixture_init(&fixture);
    fixture.domains[0].memory_resources = NULL;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_MEMORY_COUNT);

    wt_fixture_init(&fixture);
    fixture.memory[0][0].size = 0U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_EMPTY_REGION);

    wt_fixture_init(&fixture);
    fixture.memory[0][0].base = UINTPTR_MAX - 1U;
    fixture.memory[0][0].size = 4U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_ADDRESS_OVERFLOW);

    wt_fixture_init(&fixture);
    fixture.memory[0][0].attributes |= WT_MEMORY_ATTR_WRITE;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_WRITE_EXECUTE);

    wt_fixture_init(&fixture);
    fixture.memory[0][0].attributes |= (1U << 31);
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_DOMAIN_ERROR_MEMORY_ATTRIBUTES);

    wt_fixture_init(&fixture);
    fixture.memory[0][0].attributes = 0U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_DOMAIN_ERROR_MEMORY_ATTRIBUTES);

    wt_fixture_init(&fixture);
    fixture.memory[0][0].attributes |= WT_MEMORY_ATTR_DEVICE;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_DOMAIN_ERROR_MEMORY_ATTRIBUTES);

    wt_fixture_init(&fixture);
    fixture.memory[0][0].attributes = WT_MEMORY_ATTR_READ |
                                      WT_MEMORY_ATTR_RESTART_CLEAR;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_DOMAIN_ERROR_MEMORY_ATTRIBUTES);

    wt_fixture_init(&fixture);
    fixture.memory[0][0].attributes |= WT_MEMORY_ATTR_SHARED;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_SHARING);

    wt_fixture_init(&fixture);
    fixture.memory[0][0].share_id = 7U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_SHARING);

    wt_fixture_init(&fixture);
    fixture.memory[0][1].base = 0x00001800U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_OVERLAP);
}

static void wt_test_entry_and_stack(void)
{
    wt_domain_fixture_t fixture;

    wt_fixture_init(&fixture);
    fixture.domains[0].entry_point = 0x00003000U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_ENTRY_POINT);

    wt_fixture_init(&fixture);
    fixture.domains[0].stack_base = 0x00003F00U;
    fixture.domains[0].stack_size = 0x00000200U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_STACK);

    wt_fixture_init(&fixture);
    fixture.domains[0].stack_size = 0U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_STACK);

    wt_fixture_init(&fixture);
    fixture.domains[0].stack_base = UINTPTR_MAX - 1U;
    fixture.domains[0].stack_size = 4U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_ADDRESS_OVERFLOW);

    wt_fixture_init(&fixture);
    fixture.memory[0][1].attributes = WT_MEMORY_ATTR_READ;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_STACK);

    wt_fixture_init(&fixture);
    fixture.memory[1][1].base = fixture.memory[0][1].base;
    fixture.memory[1][1].size = fixture.memory[0][1].size;
    fixture.memory[0][1].attributes |= WT_MEMORY_ATTR_SHARED;
    fixture.memory[1][1].attributes = fixture.memory[0][1].attributes;
    fixture.memory[0][1].share_id = 7U;
    fixture.memory[1][1].share_id = 7U;
    fixture.domains[1].stack_base = fixture.domains[0].stack_base;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_STACK);
}

static void wt_test_memory_sharing(void)
{
    wt_domain_fixture_t fixture;
    uint32_t shared_attributes = WT_MEMORY_ATTR_READ |
                                 WT_MEMORY_ATTR_EXECUTE |
                                 WT_MEMORY_ATTR_SHARED;

    wt_fixture_init(&fixture);
    fixture.memory[1][0].base = fixture.memory[0][0].base;
    fixture.memory[1][0].size = fixture.memory[0][0].size;
    fixture.memory[0][0].attributes = shared_attributes;
    fixture.memory[1][0].attributes = shared_attributes;
    fixture.memory[0][0].share_id = 7U;
    fixture.memory[1][0].share_id = 7U;
    fixture.domains[1].entry_point = fixture.domains[0].entry_point;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_VALID);

    fixture.memory[1][0].share_id = 8U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_SHARING);

    wt_fixture_init(&fixture);
    fixture.memory[0][2].base = 0x00009000U;
    fixture.memory[0][2].size = 0x00001000U;
    fixture.memory[0][2].attributes = WT_MEMORY_ATTR_READ |
                                      WT_MEMORY_ATTR_WRITE |
                                      WT_MEMORY_ATTR_RESTART_CLEAR |
                                      WT_MEMORY_ATTR_SHARED;
    fixture.memory[0][2].share_id = 7U;
    fixture.memory[1][2].base = fixture.memory[0][2].base;
    fixture.memory[1][2].size = fixture.memory[0][2].size;
    fixture.memory[1][2].attributes = WT_MEMORY_ATTR_READ |
                                      WT_MEMORY_ATTR_WRITE |
                                      WT_MEMORY_ATTR_SHARED;
    fixture.memory[1][2].share_id = 7U;
    fixture.domains[0].memory_resource_count = 3U;
    fixture.domains[1].memory_resource_count = 3U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_SHARING);

    wt_fixture_init(&fixture);
    fixture.memory[1][0].base = 0x00001800U;
    fixture.domains[1].entry_point = 0x00001900U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_OVERLAP);

    fixture.memory[0][0].attributes = shared_attributes;
    fixture.memory[1][0].attributes = shared_attributes;
    fixture.memory[0][0].share_id = 7U;
    fixture.memory[1][0].share_id = 7U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_SHARING);
}

static void wt_test_interrupts(void)
{
    wt_domain_fixture_t fixture;

    wt_fixture_init(&fixture);
    fixture.domains[0].interrupt_resources = NULL;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_INTERRUPT_COUNT);

    wt_fixture_init(&fixture);
    fixture.interrupts[0][0].interrupt = UINT32_MAX;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_INTERRUPT);

    wt_fixture_init(&fixture);
    fixture.interrupts[0][0].attributes = (1U << 31);
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_INTERRUPT);

    wt_fixture_init(&fixture);
    fixture.interrupts[0][0].interrupt = 11U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_DOMAIN_ERROR_INTERRUPT_OWNERSHIP);

    wt_fixture_init(&fixture);
    fixture.interrupts[1][0].interrupt = 10U;
    fixture.interrupts[0][0].attributes = WT_INTERRUPT_ATTR_SHARED;
    fixture.interrupts[1][0].attributes = WT_INTERRUPT_ATTR_SHARED;
    fixture.interrupts[0][0].share_id = 9U;
    fixture.interrupts[1][0].share_id = 9U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_VALID);

    fixture.interrupts[1][0].share_id = 10U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_DOMAIN_ERROR_INTERRUPT_OWNERSHIP);
}

static void wt_test_profile_capabilities(void)
{
    wt_domain_fixture_t fixture;

    wt_fixture_init(&fixture);
    fixture.capabilities.capabilities &=
        ~WT_CAPABILITY_DOMAIN_ISOLATION;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_CAPABILITY);

    wt_fixture_init(&fixture);
    fixture.capabilities.max_domains = 1U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_COUNT);

    wt_fixture_init(&fixture);
    fixture.capabilities.max_memory_resources_per_domain = 1U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_MEMORY_COUNT);

    wt_fixture_init(&fixture);
    fixture.capabilities.max_interrupts_per_domain = 0U;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_INTERRUPT_COUNT);

    wt_fixture_init(&fixture);
    fixture.domains[0].required_capabilities = (1U << 31);
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_CAPABILITY);

    wt_fixture_init(&fixture);
    fixture.capabilities.capabilities |= (1U << 31);
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_CAPABILITY);

    wt_fixture_init(&fixture);
    EXPECT_RESULT(wt_domain_validate_set(fixture.domains, 2U,
        (wt_isolation_profile_t)99, &fixture.capabilities),
        WT_DOMAIN_ERROR_PROFILE);

    wt_fixture_init(&fixture);
    fixture.capabilities.capabilities &= ~WT_CAPABILITY_RESTART;
    EXPECT_RESULT(wt_validate(&fixture), WT_DOMAIN_ERROR_CAPABILITY);

    wt_fixture_init(&fixture);
    EXPECT_RESULT(wt_domain_validate_set(fixture.domains, 2U,
        WT_ISOLATION_PROFILE_LEVEL_1, &fixture.capabilities),
        WT_DOMAIN_ERROR_PROFILE);
    EXPECT_RESULT(wt_domain_validate_set(fixture.domains, 2U,
        WT_ISOLATION_PROFILE_LEVEL_2, &fixture.capabilities),
        WT_DOMAIN_ERROR_PROFILE);

    wt_fixture_init(&fixture);
    fixture.domains[0].interrupt_resource_count = 0U;
    fixture.domains[0].interrupt_resources = NULL;
    fixture.capabilities.capabilities = WT_CAPABILITY_SECURITY_STATE |
                                        WT_CAPABILITY_MEMORY_PROTECTION;
    EXPECT_RESULT(wt_domain_validate_set(fixture.domains, 1U,
        WT_ISOLATION_PROFILE_SERVICE_ONLY, &fixture.capabilities),
        WT_DOMAIN_VALID);
}

int main(void)
{
    wt_test_valid_contracts();
    wt_test_arguments_and_ids();
    wt_test_spm_count();
    wt_test_domain_metadata();
    wt_test_restart_policy();
    wt_test_memory_regions();
    wt_test_entry_and_stack();
    wt_test_memory_sharing();
    wt_test_interrupts();
    wt_test_profile_capabilities();

    (void)fprintf(stderr, "domain host tests: %u checks, %u failures\n",
                  g_checks, g_failures);
    return g_failures == 0U ? 0 : 1;
}
