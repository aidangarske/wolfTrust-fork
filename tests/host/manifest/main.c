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

#include "wolftrust/manifest.h"

#include <stdio.h>
#include <string.h>

typedef struct wt_manifest_fixture {
    uint8_t digest[WT_MANIFEST_DIGEST_SIZE];
    wt_memory_resource_t memory[3][3];
    wt_interrupt_resource_t domain_interrupts[3];
    wt_domain_descriptor_t domains[3];
    wt_profile_capabilities_t capabilities;
    wt_service_descriptor_t services[2];
    uint32_t dependencies[2][2];
    wt_manifest_interrupt_t interrupts[2];
    wt_partition_manifest_t partitions[2];
    wt_system_manifest_t manifest;
    uint32_t supported_features;
} wt_manifest_fixture_t;

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

static void wt_init_domain(wt_manifest_fixture_t* fixture, size_t index,
                           uintptr_t code, uintptr_t data)
{
    fixture->memory[index][0].base = code;
    fixture->memory[index][0].size = 0x1000U;
    fixture->memory[index][0].attributes =
        WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_EXECUTE;
    fixture->memory[index][1].base = data;
    fixture->memory[index][1].size = 0x1000U;
    fixture->memory[index][1].attributes =
        WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_WRITE |
        WT_MEMORY_ATTR_RESTART_CLEAR;

    fixture->domains[index].id = (wt_domain_id_t)index;
    fixture->domains[index].security_state = WT_SECURITY_STATE_SECURE;
    fixture->domains[index].initial_lifecycle =
        WT_DOMAIN_LIFECYCLE_STOPPED;
    fixture->domains[index].entry_point = code + 0x100U;
    fixture->domains[index].stack_base = data + 0x800U;
    fixture->domains[index].stack_size = 0x400U;
    fixture->domains[index].memory_resources = fixture->memory[index];
    fixture->domains[index].memory_resource_count = 2U;
}

static void wt_fixture_init(wt_manifest_fixture_t* fixture)
{
    size_t i;

    (void)memset(fixture, 0, sizeof(*fixture));
    (void)memset(fixture->digest, 0xA5, sizeof(fixture->digest));

    wt_init_domain(fixture, 0U, 0x1000U, 0x3000U);
    wt_init_domain(fixture, 1U, 0x5000U, 0x7000U);
    wt_init_domain(fixture, 2U, 0x9000U, 0xB000U);

    fixture->domains[0].domain_class = WT_DOMAIN_CLASS_SPM;
    fixture->domains[0].rot_role = WT_ROT_ROLE_SPM;
    fixture->domains[0].privilege_state = WT_PRIVILEGE_STATE_PRIVILEGED;
    fixture->domains[0].initial_lifecycle = WT_DOMAIN_LIFECYCLE_READY;
    fixture->domains[0].restart_policy.action = WT_RESTART_ACTION_PLATFORM;

    for (i = 1U; i < 3U; i++) {
        fixture->domains[i].domain_class =
            WT_DOMAIN_CLASS_SECURE_PARTITION;
        fixture->domains[i].rot_role = WT_ROT_ROLE_AROT;
        fixture->domains[i].privilege_state =
            WT_PRIVILEGE_STATE_UNPRIVILEGED;
        fixture->domains[i].restart_policy.action =
            WT_RESTART_ACTION_DOMAIN;
        fixture->domains[i].restart_policy.restart_limit = 3U;
        fixture->domains[i].restart_policy.restart_window_ticks = 100U;
        fixture->domains[i].restart_policy.initial_delay_ticks = 1U;
        fixture->domain_interrupts[i].interrupt = 20U + (uint32_t)i;
        fixture->domains[i].interrupt_resources =
            &fixture->domain_interrupts[i];
        fixture->domains[i].interrupt_resource_count = 1U;
    }

    fixture->capabilities.capabilities =
        WT_CAPABILITY_SECURITY_STATE |
        WT_CAPABILITY_PRIVILEGE_STATE |
        WT_CAPABILITY_ROT_ISOLATION |
        WT_CAPABILITY_DOMAIN_ISOLATION |
        WT_CAPABILITY_MEMORY_PROTECTION |
        WT_CAPABILITY_INTERRUPT_ISOLATION |
        WT_CAPABILITY_RESTART;
    fixture->capabilities.max_domains = 3U;
    fixture->capabilities.max_memory_resources_per_domain = 3U;
    fixture->capabilities.max_interrupts_per_domain = 1U;

    fixture->services[0].name = "SERVICE_ALPHA";
    fixture->services[0].sid = 0x1000U;
    fixture->services[0].version = 1U;
    fixture->services[0].version_policy = WT_SERVICE_VERSION_STRICT;
    fixture->services[0].signal = 0x10U;
    fixture->services[0].nonsecure_clients = 1U;
    fixture->services[0].connection_based = 1U;

    fixture->services[1].name = "SERVICE_BETA";
    fixture->services[1].sid = 0x2000U;
    fixture->services[1].version = 2U;
    fixture->services[1].version_policy = WT_SERVICE_VERSION_RELAXED;
    fixture->services[1].signal = 0x10U;
    fixture->services[1].stateless_handle_index = 1U;
    fixture->services[1].connection_based = 0U;

    fixture->dependencies[0][0] = fixture->services[1].sid;

    fixture->interrupts[0].signal_name = "ALPHA_IRQ";
    fixture->interrupts[0].interrupt =
        fixture->domain_interrupts[1].interrupt;
    fixture->interrupts[0].signal = 0x20U;
    fixture->interrupts[1].signal_name = "BETA_IRQ";
    fixture->interrupts[1].interrupt =
        fixture->domain_interrupts[2].interrupt;
    fixture->interrupts[1].signal = 0x20U;

    fixture->partitions[0].name = "PARTITION_ALPHA";
    fixture->partitions[0].domain_id = 1U;
    fixture->partitions[0].framework_version = WT_FFM_VERSION_1_0;
    fixture->partitions[0].model = WT_PARTITION_MODEL_IPC;
    fixture->partitions[0].priority = WT_PARTITION_PRIORITY_HIGH;
    fixture->partitions[0].services = &fixture->services[0];
    fixture->partitions[0].service_count = 1U;
    fixture->partitions[0].dependencies = fixture->dependencies[0];
    fixture->partitions[0].dependency_count = 1U;
    fixture->partitions[0].interrupts = &fixture->interrupts[0];
    fixture->partitions[0].interrupt_count = 1U;

    fixture->partitions[1].name = "PARTITION_BETA";
    fixture->partitions[1].domain_id = 2U;
    fixture->partitions[1].framework_version = WT_FFM_VERSION_1_1;
    fixture->partitions[1].model = WT_PARTITION_MODEL_IPC;
    fixture->partitions[1].priority = WT_PARTITION_PRIORITY_NORMAL;
    fixture->partitions[1].services = &fixture->services[1];
    fixture->partitions[1].service_count = 1U;
    fixture->partitions[1].interrupts = &fixture->interrupts[1];
    fixture->partitions[1].interrupt_count = 1U;

    fixture->manifest.format_version = WT_MANIFEST_FORMAT_VERSION;
    fixture->manifest.generator_version = "WOLFTRUST_GEN_1";
    fixture->manifest.input_digest = fixture->digest;
    fixture->manifest.input_digest_size = sizeof(fixture->digest);
    fixture->manifest.features = WT_MANIFEST_FEATURE_IPC |
                                 WT_MANIFEST_FEATURE_STATELESS;
    fixture->manifest.isolation_profile = WT_ISOLATION_PROFILE_LEVEL_3;
    fixture->manifest.profile_capabilities = &fixture->capabilities;
    fixture->manifest.domains = fixture->domains;
    fixture->manifest.domain_count = 3U;
    fixture->manifest.partitions = fixture->partitions;
    fixture->manifest.partition_count = 2U;
    fixture->manifest.limits.max_partitions = 4U;
    fixture->manifest.limits.max_services_per_partition = 4U;
    fixture->manifest.limits.max_dependencies_per_partition = 4U;
    fixture->manifest.limits.max_stateless_handles = 32U;
    fixture->supported_features = WT_MANIFEST_FEATURE_IPC |
                                  WT_MANIFEST_FEATURE_STATELESS;
}

static int wt_validate(const wt_manifest_fixture_t* fixture)
{
    return wt_manifest_validate(&fixture->manifest,
                                fixture->supported_features,
                                &fixture->capabilities);
}

static void wt_test_valid_manifest(void)
{
    wt_manifest_fixture_t fixture;

    wt_fixture_init(&fixture);
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_VALID);
}

static void wt_test_header(void)
{
    wt_manifest_fixture_t fixture;
    char long_name[WT_MANIFEST_NAME_MAX + 1U];

    EXPECT_RESULT(wt_manifest_validate(NULL, WT_MANIFEST_FEATURE_IPC, NULL),
                  WT_MANIFEST_ERROR_ARGUMENT);

    wt_fixture_init(&fixture);
    fixture.manifest.format_version++;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_FORMAT);

    wt_fixture_init(&fixture);
    fixture.manifest.generator_version = "bad-generator";
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_GENERATOR);

    wt_fixture_init(&fixture);
    (void)memset(long_name, 'A', sizeof(long_name));
    fixture.manifest.generator_version = long_name;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_GENERATOR);

    wt_fixture_init(&fixture);
    (void)memset(fixture.digest, 0, sizeof(fixture.digest));
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_DIGEST);

    wt_fixture_init(&fixture);
    fixture.manifest.input_digest_size--;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_DIGEST);

    wt_fixture_init(&fixture);
    fixture.manifest.input_digest = NULL;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_DIGEST);

    wt_fixture_init(&fixture);
    fixture.manifest.features = WT_MANIFEST_FEATURE_STATELESS;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_FEATURE);

    wt_fixture_init(&fixture);
    fixture.manifest.features |= (1U << 31);
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_FEATURE);

    wt_fixture_init(&fixture);
    fixture.manifest.features |= WT_MANIFEST_FEATURE_SFN;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_FEATURE);

    wt_fixture_init(&fixture);
    fixture.manifest.features |= WT_MANIFEST_FEATURE_MM_IOVEC;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_FEATURE);

    wt_fixture_init(&fixture);
    fixture.supported_features |= (1U << 31);
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_FEATURE);

    wt_fixture_init(&fixture);
    fixture.manifest.limits.max_partitions = 0U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_LIMIT);

    wt_fixture_init(&fixture);
    fixture.manifest.limits.max_partitions =
        WT_MANIFEST_MAX_PARTITIONS + 1U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_LIMIT);

    wt_fixture_init(&fixture);
    fixture.manifest.partition_count = 0U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_LIMIT);

    wt_fixture_init(&fixture);
    fixture.manifest.partitions = NULL;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_LIMIT);

    wt_fixture_init(&fixture);
    fixture.manifest.limits.max_stateless_handles = 31U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_LIMIT);

    wt_fixture_init(&fixture);
    fixture.manifest.limits.max_services_per_partition =
        WT_MANIFEST_MAX_SERVICES + 1U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_LIMIT);

    wt_fixture_init(&fixture);
    fixture.manifest.limits.max_dependencies_per_partition =
        WT_MANIFEST_MAX_DEPENDENCIES + 1U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_LIMIT);

    wt_fixture_init(&fixture);
    fixture.domains[1].entry_point = fixture.domains[1].stack_base;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_DOMAIN);

    wt_fixture_init(&fixture);
    fixture.manifest.profile_capabilities = NULL;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_ARGUMENT);

    wt_fixture_init(&fixture);
    fixture.manifest.domains = NULL;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_ARGUMENT);

    wt_fixture_init(&fixture);
    fixture.capabilities.capabilities &=
        ~WT_CAPABILITY_DOMAIN_ISOLATION;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_DOMAIN);
}

static void wt_test_partition(void)
{
    wt_manifest_fixture_t fixture;
    char long_name[WT_MANIFEST_NAME_MAX + 1U];

    wt_fixture_init(&fixture);
    fixture.partitions[0].name = "partition_alpha";
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_NAME);

    wt_fixture_init(&fixture);
    (void)memset(long_name, 'A', sizeof(long_name));
    fixture.partitions[0].name = long_name;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_NAME);

    wt_fixture_init(&fixture);
    fixture.partitions[0].domain_id = 99U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_PARTITION_ID);

    wt_fixture_init(&fixture);
    fixture.partitions[0].domain_id = 0U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_PARTITION_ID);

    wt_fixture_init(&fixture);
    fixture.partitions[0].domain_id = 2U;
    fixture.partitions[1].domain_id = 1U;
    fixture.interrupts[0].interrupt =
        fixture.domain_interrupts[2].interrupt;
    fixture.interrupts[1].interrupt =
        fixture.domain_interrupts[1].interrupt;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_VALID);

    wt_fixture_init(&fixture);
    fixture.partitions[0].framework_version = 0x0200U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_FRAMEWORK_VERSION);

    wt_fixture_init(&fixture);
    fixture.partitions[0].model = WT_PARTITION_MODEL_SFN;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_MODEL);

    wt_fixture_init(&fixture);
    fixture.partitions[1].model = WT_PARTITION_MODEL_SFN;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_FEATURE);

    wt_fixture_init(&fixture);
    fixture.manifest.features |= WT_MANIFEST_FEATURE_SFN;
    fixture.supported_features |= WT_MANIFEST_FEATURE_SFN;
    fixture.partitions[1].model = WT_PARTITION_MODEL_SFN;
    fixture.services[1].signal = 0U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_VALID);

    wt_fixture_init(&fixture);
    fixture.partitions[0].priority = (wt_partition_priority_t)99;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_PRIORITY);

    wt_fixture_init(&fixture);
    fixture.partitions[0].service_count = 0U;
    fixture.partitions[0].interrupt_count = 0U;
    fixture.domains[1].interrupt_resource_count = 0U;
    fixture.domains[1].interrupt_resources = NULL;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SERVICE);

    wt_fixture_init(&fixture);
    fixture.partitions[0].service_count = 0U;
    fixture.partitions[0].dependency_count = 0U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_VALID);

    wt_fixture_init(&fixture);
    fixture.manifest.limits.max_services_per_partition =
        WT_MANIFEST_MAX_SERVICES;
    fixture.partitions[0].service_count = WT_MANIFEST_MAX_SERVICES;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SIGNAL);

    wt_fixture_init(&fixture);
    fixture.partitions[0].services = NULL;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SERVICE);

    wt_fixture_init(&fixture);
    fixture.partitions[0].dependencies = NULL;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_DEPENDENCY);

    wt_fixture_init(&fixture);
    fixture.partitions[0].interrupts = NULL;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_INTERRUPT);

    wt_fixture_init(&fixture);
    fixture.manifest.partition_count = 1U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_PARTITION_ID);
}

static void wt_test_ffm_resource_ownership(void)
{
    wt_manifest_fixture_t fixture;
    size_t i;

    wt_fixture_init(&fixture);
    for (i = 1U; i < 3U; i++) {
        fixture.memory[i][2].base = 0xD000U;
        fixture.memory[i][2].size = 0x100U;
        fixture.memory[i][2].attributes =
            WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_WRITE |
            WT_MEMORY_ATTR_DEVICE | WT_MEMORY_ATTR_SHARED;
        fixture.memory[i][2].share_id = 7U;
        fixture.domains[i].memory_resource_count = 3U;
    }
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_RESOURCE_OWNERSHIP);

    wt_fixture_init(&fixture);
    fixture.domain_interrupts[2].interrupt =
        fixture.domain_interrupts[1].interrupt;
    fixture.domain_interrupts[1].attributes = WT_INTERRUPT_ATTR_SHARED;
    fixture.domain_interrupts[2].attributes = WT_INTERRUPT_ATTR_SHARED;
    fixture.domain_interrupts[1].share_id = 7U;
    fixture.domain_interrupts[2].share_id = 7U;
    fixture.interrupts[1].interrupt = fixture.interrupts[0].interrupt;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_RESOURCE_OWNERSHIP);
}

/* Isolation level 3 (WT-FFM-0011): a writable resource shared between two
 * partitions is refused at the manifest level; read-only sharing stays. */
static void wt_test_isolation_level_3(void)
{
    wt_manifest_fixture_t fixture;
    size_t i;

    wt_fixture_init(&fixture);
    for (i = 1U; i < 3U; i++) {
        fixture.memory[i][2].base = 0xD000U;
        fixture.memory[i][2].size = 0x1000U;
        fixture.memory[i][2].attributes =
            WT_MEMORY_ATTR_READ | WT_MEMORY_ATTR_SHARED;
        fixture.memory[i][2].share_id = 7U;
        fixture.domains[i].memory_resource_count = 3U;
    }
    EXPECT_RESULT(wt_validate(&fixture), WT_MANIFEST_VALID);

    for (i = 1U; i < 3U; i++) {
        fixture.memory[i][2].attributes |= WT_MEMORY_ATTR_WRITE;
    }
    EXPECT_RESULT(wt_validate(&fixture), WT_MANIFEST_ERROR_DOMAIN);
}

static void wt_test_service(void)
{
    wt_manifest_fixture_t fixture;
    wt_service_descriptor_t sfn_services[WT_MANIFEST_MAX_SERVICES];
    char sfn_names[WT_MANIFEST_MAX_SERVICES][24];
    size_t i;

    wt_fixture_init(&fixture);
    fixture.services[0].name = "SERVICE-alpha";
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_NAME);

    wt_fixture_init(&fixture);
    fixture.services[0].sid = 0U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SERVICE_ID);

    wt_fixture_init(&fixture);
    fixture.services[0].version = 0U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SERVICE_VERSION);

    wt_fixture_init(&fixture);
    fixture.services[0].version_policy =
        (wt_service_version_policy_t)99;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SERVICE_VERSION);

    wt_fixture_init(&fixture);
    fixture.services[0].nonsecure_clients = 2U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SERVICE);

    wt_fixture_init(&fixture);
    fixture.services[0].connection_based = 0U;
    fixture.services[0].stateless_handle_index = 2U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SERVICE);

    wt_fixture_init(&fixture);
    fixture.services[0].stateless_handle_index = 2U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_STATELESS_HANDLE);

    wt_fixture_init(&fixture);
    fixture.manifest.features = WT_MANIFEST_FEATURE_IPC;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_FEATURE);

    wt_fixture_init(&fixture);
    fixture.services[1].stateless_handle_index = 0U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_STATELESS_HANDLE);

    wt_fixture_init(&fixture);
    fixture.services[1].stateless_handle_index = 33U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_STATELESS_HANDLE);

    wt_fixture_init(&fixture);
    fixture.services[0].signal = WT_MANIFEST_RESERVED_SIGNALS;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SIGNAL);

    wt_fixture_init(&fixture);
    fixture.services[0].signal = 0x30U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SIGNAL);

    wt_fixture_init(&fixture);
    fixture.partitions[0].service_count = 2U;
    fixture.partitions[0].dependency_count = 0U;
    fixture.partitions[1].service_count = 0U;
    fixture.services[1].connection_based = 1U;
    fixture.services[1].stateless_handle_index = 0U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SIGNAL);

    wt_fixture_init(&fixture);
    fixture.partitions[0].framework_version = WT_FFM_VERSION_1_1;
    fixture.services[0].connection_based = 0U;
    fixture.services[0].stateless_handle_index =
        fixture.services[1].stateless_handle_index;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_STATELESS_HANDLE);

    wt_fixture_init(&fixture);
    fixture.manifest.features |= WT_MANIFEST_FEATURE_SFN;
    fixture.supported_features |= WT_MANIFEST_FEATURE_SFN;
    fixture.partitions[0].framework_version = WT_FFM_VERSION_1_1;
    fixture.partitions[0].model = WT_PARTITION_MODEL_SFN;
    fixture.partitions[0].service_count = 2U;
    fixture.partitions[0].dependency_count = 0U;
    fixture.partitions[1].service_count = 0U;
    fixture.services[0].signal = 0U;
    fixture.services[1].signal = 0U;
    fixture.services[1].connection_based = 1U;
    fixture.services[1].stateless_handle_index = 0U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_VALID);

    wt_fixture_init(&fixture);
    (void)memset(sfn_services, 0, sizeof(sfn_services));
    fixture.manifest.features |= WT_MANIFEST_FEATURE_SFN;
    fixture.supported_features |= WT_MANIFEST_FEATURE_SFN;
    fixture.partitions[0].framework_version = WT_FFM_VERSION_1_1;
    fixture.partitions[0].model = WT_PARTITION_MODEL_SFN;
    fixture.partitions[0].services = sfn_services;
    fixture.partitions[0].service_count = WT_MANIFEST_MAX_SERVICES;
    fixture.partitions[0].dependency_count = 0U;
    fixture.partitions[1].service_count = 0U;
    fixture.manifest.limits.max_services_per_partition =
        WT_MANIFEST_MAX_SERVICES;
    for (i = 0U; i < WT_MANIFEST_MAX_SERVICES; i++) {
        (void)snprintf(sfn_names[i], sizeof(sfn_names[i]),
                       "SFN_SERVICE_%u", (unsigned int)i);
        sfn_services[i].name = sfn_names[i];
        sfn_services[i].sid = 0x3000U + (uint32_t)i;
        sfn_services[i].version = 1U;
        sfn_services[i].version_policy = WT_SERVICE_VERSION_STRICT;
        sfn_services[i].connection_based = 1U;
    }
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_VALID);
}

static void wt_test_interrupt(void)
{
    wt_manifest_fixture_t fixture;

    wt_fixture_init(&fixture);
    fixture.interrupts[0].signal_name = "alpha_irq";
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SIGNAL);

    wt_fixture_init(&fixture);
    fixture.interrupts[0].interrupt++;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_INTERRUPT);

    wt_fixture_init(&fixture);
    fixture.interrupts[0].signal = fixture.services[0].signal;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SIGNAL);

    wt_fixture_init(&fixture);
    fixture.partitions[0].interrupt_count = 0U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_INTERRUPT);

    /* A Non-secure application that declares a peripheral interrupt is
     * refused: the dispatcher would unmask it before the guest's NS bank is
     * reinstated. */
    wt_fixture_init(&fixture);
    fixture.domains[2].domain_class = WT_DOMAIN_CLASS_NONSECURE_APPLICATION;
    fixture.domains[2].rot_role = WT_ROT_ROLE_NONE;
    fixture.domains[2].security_state = WT_SECURITY_STATE_NONSECURE;
    fixture.domains[2].privilege_state = WT_PRIVILEGE_STATE_UNPRIVILEGED;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_INTERRUPT);
}

static void wt_test_uniqueness(void)
{
    wt_manifest_fixture_t fixture;

    wt_fixture_init(&fixture);
    fixture.partitions[1].name = fixture.partitions[0].name;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_PARTITION_ID);

    wt_fixture_init(&fixture);
    fixture.partitions[1].domain_id = fixture.partitions[0].domain_id;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_PARTITION_ID);

    wt_fixture_init(&fixture);
    fixture.services[1].name = fixture.services[0].name;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SERVICE_ID);

    wt_fixture_init(&fixture);
    fixture.services[1].sid = fixture.services[0].sid;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SERVICE_ID);
}

static void wt_test_generated_symbols(void)
{
    wt_manifest_fixture_t fixture;

    wt_fixture_init(&fixture);
    fixture.services[0].name = "SERVICE_BETA_SID";
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_VALID);

    wt_fixture_init(&fixture);
    fixture.partitions[0].name = "SERVICE_BETA_SID";
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SYMBOL);

    wt_fixture_init(&fixture);
    fixture.interrupts[0].signal_name = "SERVICE_ALPHA_SIGNAL";
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SYMBOL);

    wt_fixture_init(&fixture);
    fixture.interrupts[1].signal_name = "SERVICE_BETA_HANDLE";
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SYMBOL);

    wt_fixture_init(&fixture);
    fixture.interrupts[1].signal_name = fixture.interrupts[0].signal_name;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SYMBOL);

    wt_fixture_init(&fixture);
    fixture.interrupts[0].signal_name = fixture.partitions[1].name;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SYMBOL);

    wt_fixture_init(&fixture);
    fixture.interrupts[0].signal_name = "PARTITION_BETA_MODEL_IPC";
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SYMBOL);

    wt_fixture_init(&fixture);
    fixture.interrupts[0].signal_name = "PARTITION_BETA_MODEL_SFN";
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SYMBOL);

    wt_fixture_init(&fixture);
    fixture.partitions[0].name = "PARTITION_BETA_MODEL_IPC";
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_SYMBOL);
}

static void wt_test_dependencies(void)
{
    wt_manifest_fixture_t fixture;

    wt_fixture_init(&fixture);
    fixture.dependencies[0][0] = 0U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_DEPENDENCY);

    wt_fixture_init(&fixture);
    fixture.dependencies[0][0] = 0x9999U;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_DEPENDENCY);

    wt_fixture_init(&fixture);
    fixture.dependencies[0][0] = fixture.services[0].sid;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_DEPENDENCY);

    wt_fixture_init(&fixture);
    fixture.partitions[0].dependency_count = 2U;
    fixture.dependencies[0][1] = fixture.dependencies[0][0];
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_DEPENDENCY);

    wt_fixture_init(&fixture);
    fixture.partitions[1].dependencies = fixture.dependencies[1];
    fixture.partitions[1].dependency_count = 1U;
    fixture.dependencies[1][0] = fixture.services[0].sid;
    EXPECT_RESULT(wt_validate(&fixture),
                  WT_MANIFEST_ERROR_DEPENDENCY_CYCLE);
}

int main(void)
{
    wt_test_valid_manifest();
    wt_test_header();
    wt_test_partition();
    wt_test_ffm_resource_ownership();
    wt_test_isolation_level_3();
    wt_test_service();
    wt_test_interrupt();
    wt_test_uniqueness();
    wt_test_generated_symbols();
    wt_test_dependencies();

    if (g_failures != 0U) {
        (void)fprintf(stderr, "%u of %u manifest checks failed\n",
                      g_failures, g_checks);
        return 1;
    }

    (void)printf("manifest checks passed: %u\n", g_checks);
    return 0;
}
