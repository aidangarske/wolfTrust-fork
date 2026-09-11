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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* WT-FFM-0011: the Level 3 profile gives every Secure Partition a distinct
 * protection domain whose private data is inaccessible to other partitions.
 * These tests exercise the architecture-neutral policy half: the resolver
 * that derives a partition's private region set from the manifest and the
 * predicate that proves a foreign domain's memory is excluded. */

#include "wolftrust/ffm_domain.h"

#include <stdio.h>

#define SP1_FLASH_BASE 0x08090000U
#define SP1_FLASH_SIZE 0x00020000U
#define SP1_RAM_BASE   0x20000000U
#define SP1_RAM_SIZE   0x00008000U
#define SP2_RAM_BASE   0x20008000U
#define SP2_RAM_SIZE   0x00008000U
#define SEC_CODE_BASE  0x0C000000U
#define SEC_CODE_SIZE  0x00060000U
#define PPB_MPU_CTRL   0xE000ED94U

static const wt_memory_resource_t sp1_memory[2] = {
    {SP1_FLASH_BASE, SP1_FLASH_SIZE, WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC, 0U},
    {SP1_RAM_BASE, SP1_RAM_SIZE,
     WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_RESTART_CLEAR, 0U}
};

static const wt_memory_resource_t sp2_memory[1] = {
    {SP2_RAM_BASE, SP2_RAM_SIZE, WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE, 0U}
};

static const wt_memory_resource_t overflow_memory[1] = {
    {0U, SP1_RAM_SIZE, WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE, 0U}
};

static const wt_domain_descriptor_t domains[5] = {
    {
        .id = 0U,
        .domain_class = WT_DOMAIN_CLASS_SPM,
        .security_state = WT_SECURITY_STATE_SECURE
    },
    {
        .id = 1U,
        .domain_class = WT_DOMAIN_CLASS_SECURE_PARTITION,
        .security_state = WT_SECURITY_STATE_SECURE,
        .memory_resources = sp1_memory,
        .memory_resource_count = 2U
    },
    {
        .id = 2U,
        .domain_class = WT_DOMAIN_CLASS_SECURE_PARTITION,
        .security_state = WT_SECURITY_STATE_SECURE,
        .memory_resources = sp2_memory,
        .memory_resource_count = 1U
    },
    {
        .id = 3U,
        .domain_class = WT_DOMAIN_CLASS_NONSECURE_APPLICATION,
        .security_state = WT_SECURITY_STATE_NONSECURE,
        .memory_resources = sp1_memory,
        .memory_resource_count = 2U
    },
    {
        /* Advertises more regions than the MPU can hold: must fail closed. */
        .id = 4U,
        .domain_class = WT_DOMAIN_CLASS_SECURE_PARTITION,
        .security_state = WT_SECURITY_STATE_SECURE,
        .memory_resources = overflow_memory,
        .memory_resource_count = WT_MAX_MEMORY_REGIONS + 1U
    }
};

static const wt_system_manifest_t manifest = {
    .domains = domains,
    .domain_count = 5U
};

static int failures;

static void check(int ok, const char* what)
{
    if (ok) {
        (void)printf("WT-FFM-0011 PASS %s\n", what);
    }
    else {
        (void)printf("WT-FFM-0011 FAIL %s\n", what);
        failures++;
    }
}

static const wt_memory_region_t secure_code[1] = {
    {SEC_CODE_BASE, SEC_CODE_SIZE, WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC}
};

int main(void)
{
    wt_secure_domain_t sp1;
    wt_secure_domain_t sp2;
    wt_secure_domain_t scratch;
    wt_secure_domain_t table;
    int result;

    /* A Secure Partition resolves to exactly its declared private regions. */
    result = wt_ffm_resolve_secure_domain(&manifest, 1U, &sp1);
    check(result == WT_SECURE_DOMAIN_OK, "resolve secure partition 1");
    check(sp1.region_count == 2U, "partition 1 region count");
    check(sp1.domain_id == 1U, "partition 1 domain id");
    /* The fault scrub records the declared restart-clear band from the
     * resolved attributes, so resolution must not strip the flag. */
    check((sp1.regions[1].attributes & WT_MEM_ATTR_RESTART_CLEAR) != 0U,
          "restart-clear survives domain resolution");

    result = wt_ffm_resolve_secure_domain(&manifest, 2U, &sp2);
    check(result == WT_SECURE_DOMAIN_OK, "resolve secure partition 2");

    /* Own regions are reachable with the permissions they were granted. */
    check(wt_secure_domain_contains(&sp1, SP1_RAM_BASE, 4U, 1) == 1,
          "partition 1 owns its RW RAM");
    check(wt_secure_domain_contains(&sp1, SP1_FLASH_BASE, 4U, 0) == 1,
          "partition 1 reads its RX flash");
    check(wt_secure_domain_contains(&sp1, SP1_FLASH_BASE, 4U, 1) == 0,
          "partition 1 cannot write its RX flash");

    /* Cross-domain isolation: partition 1 cannot reach partition 2's RAM. */
    check(wt_secure_domain_contains(&sp1, SP2_RAM_BASE, 4U, 0) == 0,
          "partition 1 excludes partition 2 RAM");
    check(wt_secure_domain_contains(&sp2, SP1_RAM_BASE, 4U, 0) == 0,
          "partition 2 excludes partition 1 RAM");

    /* A span that starts inside a region but runs past its end is rejected. */
    check(wt_secure_domain_contains(&sp1, SP1_RAM_BASE + SP1_RAM_SIZE - 2U,
                                    4U, 1) == 0,
          "partition 1 rejects span past region end");

    /* Zero length and address overflow are rejected. */
    check(wt_secure_domain_contains(&sp1, SP1_RAM_BASE, 0U, 0) == 0,
          "zero length rejected");
    check(wt_secure_domain_contains(&sp1, (uintptr_t)-1, 8U, 0) == 0,
          "address overflow rejected");

    /* Fail closed: SPM, Non-secure, unknown, oversized, and bad arguments
     * all resolve to an empty domain. */
    result = wt_ffm_resolve_secure_domain(&manifest, 0U, &scratch);
    check(result == WT_SECURE_DOMAIN_ERROR_CLASS, "SPM is not a partition");
    check(scratch.region_count == 0U, "SPM leaves empty domain");

    result = wt_ffm_resolve_secure_domain(&manifest, 3U, &scratch);
    check(result == WT_SECURE_DOMAIN_ERROR_CLASS,
          "non-secure application is not a partition");

    result = wt_ffm_resolve_secure_domain(&manifest, 4U, &scratch);
    check(result == WT_SECURE_DOMAIN_ERROR_CAPACITY,
          "oversized region set rejected");
    check(scratch.region_count == 0U, "oversized leaves empty domain");

    result = wt_ffm_resolve_secure_domain(&manifest, 99U, &scratch);
    check(result == WT_SECURE_DOMAIN_ERROR_NOT_FOUND, "unknown domain id");

    result = wt_ffm_resolve_secure_domain(NULL, 1U, &scratch);
    check(result == WT_SECURE_DOMAIN_ERROR_ARGUMENT, "null manifest rejected");

    result = wt_ffm_resolve_secure_domain(&manifest, 1U, NULL);
    check(result == WT_SECURE_DOMAIN_ERROR_ARGUMENT, "null output rejected");

    /* Composing a partition's secure MPU table: shared code plus its own
     * private regions, and nothing else. */
    result = wt_ffm_compose_secure_partition_table(&sp1, secure_code, 1U,
                                                   &table);
    check(result == WT_SECURE_DOMAIN_OK, "compose partition 1 table");
    check(table.region_count == 3U, "table holds code plus SP regions");
    check(wt_secure_domain_contains(&table, SEC_CODE_BASE, 4U, 0) == 1,
          "table maps secure code for execution");
    check(wt_secure_domain_contains(&table, SP1_RAM_BASE, 4U, 1) == 1,
          "table maps partition 1 private RAM");
    check(wt_secure_domain_contains(&table, SP2_RAM_BASE, 4U, 0) == 0,
          "table excludes partition 2 RAM");
    check(wt_secure_domain_contains(&table, PPB_MPU_CTRL, 4U, 1) == 0,
          "table excludes the MPU control block");

    /* No shared regions is allowed; a null shared with a count is not. */
    result = wt_ffm_compose_secure_partition_table(&sp1, NULL, 0U, &table);
    check(result == WT_SECURE_DOMAIN_OK, "compose with no shared regions");
    result = wt_ffm_compose_secure_partition_table(&sp1, NULL, 1U, &table);
    check(result == WT_SECURE_DOMAIN_ERROR_ARGUMENT,
          "null shared with count rejected");

    /* Overflowing the MPU fails closed with an empty table. */
    result = wt_ffm_compose_secure_partition_table(&sp1, secure_code,
        WT_MAX_MEMORY_REGIONS, &table);
    check(result == WT_SECURE_DOMAIN_ERROR_CAPACITY,
          "oversized composition rejected");
    check(table.region_count == 0U, "oversized composition leaves empty");

    if (failures != 0) {
        (void)printf("FAIL: ffm_domain (%d)\n", failures);
        return 1;
    }
    (void)printf("PASS: ffm_domain\n");
    return 0;
}
