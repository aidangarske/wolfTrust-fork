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

/* RT700 Zephyr guest0 runs the shared PSA lifecycle and two timer tasks. */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/printk-hooks.h>
#include <stdint.h>

extern void wt_guest_lifecycle(void);
extern int wt_guest_timer_crypto(void);
volatile uint32_t g_os_progress[8];
static K_THREAD_STACK_DEFINE(timer_stack, 2048);
static struct k_thread timer_thread;

static int guest_console(int c)
{
    volatile uint32_t *stat = (volatile uint32_t *)0x40110014u;
    volatile uint32_t *data = (volatile uint32_t *)0x4011001cu;
    uint32_t guard = 100000u;

    while ((*stat & 0x00800000u) == 0u && guard > 0u) {
        guard--;
    }
    if (guard != 0u) {
        *data = (uint32_t)(uint8_t)c;
    }
    return c;
}

static void timer_task(void *a, void *b, void *c)
{
    int64_t start = k_uptime_get();
    int64_t before;
    int64_t elapsed;
    uint32_t n;

    (void)a; (void)b; (void)c;
    for (n = 1u; n <= 10u; n++) {
        before = k_uptime_get();
        k_sleep(K_MSEC(100));
        elapsed = k_uptime_get() - before;
        if (elapsed < 100 || k_uptime_get() - start > 30000) {
            g_os_progress[3]++;
        }
        g_os_progress[1] = n;
        printk("guest0: Zephyr timer B wake=%u elapsed_ms=%lld\n",
               n, (long long)elapsed);
    }
    g_os_progress[7] = (uint32_t)(k_uptime_get() - start);
    for (;;) {
        k_sleep(K_MSEC(100));
        g_os_progress[4]++;
    }
}

int main(void)
{
    int64_t start;
    int64_t before;
    int64_t elapsed;
    uint32_t n;

    __printk_hook_install(guest_console);
    g_os_progress[5] = 0x5a455048u;
    printk("guest0: Zephyr kernel running\n");
    k_thread_create(&timer_thread, timer_stack,
                    K_THREAD_STACK_SIZEOF(timer_stack), timer_task,
                    NULL, NULL, NULL, 5, 0, K_NO_WAIT);
    wt_guest_lifecycle();
    start = k_uptime_get();
    for (n = 1u; n <= 10u; n++) {
        before = k_uptime_get();
        k_sleep(K_MSEC(100));
        elapsed = k_uptime_get() - before;
        if (elapsed < 100 || k_uptime_get() - start > 30000) {
            g_os_progress[3]++;
        }
        if (wt_guest_timer_crypto()) {
            g_os_progress[6]++;
        }
        else {
            g_os_progress[3]++;
        }
        g_os_progress[0] = n;
        printk("guest0: Zephyr timer A wake=%u elapsed_ms=%lld\n",
               n, (long long)elapsed);
    }
    g_os_progress[2] = (uint32_t)(k_uptime_get() - start);
    printk("guest0: Zephyr timers done errors=%u\n", g_os_progress[3]);
    for (;;) {
        k_sleep(K_MSEC(100));
        g_os_progress[4]++;
    }
}
