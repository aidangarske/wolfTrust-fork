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

/* RT700 FreeRTOS guest1 runs the shared PSA lifecycle and two timer tasks. */

#include <stdint.h>
#include <stddef.h>
#include "FreeRTOS.h"
#include "task.h"
#include "board.h"
extern void wt_guest_lifecycle(void);
extern int wt_guest_timer_crypto(void);
volatile uint32_t g_os_progress[8];
extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _estack;

/* ---- vector table + reset path ---------------------------------------- */

static void default_handler(void)
{
    for (;;) {}
}

void Reset_Handler(void);
void NMI_Handler(void) __attribute__((weak, alias("default_handler")));
void HardFault_Handler(void) __attribute__((weak, alias("default_handler")));
void MemManage_Handler(void) __attribute__((weak, alias("default_handler")));
void BusFault_Handler(void) __attribute__((weak, alias("default_handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("default_handler")));

/* FreeRTOS provides these as `vPortSVCHandler` / `xPortPendSVHandler`
 * / `xPortSysTickHandler`; FreeRTOSConfig.h aliases them onto the
 * standard CMSIS exception-vector names, so we wire them directly here. */
void SVC_Handler(void);
void PendSV_Handler(void);
void SysTick_Handler(void);

void DebugMon_Handler(void) __attribute__((weak, alias("default_handler")));

__attribute__((section(".vectors")))
const uint32_t g_vectors[16] = {
    [0]  = (uint32_t)&_estack,
    [1]  = (uint32_t)&Reset_Handler,
    [2]  = (uint32_t)&NMI_Handler,
    [3]  = (uint32_t)&HardFault_Handler,
    [4]  = (uint32_t)&MemManage_Handler,
    [5]  = (uint32_t)&BusFault_Handler,
    [6]  = (uint32_t)&UsageFault_Handler,
    [11] = (uint32_t)&SVC_Handler,
    [12] = (uint32_t)&DebugMon_Handler,
    [14] = (uint32_t)&PendSV_Handler,
    [15] = (uint32_t)&SysTick_Handler,
};

static void copy_data(void)
{
    uint32_t *src = &_sidata, *dst = &_sdata;
    while (dst < &_edata) {
        *dst++ = *src++;
    }
}

static void zero_bss(void)
{
    uint32_t *dst = &_sbss;
    while (dst < &_ebss) {
        *dst++ = 0u;
    }
}


static void line(const char *s)
{
    while (*s != '\0') {
        guest_board_uart_putc(*s++);
    }
}

static void number(uint32_t n)
{
    char digits[10];
    unsigned int used = 0;

    do {
        digits[used++] = (char)('0' + n % 10u);
        n /= 10u;
    } while (n != 0u);
    while (used > 0u) {
        guest_board_uart_putc(digits[--used]);
    }
}

void wt_os_assert(void)
{
    line("guest1: FreeRTOS assertion failed\r\n");
    for (;;) {}
}

static void run_timer(unsigned int task)
{
    TickType_t start = xTaskGetTickCount();
    TickType_t before;
    TickType_t elapsed;
    unsigned int n;

    for (n = 1u; n <= 10u; n++) {
        before = xTaskGetTickCount();
        vTaskDelay(pdMS_TO_TICKS(100));
        elapsed = xTaskGetTickCount() - before;
        if (elapsed < pdMS_TO_TICKS(100) ||
            xTaskGetTickCount() - start > pdMS_TO_TICKS(30000)) {
            g_os_progress[3]++;
        }
        if (task == 0u) {
            if (wt_guest_timer_crypto()) {
                g_os_progress[6]++;
            }
            else {
                g_os_progress[3]++;
            }
        }
        g_os_progress[task] = n;
        line(task == 0u ? "guest1: FreeRTOS timer A wake=" :
                          "guest1: FreeRTOS timer B wake=");
        number(n);
        line(" elapsed_ms=");
        number(elapsed * 1000u / configTICK_RATE_HZ);
        line("\r\n");
    }
    if (task == 1u) {
        g_os_progress[7] = (xTaskGetTickCount() - start) * 1000u /
                           configTICK_RATE_HZ;
    }
    if (task == 0u) {
        g_os_progress[2] = (xTaskGetTickCount() - start) * 1000u /
                           configTICK_RATE_HZ;
        line("guest1: FreeRTOS timers done errors=");
        number(g_os_progress[3]);
        line("\r\n");
    }
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(100));
        g_os_progress[4]++;
    }
}

static void critical_section_probe(void)
{
    uint32_t before;
    uint32_t after;
    volatile uint32_t loops;

    taskENTER_CRITICAL();
    __asm volatile("mrs %0, basepri" : "=r"(before));
    line("guest1: FreeRTOS critical start\r\n");
    for (loops = 0u; loops < 12000000u; loops++) {
        __asm volatile("nop");
    }
    __asm volatile("mrs %0, basepri" : "=r"(after));
    if (before != configMAX_SYSCALL_INTERRUPT_PRIORITY || after != before) {
        g_os_progress[3]++;
    }
    taskEXIT_CRITICAL();
    line("guest1: FreeRTOS critical end errors=");
    number(g_os_progress[3]);
    line("\r\n");
}

static void crypto_task(void *arg)
{
    (void)arg;
    wt_guest_lifecycle();
    critical_section_probe();
    run_timer(0u);
}

static void timer_task(void *arg)
{
    (void)arg;
    run_timer(1u);
}

void Reset_Handler(void)
{
    copy_data();
    zero_bss();
    g_os_progress[5] = 0x46524545u;
    line("guest1: FreeRTOS kernel running\r\n");
    if (xTaskCreate(crypto_task, "crypto", 6144, NULL, 1, NULL) != pdPASS ||
        xTaskCreate(timer_task, "timer", 512, NULL, 1, NULL) != pdPASS) {
        wt_os_assert();
    }
    vTaskStartScheduler();
    wt_os_assert();
}
