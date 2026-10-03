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

/* Portable bare-metal PSA test guest: the Non-secure client lifecycle the
 * STM32H563 Zephyr guest runs, on no operating system, so every port can
 * prove the same PSA behaviour from a guest that needs only a linker window
 * and a console. Crypto rides wolfPSA over the SPM-mediated client, storage
 * and attestation ride the OS-neutral FF-M clients, and each milestone prints
 * one marker line prefixed with the guest's name. The same source links into
 * both guest windows. */

#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#include <stdint.h>
void wt_os_assert(void);

#define configENABLE_MPU                          0
#define configENABLE_FPU                          0
#define configENABLE_TRUSTZONE                    0

#define configUSE_PREEMPTION                      1
#define configUSE_TIME_SLICING                    1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION   0
#define configMAX_PRIORITIES                      4
#define configIDLE_SHOULD_YIELD                   1
#define configUSE_16_BIT_TICKS                    0

#define configCPU_CLOCK_HZ                        237500000u
#define configTICK_RATE_HZ                        100u
/* Leave configSYSTICK_CLOCK_HZ undefined: the CM33 port then selects the
 * core clock. Defining it selects the reference clock, which is stopped
 * on the RT700 board even when its stated frequency equals the core. */

#define configTOTAL_HEAP_SIZE                     ( (size_t) ( 64 * 1024 ) )
#define configSUPPORT_DYNAMIC_ALLOCATION          1
#define configSUPPORT_STATIC_ALLOCATION           0
#define configMINIMAL_STACK_SIZE                  ( (uint16_t) 256 )
#define configMAX_TASK_NAME_LEN                   12

#define configUSE_MUTEXES                         1
#define configUSE_TICKLESS_IDLE                   0
#define configUSE_APPLICATION_TASK_TAG            0
#define configUSE_NEWLIB_REENTRANT                0
#define configUSE_CO_ROUTINES                     0
#define configUSE_COUNTING_SEMAPHORES             0
#define configUSE_RECURSIVE_MUTEXES               0
#define configUSE_QUEUE_SETS                      0
#define configUSE_TASK_NOTIFICATIONS              1
#define configUSE_TRACE_FACILITY                  0
#define configUSE_IDLE_HOOK                       0
#define configUSE_TICK_HOOK                       0
#define configCHECK_FOR_STACK_OVERFLOW            0
#define configUSE_MALLOC_FAILED_HOOK              0

#define configUSE_TIMERS                          0

#define INCLUDE_vTaskPrioritySet                  0
#define INCLUDE_uxTaskPriorityGet                 0
#define INCLUDE_vTaskDelete                       1
#define INCLUDE_vTaskSuspend                      1
#define INCLUDE_vTaskDelayUntil                   0
#define INCLUDE_vTaskDelay                        1
#define INCLUDE_xTaskGetSchedulerState            0
#define INCLUDE_xTaskGetCurrentTaskHandle         0

#define configPRIO_BITS                           3
#define configLIBRARY_LOWEST_INTERRUPT_PRIORITY   ((1 << configPRIO_BITS) - 1)
#define configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY  2
#define configKERNEL_INTERRUPT_PRIORITY \
    (configLIBRARY_LOWEST_INTERRUPT_PRIORITY << (8 - configPRIO_BITS))
#define configMAX_SYSCALL_INTERRUPT_PRIORITY \
    (configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY << (8 - configPRIO_BITS))

#define vPortSVCHandler                           SVC_Handler
#define xPortPendSVHandler                        PendSV_Handler
#define xPortSysTickHandler                       SysTick_Handler

#define configASSERT( x ) do { if (!(x)) { wt_os_assert(); } } while (0)

#endif
