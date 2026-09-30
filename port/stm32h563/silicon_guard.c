/* silicon_guard.c
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

#include <stdint.h>

#include "wolftrust/platform.h"

#include "silicon_rev.h"
#include "stm32h563_regs.h"

static void wt_silicon_putc(char c)
{
    while ((WT_USART_ISR(WT_USART3_BASE_NS) & WT_USART_ISR_TXE) == 0u) {
    }
    WT_USART_TDR(WT_USART3_BASE_NS) = (uint32_t)(uint8_t)c;
}

static void wt_silicon_puts(const char* s)
{
    while (*s != '\0') {
        wt_silicon_putc(*s);
        s++;
    }
}

static void wt_silicon_puthex(uint32_t value)
{
    static const char digits[] = "0123456789ABCDEF";
    int shift;

    for (shift = 28; shift >= 0; shift -= 4) {
        wt_silicon_putc(digits[(value >> (uint32_t)shift) & 0xFu]);
    }
}

void wt_h563_silicon_guard(void)
{
    uint32_t idcode = WT_DBGMCU_IDCODE;
    int verdict = wt_h563_silicon_check(idcode);

    if (verdict != WT_H563_SILICON_OK) {
        /* USART3 is the NUCLEO VCP; the guests have not configured it yet. */
        WT_USART_CR1(WT_USART3_BASE_NS) = 0u;
        WT_USART_BRR(WT_USART3_BASE_NS) =
            WT_STM32H563_APB1_CLOCK_HZ / 115200u;
        WT_USART_CR1(WT_USART3_BASE_NS) = WT_USART_CR1_UE | WT_USART_CR1_TE;
        if (verdict == WT_H563_SILICON_ERRATA) {
            wt_silicon_puts("wolfTrust: halt, STM32H563 engineering sample "
                            "(ES0565 2.2.9) IDCODE 0x");
        }
        else {
            wt_silicon_puts("wolfTrust: halt, unsupported silicon IDCODE 0x");
        }
        wt_silicon_puthex(idcode);
        wt_silicon_puts("\r\n");
        while ((WT_USART_ISR(WT_USART3_BASE_NS) & WT_USART_ISR_TC) == 0u) {
        }
        wt_platform_panic();
    }
}
