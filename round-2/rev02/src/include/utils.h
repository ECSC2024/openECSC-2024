//
// Created by Andrea Raineri on 21/12/23.
//

#ifndef UTILS_H
#define UTILS_H

#include "hw_memmap.h"
#include "hw_types.h"
#include "hw_sysctl.h"
#include "hw_uart.h"
#include "sysctl.h"
#include "gpio.h"
#include "grlib.h"
#include "osram128x64x4.h"
#include "uart.h"

#include <stddef.h>

static void print(const char *src) {
    if (src == NULL || *src == 0) {
        UARTCharPut(UART0_BASE, '\n');
        return;
    }
    while (*src != 0x00) {
        UARTCharPut(UART0_BASE, *src);
        src++;
    }
}

static void input(const char *prompt, char *dst, int size) {
    print(prompt);
    char *p = dst;
    char c = (char)UARTCharGet(UART0_BASE);
    while ((size == -1 || (p - dst) < size) && UARTCharsAvail(UART0_BASE)) {
        *(p++) = c;
        c = (char) UARTCharGet(UART0_BASE);
    }
    *p = 0;
}

#endif //UTILS_H
