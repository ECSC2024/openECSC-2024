#ifndef ARXELERATED_COPROCESSOR_H
#define ARXELERATED_COPROCESSOR_H

#include "utils.h"
#include <stdint-gcc.h>

__attribute__((__always_inline__))
static void _prepare_registers(uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3) {
    asm ("mov r0, %0\n" ::"r"(r0));
    asm ("mov r1, %0\n" ::"r"(r1));
    asm ("mov r2, %0\n" ::"r"(r2));
    asm ("mov r3, %0\n" ::"r"(r3));
}

__attribute__((__always_inline__))
static void LOAD_KEY(uint32_t k0, uint32_t k1, uint32_t k2, uint32_t k3) {
    _prepare_registers(k0, k1, k2, k3);
    asm (".short 0xde00\n");
}

__attribute__((__always_inline__))
static void LOAD_64(uint32_t srcx, uint32_t srcy, uint32_t r2, uint32_t r3) {
    _prepare_registers(srcx, srcy, r2, r3);
    asm (".short 0xde01\n");
}

__attribute__((__always_inline__))
static void STORE_64(uint32_t dstx, uint32_t dsty, uint32_t r2, uint32_t r3) {
    _prepare_registers(dstx, dsty, r2, r3);
    asm (".short 0xde02\n");
}

__attribute__((__always_inline__))
static void ADD_KEY(uint32_t round, uint32_t r1, uint32_t r2, uint32_t r3) {
    _prepare_registers(round, r1, r2, r3);
    asm (".short 0xde03\n");
}

__attribute__((__always_inline__))
static void ALZETTE(uint32_t round, uint32_t r1, uint32_t r2, uint32_t r3) {
    _prepare_registers(round, r1, r2, r3);
    asm (".short 0xde04\n");
}
#endif //ARXELERATED_COPROCESSOR_H
