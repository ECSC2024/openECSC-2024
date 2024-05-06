#include "include/coprocessor.h"
#include <stdint-gcc.h>

#define ROT(x, n) (((x) >> (n)) | ((x) << (32-(n))))

#define ALZETTE_(x, y, c)                    \
  (x) += ROT((y), 31), (y) ^= ROT((x), 24), \
  (x) ^= (c),                               \
  (x) += ROT((y), 17), (y) ^= ROT((x), 17), \
  (x) ^= (c),                               \
  (x) += (y),          (y) ^= ROT((x), 31), \
  (x) ^= (c),                               \
  (x) += ROT((y), 24), (y) ^= ROT((x), 16), \
  (x) ^= (c)

static const uint32_t RCON[5] = {                             \
  0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB };

typedef void(*COPROCESSOR_HANDLER_Type)(uint32_t, uint32_t, uint32_t, uint32_t);

static void coprocessor_int00(uint32_t, uint32_t, uint32_t, uint32_t);
static void coprocessor_int01(uint32_t, uint32_t, uint32_t, uint32_t);
static void coprocessor_int02(uint32_t, uint32_t, uint32_t, uint32_t);
static void coprocessor_int03(uint32_t, uint32_t, uint32_t, uint32_t);
static void coprocessor_int04(uint32_t, uint32_t, uint32_t, uint32_t);

volatile const COPROCESSOR_HANDLER_Type __COPROCESSOR_HANDLER_TABLE[6] = {
        coprocessor_int00,
        coprocessor_int01,
        coprocessor_int02,
        coprocessor_int03,
        coprocessor_int04
};

struct CRYPTO_ARXELERATOR_STATE {
        uint32_t x, y;
        uint32_t key[4];
} state;

__attribute__((__noreturn__))
void UsageFault_Handler(void) {
    __asm (
        " tst lr, #4                                                \n"
        " ite eq                                                    \n"
        " mrseq r0, msp                                             \n"
        " mrsne r0, psp                                             \n"
        " ldr r1, [r0, #24]                                         \n"
        " b coprocessor_dispatch                                    \n"
        );
}

__attribute__((__noinline__))
void coprocessor_dispatch( uint32_t *pulFaultStackAddress )
{
    volatile uint32_t *r0;
    volatile uint32_t *r1;
    volatile uint32_t *r2;
    volatile uint32_t *r3;
    volatile uint16_t **pc; /* Program counter. */
    volatile uint8_t type;

    r0 = &pulFaultStackAddress[ 0 ];
    r1 = &pulFaultStackAddress[ 1 ];
    r2 = &pulFaultStackAddress[ 2 ];
    r3 = &pulFaultStackAddress[ 3 ];
    pc = (uint16_t *)&pulFaultStackAddress[ 6 ];

    type = **pc & 0xff;
    __COPROCESSOR_HANDLER_TABLE[type](*r0, *r1, *r2, *r3);

    *pc += 1;
}

static void coprocessor_int00(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    // Load KEY in coprocessor
    state.key[0] = a;
    state.key[1] = b;
    state.key[2] = c;
    state.key[3] = d;
}
static void coprocessor_int01(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    // Load 64-bit plaintext in coprocessor
    state.x = a;
    state.y = b;
}
static void coprocessor_int02(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    // Store 64-bit ciphertext out of coprocessor
    uint32_t *ap = (uint32_t *)a;
    uint32_t *bp = (uint32_t *)b;
    *ap = state.x;
    *bp = state.y;
}
static void coprocessor_int03(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    // ADD KEY
    state.x ^= c;
    state.x ^= state.key[0 + (a%2)];
    state.y ^= state.key[1 + (a%2)];
    state.x ^= d;
}
static void coprocessor_int04(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    // ALZETTE round
    ALZETTE_(state.x, state.y, RCON[a%5]);
}
