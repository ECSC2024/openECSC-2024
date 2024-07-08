/**
 * @mebeim - 2024-06-10
 */

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "ops.h"
#include "util.h"

const struct op_descr operations[7] = {
	{ .name = "neg", .func = op_neg, .n_pop = 0, .n_push = 0 },
	{ .name = "add", .func = op_add, .n_pop = 2, .n_push = 1 },
	{ .name = "sub", .func = op_sub, .n_pop = 2, .n_push = 1 },
	{ .name = "mul", .func = op_mul, .n_pop = 2, .n_push = 1 },
	{ .name = "div", .func = op_div, .n_pop = 2, .n_push = 1 },
	{ .name = "in" , .func = op_in , .n_pop = 0, .n_push = 1 },
	{ .name = "out", .func = op_out, .n_pop = 1, .n_push = 0 },
};

void op_neg(long *const stack) {
	*stack = -*stack;
}

void op_add(long *const stack) {
	stack[0] = stack[1] + stack[0];
}

void op_sub(long *const stack) {
	stack[0] = stack[1] - stack[0];
}

void op_mul(long *const stack) {
	stack[0] = stack[1] * stack[0];
}

void op_div(long *const stack) {
	stack[0] = stack[1] / stack[0];
}

void op_in(long *const stack) {
	fputs("Input a number: ", stdout);
	fflush(stdout);

	if (scanf("%ld%*c", stack) != 1)
		die("scanf failed");
}

void op_out(long *const stack) {
	if (printf("Output: %ld\n", stack[0]) < 10)
		die("printf failed");
	fflush(stdout);
}

void sign_op(struct op *op) {
#ifdef __aarch64__
	asm volatile("pacia %0, %1" : "+r"(op->func) : "r"(op->stack));
#else
	// Emulate for debugging purposes
	uint64_t f = (uint64_t)op->func;
	uint64_t s = (uint64_t)op->stack;
	op->func = (typeof(op->func))(f ^ ((s & 0xffff) << 48));
#endif
}

void auth_op(struct op *op) {
#ifdef __aarch64__
	asm volatile("autia %0, %1" : "+r"(op->func) : "r"(op->stack));
#else
	// Emulate for debugging purposes
	uint64_t f = (uint64_t)op->func;
	uint64_t s = (uint64_t)op->stack;
	op->func = (typeof(op->func))(f ^ ((s & 0xffff) << 48));
#endif
}

bool known_op(struct op *op) {
	for (size_t j = 0; j < sizeof(operations)/sizeof(*operations); j++) {
		if (op->func == operations[j].func)
			return true;
	}

	return false;
}
