/**
 * @mebeim - 2024-06-10
 */

#pragma once
#include <stdio.h>

struct op {
	void (*func)(long *);
	long *stack;
};

struct op_descr {
	char name[16];
	void (*func)(long *);
	unsigned n_pop;
	unsigned n_push;
};

extern const struct op_descr operations[7];

void op_neg(long *const stack);
void op_add(long *const stack);
void op_sub(long *const stack);
void op_mul(long *const stack);
void op_div(long *const stack);
void op_in(long *const stack);
void op_out(long *const stack);

void sign_op(struct op *op);
void auth_op(struct op *op);
bool known_op(struct op *op);
