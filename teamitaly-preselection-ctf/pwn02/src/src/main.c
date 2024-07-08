/**
 * @mebeim - 2024-06-10
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ops.h"
#include "util.h"

#define N_SAVED_EXPRS    4
#define EXPR_MAX_OPS     32
#define EXPR_STACK_SLOTS EXPR_MAX_OPS

struct expr {
	long stack[EXPR_STACK_SLOTS];
	struct op ops[EXPR_MAX_OPS];
	long valid;
	size_t n_ops;
};

struct expr *saved_exprs;

void build(struct expr *expr, char *source) {
	long *stack;
	char *name;

	memset(expr->stack, 0, sizeof(expr->stack));
	expr->n_ops = 0;
	expr->valid = 0;

	stack = expr->stack;

	for (name = strtok(source, " ;"); name; name = strtok(NULL, " ;")) {
		struct op *op = &expr->ops[expr->n_ops];
		if (expr->n_ops >= EXPR_MAX_OPS)
			die("Expression too long!");

		for (size_t j = 0; j < sizeof(operations)/sizeof(*operations); j++) {
			const struct op_descr *descr = &operations[j];

			if (!strcmp(name, operations[j].name)) {
				op->func = descr->func;
				stack -= descr->n_pop;
				op->stack = stack;
				stack += descr->n_push;
				goto next;
			}
		}

		printf("Skipping unknown operation: \"%s\"\n", name);
next:
		expr->n_ops++;
	}
}

void validate(struct expr *expr, bool print_success) {
	expr->valid = 0;

	// BUG: signing all ops *before* validating their ->stack
	for (size_t i = 0; i < expr->n_ops; i++)
		sign_op(&expr->ops[i]);

	for (size_t i = 0; i < expr->n_ops; i++) {
		struct op *op = &expr->ops[i];

		if (op->stack < expr->stack) {
			puts("Invalid expression: stack underflow!");
			fflush(stdout);
			return;
		}

		if (op->stack >= expr->stack + EXPR_STACK_SLOTS) {
			puts("Invalid expression: stack overflow!");
			fflush(stdout);
			return;
		}
	}

	expr->valid = 1;

	if (print_success)
		puts("Valid expression");
}

void eval(struct expr *expr) {
	if (!expr->valid) {
		validate(expr, false);
		if (!expr->valid)
			return;
	}

	/* BUG: instead of using expr->n_ops we are iterating over *all* expr->ops[]
	 * and stopping at the first one that has a NULL function pointer.
	 *
	 * Since the build() function does not bother clearing expr->ops[] before
	 * overwriting old entries, we can have more than expr->n_ops non-NULL
	 * entries. Since validate() uses expr->n_ops to validate the expression,
	 * we are evaluating a potentially invalid expression containing old ops.
	 */
	for (unsigned i = 0; i < EXPR_MAX_OPS && expr->ops[i].func; i++) {
		struct op *op = &expr->ops[i];

		auth_op(op);

		// Validate op->func here because we don't want to allow arbitrary code
		// execution with forged signatures right away. We only want it to be a
		// signing gadget.
		if (!known_op(op)) {
			puts("Unknown operation encountered! Stopping.\n");
			fflush(stdout);
			return;
		}

		op->func(op->stack);
	}
}

unsigned get_uint(void) {
	unsigned res;
	if (scanf("%u%*c", &res) != 1)
		die("scanf failed");
	return res;
}

void get_str(char *out) {
	if (!fgets(out, 0x200, stdin))
		die("fgets failed");
	out[strcspn(out, "\n")] = '\0';
}

struct expr *get_expr(void) {
	unsigned slot;

	fprintf(stdout, "Index? ");
	fflush(stdout);

	slot = get_uint();
	if (slot >= N_SAVED_EXPRS)
		die("Invalid index!");
	return &saved_exprs[slot];
}

void print_banner() {
	puts(
		"  ___                          ___\n"
		" ||  |   ___ Pointer ___      ||  |\n"
		" || _|__/  _\\_______/  _\\_____|| _|\n"
		" ||(___(  (________(  (_______||((_)\n"
		" ||  |  \\___/ entic \\___/     ||  |\n"
		" ||  |    Auth ___ ated       ||  |\n"
		" || _|________/  _\\___________|| _|\n"
		" ||(_________(  (_____________||((_)\n"
		" ||  |        \\___/           ||  |\n"
		" ||  |      Calculator        ||  |\n"
		" ||  |                        ||  |\n"
	);
}

void print_menu() {
	fputs(
		"1. Build expression\n"
		"2. Validate expression\n"
		"3. Evaluate expression\n"
		"4. Show saved expression\n"
		"5. Start a debug shell\n"
		"6. Exit\n"
		"> ",
		stdout
	);
	fflush(stdout);
}

void cmd_build(void) {
	char source[0x100];

	fputs("Expression: ", stdout);
	fflush(stdout);

	/* BUG: linear buffer overflow here (read of 0x200 instead of 0x100).
	 * However:
	 *   1. x30 for this func is saved *after* allocating the local buffer, so
	 *      the caller's saved x30 needs to be targeted.
	 *   2. The caller frame is protected by PAC, so the attacker needs to forge
	 *      a valid signed pointer.
	 */
	get_str(source);
	build(get_expr(), source);
}

void cmd_validate(void) {
	validate(get_expr(), true);
}

void cmd_eval(void) {
	eval(get_expr());
	puts("Done!");
	fflush(stdout);
}

void cmd_show(void) {
	puts("Saved expressions:");
	for (unsigned i = 0; i < N_SAVED_EXPRS; i++) {
		struct expr *expr = &saved_exprs[i];

		if (expr->n_ops)
			printf(" - slot %u: %ld ops\n", i, expr->n_ops);
		else
			printf(" - slot %u: empty\n", i);
	}

	fflush(stdout);
}

void cmd_debug(void) {
	system("echo Still working on it, sorry!");
}

int main(void) {
	const long page_sz = sysconf(_SC_PAGE_SIZE);
	if (page_sz == -1)
		die("sysconf(_SC_PAGE_SIZE) failed");

	size_t sz = N_SAVED_EXPRS * sizeof(struct expr);
	sz += page_sz - 1;
	sz -= sz % page_sz;
	sz += 2 * page_sz;

	unsigned char *mem = mmap(NULL, sz, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED)
		die("mmap failed");

	saved_exprs = (struct expr *)(mem + page_sz);
	if (mprotect(saved_exprs, sz - 2 * page_sz, PROT_READ|PROT_WRITE))
		die("mprotect failed");

	print_banner();

	while (1) {
		print_menu();
		long cmd = get_uint();
		puts("---");

		switch (cmd) {
		case 1:
			cmd_build();
			break;

		case 2:
			cmd_validate();
			break;

		case 3:
			cmd_eval();
			break;

		case 4:
			cmd_show();
			break;

		case 5:
			cmd_debug();
			break;

		case 6:
			goto out;

		default:
			die("Invalid choice!");
			break;
		}

		puts("---");
		fflush(stdout);
	}

out:
	puts("Goodbye!");
	fflush(stdout);
	return 0;
}
