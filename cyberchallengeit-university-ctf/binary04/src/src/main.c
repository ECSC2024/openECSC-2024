/**
 * @mebeim - 2024-05-20
 */

#include <errno.h>
#include <stdint.h>
#include <limits.h>

#include "seccomp.h"
#include "syscalls.h"
#include "util.h"

// Exact length (in bytes) of the ROP chain to ask to the user
#define ROP_CHAIN_LENGTH 1024

// Maze generation parameters, which also indirectly control the shape of the
// directory tree. Lower MAX_CHILDREN => deeper maze. Lower MAZE_GEN_WINDOW_SIZE
// => deeper maze. Setting MAZE_GEN_WINDOW_SIZE <= MAX_CHILDREN does not make
// sense as it makes it impossible to reach MAX_CHILDREN on any directory.
#define NUM_DIRS             369
#define MAX_CHILDREN         10
#define MAZE_GEN_WINDOW_SIZE 32

struct node {
	int dirfd;
	unsigned n_children;
};

// Put this one in .data and not .bss, make it large enough so that overwriting
// it will not break rop_stack (since .bss is after .data)
static char triwizard_cup_fname[256] = "triwizard_cup";

// This one can go in .bss
static void *rop_stack;

// Give a bit more space on .bss
// (yes I am very lazy and don't want to make a good linker script for this)
static char __attribute__((unused)) bss_space[0x100];

static const char art[] = \
"  \\                         /\n"
"   \\                       /\n"
"    ]                     [         Welcome\n"
"    ]___               ___[       young wizard!\n"
"    ]  ]\\             /[  [\n"
"    ]  ] \\           / [  [         Can you\n"
"    ]  ]  ]         [  [  [         ROP your\n"
"    ]  ]  ]__     __[  [  [        way to the\n"
"    ]  ]  ] ]\\ _ /[ [  [  [      Triwizard Cup?\n"
"    ]  ]  ] ] (#) [ [  [  [\n"
"    ]  ]  ]_] nHn [_[  [  [       ___________\n"
"    ]  ]  ]  HHHHH. [  [  [      '._==_==_=_.'\n"
"    ]  ] /   `HH(\"N  \\ [  [      .-\\:      /-.\n"
"    ]__]/     HHH  \"  \\[__[     | (|:.     |) |\n"
"    ]         NNN         [      '-|:.     |-'\n"
"    ]         N/\"         [         '::. .'\n"
"    ]         N H         [           ) (\n"
"   /          N            \\        _.' '._\n"
"  /           q,            \\      `\"\"\"\"\"\"\"`\n"
"\n";

// Padding in .text to align things and make dumping the ELF easier
// (yes I am very lazy and don't want to make a good linker script for this x2)
static void __attribute__((naked,unused)) nop() {
	__asm__ __volatile__ (
		".rept 3000\n\t"
		"nop\n\t"
		".endr\n\t"
	);
}

static struct node *choose_parent(struct node *dirs, unsigned n, unsigned exclude_idx) {
	struct node *res;

	// Choose random parent dir with less than MAX_CHILDREN children among dirs
	do {
		unsigned i = rand_uint() % (n - 1);
		if (i >= exclude_idx)
			i++;

		res = &dirs[i];
	} while (res->dirfd == -1 || res->n_children >= MAX_CHILDREN);

	return res;
}

static void create_child_dir(struct node *parent, struct node *child) {
	char name[64 + 1];
	long mkdirat_res;

	// Add new child dir under parent. Retry in the unlikely event that we
	// generate a dir name that already exists.
	do {
		rand_str(name, 17 + rand_uint() % (sizeof(name) - 17));
		mkdirat_res = mkdirat(parent->dirfd, name, 0775);
	} while (mkdirat_res == -EEXIST);

	if (mkdirat_res < 0) {
		print_str("Failed to crete dir: ");
		print_long(mkdirat_res);
		die("");
	}

	parent->n_children++;
	child->dirfd = openat_chk(parent->dirfd, name, O_RDONLY, 0);
}

static void create_child_file(struct node *parent, const char *name, const char *content) {
	int fd = openat_chk(parent->dirfd, name, O_WRONLY|O_CREAT, 0440);
	write_exact(fd, content, strlen(content));
	close_chk(fd);
}

static void build_maze(const char *flag) {
	struct node dirs[MAZE_GEN_WINDOW_SIZE];
	struct node *root, *parent;

	if (access("/tmp/maze", F_OK) == -ENOENT)
		mkdir_chk("/tmp/maze", 0775);

	chdir_chk("/tmp/maze");
	if (system("rm -fr entry") != 0)
		die("Failed to delete old maze!");

	for (unsigned i = 0; i < MAZE_GEN_WINDOW_SIZE; i++) {
		dirs[i].dirfd = -1;
		dirs[i].n_children = 0;
	}

	struct rlimit rlim;
	getrlimit_chk(RLIMIT_NOFILE, &rlim);

	// Check that we have a sane limit to make things easier
	if (rlim.rlim_cur < MAZE_GEN_WINDOW_SIZE + 2) {
		print_str("Current RLIMIT_NOFILE is too low, need at least ");
		print_long(MAZE_GEN_WINDOW_SIZE + 2);
		die("!");
	}

	// Close everything, only keep stdin and stdout
	close_range_chk(2, UINT_MAX, 0);

	root = &dirs[0];
	mkdir_chk("entry", 0775);
	root->dirfd = open_chk("entry", O_RDONLY, 0);

	for (unsigned n = 1; n < NUM_DIRS; n++) {
		const unsigned i = n % MAZE_GEN_WINDOW_SIZE;

		if (dirs[i].dirfd != -1) {
			close_chk(dirs[i].dirfd);
			dirs[i].dirfd = -1;
			dirs[i].n_children = 0;
		}

		parent = choose_parent(dirs, MAZE_GEN_WINDOW_SIZE, i);
		create_child_dir(parent, &dirs[i]);
	}

	// Create "triwizard_cup" file containing the flag
	parent = choose_parent(dirs, MAZE_GEN_WINDOW_SIZE, MAZE_GEN_WINDOW_SIZE);
	create_child_file(parent, triwizard_cup_fname, flag);

	// Close everything, only keep stdin and stdout
	close_range_chk(2, UINT_MAX, 0);
}

static void print(const void *buf, size_t n) {
	write_exact(1, buf, n);
}

static void go() {
	// Avoid clash with ROP stack in case we are called again from the ROP chain
	__asm__ __volatile__ ("sub $0x10000,%esp");

	print_str("Give me your x86 32bit ROP chain (exactly "STR(ROP_CHAIN_LENGTH)" bytes):\n");
	read_exact(0, rop_stack, ROP_CHAIN_LENGTH);

	// Pivot to ROP stack. We need this alternative stack and not the "normal"
	// stack because we want to make sure that this function can also be called
	// from the ROP chain itself. In such case, we can easily run past the
	// bottom of the stack with the above read_exact(), because ropping consumes
	// stack and this function uses basically no stack at all. Therefore, it's
	// nice to have the same stack location that we can always hard-reset to.
	__asm__ __volatile__(
		"movl %0,%%esp\n\t"
		"ret\n\t"
		:: "g"(rop_stack)
	);
}

int main(int argc, char **argv, char **envp) {
	(void)argc;
	(void)argv;

	print_str(art);

	uint32_t addr = __builtin_bswap32((unsigned int)&print);
	print_str("void print(const void *buf, size_t n) is at 0x");
	print_hex(&addr, sizeof(addr));
	print_str("\n\n");

	// Locate flag env var
	char *flag = NULL;
	for (char **e = envp; *e; e++) {
		if (!strncmp(*e, "FLAG=", 5))
			flag = *e + 5;
	}

	if (!flag)
		die("Flag not found in environment!");

	build_maze(flag);

	// Wipe flag from memory
	memset(flag, 'X', strlen(flag));

	rop_stack = (void *)mmap_chk(0, (1UL << 20), PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	rop_stack += (1UL << 20) - 0x1000;

	// Load seccomp filter, which limits syscalls and also only allows openat if
	// the addr given for pathname is equal to the addr of triwizard_cup_fname.
	// This is easily bypassable by overwriting the contents of
	// triwizard_cup_fname[].
	load_seccomp_filter(triwizard_cup_fname);

	go();

	return 0;
}
