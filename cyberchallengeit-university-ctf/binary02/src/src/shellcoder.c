#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <asm/prctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "util.h"

#define PAGE_SIZE 0x1000
#define MAX_SIZE 0x200

typedef unsigned char byte;

const byte TRAPS[][2] = {
	{ 0x0F, 0x05 },
	{ 0x0F, 0x34 },
	{ 0xCD, 0x80 },
};

int arch_prctl(int code, unsigned long addr)
{    
    return syscall(SYS_arch_prctl, code, addr);
}

void get_code() {
	byte *wilderness;
	unsigned int size;

	wilderness = mmap((void *)0xbeef0000L, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

	if (wilderness != (void *)0xbeef0000L)
		die("mmap failed");

	puts("How many bytes?");

	if (scanf("%u", &size) != 1)
        die("scanf failed");

	if (size > MAX_SIZE)
		die("size too big");

	puts("Shellcode:");

	if (read_exactly(0, wilderness, size) != 0)
		die("read_exactly failed");

	for (unsigned int i = 0; i < size; i++) {
		for (unsigned int j = 0; j < sizeof(TRAPS); j++) {
			if (wilderness[i] == TRAPS[j][0] && wilderness[i + 1] == TRAPS[j][1])
				die("traps are forbidden");
		}
	}
}

void run_code() {
	puts("Bye!");

	arch_prctl(ARCH_SET_GS, 0);
	arch_prctl(ARCH_SET_FS, 0);
	
	asm volatile (
		".intel_syntax noprefix;"
		"xor rax, rax;"
		"push rax;"
		"popfq;"
		"xor rbx, rbx;"
		"xor rcx, rcx;"
		"xor rdx, rdx;"
		"xor rsi, rsi;"
		"xor rdi, rdi;"
		"xor rbp, rbp;"
		"xor rsp, rsp;"
		"xor r8, r8;"
		"xor r9, r9;"
		"xor r10, r10;"
		"xor r11, r11;"
		"xor r12, r12;"
		"xor r13, r13;"
		"xor r14, r14;"
		"xor r15, r15;"
		"vzeroall;"
		"movabs rax, 0xbeef0000;"
		"jmp rax;"
		".att_syntax noprefix;"
	);
}

int main() {

	set_buf();
	get_code();
	run_code();
}