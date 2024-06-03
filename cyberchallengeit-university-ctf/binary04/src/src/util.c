/**
 * @mebeim - 2024-05-20
 */

#include <limits.h>

#include "syscalls.h"
#include "util.h"

int strcmp(const char *s1, const char *s2) {
	while (*s1 && (*s1 == *s2)) {
		s1++;
		s2++;
	}
	return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

int strncmp(const char *_l, const char *_r, size_t n) {
	const unsigned char *l=(void *)_l, *r=(void *)_r;
	if (!n--) return 0;
	for (; *l && *r && n && *l == *r ; l++, r++, n--);
	return *l - *r;
}

size_t strlen(const char *str) {
	const char *s;
	for (s = str; *s; ++s)
		;
	return (s - str);
}

void memcpy(void *dest, const void *src, size_t n) {
	uint8_t *csrc = (uint8_t *)src;
	uint8_t *cdest = (uint8_t *)dest;

	for (size_t i = 0; i < n; i++)
		cdest[i] = csrc[i];
}

void *memset(void *s, int c, size_t len) {
	unsigned char *p = s;
	while (len--) {
		*p++ = (unsigned char)c;
	}
	return s;
}

void strcpy(char *dest, const char *src) {
	for (; (*dest = *src); src++, dest++);
}

char *strcat(char *dest, const char *src) {
	strcpy(dest + strlen(dest), src);
	return dest;
}

void print_str(const char *s) {
	write_exact(1, s, strlen(s));
}

void print_hex(const void *buf, size_t n) {
	const uint8_t *p = buf;
	const char *chars = "0123456789abcdef";

	for (size_t i = 0; i < n; i++, p++) {
		write_exact(1, &chars[(*p >> 4) & 0xf], 1);
		write_exact(1, &chars[(*p) & 0xf], 1);
	}
}

void print_long(long val) {
	const char *chars = "0123456789";
	char buf[32];
	char *p = buf;

	if (val < 0) {
		print_str("-");

		if (val == LONG_MIN) {
			*p++ = chars[-(val % 10)];
			val /= 10;
		}

		val = -val;
	}

	do {
		*p++ = chars[val % 10];
		val /= 10;
	} while (val);

	while (--p >= buf)
		write_exact(1, p, 1);
}

void read_exact(int fd, void *buf, size_t size) {
	uint8_t *p = buf;
	for (size_t nread = 0; nread < size; )
		nread += SYSCHK(read(fd, p + nread, size - nread));
}

void write_exact(int fd, const void *buf, size_t size) {
	const uint8_t *p = buf;
	for (size_t nwritten = 0; nwritten < size; )
		nwritten += SYSCHK(write(fd, p + nwritten, size - nwritten));
}

void die(const char *msg) {
	print_str(msg);
	print_str("\n");
	exit(1);
}

unsigned rand_uint(void) {
	unsigned res;
	SYSCHK(getrandom(&res, sizeof(res), 0));
	return res;
}

void rand_str(char *out, size_t size) {
	const char chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const size_t len = size - 1;
	uint8_t rands[0x100];

	CHECK(len <= sizeof(rands) / sizeof(*rands));
	SYSCHK(getrandom(rands, len * sizeof(*rands), 0));

	for (size_t i = 0; i < len; i++)
		out[i] = chars[rands[i] % (sizeof(chars) - 1)];

	out[len] = '\0';
}

#define __WTERMSIG(status)  ((status) & 0x7f)
#define WIFEXITED(status)   (__WTERMSIG(status) == 0)
#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)

int system(char *cmd) {
	int child_pid = SYSCHK(fork());
	int wstatus;

	if (child_pid == 0) {
		char *argv[] = {"/bin/sh", "-c", cmd, NULL};
		SYSCHK(execve(argv[0], argv, argv + 3));
	}

	SYSCHK(waitpid(child_pid, &wstatus, 0));
	CHECK(WIFEXITED(wstatus));
	return WEXITSTATUS(wstatus);
}
