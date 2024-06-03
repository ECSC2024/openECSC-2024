/**
 * @mebeim - 2024-05-20
 */

#pragma once
#include <stddef.h>
#include <stdint.h>

#define XSTR(x) #x
#define STR(x)  XSTR(x)

#define SYSCHK(x) ({                             \
	long __ret = (x);                            \
	if (__ret < 0L) {                            \
		print_str("SYSCALL FAILED: " #x " -> "); \
		print_long(__ret);                       \
		die("");                                 \
	};                                           \
	__ret;                                       \
})

#define CHECK(x) ({               \
	typeof(x) __ret = (x);        \
	if (!__ret)                   \
		die("CHECK FAILED: " #x); \
	__ret;                        \
})

int strcmp(const char *s1, const char *s2);
int strncmp(const char *_l, const char *_r, size_t n);
size_t strlen(const char *str);

void memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t len);
void strcpy(char *d, const char *s);
char *strcat(char *dest, const char *src);

void print_str(const char *s);
void print_hex(const void *buf, size_t n);
void print_long(long val);

void read_line(int fd, char *buf, size_t size);
void read_exact(int fd, void *buf, size_t size);
void write_exact(int fd, const void *buf, size_t size);

void die(const char *msg);

unsigned rand_uint(void);
void rand_str(char *out, size_t size);

int system(char *cmd);
