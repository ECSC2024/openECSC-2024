/**
 * @mebeim - 2024-05-20
 * Adapted from: https://git.musl-libc.org/cgit/musl/tree/arch/i386/syscall_arch.h
 */

#pragma once
#include <stddef.h>
#include <stdint.h>

#define SYSCALL_INSNS "int $128"

static inline long __syscall0(long n)
{
	unsigned long __ret;
	__asm__ __volatile__ (SYSCALL_INSNS : "=a"(__ret) : "a"(n) : "memory");
	return __ret;
}

static inline long __syscall1(long n, long a1)
{
	unsigned long __ret;
	__asm__ __volatile__ (SYSCALL_INSNS : "=a"(__ret) : "a"(n), "b"(a1) : "memory");
	return __ret;
}

static inline long __syscall2(long n, long a1, long a2)
{
	unsigned long __ret;
	__asm__ __volatile__ (SYSCALL_INSNS : "=a"(__ret) : "a"(n), "b"(a1), "c"(a2) : "memory");
	return __ret;
}

static inline long __syscall3(long n, long a1, long a2, long a3)
{
	unsigned long __ret;
	__asm__ __volatile__ (SYSCALL_INSNS : "=a"(__ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3) : "memory");
	return __ret;
}

static inline long __syscall4(long n, long a1, long a2, long a3, long a4)
{
	unsigned long __ret;
	__asm__ __volatile__ (SYSCALL_INSNS : "=a"(__ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4) : "memory");
	return __ret;
}

static inline long __syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
	unsigned long __ret;
	__asm__ __volatile__ (SYSCALL_INSNS
		: "=a"(__ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5) : "memory");
	return __ret;
}

static inline long __syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	unsigned long __ret;
	__asm__ __volatile__ ("pushl %7 ; push %%ebp ; mov 4(%%esp),%%ebp ; " SYSCALL_INSNS " ; pop %%ebp ; add $4,%%esp"
		: "=a"(__ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5), "g"(a6) : "memory");
	return __ret;
}

/*
 * Some defines/types that we cannot import from system headers (because doing
 * so would also import conflicting function declarations).
 */

#define R_OK 4
#define W_OK 2
#define X_OK 1
#define F_OK 0

#define O_RDONLY 00000000
#define O_WRONLY 00000001
#define O_RDWR   00000002
#define O_CREAT  00000100

#define RLIMIT_NOFILE 7

#define PROT_READ     0x1
#define PROT_WRITE    0x2
#define PROT_EXEC     0x4
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20

#define PR_SET_NO_NEW_PRIVS 38
#define PR_SET_SECCOMP      22
#define SECCOMP_MODE_FILTER 2

typedef unsigned long mode_t;
typedef unsigned long rlim_t;
typedef long off_t;

struct rlimit {
	rlim_t rlim_cur;
	rlim_t rlim_max;
};

/*
 * NOTE: UNLIKE normal libc syscall wrappers, these DO NOT set errno! They just
 * return the raw syscall return value, which in case of error will be -errno.
 */

long open(const char *pathname, int flags, mode_t mode);
long openat(int dirfd, const char *pathname, int flags, mode_t mode);
long read(int fd, void *buf, size_t count);
long write(int fd, const void *buf, size_t count);
long close(unsigned fd);
long close_range(unsigned fd, unsigned max_fd, unsigned flags);

long mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
long munmap(void *addr, size_t length);

long access(const char *pathname, mode_t mode);
long mkdir(const char *pathname, mode_t mode);
long mkdirat(int dirfd, const char *pathname, mode_t mode);

long getcwd(char *buf, size_t size);
long chdir(const char *path);

long getrandom(void *buf, size_t buflen, unsigned int flags);

long execve(const char *pathname, char *const argv[], char *const envp[]);

long fork(void);
long waitpid(int pid, int *wstatus, int options);

long getrlimit(int resource, struct rlimit *rlim);

long prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

void __attribute__((noreturn)) exit(int ret);

/*
 * Convenience wrappers to avoid generating a bunch of checks that are annoying
 * to look at in decompiled code.
 */

long open_chk(const char *pathname, int flags, mode_t mode);
long openat_chk(int dirfd, const char *pathname, int flags, mode_t mode);
long read_chk(int fd, void *buf, size_t count);
long write_chk(int fd, const void *buf, size_t count);
long close_chk(unsigned fd);
long close_range_chk(unsigned fd, unsigned max_fd, unsigned flags);

long mmap_chk(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
long munmap_chk(void *addr, size_t length);

long access_chk(const char *pathname, mode_t mode);
long mkdir_chk(const char *pathname, mode_t mode);
long mkdirat_chk(int dirfd, const char *pathname, mode_t mode);

long getcwd_chk(char *buf, size_t size);
long chdir_chk(const char *path);

long getrandom_chk(void *buf, size_t buflen, unsigned int flags);

long execve_chk(const char *pathname, char *const argv[], char *const envp[]);

long fork_chk(void);
long waitpid_chk(int pid, int *wstatus, int options);

long getrlimit_chk(int resource, struct rlimit *rlim);

long prctl_chk(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
