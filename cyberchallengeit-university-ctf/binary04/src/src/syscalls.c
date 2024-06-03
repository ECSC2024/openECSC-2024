/**
 * @mebeim - 2024-05-20
 */

#include <stdint.h>
#include <stddef.h>
#include <sys/syscall.h>

#include "syscalls.h"
#include "util.h"

long open(const char *pathname, int flags, mode_t mode) {
	return __syscall3((long)__NR_open, (long)pathname, (long)flags, (long)mode);
}

long openat(int dirfd, const char *pathname, int flags, mode_t mode) {
	return __syscall4((long)__NR_openat, (long)dirfd, (long)pathname, (long)flags, (long)mode);
}

long read(int fd, void *buf, size_t count) {
	return __syscall3((long)__NR_read, (long)fd, (long)buf, (long)count);
}

long write(int fd, const void *buf, size_t count) {
	return __syscall3((long)__NR_write, (long)fd, (long)buf, (long)count);
}

long close(unsigned fd) {
	return __syscall1((long)__NR_close, (long)fd);
}

long close_range(unsigned fd, unsigned max_fd, unsigned flags) {
	return __syscall3((long)__NR_close_range, (long)fd, (long)max_fd, (long)flags);
}

long mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	return __syscall6((long)__NR_mmap2, (long)addr, (long)length, (long)prot, (long)flags, (long)fd, (long)offset);
}

long munmap(void *addr, size_t length) {
	return __syscall2((long)__NR_munmap, (long)addr, (long)length);
}

long access(const char *pathname, mode_t mode) {
	return __syscall2((long)__NR_access, (long)pathname, (long)mode);
}

long mkdir(const char *pathname, mode_t mode) {
	return __syscall2((long)__NR_mkdir, (long)pathname, (long)mode);
}

long mkdirat(int dirfd, const char *pathname, mode_t mode) {
	return __syscall3((long)__NR_mkdirat, (long)dirfd, (long)pathname, (long)mode);
}

long getcwd(char *buf, size_t size) {
	return __syscall2((long)__NR_getcwd, (long)buf, (long)size);
}

long chdir(const char *path) {
	return __syscall1((long)__NR_chdir, (long)path);
}

long getrandom(void *buf, size_t buflen, unsigned int flags) {
	return __syscall3((long)__NR_getrandom, (long)buf, (long)buflen, (long)flags);
}

long execve(const char *pathname, char *const argv[], char *const envp[]) {
	return __syscall3((long)__NR_execve, (long)pathname, (long)argv, (long)envp);
}

long fork(void) {
	return __syscall0((long)__NR_fork);
}

long waitpid(int pid, int *wstatus, int options) {
	return __syscall3((long)__NR_waitpid, (long)pid, (long)wstatus, (long)options);
}

long getrlimit(int resource, struct rlimit *rlim) {
	return __syscall2((long)__NR_getrlimit, (long)resource, (long)rlim);
}

long prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
	return __syscall5((long)__NR_prctl, (long)option, (long)arg2, (long)arg3, (long)arg4, (long)arg5);
}

void __attribute__((noreturn)) exit(int ret) {
	__syscall1((long)__NR_exit, (long)ret);
	__asm__ __volatile__ ("ud2");
	while (1);
}

// -----------------------------------------------------------------------------

long open_chk(const char *pathname, int flags, mode_t mode) {
	return SYSCHK(open(pathname, flags, mode));
}

long openat_chk(int dirfd, const char *pathname, int flags, mode_t mode) {
	return SYSCHK(openat(dirfd, pathname, flags, mode));
}

long read_chk(int fd, void *buf, size_t count) {
	return SYSCHK(read(fd, buf, count));
}

long write_chk(int fd, const void *buf, size_t count) {
	return SYSCHK(write(fd, buf, count));
}

long close_chk(unsigned fd) {
	return SYSCHK(close(fd));
}

long close_range_chk(unsigned fd, unsigned max_fd, unsigned flags) {
	return SYSCHK(close_range(fd, max_fd, flags));
}

long mmap_chk(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	long res = mmap(addr, length, prot, flags, fd, offset);
	if (res < 0 && res > -0xfff) {
		print_str("SYSCALL FAILED: mmap(addr, length, prot, flags, fd, offset) -> ");
		print_long(res);
		die("");
	}

	return res;
}

long munmap_chk(void *addr, size_t length) {
	return SYSCHK(munmap(addr, length));
}

long access_chk(const char *pathname, mode_t mode) {
	return SYSCHK(access(pathname, mode));
}

long mkdir_chk(const char *pathname, mode_t mode) {
	return SYSCHK(mkdir(pathname, mode));
}

long mkdirat_chk(int dirfd, const char *pathname, mode_t mode) {
	return SYSCHK(mkdirat(dirfd, pathname, mode));
}

long getcwd_chk(char *buf, size_t size) {
	return SYSCHK(getcwd(buf, size));
}

long chdir_chk(const char *path) {
	return SYSCHK(chdir(path));
}

long getrandom_chk(void *buf, size_t buflen, unsigned int flags) {
	return SYSCHK(getrandom(buf, buflen, flags));
}

long execve_chk(const char *pathname, char *const argv[], char *const envp[]) {
	return SYSCHK(execve(pathname, argv, envp));
}

long fork_chk(void) {
	return SYSCHK(fork());
}

long waitpid_chk(int pid, int *wstatus, int options) {
	return SYSCHK(waitpid(pid, wstatus, options));
}

long getrlimit_chk(int resource, struct rlimit *rlim) {
	return SYSCHK(getrlimit(resource, rlim));
}

long prctl_chk(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
	return SYSCHK(prctl(option, arg2, arg3, arg4, arg5));
}
