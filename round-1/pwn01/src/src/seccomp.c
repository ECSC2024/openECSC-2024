#include <err.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

void init_seccomp(void) {
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS , offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 0, 8),
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS , offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_exit      , 7, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_exit_group, 6, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_mmap      , 5, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_open      , 4, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_openat    , 3, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_read      , 2, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_write     , 1, 0),
		BPF_STMT(BPF_RET|BPF_K        , SECCOMP_RET_KILL),
		BPF_STMT(BPF_RET|BPF_K        , SECCOMP_RET_ALLOW),
	};

	struct sock_fprog prog = {
		.len = sizeof(filter) / sizeof(*filter),
		.filter = filter
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		err(1, "prctl(PR_SET_NO_NEW_PRIVS)");

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0))
		err(1, "prctl(PR_SET_SECCOMP)");
}
