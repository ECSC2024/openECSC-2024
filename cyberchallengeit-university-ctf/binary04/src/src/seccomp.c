/**
 * @mebeim - 2024-05-20
 */

#include <stddef.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <sys/syscall.h>

#include "syscalls.h"
#include "util.h"

void load_seccomp_filter(const char *allowed_open_arg) {
	/* Allow only these i386 syscalls: readdir, read, write, close, exit.
	 * Additionally, allow openat but only if filename == allowed_open_arg.
	 *
	 * The check on the file name only takes into account the address at the
	 * moment of the syscall, not its content, so it is easily bypassable.
	 */
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS , offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_I386        , 0, 9),
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS , offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_readdir           , 8, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_read              , 7, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_write             , 6, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_close             , 5, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_exit              , 4, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_openat            , 0, 2),
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS , offsetof(struct seccomp_data, args[1])),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (__u32)allowed_open_arg, 1, 0),
		BPF_STMT(BPF_RET|BPF_K        , SECCOMP_RET_KILL),
		BPF_STMT(BPF_RET|BPF_K        , SECCOMP_RET_ALLOW),
	};

	struct sock_fprog prog = {
		.filter = filter,
		.len = sizeof(filter) / sizeof(*filter)
	};

	SYSCHK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	SYSCHK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (long)&prog, 0, 0));
}
