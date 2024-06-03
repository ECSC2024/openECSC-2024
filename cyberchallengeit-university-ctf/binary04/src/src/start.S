/**
 * @mebeim - 2024-05-20
 */

#include <sys/syscall.h>

.text
.globl _start
.type _start,@function

_start:
	xorl  %ebp, %ebp
	popl  %edi                 /* argc */
	movl  %esp, %esi           /* argv */
	leal  4(%esp,%edi,4), %edx /* envp */

	/* ensure 16-byte alignment */
	sub   $4, %esp

	pushl %edx
	pushl %esi
	pushl %edi
	call  main

	movl  %eax, %ebx
	movl  $__NR_exit, %eax
	int   $0x80
	ud2
