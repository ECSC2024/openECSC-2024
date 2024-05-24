# Xv6 Homework

> My operating systems professor is teaching us using xv6. At the end of the
> lecture, he pointed us to section 6.10 exercise 1 of the book, which states:
>
> > Comment out the calls to `acquire` and `release` in `kalloc`
> > (`kernel/kalloc.c:69`). This seems like it should cause problems for kernel
> > code that calls `kalloc`; what symptoms do you expect to see? When you run
> > xv6, do you see these symptoms? How about when running `usertests`? If you
> > don’t see a problem, why not? See if you can provoke a problem by inserting
> > dummy loops into the critical section of `kalloc`.
>
> Can you help me write a decent answer before the next lecture?

The program you provide to the challenge server is a RISC-V 64-bit ELF binary
built for [xv6-riscv][repo]. The binary will be placed in the filesystem of a
xv6 QEMU VM as `exe`, and you will then get a shell inside the VM.

The flag is in the QEMU host (inside the Docker container) at `/home/user/flag`.
You don't need to pwn QEMU itself. You can prove you have arbitrary kernel code
execution by leveraging the `-semihosting` feature of QEMU.


Building a program for xv6
--------------------------

Assuming that you are not running a RISC-V system, you will need a
cross-compilation toolchain. If your distro does not provide one, you can easily
get it from [here][toolchains] (pretty lightweight since no libc is needed):

```sh
# riscv64 toolchain for x86_64 host
wget 'https://mirrors.edge.kernel.org/pub/tools/crosstool/files/bin/x86_64/10.4.0/x86_64-gcc-10.4.0-nolibc-riscv64-linux.tar.xz'
tar xf x86_64-gcc-10.4.0-nolibc-riscv64-linux.tar.xz
export PATH="$PWD/gcc-10.4.0-nolibc/riscv64-linux/bin:$PATH"
```

Now you can clone the [xv6-riscv repository][repo] and build with `make`:

```sh
git clone https://github.com/mit-pdos/xv6-riscv.git
cd xv6-riscv
git checkout f5b93ef12f7159f74f80f94729ee4faabe42c360
git apply path/to/chall.patch
make TOOLPREFIX=riscv64-linux-
```

The program you need to build and provide to the challenge server is an xv6
userspace program like the ones you can find under the `user/` directory of the
repository. You can check the `Makefile` to see how they are built and edit it
to also build your own. Alternatively you can just replace the source code of
one of the existing commands (e.g. `user/echo.c`) and then build it.


Debugging
---------

To enable debugging for the challenge running in Docker, check the comments in
`chall.sh`.

If you want to debug a local xv6 build (see build instructions above), you can
simply run `make qemu-gdb`. Then, on a second terminal, connect to the VM
launching `gdb-multiarch` from within the root of the repository, which already
provides a `.gdbinit` script to automatically connect to QEMU.

**NOTE**: you will need `qemu-system-riscv64` version 6.0 or higher if you want
to run xv6 locally with `-semihosting` enabled. You can nonetheless still use
older versions of QEMU without `-semihosting`.


[repo]:       https://github.com/mit-pdos/xv6-riscv
[toolchains]: https://mirrors.edge.kernel.org/pub/tools/crosstool/files/bin/
