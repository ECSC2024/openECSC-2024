# openECSC 2024 - Final Round

## [misc] chmod 772 (12 solves)

Someone run `chmod 772` on the flag.

I had `1kat` installed, but it can read only the first kB of a file, can you read the flag?

`nc chmod772.challs.open.ecsc2024.it 47002`

Author: Giovanni Minotti <@Giotino>

## Overview

The player is presented with a linux shell, by running the `ls` command a file named `flag.txt` is show. The file cannot be read since ti has `772` permissions and the shell is running as a non-owner user and group from the file perspective.  
There's is also a binary named `1kat` that can read only the first kB of a file and its SUID bit is set, hence it can read the flag.  
The flag if precedeed by "`Flag at the end of the file -> `" and 2048 `*`; `1kat` can't read it all.

## Solution

https://man7.org/linux/man-pages/man2/fallocate.2.html

The syscall `fallocate` "allows the caller to directly manipulate the allocated disk space for the file", it's mainly used to allocate disk space, but it can also manipulate the file space in other ways.  
The `FALLOC_FL_COLLAPSE_RANGE` (`0x8`) flag is used to collapse space.

```
int fallocate(int fd, int mode, off_t offset, off_t len);

[...]

Collapsing file space

Specifying the FALLOC_FL_COLLAPSE_RANGE flag (available since
Linux 3.15) in mode removes a byte range from a file, without
leaving a hole.  The byte range to be collapsed starts at offset
and continues for len bytes.  At the completion of the operation,
the contents of the file starting at the location offset+len will
be appended at the location offset, and the file will be len
bytes smaller.

A filesystem may place limitations on the granularity of the
operation, in order to ensure efficient implementation.
Typically, offset and len must be a multiple of the filesystem
logical block size, which varies according to the filesystem type
and configuration.  If a filesystem has such a requirement,
fallocate() fails with the error EINVAL if this requirement is
violated.

If the region specified by offset plus len reaches or passes the
end of file, an error is returned; instead, use ftruncate(2) to
truncate a file.

No other flags may be specified in mode in conjunction with
FALLOC_FL_COLLAPSE_RANGE.

As at Linux 3.15, FALLOC_FL_COLLAPSE_RANGE is supported by ext4
(only for extent-based files) and XFS.
```

In this case we can collapse multiples of `1024` bytes, since the block size is `1024` bytes (as shown using `stat -fc %s .` in the challenge directory), and the file system is ext4 (as shown using `mount`).

After collapsing the file, we can read the flag with `1kat`.


## Exploit

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
  int start = 1024 * 2; // Must be a multiple of the block size (1024)

  int fd = open("flag.txt", O_APPEND | O_WRONLY);
  printf("FD = %d\n", fd);

  int r = fallocate(fd, 0x8, 0, start);
  printf("r = %d\n", r);
  perror("fallocate");

  close(fd);
  return 0;
}
```
