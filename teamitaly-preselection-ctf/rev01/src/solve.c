#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>


void fatal(const char* fmt, ...) {
  perror(fmt);
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  puts("");
  va_end(args);
  exit(-1);
}



int main(int argc, char* argv[]) {
  int offset;
  int fd;
  struct stat sb;

  if (argc != 3) fatal("./solve filename offset");

  offset = strtol(argv[2], NULL, 16);
  fd = open(argv[1], O_RDONLY);
  if (fd < 0) fatal("open");

  if (lstat(argv[1], &sb) == -1) fatal("stat");

  char* addr = (char*) mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
  if (addr == MAP_FAILED) fatal("mmap");

  void (*fun)() = addr + offset;

  asm volatile ("int3");
  fun();

  return 0;
}
