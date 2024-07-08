CC = gcc
CFLAGS = -D_GLIBCXX_ASSERTIONS -Wall -Wextra -Wformat=2 -Wdate-time -Werror=format-security -fasynchronous-unwind-tables -fexceptions -pedantic -z defs -z noexecstack -z now -z relro -z text -fPIE -pie -O2

.PHONY: clean


all: forgot solve


clean:
	rm -f main.S tmp solve

forgot: main.S main.c
	$(CC) $(CFLAGS) -nostdlib -o tmp $^
	./copy_section.py --input tmp --output $@


solve: solve.c
	$(CC) $(CFLAGS) -g -o $@ $^
