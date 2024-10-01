CFLAGS = -std=c11 -O2 -D_FORTIFY_SOURCE=2 -D_GLIBCXX_ASSERTIONS -Wall -Wextra -Wformat=2 -Wdate-time -Werror=format-security -Wstack-protector -fasynchronous-unwind-tables -fexceptions -fstack-protector-strong -fstack-clash-protection -pedantic -z defs -z noexecstack -z now -z relro -z text -fPIE -fpie -static-pie
CC = clang
.PHONY: clean


matrix: main.c matrices.c
	$(CC) -o $@ $(CFLAGS) $<
	cp $@ $@_strip
	strip $@_strip

clean:
	rm -f chall
