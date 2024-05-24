CFLAGS = -D_FORTIFY_SOURCE=2 -D_GLIBCXX_ASSERTIONS -Wall -Wextra -Wformat=2 -Wdate-time -Werror=format-security -Wstack-protector -fasynchronous-unwind-tables -fexceptions -fstack-protector-strong -fstack-clash-protection -pedantic -z defs -z noexecstack -z now -z relro -z text -fPIE -pie -O2
.PHONY = clean

all: cop

scrambler.o: scrambler.S
	gcc -c $(CFLAGS) -o $@ $^

clean:
	rm -f *.o *.s *.S

cop: main.c scrambler.o
	gcc $(CFLAGS) -o $@ $^
	cp $@ $@.dbg
	strip $@
