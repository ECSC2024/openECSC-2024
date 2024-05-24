CC     := gcc
OUTDIR := build
CFLAGS = -D_GLIBCXX_ASSERTIONS -Wall -Wextra -Wformat=2 -Wdate-time -Wno-format-nonliteral -Wformat-security -Wstack-protector -fasynchronous-unwind-tables -fexceptions -fstack-protector-strong -fstack-clash-protection -pedantic -z defs -z noexecstack -z relro -z text -fPIE -pie

.PHONY: all clean


all: build/logloglog


clean:
	rm -f logloglog

build:
	mkdir -p $@

build/logloglog: logloglog.c build
	$(CC) $(CFLAGS) $< -lpcre -o $@
	cp $@ ../attachments/logloglog
	pwninit --bin $@ --libc ../checker/libc.so.6 --ld ../checker/ld.so
	rm solve.py
	mv build/logloglog_patched ../checker/
