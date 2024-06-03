SRCDIR := src
OUTDIR := build
SRCS   := $(wildcard $(SRCDIR)/*.c) $(wildcard $(SRCDIR)/*.S)
OBJS   := $(filter %.o,$(patsubst $(SRCDIR)/%.c,$(OUTDIR)/%.o,$(SRCS)))
OBJS   += $(filter %.o,$(patsubst $(SRCDIR)/%.S,$(OUTDIR)/%.o,$(SRCS)))
DEPS   := $(OBJS:.o=.d)
BINARY := $(OUTDIR)/triwizard-maze

CC := gcc
LD := ld

CFLAGS := -m32 -O0 -std=gnu99 -MMD -Wall -Wextra \
	-static -no-pie -fno-pie -nostdlib -ffreestanding \
	-fno-asynchronous-unwind-tables \
	-Isrc

LDFLAGS := -m elf_i386 -s -z noexecstack \
	--image-base=0x13370000 \
	--section-start=.text=0x13371000

MAKEFLAGS += --silent
.DEFAULT_GOAL := $(BINARY)

-include $(DEPS)

$(BINARY): $(OBJS)
	echo 'LD    $@'
	$(LD) $(LDFLAGS) -o $@ $^
	objcopy --remove-section .comment $@ || true

$(OUTDIR)/%.o: $(SRCDIR)/%.S | $(OUTDIR)
	echo 'CC    $@'
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUTDIR)/%.o: $(SRCDIR)/%.c | $(OUTDIR)
	echo 'CC    $@'
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUTDIR):
	echo 'MKDIR $@'
	mkdir -p $@

test: $(BINARY) dump_and_test.py
	echo 'TEST'
	./dump_and_test.py

.PHONY: test

clean:
	echo 'CLEAN $(OUTDIR)'
	rm -fr '$(OUTDIR)'
.PHONY: clean
