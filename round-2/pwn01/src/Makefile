CHALL := the_wilderness
SRCDIR := src
LIBDIR := libs
OUTDIR := build
SRCS   := $(wildcard $(SRCDIR)/*.c)
OBJS   := $(patsubst $(SRCDIR)/%.c,$(OUTDIR)/%.o,$(SRCS))
DEPS   := $(OBJS:.o=.d)
BINARY := $(OUTDIR)/$(CHALL)
DIST_DIR := ../attachments
CHECKER_DIR := ../checker

CC     := gcc
CFLAGS := -std=gnu99 -Wall -Wextra -pedantic -O0

.PHONY: all clean dist
.DEFAULT_GOAL := $(BINARY)

-include $(DEPS)

all: $(BINARY)

$(BINARY): $(OBJS)
	echo 'CCLD  $@'
	$(CC) $(CFLAGS) -o $@ $^

$(OUTDIR)/%.o: $(SRCDIR)/%.c | $(OUTDIR)
	echo 'CC    $@'
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUTDIR):
	echo 'MKDIR $@'
	mkdir -p $@

dist: clean $(BINARY)
	echo 'DIST $(DIST_DIR)'
	mkdir -p $(DIST_DIR)
	./make_attachment.sh
	cp $(BINARY) $(CHECKER_DIR)
	cp $(LIBDIR)/libc.so.6 $(LIBDIR)/ld-linux-x86-64.so.2 $(CHECKER_DIR)

clean:
	echo 'CLEAN $(OUTDIR)'
	rm -rf $(OUTDIR)/*
	echo 'CLEAN $(DIST_DIR)'
	rm -rf $(DIST_DIR)/*
	rm -rf $(CHECKER_DIR)/$(CHALL)
