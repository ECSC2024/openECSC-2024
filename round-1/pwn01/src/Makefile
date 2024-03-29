SRCDIR := src
OUTDIR := build
SRCS   := $(wildcard $(SRCDIR)/*.c)
OBJS   := $(patsubst $(SRCDIR)/%.c,$(OUTDIR)/%.o,$(SRCS))
DEPS   := $(OBJS:.o=.d)
BINARY := $(OUTDIR)/no_headache

CC     := gcc
CFLAGS := -std=gnu99 -MMD -Wall -Wextra -pedantic -O0

MAKEFLAGS += --silent
.DEFAULT_GOAL := $(BINARY)

-include $(DEPS)

$(BINARY): $(OBJS)
	echo 'CCLD  $@'
	$(CC) $(CFLAGS) -o $@ $^
	echo 'STRIP $@'
	strip -R.comment $@

$(OUTDIR)/%.o: $(SRCDIR)/%.c | $(OUTDIR)
	echo 'CC    $@'
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUTDIR):
	echo 'MKDIR $@'
	mkdir -p $@

clean:
	echo 'CLEAN $(OUTDIR)'
	rm -fr '$(OUTDIR)'
.PHONY: clean
