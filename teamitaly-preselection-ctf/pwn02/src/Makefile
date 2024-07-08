#
# @mebeim - 2024-06-10
#
SRCDIR := src
OUTDIR := build
SRCS   := $(wildcard $(SRCDIR)/*.c)
OBJS   := $(patsubst $(SRCDIR)/%.c,$(OUTDIR)/%.o,$(SRCS))
DEPS   := $(OBJS:.o=.d)

CHALL_NAME  := pac
BINARY      := $(OUTDIR)/$(CHALL_NAME)
ARCHIVE_DIR := $(CHALL_NAME)
ARCHIVE     := ../attachments/$(CHALL_NAME).tar.gz

CC := aarch64-linux-gnu-gcc

CFLAGS := -O0 -std=gnu99 -MMD -Wall -Wextra \
	-static -no-pie -fno-pie -fno-asynchronous-unwind-tables \
	-fno-stack-protector \
	-Isrc

ifneq (,$(findstring aarch64,$(CC)))
	CFLAGS += -march=armv8.3-a -mbranch-protection=pac-ret
endif

MAKEFLAGS += --silent
.DEFAULT_GOAL := $(BINARY)

-include $(DEPS)

$(BINARY): $(OBJS) | $(OUTDIR)
	echo 'CCLD  $@'
	$(CC) $(CFLAGS) -o $@ $^

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

archive: $(ARCHIVE)

$(ARCHIVE): $(BINARY) qemu-7.2.12.patch docker-compose.yml Dockerfile PLAYER_README.md
	mkdir -p $(ARCHIVE_DIR)
	cp $(BINARY) qemu-7.2.12.patch Dockerfile $(ARCHIVE_DIR)
	cp PLAYER_README.md $(ARCHIVE_DIR)/README.md
	sed -e 's/TIMEOUT=[[:digit:]]\+/TIMEOUT=9999/' \
		-e 's/FLAG=TeamItaly{[^}]\+}/FLAG=TeamItaly{redacted}/' \
		-e '/POW_BYPASS_HASH=/d' \
		-e '/POW_BITS=/d' \
		docker-compose.yml > $(ARCHIVE_DIR)/docker-compose.yml
	tar czf $(ARCHIVE) $(ARCHIVE_DIR)
	rm -rf $(ARCHIVE_DIR)
