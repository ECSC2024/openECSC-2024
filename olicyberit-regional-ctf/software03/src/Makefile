CC     := gcc
CFLAGS := -std=c99 -Wall -Wextra -pedantic -O0
LDFLAGS := -no-pie

CHALL := age_calculator_pro
OUTDIR := build
SOURCE := $(CHALL).c
BINARY := $(OUTDIR)/$(patsubst %.c,%,$(SOURCE))
DIST_DIR := ../attachments
CHECKER_DIR := ../checker

.PHONY: all clean dist
# .SILENT: all clean dist $(OUTDIR) $(BINARY)

all: $(BINARY)

$(OUTDIR):
	echo 'MKDIR $@'
	mkdir -p $@

$(BINARY): $(SOURCE) | $(OUTDIR)
	echo 'CCLD  $@'
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

dist: clean $(BINARY)
	echo 'DIST $(DIST_DIR)'
	mkdir -p $(DIST_DIR)
	./make_attachment.sh
	cp $(BINARY) $(CHECKER_DIR)

clean:
	echo 'CLEAN $(OUTDIR)'
	rm -rf $(OUTDIR)
	echo 'CLEAN $(DIST_DIR)'
	find $(DIST_DIR) -mindepth 1 -delete
	rm -rf $(CHECKER_DIR)/$(CHALL)
