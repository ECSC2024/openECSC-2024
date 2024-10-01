CHALL := middleout
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
	echo 'CCLD $@'
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

dist:
	echo 'DIST $(DIST_DIR)'
	mkdir -p $(DIST_DIR)
	./make_attachment.sh
	cp $(BINARY) $(CHECKER_DIR)

clean:
	echo 'CLEAN $(OUTDIR)'
	rm -rf $(OUTDIR)
	echo 'CLEAN $(DIST_DIR)'
	rm -rf $(DIST_DIR)/*
	rm -rf $(CHECKER_DIR)/$(CHALL)
