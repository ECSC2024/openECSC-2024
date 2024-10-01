CHALL_NAME := backfired

OUTDIR     := dist
D8_BINARY  := $(OUTDIR)/d8
ARGS_GN    := args.gn
DOCKERFILE := Dockerfile.v8build

PATCHES_DIR := patches
PATCHES     := $(wildcard $(PATCHES_DIR)/*.patch)

ARCHIVE_DIR := $(CHALL_NAME)
ARCHIVE     := ../attachments/$(CHALL_NAME).tar.gz

DOCKER_CMD := DOCKER_BUILDKIT=1 docker build -f $(DOCKERFILE) --progress=plain --target release --output type=local,dest=$(OUTDIR) .
ifneq ($(shell id -Gn | grep -qw docker; echo $$?),0)
	ORIG_USER  := $(shell whoami)
	DOCKER_CMD := sudo sh -c '$(DOCKER_CMD) && chown -R $(ORIG_USER):$(ORIG_USER) $(OUTDIR)'
endif

$(D8_BINARY): $(DOCKERFILE) $(ARGS_GN) $(PATCHES)
	$(DOCKER_CMD)

.PHONY: archive
archive: $(ARCHIVE)

$(ARCHIVE): $(D8_BINARY) $(ARGS_GN) $(PATCHES) $(DOCKERFILE) chall.sh docker-compose.yml PLAYER_README.md
	mkdir -p $(ARCHIVE_DIR)
	mkdir -p $(ARCHIVE_DIR)/dist
	cp -r $(PATCHES_DIR) $(ARCHIVE_DIR)
	cp chall.sh $(ARCHIVE_DIR)
	cp PLAYER_README.md $(ARCHIVE_DIR)/README.md
	cp $(D8_BINARY) $(ARGS_GN) $(ARCHIVE_DIR)/dist
	sed -e 's|ARG ARGS_GN=args.gn|ARG ARGS_GN=dist/args.gn|' \
		$(DOCKERFILE) > $(ARCHIVE_DIR)/$(DOCKERFILE)
	sed -e 's/TIMEOUT=[[:digit:]]\+/TIMEOUT=9999/' \
		-e 's/FLAG=openECSC{[^}]\+}/FLAG=openECSC{redacted}/' \
		-e '/POW_BYPASS_HASH=/d' \
		-e '/POW_BITS=/d' \
		docker-compose.yml > $(ARCHIVE_DIR)/docker-compose.yml
	tar czf $(ARCHIVE) $(ARCHIVE_DIR)
	rm -rf $(ARCHIVE_DIR)
