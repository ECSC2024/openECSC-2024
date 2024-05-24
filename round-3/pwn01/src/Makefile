CHALL_NAME  := xv6_homework
ARCHIVE_DIR := $(CHALL_NAME)
ARCHIVE     := ../attachments/$(CHALL_NAME).tar.gz

$(ARCHIVE): chall.patch chall.sh checksums.txt docker-compose.yml Dockerfile PLAYER_README.md
	mkdir -p $(ARCHIVE_DIR)
	cp chall.patch chall.sh checksums.txt Dockerfile $(ARCHIVE_DIR)
	cp PLAYER_README.md $(ARCHIVE_DIR)/README.md
	sed -e 's/TIMEOUT=[[:digit:]]\+/TIMEOUT=9999/' \
		-e 's/FLAG=openECSC{[^}]\+}/FLAG=openECSC{redacted}/' \
		-e '/POW_BYPASS_HASH=/d' \
		-e '/POW_BITS=/d' \
		docker-compose.yml > $(ARCHIVE_DIR)/docker-compose.yml
	tar czf $(ARCHIVE) $(ARCHIVE_DIR)
	rm -rf $(ARCHIVE_DIR)
