CC := gcc
CFLAGS := -Wall -Wextra -Werror -std=c17 -pedantic -O0 -fPIE -pie
LFLAGS := -Wl,-z,relro,-z,now
SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin
INC_DIR := include
BINARY := $(BIN_DIR)/ctf-teams
ABS_BIN_DIR := $(shell realpath $(BIN_DIR))

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

CFLAGS += -I$(INC_DIR)

# Debug mode
DEBUG := 0
ifeq ($(DEBUG), 1)
	CFLAGS += -g -O0 -DDEBUG
endif

all: $(BINARY)

$(BINARY): $(OBJS) | $(BIN_DIR)
	@echo "Linking final binary: $@"
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS)

$(OBJS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c | $(OBJ_DIR)
	@echo "Compiling object $@"
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Directories targets
$(BIN_DIR):
	@echo "MKDIR $@"
	@mkdir -p $@

$(OBJ_DIR):
	@echo "MKDIR $@"
	@mkdir -p $@

clean:
	@echo "RM $(OBJ_DIR) $(BIN_DIR)"
	rm -rf $(OBJ_DIR) $(BIN_DIR)

patch: $(BINARY)
	@echo "Patching binary"
	cp -r ./glibc $(BIN_DIR)/glibc
	patchelf --set-interpreter $(ABS_BIN_DIR)/glibc/ld-linux-x86-64.so.2 --set-rpath $(ABS_BIN_DIR)/glibc/ $(BINARY)
	@echo "Done"

# Include dependency files
-include $(OBJS:.o=.d)

.PHONY: all clean
