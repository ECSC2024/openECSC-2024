CC     := gcc
CFLAGS := -std=c17 -Wall -Wextra -pedantic
LFLAGS := -Wl,-z,relro,-z,now
OUTDIR := bin
OBJDIR := obj
SRCDIR := src
BINARY := $(OUTDIR)/blind_writer

SRCS   := $(wildcard $(SRCDIR)/*.c)
OBJS := $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
INC := -Iinclude

DEBUG  := 0
ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG -g -O0
else
	CFLAGS += -O0
endif

.PHONY: all clean
.SILENT: all clean $(OUTDIR) $(BINARY) $(OBJDIR) $(OBJS)

all: $(BINARY)

$(BINARY): $(OBJS) | $(OUTDIR)
	@echo "Linking final binary $@"
	$(CC) $(CFLAGS) $(INC) $^ -o $@ $(LFLAGS)

$(OBJS): $(OBJDIR)/%.o : $(SRCDIR)/%.c | $(OBJDIR)
	@echo "Compiling object $@"
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

$(OUTDIR):
	@echo "MKDIR $@"
	mkdir -p $@

$(OBJDIR):
	@echo "MKDIR $@"
	mkdir -p $@

clean:
	@echo "RM $(OUTDIR) $(OBJDIR)"
	rm -fr $(OUTDIR) $(OBJDIR)
