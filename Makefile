CC      = clang
CFLAGS  = -std=c23 -Wall -Wextra -Wpedantic -O2 -D_POSIX_C_SOURCE=200809L \
          -Isrc/include
LDFLAGS = -pthread

SRCDIR  = src
OBJDIR  = build
TARGET  = build/dnska

SRCS    = $(SRCDIR)/main.c $(SRCDIR)/config.c $(SRCDIR)/dns.c $(SRCDIR)/server.c $(SRCDIR)/resolver.c
OBJS    = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))
HDRS    = $(wildcard $(SRCDIR)/include/*.h)

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJDIR)

.PHONY: all clean
