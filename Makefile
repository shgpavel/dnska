CC      = clang
CFLAGS  = -std=c23 -Wall -Wextra -Wpedantic -O2 -D_POSIX_C_SOURCE=200809L \
          -Isrc/include -Itest
LDFLAGS = -pthread

SRCDIR  = src
OBJDIR  = build
TARGET  = build/dnska
TESTDIR = test
TESTOBJDIR = $(OBJDIR)/test

SRCS    = $(SRCDIR)/main.c $(SRCDIR)/cache.c $(SRCDIR)/config.c $(SRCDIR)/dns.c $(SRCDIR)/random.c $(SRCDIR)/server.c $(SRCDIR)/resolver.c $(SRCDIR)/wire.c
OBJS    = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))
HDRS    = $(wildcard $(SRCDIR)/include/*.h)
TEST_SRCS = $(wildcard $(TESTDIR)/*/*_test.c)
TEST_NAMES = $(notdir $(basename $(TEST_SRCS)))
TEST_TARGETS = $(addprefix $(TESTOBJDIR)/,$(TEST_NAMES))

all: $(TARGET)

check: $(TEST_TARGETS)
	for t in $(TEST_TARGETS); do ./$$t; done

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TESTOBJDIR)/cache_test: $(TESTDIR)/cache/cache_test.c $(SRCDIR)/cache.c $(SRCDIR)/random.c $(SRCDIR)/wire.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/cache/cache_test.c $(SRCDIR)/cache.c $(SRCDIR)/random.c $(SRCDIR)/wire.c

$(TESTOBJDIR)/dns_test: $(TESTDIR)/dns/dns_test.c $(SRCDIR)/dns.c $(SRCDIR)/wire.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/dns/dns_test.c $(SRCDIR)/dns.c $(SRCDIR)/wire.c

$(TESTOBJDIR)/resolver_test: $(TESTDIR)/resolver/resolver_test.c $(SRCDIR)/resolver.c $(SRCDIR)/random.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/resolver/resolver_test.c $(SRCDIR)/resolver.c $(SRCDIR)/random.c

clean:
	rm -rf $(OBJDIR)

.PHONY: all check clean
