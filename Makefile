CC      = clang
CFLAGS  = -std=c23 -Wall -Wextra -Wpedantic -O2 -D_POSIX_C_SOURCE=200809L \
          -Isrc/include -Itest
LDFLAGS = -pthread -lssl -lcrypto

SRCDIR  = src
OBJDIR  = build
TARGET  = build/dnska
TESTDIR = test
TESTOBJDIR = $(OBJDIR)/test

PREFIX     ?= /usr
BINDIR     ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc
DOCDIR     ?= $(PREFIX)/share/doc/dnska

SRCS    = $(SRCDIR)/main.c $(SRCDIR)/cache.c $(SRCDIR)/config.c $(SRCDIR)/dns.c $(SRCDIR)/dnssec.c $(SRCDIR)/doh_server.c $(SRCDIR)/log.c $(SRCDIR)/odoh.c $(SRCDIR)/print.c $(SRCDIR)/random.c $(SRCDIR)/server.c $(SRCDIR)/resolver.c $(SRCDIR)/wire.c
OBJS    = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))
HDRS    = $(wildcard $(SRCDIR)/include/*.h)
TEST_SRCS = $(wildcard $(TESTDIR)/*/*_test.c)
TEST_NAMES = $(notdir $(basename $(TEST_SRCS)))
TEST_TARGETS = $(addprefix $(TESTOBJDIR)/,$(TEST_NAMES))

PERF_SRCS = $(wildcard $(TESTDIR)/perf/*_perf.c)
PERF_NAMES = $(notdir $(basename $(PERF_SRCS)))
PERF_TARGETS = $(addprefix $(TESTOBJDIR)/,$(PERF_NAMES))

all: $(TARGET)

check: $(TEST_TARGETS)
	set -e; for t in $(TEST_TARGETS); do "$$t"; done

perf: $(PERF_TARGETS)
	set -e; for t in $(PERF_TARGETS); do "$$t"; done

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TESTOBJDIR)/cache_test: $(TESTDIR)/cache/cache_test.c $(SRCDIR)/cache.c $(SRCDIR)/random.c $(SRCDIR)/wire.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/cache/cache_test.c $(SRCDIR)/cache.c $(SRCDIR)/random.c $(SRCDIR)/wire.c

$(TESTOBJDIR)/config_test: $(TESTDIR)/config/config_test.c $(SRCDIR)/config.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/config/config_test.c $(SRCDIR)/config.c

$(TESTOBJDIR)/dns_test: $(TESTDIR)/dns/dns_test.c $(SRCDIR)/dns.c $(SRCDIR)/wire.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/dns/dns_test.c $(SRCDIR)/dns.c $(SRCDIR)/wire.c

$(TESTOBJDIR)/dnssec_test: $(TESTDIR)/dnssec/dnssec_test.c $(SRCDIR)/dnssec.c $(SRCDIR)/dns.c $(SRCDIR)/wire.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/dnssec/dnssec_test.c $(SRCDIR)/dnssec.c $(SRCDIR)/dns.c $(SRCDIR)/wire.c

$(TESTOBJDIR)/doh_server_test: $(TESTDIR)/doh_server/doh_server_test.c $(SRCDIR)/doh_server.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/doh_server/doh_server_test.c $(SRCDIR)/doh_server.c

$(TESTOBJDIR)/odoh_test: $(TESTDIR)/odoh/odoh_test.c $(SRCDIR)/odoh.c $(SRCDIR)/wire.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/odoh/odoh_test.c $(SRCDIR)/odoh.c $(SRCDIR)/wire.c

$(TESTOBJDIR)/print_test: $(TESTDIR)/print/print_test.c $(SRCDIR)/print.c $(SRCDIR)/dns.c $(SRCDIR)/wire.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/print/print_test.c $(SRCDIR)/print.c $(SRCDIR)/dns.c $(SRCDIR)/wire.c

$(TESTOBJDIR)/resolver_test: $(TESTDIR)/resolver/resolver_test.c $(SRCDIR)/resolver.c $(SRCDIR)/dns.c $(SRCDIR)/random.c $(SRCDIR)/wire.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/resolver/resolver_test.c $(SRCDIR)/resolver.c $(SRCDIR)/dns.c $(SRCDIR)/random.c $(SRCDIR)/wire.c

$(TESTOBJDIR)/server_test: $(TESTDIR)/server/server_test.c \
    $(SRCDIR)/server.c $(SRCDIR)/cache.c $(SRCDIR)/config.c \
    $(SRCDIR)/doh_server.c \
    $(SRCDIR)/dns.c $(SRCDIR)/dnssec.c $(SRCDIR)/log.c $(SRCDIR)/random.c \
    $(SRCDIR)/resolver.c $(SRCDIR)/wire.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/server/server_test.c \
	    $(SRCDIR)/server.c $(SRCDIR)/cache.c $(SRCDIR)/config.c \
	    $(SRCDIR)/doh_server.c \
	    $(SRCDIR)/dns.c $(SRCDIR)/dnssec.c $(SRCDIR)/log.c $(SRCDIR)/random.c \
	    $(SRCDIR)/resolver.c $(SRCDIR)/wire.c

$(TESTOBJDIR)/dns_perf: $(TESTDIR)/perf/dns_perf.c $(SRCDIR)/dns.c $(SRCDIR)/wire.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/perf/dns_perf.c $(SRCDIR)/dns.c $(SRCDIR)/wire.c

$(TESTOBJDIR)/cache_perf: $(TESTDIR)/perf/cache_perf.c \
    $(SRCDIR)/cache.c $(SRCDIR)/random.c $(SRCDIR)/wire.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TESTDIR)/perf/cache_perf.c \
	    $(SRCDIR)/cache.c $(SRCDIR)/random.c $(SRCDIR)/wire.c

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/dnska
	install -d $(DESTDIR)$(SYSCONFDIR)/dnska
	install -m 0644 dnska.conf.example $(DESTDIR)$(SYSCONFDIR)/dnska/dnska.conf.example
	install -d $(DESTDIR)$(DOCDIR)
	install -m 0644 README.md $(DESTDIR)$(DOCDIR)/README.md

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/dnska
	rm -f $(DESTDIR)$(SYSCONFDIR)/dnska/dnska.conf.example
	-rmdir $(DESTDIR)$(SYSCONFDIR)/dnska 2>/dev/null
	rm -f $(DESTDIR)$(DOCDIR)/README.md
	-rmdir $(DESTDIR)$(DOCDIR) 2>/dev/null

clean:
	rm -rf $(OBJDIR)

.PHONY: all check perf install uninstall clean
