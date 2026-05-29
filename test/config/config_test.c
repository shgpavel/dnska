/* SPDX-License-Identifier: MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "doh_server.h"
#include "test.h"

static void
init_config(struct dns_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->listen_port        = 53;
	cfg->listen_mode        = DNS_LISTEN_AUTO;
	cfg->doh_listen_port    = DOH_SERVER_DEFAULT_PORT;
	cfg->upstream_port      = 53;
	cfg->edns_padding_block = DNS_EDNS_PADDING_DEFAULT_BLOCK;
}

static void
load_config_text(const char *text, struct dns_config *cfg)
{
	char path[] = "/tmp/dnska-config-test-XXXXXX";
	int  fd     = mkstemp(path);
	TEST_CHECK(fd >= 0);

	FILE *f = fdopen(fd, "w");
	TEST_CHECK(f != NULL);
	TEST_CHECK(fputs(text, f) >= 0);
	TEST_CHECK(fclose(f) == 0);

	TEST_CHECK(config_load(path, cfg) == 0);
	unlink(path);
}

static int
try_load_config_text(const char *text, struct dns_config *cfg)
{
	char path[] = "/tmp/dnska-config-test-XXXXXX";
	int  fd     = mkstemp(path);
	TEST_CHECK(fd >= 0);

	FILE *f = fdopen(fd, "w");
	TEST_CHECK(f != NULL);
	TEST_CHECK(fputs(text, f) >= 0);
	TEST_CHECK(fclose(f) == 0);

	int rc = config_load(path, cfg);
	unlink(path);
	return rc;
}

static void
test_listen_mode_and_semicolon_comments(void)
{
	struct dns_config cfg;
	init_config(&cfg);

	load_config_text("; whole-line comment\n"
	                 "[dns]\n"
	                 "listen_mode = plain ; inline comment\n"
	                 "port = 5353 ; listen port\n"
	                 "upstream_port = 8853 ; upstream port\n",
	                 &cfg);

	TEST_EXPECT_INT_EQ(cfg.listen_mode, DNS_LISTEN_PLAIN);
	TEST_EXPECT_INT_EQ(cfg.listen_port, 5353);
	TEST_CHECK(cfg.listen_port_explicit);
	TEST_EXPECT_INT_EQ(cfg.upstream_port, 8853);
	TEST_CHECK(cfg.upstream_port_explicit);
}

static void
test_doh_listener_config(void)
{
	struct dns_config cfg;
	init_config(&cfg);

	load_config_text("[dns]\n"
	                 "listen_doh = true\n"
	                 "doh_listen_port = 8054\n",
	                 &cfg);

	TEST_CHECK(cfg.listen_doh);
	TEST_EXPECT_INT_EQ(cfg.doh_listen_port, 8054);
	TEST_CHECK(cfg.doh_listen_port_explicit);
}

static void
test_invalid_listen_mode_rejected(void)
{
	struct dns_config cfg;
	init_config(&cfg);

	TEST_CHECK(try_load_config_text("[dns]\nlisten_mode = tls\n",
	                                &cfg)
	           < 0);
}

static void
test_invalid_upstream_transport_rejected(void)
{
	struct dns_config cfg;
	init_config(&cfg);

	TEST_CHECK(try_load_config_text("[dns]\n"
	                                "upstream_transport = doq\n",
	                                &cfg)
	           < 0);
}

static void
test_invalid_doh_listen_port_rejected(void)
{
	struct dns_config cfg;
	init_config(&cfg);

	TEST_CHECK(try_load_config_text("[dns]\n"
	                                "doh_listen_port = 0\n",
	                                &cfg)
	           < 0);
}

static void
test_transport_defaults_legacy_dot_auto(void)
{
	struct dns_config cfg;
	init_config(&cfg);
	cfg.upstream_tls = true;

	config_apply_transport_defaults(&cfg, false);

	TEST_EXPECT_INT_EQ(cfg.upstream_transport,
	                   DNS_UPSTREAM_TRANSPORT_DOT);
	TEST_EXPECT_INT_EQ(config_effective_listen_mode(&cfg),
	                   DNS_LISTEN_DOT);
	TEST_EXPECT_INT_EQ(cfg.listen_port, 853);
	TEST_EXPECT_INT_EQ(cfg.upstream_port, 853);
}

static void
test_transport_defaults_plain_listener_dot_upstream(void)
{
	struct dns_config cfg;
	init_config(&cfg);
	cfg.listen_mode  = DNS_LISTEN_PLAIN;
	cfg.upstream_tls = true;

	config_apply_transport_defaults(&cfg, false);

	TEST_EXPECT_INT_EQ(cfg.upstream_transport,
	                   DNS_UPSTREAM_TRANSPORT_DOT);
	TEST_EXPECT_INT_EQ(config_effective_listen_mode(&cfg),
	                   DNS_LISTEN_PLAIN);
	TEST_EXPECT_INT_EQ(cfg.listen_port, 53);
	TEST_EXPECT_INT_EQ(cfg.upstream_port, 853);
}

static void
test_transport_defaults_dot_listener_doh_upstream(void)
{
	struct dns_config cfg;
	init_config(&cfg);
	cfg.listen_mode  = DNS_LISTEN_DOT;
	cfg.upstream_doh = true;

	config_apply_transport_defaults(&cfg, false);

	TEST_EXPECT_INT_EQ(cfg.upstream_transport,
	                   DNS_UPSTREAM_TRANSPORT_DOH);
	TEST_EXPECT_INT_EQ(config_effective_listen_mode(&cfg),
	                   DNS_LISTEN_DOT);
	TEST_CHECK(cfg.upstream_tls);
	TEST_CHECK(cfg.upstream_doh);
	TEST_EXPECT_INT_EQ(cfg.listen_port, 853);
	TEST_EXPECT_INT_EQ(cfg.upstream_port, 443);
	TEST_EXPECT_STR_EQ(cfg.doh_path, "/dns-query");
}

static void
test_transport_selector_config_doh(void)
{
	struct dns_config cfg;
	init_config(&cfg);

	load_config_text("[dns]\n"
	                 "upstream_transport = doh\n"
	                 "doh_path = /dns-alt\n",
	                 &cfg);

	config_apply_transport_defaults(&cfg, false);

	TEST_EXPECT_INT_EQ(cfg.upstream_transport,
	                   DNS_UPSTREAM_TRANSPORT_DOH);
	TEST_CHECK(cfg.upstream_transport_explicit);
	TEST_CHECK(cfg.upstream_tls);
	TEST_CHECK(cfg.upstream_doh);
	TEST_EXPECT_INT_EQ(cfg.upstream_port, 443);
	TEST_EXPECT_STR_EQ(cfg.doh_path, "/dns-alt");
}

static void
test_transport_selector_plain_overrides_hostname_default(void)
{
	struct dns_config cfg;
	init_config(&cfg);
	cfg.upstream_transport          = DNS_UPSTREAM_TRANSPORT_PLAIN;
	cfg.upstream_transport_explicit = true;

	config_apply_transport_defaults(&cfg, true);

	TEST_EXPECT_INT_EQ(cfg.upstream_transport,
	                   DNS_UPSTREAM_TRANSPORT_PLAIN);
	TEST_CHECK(!cfg.upstream_tls);
	TEST_CHECK(!cfg.upstream_doh);
	TEST_EXPECT_INT_EQ(config_effective_listen_mode(&cfg),
	                   DNS_LISTEN_PLAIN);
	TEST_EXPECT_INT_EQ(cfg.upstream_port, 53);
}

static void
test_transport_selector_conflicts_rejected(void)
{
	struct dns_config cfg;
	init_config(&cfg);

	TEST_CHECK(try_load_config_text("[dns]\n"
	                                "upstream_transport = plain\n"
	                                "upstream_tls = true\n",
	                                &cfg)
	           < 0);

	init_config(&cfg);
	TEST_CHECK(try_load_config_text("[dns]\n"
	                                "upstream_transport = dot\n"
	                                "upstream_doh = true\n",
	                                &cfg)
	           < 0);
}

static void
test_explicit_ports_survive_hostname_defaults(void)
{
	struct dns_config cfg;
	init_config(&cfg);
	cfg.listen_port            = 5300;
	cfg.listen_port_explicit   = true;
	cfg.upstream_port          = 5353;
	cfg.upstream_port_explicit = true;

	config_apply_transport_defaults(&cfg, true);

	TEST_EXPECT_INT_EQ(cfg.upstream_transport,
	                   DNS_UPSTREAM_TRANSPORT_DOT);
	TEST_CHECK(cfg.upstream_tls);
	TEST_EXPECT_INT_EQ(config_effective_listen_mode(&cfg),
	                   DNS_LISTEN_DOT);
	TEST_EXPECT_INT_EQ(cfg.listen_port, 5300);
	TEST_EXPECT_INT_EQ(cfg.upstream_port, 5353);
}

static void
test_edns_padding_and_discovery_config(void)
{
	struct dns_config cfg;
	init_config(&cfg);

	load_config_text("[dns]\n"
	                 "edns_padding = true\n"
	                 "edns_padding_block = 256\n"
	                 "resolver_discovery = true\n"
	                 "resolver_discovery_name = dns.example\n",
	                 &cfg);

	TEST_CHECK(cfg.edns_padding);
	TEST_EXPECT_INT_EQ(cfg.edns_padding_block, 256);
	TEST_CHECK(cfg.resolver_discovery);
	TEST_EXPECT_STR_EQ(cfg.resolver_discovery_name, "dns.example");
}

static void
test_edns_padding_default_block(void)
{
	struct dns_config cfg;
	init_config(&cfg);
	cfg.edns_padding_block = 0;
	cfg.edns_padding       = true;

	config_apply_transport_defaults(&cfg, false);

	TEST_EXPECT_INT_EQ(cfg.edns_padding_block,
	                   DNS_EDNS_PADDING_DEFAULT_BLOCK);
}

static void
test_doh_listener_default_port(void)
{
	struct dns_config cfg;
	init_config(&cfg);
	cfg.doh_listen_port = 0;
	cfg.listen_doh      = true;

	config_apply_transport_defaults(&cfg, false);

	TEST_EXPECT_INT_EQ(cfg.doh_listen_port, DOH_SERVER_DEFAULT_PORT);
}

static void
test_invalid_edns_padding_block_rejected(void)
{
	struct dns_config cfg;
	init_config(&cfg);

	TEST_CHECK(try_load_config_text("[dns]\n"
	                                "edns_padding_block = 1024\n",
	                                &cfg)
	           < 0);
}

int
main(void)
{
	test_listen_mode_and_semicolon_comments();
	test_doh_listener_config();
	test_invalid_listen_mode_rejected();
	test_invalid_upstream_transport_rejected();
	test_invalid_doh_listen_port_rejected();
	test_transport_defaults_legacy_dot_auto();
	test_transport_defaults_plain_listener_dot_upstream();
	test_transport_defaults_dot_listener_doh_upstream();
	test_transport_selector_config_doh();
	test_transport_selector_plain_overrides_hostname_default();
	test_transport_selector_conflicts_rejected();
	test_explicit_ports_survive_hostname_defaults();
	test_edns_padding_and_discovery_config();
	test_edns_padding_default_block();
	test_doh_listener_default_port();
	test_invalid_edns_padding_block_rejected();

	puts("config tests passed");
	return 0;
}
