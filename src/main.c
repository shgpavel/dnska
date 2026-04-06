/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "server.h"

static struct dns_config g_config;
static struct server     g_server;

static struct option     long_options[] = {
	{ "config",        required_argument, NULL, 'c' },
	{ "port",          required_argument, NULL, 'p' },
	{ "upstream",      required_argument, NULL, 'u' },
	{ "upstream-port", required_argument, NULL, 'P' },
	{ "help",          no_argument,       NULL, 'h' },
	{ NULL,            0,                 NULL, 0   },
};

static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n", prog);
	fprintf(stderr, "  -c, --config FILE      "
	                "Config file (default: dnska.conf)\n");
	fprintf(stderr, "  -p, --port PORT        "
	                "Listen port (default: 53)\n");
	fprintf(stderr, "  -u, --upstream ADDR    "
	                "Upstream DNS server (default: 8.8.8.8)\n");
	fprintf(stderr, "  -P, --upstream-port N  "
	                "Upstream port (default: 53)\n");
	fprintf(stderr, "  -h, --help             Show this help\n");
}

static void
signal_handler(int sig)
{
	(void)sig;
	g_server.running = 0;
}

static void
find_config_path(int argc, char **argv, const char **config_path,
                 bool *config_explicit)
{
	int saved_opterr = opterr;
	int opt;

	opterr           = 0;
	optind           = 1;
	*config_path     = "dnska.conf";
	*config_explicit = false;

	while ((opt = getopt_long(argc, argv, "c:p:u:P:h",
	                          long_options, NULL))
	       != -1) {
		if (opt == 'c') {
			*config_path     = optarg;
			*config_explicit = true;
		}
	}

	opterr = saved_opterr;
	optind = 1;
}

int
main(int argc, char **argv)
{
	memset(&g_config, 0, sizeof(g_config));
	memset(&g_server, 0, sizeof(g_server));
	g_config.listen_port = 53;
	snprintf(g_config.upstream_addr, sizeof(g_config.upstream_addr),
	         "8.8.8.8");
	g_config.upstream_port = 53;

	const char *config_path;
	bool        config_explicit;

	find_config_path(argc, argv, &config_path, &config_explicit);
	if (config_explicit || access(config_path, F_OK) == 0) {
		if (config_load(config_path, &g_config) < 0) {
			fprintf(stderr, "error: failed to load config file: %s\n",
			        config_path);
			return 1;
		}
	}

	int opt;
	while ((opt = getopt_long(argc, argv, "c:p:u:P:h",
	                          long_options, NULL))
	       != -1) {
		switch (opt) {
		case 'c':
			break;
		case 'p': {
			uint16_t port;
			if (config_parse_port_u16(optarg, &port) < 0) {
				fprintf(stderr, "error: invalid port: %s\n",
				        optarg);
				return 1;
			}
			g_config.listen_port = (int)port;
			break;
		}
		case 'u':
			snprintf(g_config.upstream_addr,
			         sizeof(g_config.upstream_addr), "%s", optarg);
			break;
		case 'P': {
			uint16_t port;
			if (config_parse_port_u16(optarg, &port) < 0) {
				fprintf(stderr, "error: invalid upstream "
				                "port: %s\n",
				        optarg);
				return 1;
			}
			g_config.upstream_port = port;
			break;
		}
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	struct in_addr  tmp4;
	struct in6_addr tmp6;
	if (inet_pton(AF_INET, g_config.upstream_addr, &tmp4) != 1
	    && inet_pton(AF_INET6, g_config.upstream_addr,
	                 &tmp6)
	               != 1) {
		fprintf(stderr, "error: invalid upstream address: %s\n",
		        g_config.upstream_addr);
		return 1;
	}

	struct sigaction sa = {
		.sa_handler = signal_handler,
		.sa_flags   = 0,
	};
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (server_init(&g_server, &g_config) < 0)
		return 1;

	int rc = server_run(&g_server);
	server_stop(&g_server);

	return rc < 0 ? 1 : 0;
}
