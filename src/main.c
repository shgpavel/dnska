/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "server.h"

static struct server_config g_config;

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
	g_config.running = 0;
}

static int
parse_port(const char *s, int *out)
{
	char *endptr;
	errno    = 0;
	long val = strtol(s, &endptr, 10);
	if (errno != 0 || endptr == s || *endptr != '\0')
		return -1;
	if (val <= 0 || val > 65535)
		return -1;
	*out = (int)val;
	return 0;
}

int
main(int argc, char **argv)
{
	memset(&g_config, 0, sizeof(g_config));
	g_config.listen_port = 53;
	snprintf(g_config.upstream_addr, sizeof(g_config.upstream_addr),
	         "8.8.8.8");
	g_config.upstream_port      = 53;
	g_config.sock_fd            = -1;
	g_config.sock_fd6           = -1;

	const char *config_path     = "dnska.conf";
	bool        config_explicit = false;
	for (int i = 1; i < argc; i++) {
		if ((strcmp(argv[i], "-c") == 0
		     || strcmp(argv[i], "--config") == 0)
		    && i + 1 < argc) {
			config_path     = argv[i + 1];
			config_explicit = true;
			break;
		}
		if (strncmp(argv[i], "--config=", 9) == 0) {
			config_path     = argv[i] + 9;
			config_explicit = true;
			break;
		}
	}

	if (config_load(config_path, &g_config) < 0 && config_explicit) {
		fprintf(stderr, "error: cannot open config file: %s\n",
		        config_path);
		return 1;
	}

	static struct option long_options[] = {
		{ "config",        required_argument, NULL, 'c' },
		{ "port",          required_argument, NULL, 'p' },
		{ "upstream",      required_argument, NULL, 'u' },
		{ "upstream-port", required_argument, NULL, 'P' },
		{ "help",          no_argument,       NULL, 'h' },
		{ NULL,            0,                 NULL, 0   },
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "c:p:u:P:h",
	                          long_options, NULL))
	       != -1) {
		switch (opt) {
		case 'c':
			break;
		case 'p': {
			int port;
			if (parse_port(optarg, &port) < 0) {
				fprintf(stderr, "error: invalid port: %s\n",
				        optarg);
				return 1;
			}
			g_config.listen_port = port;
			break;
		}
		case 'u':
			snprintf(g_config.upstream_addr,
			         sizeof(g_config.upstream_addr), "%s", optarg);
			break;
		case 'P': {
			int port;
			if (parse_port(optarg, &port) < 0) {
				fprintf(stderr, "error: invalid upstream "
				                "port: %s\n",
				        optarg);
				return 1;
			}
			g_config.upstream_port = (uint16_t)port;
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

	if (server_init(&g_config) < 0)
		return 1;

	int rc = server_run(&g_config);
	server_stop(&g_config);

	return rc < 0 ? 1 : 0;
}
