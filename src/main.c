/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "server.h"

/* Only the running flag needs to survive as a global for the signal handler */
static volatile sig_atomic_t *g_running;

static struct option          long_options[] = {
	{ "config",        required_argument, NULL, 'c' },
	{ "port",          required_argument, NULL, 'p' },
	{ "upstream",      required_argument, NULL, 'u' },
	{ "upstream-port", required_argument, NULL, 'P' },
	{ "verbose",       no_argument,       NULL, 'v' },
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
	fprintf(stderr, "  -v, --verbose          "
	                "Enable debug logging\n");
	fprintf(stderr, "  -h, --help             Show this help\n");
}

static void
signal_handler(int sig)
{
	(void)sig;
	if (g_running)
		*g_running = 0;
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

	while ((opt = getopt_long(argc, argv, "c:p:u:P:vh",
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
	struct dns_config cfg;
	struct server     srv;

	memset(&cfg, 0, sizeof(cfg));
	cfg.listen_port = 53;
	snprintf(cfg.upstream_addr, sizeof(cfg.upstream_addr), "8.8.8.8");
	cfg.upstream_port = 53;

	const char *config_path;
	bool        config_explicit;

	find_config_path(argc, argv, &config_path, &config_explicit);
	if (config_explicit || access(config_path, F_OK) == 0) {
		if (config_load(config_path, &cfg) < 0) {
			fprintf(stderr, "error: failed to load config file: %s\n",
			        config_path);
			return 1;
		}
	}

	int opt;
	while ((opt = getopt_long(argc, argv, "c:p:u:P:vh",
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
			cfg.listen_port = (int)port;
			break;
		}
		case 'u':
			snprintf(cfg.upstream_addr, sizeof(cfg.upstream_addr),
			         "%s", optarg);
			break;
		case 'P': {
			uint16_t port;
			if (config_parse_port_u16(optarg, &port) < 0) {
				fprintf(stderr,
				        "error: invalid upstream port: %s\n",
				        optarg);
				return 1;
			}
			cfg.upstream_port = port;
			break;
		}
		case 'v':
			log_set_level(LOG_DEBUG);
			break;
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
	if (inet_pton(AF_INET, cfg.upstream_addr, &tmp4) != 1
	    && inet_pton(AF_INET6, cfg.upstream_addr, &tmp6) != 1) {
		fprintf(stderr, "error: invalid upstream address: %s\n",
		        cfg.upstream_addr);
		return 1;
	}

	if (server_init(&srv, &cfg) < 0)
		return 1;

	g_running           = &srv.running;

	struct sigaction sa = {
		.sa_handler = signal_handler,
		.sa_flags   = 0,
	};
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	int rc = server_run(&srv);
	server_stop(&srv);

	return rc < 0 ? 1 : 0;
}
