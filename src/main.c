/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
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
	{ "upstream-port", required_argument, NULL, 'P' }, /* long only */
	{ "upstream-tls",  no_argument,       NULL, 't' },
	{ "tls-cert",      required_argument, NULL, 'C' }, /* long only */
	{ "tls-key",       required_argument, NULL, 'k' },
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
	                "Upstream DNS server IP or hostname (default: 8.8.8.8);\n"
	                "                         "
	                "hostname implies DoT (port 853)\n");
	fprintf(stderr, "      --upstream-port N  "
	                "Upstream port (default: 53)\n");
	fprintf(stderr, "  -t, --upstream-tls     "
	                "Force DoT upstream when using an IP address\n");
	fprintf(stderr, "      --tls-cert FILE    "
	                "TLS certificate (PEM) for DoT listener (optional;\n"
	                "                         "
	                "auto-generated if omitted)\n");
	fprintf(stderr, "  -k, --tls-key  FILE    "
	                "TLS private key (PEM) for DoT listener\n");
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

	while ((opt = getopt_long(argc, argv, "c:p:u:tk:vh",
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

	bool upstream_port_explicit = false;
	bool listen_port_explicit   = false;
	int  opt;
	while ((opt = getopt_long(argc, argv, "c:p:u:tk:vh",
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
			cfg.listen_port      = (int)port;
			listen_port_explicit = true;
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
			cfg.upstream_port      = port;
			upstream_port_explicit = true;
			break;
		}
		case 't':
			cfg.upstream_tls = true;
			break;
		case 'C':
			snprintf(cfg.tls_cert, sizeof(cfg.tls_cert),
			         "%s", optarg);
			break;
		case 'k':
			snprintf(cfg.tls_key, sizeof(cfg.tls_key),
			         "%s", optarg);
			break;
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
		/*
		 * Not a literal IP address: treat as a hostname and resolve
		 * it.  A hostname upstream implies DoT; default to port 853
		 * unless the user set a port explicitly.
		 */
		snprintf(cfg.upstream_hostname, sizeof(cfg.upstream_hostname),
		         "%s", cfg.upstream_addr);
		cfg.upstream_tls = true;
		if (!upstream_port_explicit)
			cfg.upstream_port = 853;

		struct addrinfo  hints;
		struct addrinfo *res = NULL;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family   = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		int gai           = getaddrinfo(cfg.upstream_addr, NULL, &hints, &res);
		if (gai != 0) {
			fprintf(stderr,
			        "error: cannot resolve upstream hostname '%s': %s\n",
			        cfg.upstream_addr, gai_strerror(gai));
			return 1;
		}

		if (res->ai_family == AF_INET6) {
			struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)res->ai_addr;
			inet_ntop(AF_INET6, &a6->sin6_addr,
			          cfg.upstream_addr, sizeof(cfg.upstream_addr));
		} else {
			struct sockaddr_in *a4 = (struct sockaddr_in *)res->ai_addr;
			inet_ntop(AF_INET, &a4->sin_addr,
			          cfg.upstream_addr, sizeof(cfg.upstream_addr));
		}

		freeaddrinfo(res);
	}

	/*
	 * When DoT mode is active (hostname upstream or -t flag) default the
	 * listen port to 853 unless the user set one explicitly.
	 */
	if (cfg.upstream_tls && !listen_port_explicit)
		cfg.listen_port = 853;

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
