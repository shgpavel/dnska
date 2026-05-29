/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "dns.h"
#include "log.h"
#include "print.h"
#include "random.h"
#include "resolver.h"
#include "server.h"

/* Only the running flag needs to survive as a global for the signal handler */
static volatile sig_atomic_t *g_running;

static struct option          long_options[] = {
	{ "config",        required_argument, NULL, 'c' },
	{ "port",          required_argument, NULL, 'p' },
	{ "listen-mode",   required_argument, NULL, 'M' }, /* long only */
	{ "upstream",      required_argument, NULL, 'u' },
	{ "upstream-port", required_argument, NULL, 'P' }, /* long only */
	{ "upstream-tls",  no_argument,       NULL, 't' },
	{ "tls-cert",      required_argument, NULL, 'C' }, /* long only */
	{ "tls-key",       required_argument, NULL, 'k' },
	{ "tls-ca",        required_argument, NULL, 'A' }, /* long only */
	{ "tls-auth-name", required_argument, NULL, 'N' }, /* long only */
	{ "insecure",      no_argument,       NULL, 'I' }, /* long only */
	{ "upstream-doh",  no_argument,       NULL, 'D' }, /* long only */
	{ "doh-path",      required_argument, NULL, 'X' }, /* long only */
	{ "query",         required_argument, NULL, 'q' },
	{ "type",          required_argument, NULL, 'T' }, /* long only */
	{ "class",         required_argument, NULL, 'L' }, /* long only */
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
	                "Listen port (default: 53; 853 for DoT listener)\n");
	fprintf(stderr, "      --listen-mode M    "
	                "Listener mode: auto, plain, or dot\n");
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
	fprintf(stderr, "      --tls-ca FILE      "
	                "CA bundle (PEM) for upstream cert verification\n"
	                "                         "
	                "(default: system trust paths)\n");
	fprintf(stderr, "      --tls-auth-name N  "
	                "Override SNI/verify name for IP-literal DoT\n");
	fprintf(stderr, "      --insecure         "
	                "Skip upstream cert verification (testing only)\n");
	fprintf(stderr, "      --upstream-doh     "
	                "Forward to upstream over DoH (RFC 8484);\n"
	                "                         "
	                "implies TLS, default port 443\n");
	fprintf(stderr, "      --doh-path PATH    "
	                "DoH URL path (default /dns-query)\n");
	fprintf(stderr, "  -q, --query NAME       "
	                "Client mode: look up NAME against the upstream\n"
	                "                         "
	                "and exit (does not start a server)\n");
	fprintf(stderr, "      --type TYPE        "
	                "RR type for -q (default A; "
	                "e.g. A, AAAA, MX, TYPE99)\n");
	fprintf(stderr, "      --class CLASS      "
	                "RR class for -q (default IN)\n");
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
	optind           = 0;
	*config_path     = "dnska.conf";
	*config_explicit = false;

	while ((opt = getopt_long(argc, argv, "c:p:u:tk:q:vh",
	                          long_options, NULL))
	       != -1) {
		if (opt == 'c') {
			*config_path     = optarg;
			*config_explicit = true;
		}
	}

	opterr = saved_opterr;
	optind = 0; /* glibc: full reset required after permutation */
}

static size_t
build_query_wire(uint8_t *buf, size_t buf_size, uint16_t id, const char *qname,
                 uint16_t qtype, uint16_t qclass)
{
	if (buf_size < DNS_HEADER_SIZE)
		return 0;

	memset(buf, 0, DNS_HEADER_SIZE);
	buf[0]             = (uint8_t)(id >> 8);
	buf[1]             = (uint8_t)id;
	buf[2]             = 0x01; /* RD=1, QR=0, opcode=QUERY */
	buf[3]             = 0x00;
	buf[5]             = 1;    /* QDCOUNT */

	size_t      pos    = DNS_HEADER_SIZE;
	const char *p      = qname;
	const char *labels = qname;

	while (1) {
		if (*p == '.' || *p == '\0') {
			size_t llen = (size_t)(p - labels);
			if (llen > DNS_MAX_LABEL_LEN)
				return 0;
			if (llen == 0 && *p != '\0')
				return 0;
			if (llen > 0) {
				if (pos + 1 + llen > buf_size)
					return 0;
				buf[pos++] = (uint8_t)llen;
				memcpy(buf + pos, labels, llen);
				pos += llen;
			}
			if (*p == '\0')
				break;
			labels = p + 1;
		}
		p++;
	}
	if (pos + 1 + 4 > buf_size)
		return 0;
	buf[pos++] = 0; /* root label */

	buf[pos++] = (uint8_t)(qtype >> 8);
	buf[pos++] = (uint8_t)qtype;
	buf[pos++] = (uint8_t)(qclass >> 8);
	buf[pos++] = (uint8_t)qclass;
	return pos;
}

static int
run_client_mode(struct dns_config *cfg, const char *qname, uint16_t qtype,
                uint16_t qclass)
{
	uint8_t  query[DNS_MAX_MSG_SIZE];
	uint8_t  response[DNS_MAX_MSG_SIZE];
	uint16_t id = 0;

	if (random_bytes(&id, sizeof(id)) < 0) {
		fprintf(stderr, "error: random id failed\n");
		return 1;
	}

	size_t query_len = build_query_wire(query, sizeof(query), id, qname,
	                                    qtype, qclass);
	if (query_len == 0) {
		fprintf(stderr, "error: invalid qname: %s\n", qname);
		return 1;
	}

	resolver_set_tls_config(cfg->tls_ca_file, cfg->tls_auth_name,
	                        cfg->tls_insecure);

	size_t response_len = 0;
	int    rc           = resolver_forward(cfg->upstream_addrs,
	                                       cfg->upstream_addr_count,
	                                       cfg->upstream_port,
	                                       cfg->upstream_tls,
	                                       cfg->upstream_doh, cfg->doh_path,
	                                       cfg->upstream_hostname, query,
	                                       query_len, response,
	                                       sizeof(response), &response_len);
	if (rc < 0) {
		fprintf(stderr, "error: upstream forward failed\n");
		return 1;
	}

	if (dns_print_response(stdout, response, response_len) < 0) {
		fprintf(stderr, "error: failed to parse upstream response\n");
		return 1;
	}

	uint8_t rcode = (uint8_t)(response[3] & DNS_FLAGS_RCODE_MASK);
	return rcode == DNS_RCODE_OK ? 0 : 2;
}

int
main(int argc, char **argv)
{
	struct dns_config cfg;
	struct server     srv;
	const char       *query_name  = NULL;
	uint16_t          query_type  = DNS_TYPE_A;
	uint16_t          query_class = DNS_CLASS_IN;

	memset(&cfg, 0, sizeof(cfg));
	cfg.listen_port = 53;
	cfg.listen_mode = DNS_LISTEN_AUTO;
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
	optind = 0;
	while ((opt = getopt_long(argc, argv, "c:p:u:tk:q:vh",
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
			cfg.listen_port          = (int)port;
			cfg.listen_port_explicit = true;
			break;
		}
		case 'M':
			if (config_parse_listen_mode(optarg,
			                             &cfg.listen_mode)
			    < 0) {
				fprintf(stderr,
				        "error: invalid listen mode: %s\n",
				        optarg);
				return 1;
			}
			break;
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
			cfg.upstream_port          = port;
			cfg.upstream_port_explicit = true;
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
		case 'A':
			snprintf(cfg.tls_ca_file, sizeof(cfg.tls_ca_file),
			         "%s", optarg);
			break;
		case 'N':
			snprintf(cfg.tls_auth_name, sizeof(cfg.tls_auth_name),
			         "%s", optarg);
			break;
		case 'I':
			cfg.tls_insecure = true;
			break;
		case 'D':
			cfg.upstream_doh = true;
			break;
		case 'X':
			snprintf(cfg.doh_path, sizeof(cfg.doh_path), "%s",
			         optarg);
			break;
		case 'q':
			query_name = optarg;
			break;
		case 'T':
			if (dns_type_from_str(optarg, &query_type) < 0) {
				fprintf(stderr, "error: unknown type: %s\n",
				        optarg);
				return 1;
			}
			break;
		case 'L':
			if (strcasecmp(optarg, "IN") == 0)
				query_class = DNS_CLASS_IN;
			else {
				fprintf(stderr, "error: only class IN supported "
				                "(got %s)\n",
				        optarg);
				return 1;
			}
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
	bool            upstream_is_hostname = false;

	if (inet_pton(AF_INET, cfg.upstream_addr, &tmp4) != 1
	    && inet_pton(AF_INET6, cfg.upstream_addr, &tmp6) != 1)
		upstream_is_hostname = true;

	if (upstream_is_hostname) {
		/*
		 * Not a literal IP address: treat as a hostname and resolve
		 * it.  Transport defaults are applied after resolution.
		 */
		snprintf(cfg.upstream_hostname, sizeof(cfg.upstream_hostname),
		         "%s", cfg.upstream_addr);

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

		cfg.upstream_addr_count = 0;
		for (struct addrinfo *ai = res;
		     ai != NULL
		     && cfg.upstream_addr_count < DNS_UPSTREAM_MAX_ADDRS;
		     ai = ai->ai_next) {
			char *slot = cfg.upstream_addrs[cfg.upstream_addr_count];
			if (ai->ai_family == AF_INET6) {
				struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)ai->ai_addr;
				inet_ntop(AF_INET6, &a6->sin6_addr, slot,
				          INET6_ADDRSTRLEN);
			} else if (ai->ai_family == AF_INET) {
				struct sockaddr_in *a4 = (struct sockaddr_in *)ai->ai_addr;
				inet_ntop(AF_INET, &a4->sin_addr, slot,
				          INET6_ADDRSTRLEN);
			} else {
				continue;
			}
			cfg.upstream_addr_count++;
		}
		freeaddrinfo(res);

		if (cfg.upstream_addr_count == 0) {
			fprintf(stderr,
			        "error: no usable addresses for '%s'\n",
			        cfg.upstream_hostname);
			return 1;
		}
		snprintf(cfg.upstream_addr, sizeof(cfg.upstream_addr), "%s",
		         cfg.upstream_addrs[0]);
	} else {
		snprintf(cfg.upstream_addrs[0], INET6_ADDRSTRLEN, "%s",
		         cfg.upstream_addr);
		cfg.upstream_addr_count = 1;
	}

	config_apply_transport_defaults(&cfg, upstream_is_hostname);

	/*
	 * DoH implies TLS upstream and requires a hostname (Host header).
	 * For an IP-literal upstream the operator must supply --tls-auth-name.
	 */
	if (cfg.upstream_doh) {
		if (cfg.upstream_hostname[0] == '\0'
		    && cfg.tls_auth_name[0] == '\0') {
			fprintf(stderr,
			        "error: --upstream-doh with an IP-literal "
			        "upstream requires --tls-auth-name\n");
			return 1;
		}
	}

	/*
	 * Client mode: skip the server entirely, look up the name and
	 * print the response in dig-style.
	 */
	if (query_name != NULL)
		return run_client_mode(&cfg, query_name, query_type,
		                       query_class);

	/*
	 * Refuse a world- or group-readable TLS private key.
	 */
	if (cfg.tls_key[0] != '\0') {
		struct stat st;
		if (stat(cfg.tls_key, &st) < 0) {
			fprintf(stderr, "error: cannot stat tls key %s: %s\n",
			        cfg.tls_key, strerror(errno));
			return 1;
		}
		if ((st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH))
		    != 0) {
			fprintf(stderr,
			        "error: tls key %s is group/other accessible "
			        "(mode %04o); chmod 600\n",
			        cfg.tls_key, st.st_mode & 0777);
			return 1;
		}
	}

	resolver_set_tls_config(cfg.tls_ca_file, cfg.tls_auth_name,
	                        cfg.tls_insecure);
	if (cfg.tls_insecure)
		log_msg(LOG_WARN,
		        "resolver: --insecure: upstream certs NOT verified\n");

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
