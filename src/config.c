/* SPDX-License-Identifier: MIT */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

static char *
trim(char *s)
{
	while (isspace((unsigned char)*s))
		s++;
	char *end = s + strlen(s);
	while (end > s && isspace((unsigned char)*(end - 1)))
		end--;
	*end = '\0';
	return s;
}

static void
strip_comment(char *s)
{
	bool in_quote = false;

	for (; *s != '\0'; s++) {
		if (*s == '"')
			in_quote = !in_quote;
		if (!in_quote && (*s == '#' || *s == ';')) {
			*s = '\0';
			return;
		}
	}
}

static bool
parse_bool(const char *value)
{
	return strcmp(value, "1") == 0
	       || strcmp(value, "yes") == 0
	       || strcmp(value, "true") == 0
	       || strcmp(value, "on") == 0;
}

int
config_parse_port_u16(const char *value, uint16_t *out)
{
	char *endptr;

	errno     = 0;
	long port = strtol(value, &endptr, 10);
	if (errno != 0 || endptr == value || *endptr != '\0')
		return -1;
	if (port <= 0 || port > 65535)
		return -1;

	*out = (uint16_t)port;
	return 0;
}

int
config_parse_edns_padding_block(const char *value, uint16_t *out)
{
	uint16_t block;

	if (config_parse_port_u16(value, &block) < 0)
		return -1;
	if (block > DNS_EDNS_PADDING_MAX_BLOCK)
		return -1;

	*out = block;
	return 0;
}

int
config_parse_listen_mode(const char *value, enum dns_listen_mode *out)
{
	if (strcmp(value, "auto") == 0) {
		*out = DNS_LISTEN_AUTO;
		return 0;
	}
	if (strcmp(value, "plain") == 0) {
		*out = DNS_LISTEN_PLAIN;
		return 0;
	}
	if (strcmp(value, "dot") == 0) {
		*out = DNS_LISTEN_DOT;
		return 0;
	}

	return -1;
}

enum dns_listen_mode
config_effective_listen_mode(const struct dns_config *cfg)
{
	if (cfg->listen_mode != DNS_LISTEN_AUTO)
		return cfg->listen_mode;

	if (cfg->upstream_tls && !cfg->upstream_doh)
		return DNS_LISTEN_DOT;

	return DNS_LISTEN_PLAIN;
}

void
config_apply_transport_defaults(struct dns_config *cfg, bool upstream_is_hostname)
{
	if (upstream_is_hostname)
		cfg->upstream_tls = true;
	if (cfg->edns_padding && cfg->edns_padding_block == 0)
		cfg->edns_padding_block = DNS_EDNS_PADDING_DEFAULT_BLOCK;

	if (cfg->upstream_doh) {
		cfg->upstream_tls = true;
		if (cfg->doh_path[0] == '\0')
			snprintf(cfg->doh_path, sizeof(cfg->doh_path),
			         "/dns-query");
	}

	if (!cfg->upstream_port_explicit) {
		if (cfg->upstream_doh)
			cfg->upstream_port = 443;
		else if (cfg->upstream_tls)
			cfg->upstream_port = 853;
	}

	if (!cfg->listen_port_explicit) {
		enum dns_listen_mode mode = config_effective_listen_mode(cfg);
		cfg->listen_port          = mode == DNS_LISTEN_DOT ? 853 : 53;
	}
}

int
config_load(const char *path, struct dns_config *cfg)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;

	char line[512];
	char section[64] = "";
	int  line_no     = 0;

	while (fgets(line, sizeof(line), f)) {
		line_no++;
		size_t line_len = strlen(line);
		if (line_len > 0 && line[line_len - 1] != '\n' && !feof(f)) {
			fprintf(stderr, "config: line %d exceeds %zu bytes\n",
			        line_no, sizeof(line) - 1);
			fclose(f);
			return -1;
		}

		strip_comment(line);
		char *p = trim(line);

		if (*p == '\0')
			continue;

		if (*p == '[') {
			char *end = strchr(p + 1, ']');
			if (!end)
				continue;
			*end = '\0';
			snprintf(section, sizeof(section), "%s", trim(p + 1));
			if (section[0] != '\0' && strcmp(section, "dns") != 0) {
				fprintf(stderr,
				        "config: warning: unrecognized section '[%s]'\n",
				        section);
			}
			continue;
		}

		char *eq = strchr(p, '=');
		if (!eq)
			continue;

		*eq         = '\0';
		char  *key  = trim(p);
		char  *val  = trim(eq + 1);

		size_t vlen = strlen(val);
		if (vlen >= 2 && val[0] == '"' && val[vlen - 1] == '"') {
			val[vlen - 1] = '\0';
			val++;
		}

		if (strcmp(section, "dns") == 0
		    && strcmp(key, "upstream") == 0) {
			snprintf(cfg->upstream_addr,
			         sizeof(cfg->upstream_addr), "%s", val);
		} else if (strcmp(section, "dns") == 0
		           && (strcmp(key, "port") == 0
		               || strcmp(key, "listen_port") == 0)) {
			uint16_t port;

			if (config_parse_port_u16(val, &port) < 0) {
				fprintf(stderr, "config: invalid listen port: %s\n",
				        val);
				fclose(f);
				return -1;
			}
			cfg->listen_port          = (int)port;
			cfg->listen_port_explicit = true;
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "upstream_port") == 0) {
			uint16_t port;

			if (config_parse_port_u16(val, &port) < 0) {
				fprintf(stderr, "config: invalid upstream port: %s\n",
				        val);
				fclose(f);
				return -1;
			}
			cfg->upstream_port          = port;
			cfg->upstream_port_explicit = true;
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "listen_mode") == 0) {
			if (config_parse_listen_mode(val,
			                             &cfg->listen_mode)
			    < 0) {
				fprintf(stderr, "config: invalid listen mode: %s\n",
				        val);
				fclose(f);
				return -1;
			}
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "upstream_tls") == 0) {
			cfg->upstream_tls = parse_bool(val);
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "upstream_doh") == 0) {
			cfg->upstream_doh = parse_bool(val);
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "doh_path") == 0) {
			snprintf(cfg->doh_path, sizeof(cfg->doh_path), "%s", val);
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "edns_padding") == 0) {
			cfg->edns_padding = parse_bool(val);
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "edns_padding_block") == 0) {
			uint16_t block;

			if (config_parse_edns_padding_block(val, &block) < 0) {
				fprintf(stderr,
				        "config: invalid EDNS padding block: %s\n",
				        val);
				fclose(f);
				return -1;
			}
			cfg->edns_padding_block = block;
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "resolver_discovery") == 0) {
			cfg->resolver_discovery = parse_bool(val);
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "resolver_discovery_name") == 0) {
			snprintf(cfg->resolver_discovery_name,
			         sizeof(cfg->resolver_discovery_name),
			         "%s", val);
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "tls_cert") == 0) {
			snprintf(cfg->tls_cert, sizeof(cfg->tls_cert), "%s", val);
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "tls_key") == 0) {
			snprintf(cfg->tls_key, sizeof(cfg->tls_key), "%s", val);
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "tls_ca_file") == 0) {
			snprintf(cfg->tls_ca_file, sizeof(cfg->tls_ca_file),
			         "%s", val);
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "tls_auth_name") == 0) {
			snprintf(cfg->tls_auth_name, sizeof(cfg->tls_auth_name),
			         "%s", val);
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "tls_insecure") == 0) {
			cfg->tls_insecure = parse_bool(val);
		} else {
			fprintf(stderr,
			        "config: warning: unrecognized key '%s' in section '[%s]'\n",
			        key, section);
		}
	}

	fclose(f);
	return 0;
}
