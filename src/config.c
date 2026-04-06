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

		char *p = trim(line);

		if (*p == '\0' || *p == '#')
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
			cfg->listen_port = (int)port;
		} else if (strcmp(section, "dns") == 0
		           && strcmp(key, "upstream_port") == 0) {
			uint16_t port;

			if (config_parse_port_u16(val, &port) < 0) {
				fprintf(stderr, "config: invalid upstream port: %s\n",
				        val);
				fclose(f);
				return -1;
			}
			cfg->upstream_port = port;
		} else {
			fprintf(stderr,
			        "config: warning: unrecognized key '%s' in section '[%s]'\n",
			        key, section);
		}
	}

	fclose(f);
	return 0;
}
