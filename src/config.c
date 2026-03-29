/* SPDX-License-Identifier: MIT */

#include <ctype.h>
#include <stdio.h>
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
config_load(const char *path, struct server_config *cfg)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;

	char line[512];
	char section[64] = "";

	while (fgets(line, sizeof(line), f)) {
		char *p = trim(line);

		if (*p == '\0' || *p == '#')
			continue;

		if (*p == '[') {
			char *end = strchr(p + 1, ']');
			if (!end)
				continue;
			*end = '\0';
			snprintf(section, sizeof(section), "%s", trim(p + 1));
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
		}
	}

	fclose(f);
	return 0;
}
