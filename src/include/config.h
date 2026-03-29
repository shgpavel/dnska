/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_CONFIG_H
#define DNSKA_CONFIG_H

#include "server.h"

int
config_load(const char *path, struct server_config *cfg);

#endif /* DNSKA_CONFIG_H */
