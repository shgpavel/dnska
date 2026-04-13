/* SPDX-License-Identifier: MIT */

#include <stdarg.h>
#include <stdio.h>

#include "log.h"

static enum log_level g_level = LOG_INFO;

void
log_set_level(enum log_level level)
{
	g_level = level;
}

void
log_msg(enum log_level level, const char *fmt, ...)
{
	va_list ap;

	if (level > g_level)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}
