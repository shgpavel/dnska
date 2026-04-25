/* SPDX-License-Identifier: MIT */

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include "log.h"

static enum log_level g_level = LOG_INFO;

static const char *
level_tag(enum log_level level)
{
	switch (level) {
	case LOG_ERROR:
		return "ERROR";
	case LOG_WARN:
		return "WARN";
	case LOG_INFO:
		return "INFO";
	case LOG_DEBUG:
		return "DEBUG";
	}
	return "?";
}

void
log_set_level(enum log_level level)
{
	g_level = level;
}

void
log_msg(enum log_level level, const char *fmt, ...)
{
	va_list         ap;
	struct timespec ts;
	struct tm       tm;
	char            stamp[20];

	if (level > g_level)
		return;

	if (clock_gettime(CLOCK_REALTIME, &ts) == 0
	    && localtime_r(&ts.tv_sec, &tm) != NULL
	    && strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm) > 0)
		fprintf(stderr, "%s %-5s ", stamp, level_tag(level));
	else
		fprintf(stderr, "%-5s ", level_tag(level));

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}
