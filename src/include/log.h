/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_LOG_H
#define DNSKA_LOG_H

enum log_level {
	LOG_ERROR = 0,
	LOG_WARN  = 1,
	LOG_INFO  = 2,
	LOG_DEBUG = 3,
};

void
log_set_level(enum log_level level);
void
log_msg(enum log_level level, const char *fmt, ...);

#endif /* DNSKA_LOG_H */
