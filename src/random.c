/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/random.h>
#include <unistd.h>

#include "random.h"

int
random_bytes(void *buf, size_t len)
{
	uint8_t *p = buf;

	while (len > 0) {
		ssize_t n = getrandom(p, len, 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0)
			break;
		p   += (size_t)n;
		len -= (size_t)n;
	}

	if (len == 0)
		return 0;

	int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	while (len > 0) {
		ssize_t n = read(fd, p, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		if (n == 0) {
			close(fd);
			return -1;
		}
		p   += (size_t)n;
		len -= (size_t)n;
	}

	close(fd);
	return 0;
}
