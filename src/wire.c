/* SPDX-License-Identifier: MIT */

#include <stdbool.h>

#include "wire.h"

int
wire_skip_name(const uint8_t *buf, size_t buf_len, size_t offset)
{
	size_t pos    = offset;
	bool   jumped = false;
	int    result = -1;
	int    hops   = 0;

	while (pos < buf_len) {
		uint8_t b = buf[pos];

		if ((b & 0xC0) == 0xC0) {
			if (pos + 1 >= buf_len || ++hops > WIRE_NAME_MAX_HOPS)
				return -1;
			if (!jumped)
				result = (int)(pos - offset + 2);
			pos    = (size_t)((b & 0x3F) << 8 | buf[pos + 1]);
			jumped = true;
		} else if (b == 0) {
			if (!jumped)
				result = (int)(pos - offset + 1);
			return result;
		} else if ((b & 0xC0) == 0x00) {
			if (pos + 1 + (size_t)b > buf_len)
				return -1;
			pos += 1 + b;
		} else {
			return -1;
		}
	}

	return -1;
}
