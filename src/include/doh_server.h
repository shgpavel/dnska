/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_DOH_SERVER_H
#define DNSKA_DOH_SERVER_H

#include <stddef.h>
#include <stdint.h>

enum {
	DOH_SERVER_DEFAULT_PORT    = 8053,
	DOH_SERVER_MAX_HEADER_SIZE = 8192,
};

enum doh_server_parse_result {
	DOH_SERVER_PARSE_OK         = 0,
	DOH_SERVER_PARSE_INCOMPLETE = 1,
	DOH_SERVER_PARSE_HTTP_ERROR = -1,
};

enum doh_server_http_status {
	DOH_HTTP_OK                     = 200,
	DOH_HTTP_BAD_REQUEST            = 400,
	DOH_HTTP_NOT_FOUND              = 404,
	DOH_HTTP_METHOD_NOT_ALLOWED     = 405,
	DOH_HTTP_LENGTH_REQUIRED        = 411,
	DOH_HTTP_PAYLOAD_TOO_LARGE      = 413,
	DOH_HTTP_URI_TOO_LONG           = 414,
	DOH_HTTP_UNSUPPORTED_MEDIA_TYPE = 415,
	DOH_HTTP_REQUEST_HEADER_TOO_BIG = 431,
	DOH_HTTP_VERSION_NOT_SUPPORTED  = 505,
};

struct doh_server_request {
	size_t body_offset;
	size_t body_len;
	int    status_code;
};

int
doh_server_parse_request(const uint8_t *request, size_t request_len,
                         const char                *expected_path,
                         struct doh_server_request *out);
int
doh_server_read_request(int fd, const char *expected_path,
                        uint8_t *dns_body, size_t dns_body_size,
                        size_t *dns_body_len, int *status_code);
int
doh_server_send_error(int fd, int status_code);
int
doh_server_send_dns_response(int fd, const uint8_t *response,
                             size_t response_len);

#endif /* DNSKA_DOH_SERVER_H */
