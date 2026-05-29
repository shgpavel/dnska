/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dns.h"
#include "doh_server.h"

static const char *
http_status_text(int status_code)
{
	switch (status_code) {
	case DOH_HTTP_OK:
		return "OK";
	case DOH_HTTP_BAD_REQUEST:
		return "Bad Request";
	case DOH_HTTP_NOT_FOUND:
		return "Not Found";
	case DOH_HTTP_METHOD_NOT_ALLOWED:
		return "Method Not Allowed";
	case DOH_HTTP_LENGTH_REQUIRED:
		return "Length Required";
	case DOH_HTTP_PAYLOAD_TOO_LARGE:
		return "Payload Too Large";
	case DOH_HTTP_URI_TOO_LONG:
		return "URI Too Long";
	case DOH_HTTP_UNSUPPORTED_MEDIA_TYPE:
		return "Unsupported Media Type";
	case DOH_HTTP_REQUEST_HEADER_TOO_BIG:
		return "Request Header Fields Too Large";
	case DOH_HTTP_VERSION_NOT_SUPPORTED:
		return "HTTP Version Not Supported";
	default:
		return "Bad Request";
	}
}

static int
writen(int fd, const uint8_t *buf, size_t len)
{
	size_t sent = 0;

	while (sent < len) {
		ssize_t n = write(fd, buf + sent, len - sent);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		sent += (size_t)n;
	}
	return 0;
}

static const uint8_t *
find_header_end(const uint8_t *buf, size_t len)
{
	if (len < 4)
		return NULL;

	for (size_t i = 3; i < len; i++) {
		if (buf[i - 3] == '\r' && buf[i - 2] == '\n' && buf[i - 1] == '\r' && buf[i] == '\n')
			return buf + i + 1;
	}
	return NULL;
}

static bool
token_equals(const char *begin, const char *end, const char *want)
{
	size_t want_len = strlen(want);
	return (size_t)(end - begin) == want_len
	       && strncasecmp(begin, want, want_len) == 0;
}

static bool
content_type_is_dns_message(const char *begin, const char *end)
{
	static const char media_type[] = "application/dns-message";
	size_t            media_len    = sizeof(media_type) - 1;

	while (begin < end && (*begin == ' ' || *begin == '\t'))
		begin++;
	while (end > begin && (end[-1] == ' ' || end[-1] == '\t'))
		end--;

	if ((size_t)(end - begin) < media_len
	    || strncasecmp(begin, media_type, media_len) != 0)
		return false;

	begin += media_len;
	return begin == end || *begin == ';';
}

static int
parse_content_length(const char *begin, const char *end, size_t *out)
{
	unsigned long value = 0;

	while (begin < end && (*begin == ' ' || *begin == '\t'))
		begin++;
	while (end > begin && (end[-1] == ' ' || end[-1] == '\t'))
		end--;
	if (begin == end)
		return -1;

	for (const char *p = begin; p < end; p++) {
		if (*p < '0' || *p > '9')
			return -1;
		unsigned int digit = (unsigned int)(*p - '0');
		if (value > (ULONG_MAX - digit) / 10)
			return -1;
		value = value * 10 + digit;
	}

	*out = (size_t)value;
	return 0;
}

static void
set_error(struct doh_server_request *out, int status_code)
{
	out->body_offset = 0;
	out->body_len    = 0;
	out->status_code = status_code;
}

int
doh_server_parse_request(const uint8_t *request, size_t request_len,
                         const char                *expected_path,
                         struct doh_server_request *out)
{
	memset(out, 0, sizeof(*out));
	out->status_code          = DOH_HTTP_BAD_REQUEST;

	const uint8_t *header_end = find_header_end(request, request_len);
	if (header_end == NULL) {
		if (request_len >= DOH_SERVER_MAX_HEADER_SIZE) {
			set_error(out, DOH_HTTP_REQUEST_HEADER_TOO_BIG);
			return DOH_SERVER_PARSE_HTTP_ERROR;
		}
		return DOH_SERVER_PARSE_INCOMPLETE;
	}

	size_t header_len = (size_t)(header_end - request);
	if (header_len > DOH_SERVER_MAX_HEADER_SIZE) {
		set_error(out, DOH_HTTP_REQUEST_HEADER_TOO_BIG);
		return DOH_SERVER_PARSE_HTTP_ERROR;
	}

	char header_buf[DOH_SERVER_MAX_HEADER_SIZE + 1];
	memcpy(header_buf, request, header_len);
	header_buf[header_len] = '\0';

	const char *headers    = header_buf;
	const char *limit      = headers + header_len;
	const char *line_end   = strstr(headers, "\r\n");
	if (line_end == NULL || line_end == headers) {
		set_error(out, DOH_HTTP_BAD_REQUEST);
		return DOH_SERVER_PARSE_HTTP_ERROR;
	}

	const char *method_end = memchr(headers, ' ', (size_t)(line_end - headers));
	if (method_end == NULL) {
		set_error(out, DOH_HTTP_BAD_REQUEST);
		return DOH_SERVER_PARSE_HTTP_ERROR;
	}
	const char *target     = method_end + 1;
	const char *target_end = memchr(target, ' ', (size_t)(line_end - target));
	if (target_end == NULL || target == target_end) {
		set_error(out, DOH_HTTP_BAD_REQUEST);
		return DOH_SERVER_PARSE_HTTP_ERROR;
	}
	const char *version = target_end + 1;
	if (version == line_end) {
		set_error(out, DOH_HTTP_BAD_REQUEST);
		return DOH_SERVER_PARSE_HTTP_ERROR;
	}

	if (!token_equals(headers, method_end, "POST")) {
		set_error(out, DOH_HTTP_METHOD_NOT_ALLOWED);
		return DOH_SERVER_PARSE_HTTP_ERROR;
	}

	size_t expected_len = strlen(expected_path);
	if ((size_t)(target_end - target) != expected_len
	    || memcmp(target, expected_path, expected_len) != 0) {
		if ((size_t)(target_end - target) > 2048)
			set_error(out, DOH_HTTP_URI_TOO_LONG);
		else
			set_error(out, DOH_HTTP_NOT_FOUND);
		return DOH_SERVER_PARSE_HTTP_ERROR;
	}

	if (!token_equals(version, line_end, "HTTP/1.1")
	    && !token_equals(version, line_end, "HTTP/1.0")) {
		set_error(out, DOH_HTTP_VERSION_NOT_SUPPORTED);
		return DOH_SERVER_PARSE_HTTP_ERROR;
	}

	bool        have_content_type   = false;
	bool        have_content_length = false;
	size_t      content_length      = 0;
	const char *line                = line_end + 2;

	while (line < limit) {
		const char *next = strstr(line, "\r\n");
		if (next == NULL || next > limit)
			break;
		if (next == line)
			break;

		const char *colon = memchr(line, ':', (size_t)(next - line));
		if (colon == NULL) {
			set_error(out, DOH_HTTP_BAD_REQUEST);
			return DOH_SERVER_PARSE_HTTP_ERROR;
		}

		if (token_equals(line, colon, "Content-Type")) {
			have_content_type = content_type_is_dns_message(
			        colon + 1, next);
		} else if (token_equals(line, colon, "Content-Length")) {
			size_t parsed_len = 0;
			if (have_content_length
			    || parse_content_length(colon + 1, next,
			                            &parsed_len)
			               < 0) {
				set_error(out, DOH_HTTP_BAD_REQUEST);
				return DOH_SERVER_PARSE_HTTP_ERROR;
			}
			have_content_length = true;
			content_length      = parsed_len;
		}

		line = next + 2;
	}

	if (!have_content_type) {
		set_error(out, DOH_HTTP_UNSUPPORTED_MEDIA_TYPE);
		return DOH_SERVER_PARSE_HTTP_ERROR;
	}
	if (!have_content_length) {
		set_error(out, DOH_HTTP_LENGTH_REQUIRED);
		return DOH_SERVER_PARSE_HTTP_ERROR;
	}
	if (content_length > DNS_MAX_MSG_SIZE) {
		set_error(out, DOH_HTTP_PAYLOAD_TOO_LARGE);
		return DOH_SERVER_PARSE_HTTP_ERROR;
	}
	if (content_length < DNS_HEADER_SIZE) {
		set_error(out, DOH_HTTP_BAD_REQUEST);
		return DOH_SERVER_PARSE_HTTP_ERROR;
	}

	out->body_offset = header_len;
	out->body_len    = content_length;
	out->status_code = DOH_HTTP_OK;

	if (request_len - header_len < content_length)
		return DOH_SERVER_PARSE_INCOMPLETE;

	return DOH_SERVER_PARSE_OK;
}

int
doh_server_read_request(int fd, const char *expected_path,
                        uint8_t *dns_body, size_t dns_body_size,
                        size_t *dns_body_len, int *status_code)
{
	uint8_t request[DOH_SERVER_MAX_HEADER_SIZE + DNS_MAX_MSG_SIZE];
	size_t  request_len = 0;

	*dns_body_len       = 0;
	*status_code        = DOH_HTTP_BAD_REQUEST;

	for (;;) {
		struct doh_server_request parsed;
		int                       rc = doh_server_parse_request(request, request_len,
		                                                        expected_path, &parsed);
		if (rc == DOH_SERVER_PARSE_OK) {
			if (parsed.body_len > dns_body_size) {
				*status_code = DOH_HTTP_PAYLOAD_TOO_LARGE;
				return -1;
			}
			memcpy(dns_body, request + parsed.body_offset,
			       parsed.body_len);
			*dns_body_len = parsed.body_len;
			*status_code  = DOH_HTTP_OK;
			return 0;
		}
		if (rc == DOH_SERVER_PARSE_HTTP_ERROR) {
			*status_code = parsed.status_code;
			return -1;
		}
		if (request_len == sizeof(request)) {
			*status_code = DOH_HTTP_PAYLOAD_TOO_LARGE;
			return -1;
		}

		ssize_t n = recv(fd, request + request_len,
		                 sizeof(request) - request_len, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			*status_code = DOH_HTTP_BAD_REQUEST;
			return -1;
		}
		if (n == 0) {
			*status_code = DOH_HTTP_BAD_REQUEST;
			return -1;
		}
		request_len += (size_t)n;
	}
}

int
doh_server_send_error(int fd, int status_code)
{
	char header[256];
	int  n = snprintf(header, sizeof(header),
	                  "HTTP/1.1 %d %s\r\n"
	                  "Content-Length: 0\r\n"
	                  "Connection: close\r\n"
	                  "%s"
	                  "\r\n",
	                  status_code, http_status_text(status_code),
	                  status_code == DOH_HTTP_METHOD_NOT_ALLOWED ?
	                          "Allow: POST\r\n" :
	                          "");
	if (n < 0 || (size_t)n >= sizeof(header))
		return -1;

	return writen(fd, (const uint8_t *)header, (size_t)n);
}

int
doh_server_send_dns_response(int fd, const uint8_t *response,
                             size_t response_len)
{
	char header[256];
	int  n = snprintf(header, sizeof(header),
	                  "HTTP/1.1 200 OK\r\n"
	                  "Content-Type: application/dns-message\r\n"
	                  "Content-Length: %zu\r\n"
	                  "Connection: close\r\n"
	                  "\r\n",
	                  response_len);
	if (n < 0 || (size_t)n >= sizeof(header))
		return -1;

	if (writen(fd, (const uint8_t *)header, (size_t)n) < 0)
		return -1;
	return writen(fd, response, response_len);
}
