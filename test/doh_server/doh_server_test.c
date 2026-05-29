/* SPDX-License-Identifier: MIT */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"
#include "doh_server.h"
#include "test.h"

static size_t
build_request(uint8_t *buf, size_t buf_size, const char *method,
              const char *path, const char *content_type,
              const uint8_t *body, size_t body_len)
{
	int n = snprintf((char *)buf, buf_size,
	                 "%s %s HTTP/1.1\r\n"
	                 "Host: localhost\r\n"
	                 "Content-Type: %s\r\n"
	                 "Content-Length: %zu\r\n"
	                 "\r\n",
	                 method, path, content_type, body_len);
	TEST_CHECK(n > 0);
	TEST_CHECK((size_t)n + body_len <= buf_size);
	memcpy(buf + n, body, body_len);
	return (size_t)n + body_len;
}

static void
test_parse_valid_post(void)
{
	uint8_t                   body[DNS_HEADER_SIZE] = { 0 };
	uint8_t                   req[512];
	size_t                    req_len = build_request(req, sizeof(req), "POST",
	                                                  "/dns-query",
	                                                  "application/dns-message",
	                                                  body, sizeof(body));

	struct doh_server_request parsed;
	int                       rc = doh_server_parse_request(req, req_len, "/dns-query",
	                                                        &parsed);

	TEST_EXPECT_INT_EQ(rc, DOH_SERVER_PARSE_OK);
	TEST_EXPECT_INT_EQ(parsed.status_code, DOH_HTTP_OK);
	TEST_EXPECT_SIZE_EQ(parsed.body_len, sizeof(body));
	TEST_CHECK(memcmp(req + parsed.body_offset, body, sizeof(body)) == 0);
}

static void
test_parse_content_type_parameter(void)
{
	uint8_t                   body[DNS_HEADER_SIZE] = { 0 };
	uint8_t                   req[512];
	size_t                    req_len = build_request(req, sizeof(req), "POST",
	                                                  "/dns-query",
	                                                  "application/dns-message; charset=binary",
	                                                  body, sizeof(body));

	struct doh_server_request parsed;
	int                       rc = doh_server_parse_request(req, req_len, "/dns-query",
	                                                        &parsed);

	TEST_EXPECT_INT_EQ(rc, DOH_SERVER_PARSE_OK);
	TEST_EXPECT_SIZE_EQ(parsed.body_len, sizeof(body));
}

static void
test_reject_unsupported_method(void)
{
	const char                req[] = "GET /dns-query HTTP/1.1\r\n"
	                                  "Host: localhost\r\n"
	                                  "\r\n";
	struct doh_server_request parsed;
	int                       rc = doh_server_parse_request((const uint8_t *)req,
	                                                        sizeof(req) - 1,
	                                                        "/dns-query", &parsed);

	TEST_EXPECT_INT_EQ(rc, DOH_SERVER_PARSE_HTTP_ERROR);
	TEST_EXPECT_INT_EQ(parsed.status_code, DOH_HTTP_METHOD_NOT_ALLOWED);
}

static void
test_reject_wrong_path(void)
{
	uint8_t                   body[DNS_HEADER_SIZE] = { 0 };
	uint8_t                   req[512];
	size_t                    req_len = build_request(req, sizeof(req), "POST",
	                                                  "/not-dns",
	                                                  "application/dns-message",
	                                                  body, sizeof(body));
	struct doh_server_request parsed;
	int                       rc = doh_server_parse_request(req, req_len, "/dns-query",
	                                                        &parsed);

	TEST_EXPECT_INT_EQ(rc, DOH_SERVER_PARSE_HTTP_ERROR);
	TEST_EXPECT_INT_EQ(parsed.status_code, DOH_HTTP_NOT_FOUND);
}

static void
test_reject_bad_content_type(void)
{
	uint8_t                   body[DNS_HEADER_SIZE] = { 0 };
	uint8_t                   req[512];
	size_t                    req_len = build_request(req, sizeof(req), "POST",
	                                                  "/dns-query", "application/json",
	                                                  body, sizeof(body));
	struct doh_server_request parsed;
	int                       rc = doh_server_parse_request(req, req_len, "/dns-query",
	                                                        &parsed);

	TEST_EXPECT_INT_EQ(rc, DOH_SERVER_PARSE_HTTP_ERROR);
	TEST_EXPECT_INT_EQ(parsed.status_code,
	                   DOH_HTTP_UNSUPPORTED_MEDIA_TYPE);
}

static void
test_reject_missing_content_length(void)
{
	const char                req[] = "POST /dns-query HTTP/1.1\r\n"
	                                  "Host: localhost\r\n"
	                                  "Content-Type: application/dns-message\r\n"
	                                  "\r\n";
	struct doh_server_request parsed;
	int                       rc = doh_server_parse_request((const uint8_t *)req,
	                                                        sizeof(req) - 1,
	                                                        "/dns-query", &parsed);

	TEST_EXPECT_INT_EQ(rc, DOH_SERVER_PARSE_HTTP_ERROR);
	TEST_EXPECT_INT_EQ(parsed.status_code, DOH_HTTP_LENGTH_REQUIRED);
}

static void
test_content_length_limit(void)
{
	char req[256];
	int  n = snprintf(req, sizeof(req),
	                  "POST /dns-query HTTP/1.1\r\n"
	                  "Content-Type: application/dns-message\r\n"
	                  "Content-Length: %d\r\n"
	                  "\r\n",
	                  DNS_MAX_MSG_SIZE + 1);
	TEST_CHECK(n > 0);

	struct doh_server_request parsed;
	int                       rc = doh_server_parse_request((const uint8_t *)req, (size_t)n,
	                                                        "/dns-query", &parsed);

	TEST_EXPECT_INT_EQ(rc, DOH_SERVER_PARSE_HTTP_ERROR);
	TEST_EXPECT_INT_EQ(parsed.status_code, DOH_HTTP_PAYLOAD_TOO_LARGE);
}

static void
test_short_dns_body_is_bad_request(void)
{
	const char                req[] = "POST /dns-query HTTP/1.1\r\n"
	                                  "Content-Type: application/dns-message\r\n"
	                                  "Content-Length: 4\r\n"
	                                  "\r\n"
	                                  "abcd";
	struct doh_server_request parsed;
	int                       rc = doh_server_parse_request((const uint8_t *)req,
	                                                        sizeof(req) - 1,
	                                                        "/dns-query", &parsed);

	TEST_EXPECT_INT_EQ(rc, DOH_SERVER_PARSE_HTTP_ERROR);
	TEST_EXPECT_INT_EQ(parsed.status_code, DOH_HTTP_BAD_REQUEST);
}

static void
test_incomplete_body(void)
{
	const char                req[] = "POST /dns-query HTTP/1.1\r\n"
	                                  "Content-Type: application/dns-message\r\n"
	                                  "Content-Length: 12\r\n"
	                                  "\r\n"
	                                  "abc";
	struct doh_server_request parsed;
	int                       rc = doh_server_parse_request((const uint8_t *)req,
	                                                        sizeof(req) - 1,
	                                                        "/dns-query", &parsed);

	TEST_EXPECT_INT_EQ(rc, DOH_SERVER_PARSE_INCOMPLETE);
	TEST_EXPECT_INT_EQ(parsed.status_code, DOH_HTTP_OK);
	TEST_EXPECT_SIZE_EQ(parsed.body_len, DNS_HEADER_SIZE);
}

int
main(void)
{
	test_parse_valid_post();
	test_parse_content_type_parameter();
	test_reject_unsupported_method();
	test_reject_wrong_path();
	test_reject_bad_content_type();
	test_reject_missing_content_length();
	test_content_length_limit();
	test_short_dns_body_is_bad_request();
	test_incomplete_body();

	puts("doh server tests passed");
	return 0;
}
