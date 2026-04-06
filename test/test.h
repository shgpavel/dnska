/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_TEST_H
#define DNSKA_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_FAIL(...)                                                       \
	do {                                                                 \
		fprintf(stderr, __VA_ARGS__);                                \
		fputc('\n', stderr);                                         \
		abort();                                                     \
	} while (0)

#define TEST_SKIP(...)                                                       \
	do {                                                                 \
		fprintf(stdout, __VA_ARGS__);                                \
		fputc('\n', stdout);                                         \
		exit(0);                                                     \
	} while (0)

#define TEST_CHECK(expr)                                                     \
	do {                                                                 \
		if (!(expr))                                                 \
			TEST_FAIL("%s:%d: check failed: %s",                \
			          __FILE__, __LINE__, #expr);               \
	} while (0)

#define TEST_EXPECT_INT_EQ(actual, expected)                                 \
	do {                                                                 \
		long long test_actual__   = (long long)(actual);            \
		long long test_expected__ = (long long)(expected);          \
		if (test_actual__ != test_expected__)                       \
			TEST_FAIL("%s:%d: expected %s == %lld, got %lld",   \
			          __FILE__, __LINE__, #actual,            \
			          test_expected__, test_actual__);        \
	} while (0)

#define TEST_EXPECT_SIZE_EQ(actual, expected)                                \
	do {                                                                 \
		unsigned long long test_actual__                             \
		    = (unsigned long long)(actual);                          \
		unsigned long long test_expected__                           \
		    = (unsigned long long)(expected);                        \
		if (test_actual__ != test_expected__)                       \
			TEST_FAIL("%s:%d: expected %s == %llu, got %llu",   \
			          __FILE__, __LINE__, #actual,            \
			          test_expected__, test_actual__);        \
	} while (0)

#define TEST_EXPECT_STR_EQ(actual, expected)                                 \
	do {                                                                 \
		const char *test_actual__   = (actual);                     \
		const char *test_expected__ = (expected);                   \
		if (strcmp(test_actual__, test_expected__) != 0)            \
			TEST_FAIL("%s:%d: expected %s == \"%s\", got \"%s\"",\
			          __FILE__, __LINE__, #actual,             \
			          test_expected__, test_actual__);         \
	} while (0)

#endif /* DNSKA_TEST_H */
