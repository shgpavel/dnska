/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_PRINT_H
#define DNSKA_PRINT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Pretty-print a DNS response in dig-style: header line, status,
 * question, answer/authority/additional sections.  Returns 0 on
 * success, -1 if the message cannot be parsed.
 */
int
dns_print_response(FILE *out, const uint8_t *msg, size_t len);

/* Parse a DNS type mnemonic ("A", "AAAA", ...) or "TYPEnnn".  Returns 0
 * on success, -1 if unrecognized. */
int
dns_type_from_str(const char *s, uint16_t *out);

#endif /* DNSKA_PRINT_H */
