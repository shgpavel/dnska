/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_CACHE_H
#define DNSKA_CACHE_H

#include <stdbool.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "dns.h"

enum {
	CACHE_NONE               = -1, /* sentinel: no entry / empty slot */
	CACHE_SLOTS              = 1024,
	CACHE_BUCKETS            = 1024,
	CACHE_NEGATIVE_FLOOR_TTL = 30,
	CACHE_SERVFAIL_TTL       = 5, /* TTL for upstream SERVFAIL responses */
	CACHE_STALE_WINDOW_SEC   = 3600,
	CACHE_STALE_ANSWER_TTL   = 30,
};

struct cache_entry {
	char                       name[DNS_MAX_NAME_LEN + 1];
	uint16_t                   qtype;
	uint16_t                   qclass;
	struct dns_query_cache_key query_key;
	uint8_t                    response[DNS_MAX_MSG_SIZE];
	size_t                     response_len;
	size_t                     question_wire_len;
	struct timespec            inserted_at;
	uint32_t                   min_ttl;
	uint32_t                   ttl_cap;
	int                        lru_prev;  /* more-recently-used index, or CACHE_NONE */
	int                        lru_next;  /* less-recently-used index, or CACHE_NONE */
	int                        free_next; /* next free entry index, or CACHE_NONE */
	int                        hash_next; /* next entry in hash chain, or CACHE_NONE */
	int                        bucket;    /* precomputed hash bucket index, or CACHE_NONE */
	bool                       in_use;
};

struct cache {
	struct cache_entry entries[CACHE_SLOTS];
	int                buckets[CACHE_BUCKETS]; /* hash chain heads, CACHE_NONE if empty */
	int                lru_head;               /* most-recently-used index, or CACHE_NONE */
	int                lru_tail;               /* least-recently-used index, or CACHE_NONE */
	int                free_head;              /* head of free list via free_next, or CACHE_NONE */
	int                count;
	uint32_t           hash_seed;
	pthread_rwlock_t   lock;
};

int
cache_init(struct cache *c);
void
cache_destroy(struct cache *c);
bool
cache_lru_head_name(struct cache *c, char *buf, size_t buf_size);
bool
cache_lru_tail_name(struct cache *c, char *buf, size_t buf_size);

/*
 * Returns 1 on hit (response copied into buf with the caller's question bytes,
 * plus patched ID and TTLs),
 * 0 on miss, -1 if buf is too small, -2 if entry is expired.
 * Expired entries remain available to cache_lookup_stale() until the stale
 * window elapses.
 */
int
cache_lookup(struct cache *c, const char *name, uint16_t qtype, uint16_t qclass,
             const struct dns_query_cache_key *query_key, uint16_t id,
             const uint8_t *question, size_t question_len,
             uint8_t *buf, size_t buf_size, size_t *len);

/*
 * Returns a stale positive or negative response when the matching entry is
 * expired but still within CACHE_STALE_WINDOW_SEC.  TTLs are rewritten to
 * CACHE_STALE_ANSWER_TTL.  Return values otherwise match cache_lookup().
 */
int
cache_lookup_stale(struct cache *c, const char *name, uint16_t qtype,
                   uint16_t                          qclass,
                   const struct dns_query_cache_key *query_key, uint16_t id,
                   const uint8_t *question, size_t question_len,
                   uint8_t *buf, size_t buf_size, size_t *len);

/*
 * If ttl_override is non-zero it is used directly; otherwise the minimum TTL
 * is read from the response wire data.
 */
void
cache_insert(struct cache *c, const char *name, uint16_t qtype, uint16_t qclass,
             const struct dns_query_cache_key *query_key,
             const uint8_t *response, size_t response_len, uint32_t ttl_override);

#endif /* DNSKA_CACHE_H */
