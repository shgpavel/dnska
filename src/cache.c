/* SPDX-License-Identifier: MIT */

#include <assert.h>
#include <ctype.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "cache.h"
#include "dns.h"
#include "random.h"
#include "wire.h"

static void
write_u32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static bool
monotonic_now(struct timespec *ts)
{
	return clock_gettime(CLOCK_MONOTONIC, ts) == 0;
}

static uint32_t
elapsed_since(const struct timespec *start, const struct timespec *end)
{
	time_t sec  = end->tv_sec - start->tv_sec;
	long   nsec = end->tv_nsec - start->tv_nsec;

	if (sec < 0)
		return 0;
	if (nsec < 0) {
		if (sec == 0)
			return 0;
		sec--;
	}
	if ((uint64_t)sec > UINT32_MAX)
		return UINT32_MAX;
	return (uint32_t)sec;
}

static uint32_t
hash_key(const struct cache *c, const char *name, uint16_t qtype, uint16_t qclass,
         const struct dns_query_cache_key *query_key)
{
	uint32_t h = c->hash_seed;
	for (const char *p = name; *p; p++)
		h = h * 33 ^ (unsigned char)tolower((unsigned char)*p);
	h = h * 33 ^ (uint32_t)qtype;
	h = h * 33 ^ (uint32_t)qclass;
	h = h * 33 ^ (uint32_t)query_key->flags;
	h = h * 33 ^ (uint32_t)query_key->has_opt;
	h = h * 33 ^ (uint32_t)query_key->opt_udp_size;
	h = h * 33 ^ (uint32_t)query_key->opt_rdlen;
	h = h * 33 ^ query_key->opt_ttl;
	h = h * 33 ^ (uint32_t)query_key->opt_rdata_hash;
	h = h * 33 ^ (uint32_t)(query_key->opt_rdata_hash >> 32);
	return h;
}

/*
 * Returns the wire offset just past the question section,
 * or SIZE_MAX on parse error.
 */
static size_t
skip_questions(const uint8_t *buf, size_t buf_len, uint16_t qdcount)
{
	size_t pos = DNS_HEADER_SIZE;
	for (uint16_t i = 0; i < qdcount; i++) {
		int n = wire_skip_name(buf, buf_len, pos);
		if (n < 0)
			return SIZE_MAX;
		pos += (size_t)n + 4;
		if (pos > buf_len)
			return SIZE_MAX;
	}
	return pos;
}

/*
 * Parse the DNS header to count total RRs (AN+NS+AR), skip the question
 * section, and return the wire offset of the first RR.
 * Returns SIZE_MAX on any parse error.
 */
static size_t
wire_rr_start(const uint8_t *buf, size_t buf_len, uint32_t *rrs_out)
{
	if (buf_len < DNS_HEADER_SIZE)
		return SIZE_MAX;
	*rrs_out = (uint32_t)wire_read_u16(buf + 6)
	           + (uint32_t)wire_read_u16(buf + 8)
	           + (uint32_t)wire_read_u16(buf + 10);
	return skip_questions(buf, buf_len, wire_read_u16(buf + 4));
}

static size_t
first_question_wire_len(const uint8_t *buf, size_t buf_len)
{
	if (buf_len < DNS_HEADER_SIZE || wire_read_u16(buf + 4) != 1)
		return SIZE_MAX;

	size_t end = skip_questions(buf, buf_len, 1);
	if (end == SIZE_MAX || end < DNS_HEADER_SIZE)
		return SIZE_MAX;
	return end - DNS_HEADER_SIZE;
}

static uint32_t
soa_negative_ttl(const uint8_t *buf, size_t buf_len, size_t rdata_pos,
                 uint16_t rdlen, uint32_t ttl)
{
	size_t rdata_end = rdata_pos + rdlen;
	size_t pos       = rdata_pos;

	if (rdata_end > buf_len)
		return 0;

	int n = wire_skip_name(buf, rdata_end, pos);
	if (n < 0)
		return 0;
	pos += (size_t)n;
	if (pos > rdata_end)
		return 0;

	n = wire_skip_name(buf, rdata_end, pos);
	if (n < 0)
		return 0;
	pos += (size_t)n;
	if (pos + 20 > rdata_end)
		return 0;

	uint32_t minimum = wire_read_u32(buf + pos + 16);
	return ttl < minimum ? ttl : minimum;
}

static uint32_t
negative_response_ttl(const uint8_t *buf, size_t buf_len)
{
	if (buf_len < DNS_HEADER_SIZE)
		return 0;

	uint16_t ancount = wire_read_u16(buf + 6);
	uint16_t nscount = wire_read_u16(buf + 8);
	uint16_t rcode   = buf[3] & DNS_FLAGS_RCODE_MASK;

	if (nscount == 0)
		return 0;
	if (rcode != DNS_RCODE_NXDOMAIN
	    && !(rcode == DNS_RCODE_OK && ancount == 0))
		return 0;

	size_t pos = skip_questions(buf, buf_len, wire_read_u16(buf + 4));
	if (pos == SIZE_MAX)
		return 0;

	for (uint16_t i = 0; i < ancount; i++) {
		int n = wire_skip_name(buf, buf_len, pos);
		if (n < 0)
			return 0;
		pos += (size_t)n;
		if (pos + 10 > buf_len)
			return 0;
		pos += 10 + wire_read_u16(buf + pos + 8);
		if (pos > buf_len)
			return 0;
	}

	uint32_t min = UINT32_MAX;
	for (uint16_t i = 0; i < nscount; i++) {
		int n = wire_skip_name(buf, buf_len, pos);
		if (n < 0)
			return 0;
		pos += (size_t)n;
		if (pos + 10 > buf_len)
			return 0;

		uint16_t rtype     = wire_read_u16(buf + pos);
		uint32_t ttl       = wire_read_u32(buf + pos + 4);
		uint16_t rdlen     = wire_read_u16(buf + pos + 8);
		size_t   rdata_pos = pos + 10;
		uint32_t candidate = 0;

		if (rtype == DNS_TYPE_SOA)
			candidate = soa_negative_ttl(buf, buf_len, rdata_pos, rdlen, ttl);
		if (candidate != 0 && candidate < min)
			min = candidate;

		pos = rdata_pos + rdlen;
		if (pos > buf_len)
			return 0;
	}

	return min == UINT32_MAX ? 0 : min;
}

static uint32_t
rrs_min_ttl(const uint8_t *buf, size_t buf_len)
{
	uint32_t rrs;
	uint32_t min = UINT32_MAX;

	size_t   pos = wire_rr_start(buf, buf_len, &rrs);
	if (pos == SIZE_MAX)
		return 0;

	for (uint32_t i = 0; i < rrs; i++) {
		int n = wire_skip_name(buf, buf_len, pos);
		if (n < 0)
			return 0;
		pos += (size_t)n;
		if (pos + 10 > buf_len)
			return 0;

		uint16_t rtype = wire_read_u16(buf + pos);
		uint32_t ttl   = wire_read_u32(buf + pos + 4);
		if (rtype != DNS_TYPE_OPT && ttl < min)
			min = ttl;

		pos += 10 + wire_read_u16(buf + pos + 8);
		if (pos > buf_len)
			return 0;
	}

	return min == UINT32_MAX ? 0 : min;
}

static void
patch_ttls(uint8_t *buf, size_t buf_len, uint32_t elapsed, uint32_t ttl_cap)
{
	uint32_t rrs;
	uint32_t cap_left = 0;
	bool     cap_ttls = ttl_cap != 0;

	if (cap_ttls)
		cap_left = (elapsed < ttl_cap) ? ttl_cap - elapsed : 0;

	size_t pos = wire_rr_start(buf, buf_len, &rrs);
	if (pos == SIZE_MAX)
		return;

	for (uint32_t i = 0; i < rrs; i++) {
		int n = wire_skip_name(buf, buf_len, pos);
		if (n < 0)
			return;
		pos += (size_t)n;
		if (pos + 10 > buf_len)
			return;

		uint16_t rtype = wire_read_u16(buf + pos);
		if (rtype != DNS_TYPE_OPT) {
			uint32_t ttl = wire_read_u32(buf + pos + 4);
			ttl          = (elapsed < ttl) ? ttl - elapsed : 0;
			if (cap_ttls && ttl > cap_left)
				ttl = cap_left;

			write_u32(buf + pos + 4, ttl);
		}

		pos += 10 + wire_read_u16(buf + pos + 8);
		if (pos > buf_len)
			return;
	}
}

static bool
query_key_matches(const struct dns_query_cache_key *a,
                  const struct dns_query_cache_key *b)
{
	return a->flags == b->flags
	       && a->has_opt == b->has_opt
	       && a->opt_udp_size == b->opt_udp_size
	       && a->opt_rdlen == b->opt_rdlen
	       && a->opt_ttl == b->opt_ttl
	       && a->opt_rdata_hash == b->opt_rdata_hash;
}

static bool
key_matches(const struct cache_entry *e, const char *name,
            uint16_t qtype, uint16_t qclass,
            const struct dns_query_cache_key *query_key)
{
	return strcasecmp(e->name, name) == 0
	       && e->qtype == qtype
	       && e->qclass == qclass
	       && query_key_matches(&e->query_key, query_key);
}

/* LRU list and hash table helpers (called with write lock held) */

static void
lru_detach(struct cache *c, int idx)
{
	struct cache_entry *e = &c->entries[idx];

	assert(e->in_use);

	if (e->lru_prev != CACHE_NONE)
		c->entries[e->lru_prev].lru_next = e->lru_next;
	else
		c->lru_head = e->lru_next;

	if (e->lru_next != CACHE_NONE)
		c->entries[e->lru_next].lru_prev = e->lru_prev;
	else
		c->lru_tail = e->lru_prev;

	e->lru_prev = CACHE_NONE;
	e->lru_next = CACHE_NONE;
}

static void
lru_push_front(struct cache *c, int idx)
{
	struct cache_entry *e = &c->entries[idx];

	assert(e->in_use);

	e->lru_prev = CACHE_NONE;
	e->lru_next = c->lru_head;

	if (c->lru_head != CACHE_NONE)
		c->entries[c->lru_head].lru_prev = idx;
	else
		c->lru_tail = idx;

	c->lru_head = idx;
}

static void
hash_remove(struct cache *c, int bucket, int idx)
{
	assert(c->entries[idx].in_use);

	int *cur = &c->buckets[bucket];
	while (*cur != CACHE_NONE) {
		if (*cur == idx) {
			*cur                      = c->entries[idx].hash_next;
			c->entries[idx].hash_next = CACHE_NONE;
			return;
		}
		cur = &c->entries[*cur].hash_next;
	}
}

static void
lru_touch(struct cache *c, int idx)
{
	assert(c->entries[idx].in_use);

	if (c->lru_head == idx)
		return;

	lru_detach(c, idx);
	lru_push_front(c, idx);
}

static void
free_push(struct cache *c, int idx)
{
	struct cache_entry *e = &c->entries[idx];

	e->lru_prev           = CACHE_NONE;
	e->lru_next           = CACHE_NONE;
	e->hash_next          = CACHE_NONE;
	e->bucket             = CACHE_NONE;
	e->free_next          = c->free_head;
	e->in_use             = false;
	c->free_head          = idx;
	c->count--;
}

static void
evict_expired_entry(struct cache *c, int bucket, int idx)
{
	lru_detach(c, idx);
	hash_remove(c, bucket, idx);
	free_push(c, idx);
}

static int
build_cached_response(const struct cache_entry *e, uint16_t id,
                      const uint8_t *question, size_t question_len,
                      uint8_t *buf, size_t buf_size, size_t *len,
                      uint32_t *ttl_cap_out)
{
	if (question == NULL || question_len == 0 || e->response_len < DNS_HEADER_SIZE + e->question_wire_len) {
		return -1;
	}

	size_t suffix_len = e->response_len - DNS_HEADER_SIZE - e->question_wire_len;
	size_t out_len    = DNS_HEADER_SIZE + question_len + suffix_len;

	if (out_len > buf_size)
		return -1;

	memcpy(buf, e->response, DNS_HEADER_SIZE);
	memcpy(buf + DNS_HEADER_SIZE, question, question_len);
	memcpy(buf + DNS_HEADER_SIZE + question_len,
	       e->response + DNS_HEADER_SIZE + e->question_wire_len,
	       suffix_len);
	buf[0]       = (uint8_t)(id >> 8);
	buf[1]       = (uint8_t)id;
	*len         = out_len;
	*ttl_cap_out = e->ttl_cap;
	return 1;
}

static int
find_entry_idx(struct cache *c, int bucket, const char *name,
               uint16_t qtype, uint16_t qclass,
               const struct dns_query_cache_key *query_key)
{
	int idx = c->buckets[bucket];

	while (idx != CACHE_NONE) {
		if (key_matches(&c->entries[idx], name, qtype, qclass, query_key))
			return idx;
		idx = c->entries[idx].hash_next;
	}

	return CACHE_NONE;
}

/*
 * Get a slot for a new entry.  Takes from the free list when available
 * (incrementing count); otherwise evicts the LRU tail without changing count,
 * because the eviction and the subsequent insert by the caller are net-zero.
 * Must be called with write lock held; caller must always fill the returned slot.
 */
static int
alloc_slot(struct cache *c)
{
	if (c->free_head != CACHE_NONE) {
		int idx                   = c->free_head;
		c->free_head              = c->entries[idx].free_next;
		c->entries[idx].free_next = CACHE_NONE;
		c->entries[idx].in_use    = true;
		c->count++;
		return idx;
	}

	int idx = c->lru_tail;
	if (idx == CACHE_NONE)
		return CACHE_NONE;

	lru_detach(c, idx);
	hash_remove(c, c->entries[idx].bucket, idx);
	c->entries[idx].hash_next = CACHE_NONE;
	c->entries[idx].bucket    = CACHE_NONE;
	return idx; /* count unchanged: evicting one, inserting one */
}

int
cache_init(struct cache *c)
{
	c->lru_head  = CACHE_NONE;
	c->lru_tail  = CACHE_NONE;
	c->free_head = 0;
	c->count     = 0;

	if (random_bytes(&c->hash_seed, sizeof(c->hash_seed)) < 0)
		return -1;

	for (int i = 0; i < CACHE_BUCKETS; i++)
		c->buckets[i] = CACHE_NONE;

	/* build free list through free_next */
	for (int i = 0; i < CACHE_SLOTS; i++) {
		c->entries[i].lru_prev  = CACHE_NONE;
		c->entries[i].lru_next  = CACHE_NONE;
		c->entries[i].free_next = (i + 1 < CACHE_SLOTS) ? i + 1 : CACHE_NONE;
		c->entries[i].hash_next = CACHE_NONE;
		c->entries[i].bucket    = CACHE_NONE;
		c->entries[i].in_use    = false;
	}

	if (pthread_rwlock_init(&c->lock, NULL) != 0)
		return -1;
	return 0;
}

void
cache_destroy(struct cache *c)
{
	pthread_rwlock_destroy(&c->lock);
}

static bool
copy_lru_name(struct cache *c, bool head, char *buf, size_t buf_size)
{
	int idx;

	if (buf == NULL || buf_size == 0)
		return false;

	pthread_rwlock_rdlock(&c->lock);
	idx = head ? c->lru_head : c->lru_tail;
	if (idx == CACHE_NONE) {
		pthread_rwlock_unlock(&c->lock);
		return false;
	}

	snprintf(buf, buf_size, "%s", c->entries[idx].name);
	pthread_rwlock_unlock(&c->lock);
	return true;
}

bool
cache_lru_head_name(struct cache *c, char *buf, size_t buf_size)
{
	return copy_lru_name(c, true, buf, buf_size);
}

bool
cache_lru_tail_name(struct cache *c, char *buf, size_t buf_size)
{
	return copy_lru_name(c, false, buf, buf_size);
}

int
cache_lookup(struct cache *c, const char *name, uint16_t qtype, uint16_t qclass,
             const struct dns_query_cache_key *query_key, uint16_t id,
             const uint8_t *question, size_t question_len,
             uint8_t *buf, size_t buf_size, size_t *len)
{
	int                bucket = (int)(hash_key(c, name, qtype, qclass, query_key) % CACHE_BUCKETS);
	struct cache_entry snapshot;
	uint32_t           ttl_cap = 0;
	uint32_t           elapsed;
	int                build_rc;
	struct timespec    now;
	int                idx;

	pthread_rwlock_wrlock(&c->lock);

	idx = find_entry_idx(c, bucket, name, qtype, qclass, query_key);
	if (idx == CACHE_NONE) {
		pthread_rwlock_unlock(&c->lock);
		return 0;
	}

	struct cache_entry *e = &c->entries[idx];
	if (!monotonic_now(&now)) {
		pthread_rwlock_unlock(&c->lock);
		return 0;
	}

	elapsed = elapsed_since(&e->inserted_at, &now);
	if (elapsed >= e->min_ttl) {
		evict_expired_entry(c, bucket, idx);
		pthread_rwlock_unlock(&c->lock);
		return -2;
	}
	if (e->response_len < DNS_HEADER_SIZE + e->question_wire_len) {
		evict_expired_entry(c, bucket, idx);
		pthread_rwlock_unlock(&c->lock);
		return -1;
	}

	lru_touch(c, idx);
	snapshot = *e;
	pthread_rwlock_unlock(&c->lock);

	build_rc = build_cached_response(&snapshot, id, question, question_len,
	                                 buf, buf_size, len, &ttl_cap);
	if (build_rc != 1)
		return build_rc;

	patch_ttls(buf, *len, elapsed, ttl_cap);
	return 1;
}

void
cache_insert(struct cache *c, const char *name, uint16_t qtype, uint16_t qclass,
             const struct dns_query_cache_key *query_key,
             const uint8_t *response, size_t response_len, uint32_t ttl_override)
{
	if (response_len > DNS_MAX_MSG_SIZE || strlen(name) > DNS_MAX_NAME_LEN)
		return;

	size_t question_wire_len = first_question_wire_len(response, response_len);
	if (question_wire_len == SIZE_MAX)
		return;

	uint32_t min_ttl;
	uint32_t ttl_cap      = 0;
	uint32_t negative_ttl = negative_response_ttl(response, response_len);
	uint16_t rcode        = response[3] & DNS_FLAGS_RCODE_MASK;
	if (ttl_override) {
		min_ttl = ttl_override;
		ttl_cap = ttl_override;
	} else if (negative_ttl != 0) {
		min_ttl = negative_ttl;
		ttl_cap = negative_ttl;
	} else if (rcode == DNS_RCODE_NXDOMAIN) {
		min_ttl = CACHE_NEGATIVE_FLOOR_TTL;
		ttl_cap = CACHE_NEGATIVE_FLOOR_TTL;
	} else {
		min_ttl = rrs_min_ttl(response, response_len);
		if (min_ttl == 0)
			return;
		ttl_cap = min_ttl;
	}

	int             bucket = (int)(hash_key(c, name, qtype, qclass, query_key) % CACHE_BUCKETS);
	struct timespec now;

	if (!monotonic_now(&now))
		return;

	pthread_rwlock_wrlock(&c->lock);

	/* update in place if the key already exists */
	int idx = find_entry_idx(c, bucket, name, qtype, qclass, query_key);
	if (idx != CACHE_NONE) {
		struct cache_entry *e = &c->entries[idx];

		memcpy(e->response, response, response_len);
		e->response_len      = response_len;
		e->question_wire_len = question_wire_len;
		e->inserted_at       = now;
		e->min_ttl           = min_ttl;
		e->ttl_cap           = ttl_cap;
		lru_touch(c, idx);
		pthread_rwlock_unlock(&c->lock);
		return;
	}

	idx = alloc_slot(c);
	if (idx == CACHE_NONE) {
		pthread_rwlock_unlock(&c->lock);
		return;
	}

	struct cache_entry *e = &c->entries[idx];
	memcpy(e->name, name, strlen(name) + 1);
	e->qtype     = qtype;
	e->qclass    = qclass;
	e->query_key = *query_key;
	memcpy(e->response, response, response_len);
	e->response_len      = response_len;
	e->question_wire_len = question_wire_len;
	e->inserted_at       = now;
	e->min_ttl           = min_ttl;
	e->ttl_cap           = ttl_cap;
	e->bucket            = bucket;
	e->hash_next         = c->buckets[bucket];
	e->free_next         = CACHE_NONE;
	e->in_use            = true;
	c->buckets[bucket]   = idx;
	lru_push_front(c, idx);

	pthread_rwlock_unlock(&c->lock);
}
