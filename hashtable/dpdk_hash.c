/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 * Copyright(c) 2018 Arm Limited
 */

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_memory.h>         /* for definition of RTE_CACHE_LINE_SIZE */
#include <rte_log.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>
#include <rte_compat.h>
#include <rte_vect.h>

#include "dpdk.h"
#include "dpdk_cuckoo_hash.h"
#include "hashtable/fsring.h"

/* Mask of all flags supported by this version */
#define DPDK_HASH_EXTRA_FLAGS_MASK ( \
				   DPDK_HASH_EXTRA_FLAGS_EXT_TABLE)

void dpdk_hash_set_cmp_func(struct dpdk_hash *h, dpdk_hash_cmp_eq_t func)
{
	h->cmp_jump_table_idx = KEY_CUSTOM;
	h->dpdk_hash_custom_cmp_eq = func;
}

static inline int
dpdk_hash_cmp_eq(const void *key1, const void *key2, const struct dpdk_hash *h)
{
	if (h->cmp_jump_table_idx == KEY_CUSTOM)
		return h->dpdk_hash_custom_cmp_eq(key1, key2, h->key_len);
	else
		return cmp_jump_table[h->cmp_jump_table_idx](key1, key2, h->key_len);
}

/*
 * We use higher 16 bits of hash as the signature value stored in table.
 * We use the lower bits for the primary bucket
 * location. Then we XOR primary bucket location and the signature
 * to get the secondary bucket location. This is same as
 * proposed in Bin Fan, et al's paper
 * "MemC3: Compact and Concurrent MemCache with Dumber Caching and
 * Smarter Hashing". The benefit to use
 * XOR is that one could derive the alternative bucket location
 * by only using the current bucket location and the signature.
 */
static inline uint16_t
get_short_sig(const hash_sig_t hash)
{
	return hash >> 16;
}

static inline uint32_t
get_prim_bucket_index(const struct dpdk_hash *h, const hash_sig_t hash)
{
	return hash & h->bucket_bitmask;
}

static inline uint32_t
get_alt_bucket_index(const struct dpdk_hash *h,
			uint32_t cur_bkt_idx, uint16_t sig)
{
	return (cur_bkt_idx ^ sig) & h->bucket_bitmask;
}

struct dpdk_hash *
dpdk_hash_create(const struct dpdk_hash_parameters *params)
{
	struct dpdk_hash *h = NULL;
	struct fsring *r = NULL;
	char hash_name[DPDK_HASH_NAMESIZE];
	void *k = NULL;
	void *buckets = NULL;
#define STACK_NAMESIZE 64
	char ring_name[STACK_NAMESIZE];
#undef STACK_NAMESIZE
	unsigned num_key_slots;
	uint32_t *tbl_chng_cnt = NULL;
	uint32_t i;

	dpdk_hash_function default_hash_func = (dpdk_hash_function)rte_jhash;

	if (params == NULL) {
		RTE_LOG(ERR, HASH, "dpdk_hash_create has no parameters\n");
		return NULL;
	}

	/* Check for valid parameters */
	if ((params->entries > DPDK_HASH_ENTRIES_MAX) ||
			(params->entries < DPDK_HASH_BUCKET_ENTRIES) ||
			(params->key_len == 0)) {
		rte_errno = EINVAL;
		RTE_LOG(ERR, HASH, "dpdk_hash_create has invalid parameters\n");
		return NULL;
	}

	if (params->extra_flag & ~DPDK_HASH_EXTRA_FLAGS_MASK) {
		rte_errno = EINVAL;
		RTE_LOG(ERR, HASH, "dpdk_hash_create: unsupported extra flags\n");
		return NULL;
	}

	num_key_slots = params->entries + 1;

	snprintf(ring_name, sizeof(ring_name), "HT_%s", params->name);
	/* Create ring (Dummy slot index is not enqueued) */
    r = fsring_create(rte_align32pow2(num_key_slots), params->socket_id);
	if (r == NULL) {
		RTE_LOG(ERR, HASH, "memory allocation failed\n");
		goto err;
	}

	const uint32_t num_buckets = rte_align32pow2(params->entries) /
						DPDK_HASH_BUCKET_ENTRIES;

	snprintf(hash_name, sizeof(hash_name), "HT_%s", params->name);

	h = (struct dpdk_hash *)rte_zmalloc_socket(hash_name, sizeof(struct dpdk_hash),
					RTE_CACHE_LINE_SIZE, params->socket_id);

	if (h == NULL) {
		RTE_LOG(ERR, HASH, "memory allocation failed\n");
		goto err_unlock;
	}

	buckets = rte_zmalloc_socket(NULL,
				num_buckets * sizeof(struct dpdk_hash_bucket),
				RTE_CACHE_LINE_SIZE, params->socket_id);

	if (buckets == NULL) {
		RTE_LOG(ERR, HASH, "buckets memory allocation failed\n");
		goto err_unlock;
	}

	const uint32_t key_entry_size =
		RTE_ALIGN(sizeof(struct dpdk_hash_key) + params->key_len,
			  KEY_ALIGNMENT);
	const uint64_t key_tbl_size = (uint64_t) key_entry_size * num_key_slots;

	k = rte_zmalloc_socket(NULL, key_tbl_size,
			RTE_CACHE_LINE_SIZE, params->socket_id);

	if (k == NULL) {
		RTE_LOG(ERR, HASH, "memory allocation failed\n");
		goto err_unlock;
	}

	tbl_chng_cnt = rte_zmalloc_socket(NULL, sizeof(uint32_t),
			RTE_CACHE_LINE_SIZE, params->socket_id);

	if (tbl_chng_cnt == NULL) {
		RTE_LOG(ERR, HASH, "memory allocation failed\n");
		goto err_unlock;
	}

/*
 * If x86 architecture is used, select appropriate compare function,
 * which may use x86 intrinsics, otherwise use memcmp
 */
#if defined(RTE_ARCH_X86) || defined(RTE_ARCH_ARM64)
	/* Select function to compare keys */
	switch (params->key_len) {
	case 16:
		h->cmp_jump_table_idx = KEY_16_BYTES;
		break;
	case 32:
		h->cmp_jump_table_idx = KEY_32_BYTES;
		break;
	case 48:
		h->cmp_jump_table_idx = KEY_48_BYTES;
		break;
	case 64:
		h->cmp_jump_table_idx = KEY_64_BYTES;
		break;
	case 80:
		h->cmp_jump_table_idx = KEY_80_BYTES;
		break;
	case 96:
		h->cmp_jump_table_idx = KEY_96_BYTES;
		break;
	case 112:
		h->cmp_jump_table_idx = KEY_112_BYTES;
		break;
	case 128:
		h->cmp_jump_table_idx = KEY_128_BYTES;
		break;
	default:
		/* If key is not multiple of 16, use generic memcmp */
		h->cmp_jump_table_idx = KEY_OTHER_BYTES;
	}
#else
	h->cmp_jump_table_idx = KEY_OTHER_BYTES;
#endif

	/* Default hash function */
#if defined(RTE_ARCH_X86)
	default_hash_func = (dpdk_hash_function)rte_hash_crc;
#elif defined(RTE_ARCH_ARM64)
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_CRC32))
		default_hash_func = (dpdk_hash_function)dpdk_hash_crc;
#endif
	/* Setup hash context */
	strlcpy(h->name, params->name, sizeof(h->name));
	h->entries = params->entries;
	h->key_len = params->key_len;
	h->key_entry_size = key_entry_size;
	h->hash_func_init_val = params->hash_func_init_val;

	h->num_buckets = num_buckets;
	h->bucket_bitmask = h->num_buckets - 1;
	h->buckets = buckets;
	h->hash_func = (params->hash_func == NULL) ?
		default_hash_func : params->hash_func;
	h->key_store = k;
	h->free_slots = r;
	h->tbl_chng_cnt = tbl_chng_cnt;
	*h->tbl_chng_cnt = 0;

#if defined(RTE_ARCH_X86)
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSE2))
		h->sig_cmp_fn = DPDK_HASH_COMPARE_SSE;
	else
#elif defined(RTE_ARCH_ARM64)
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_NEON))
		h->sig_cmp_fn = DPDK_HASH_COMPARE_NEON;
	else
#endif
		h->sig_cmp_fn = DPDK_HASH_COMPARE_SCALAR;

	/* Populate free slots ring. Entry zero is reserved for key misses. */
	for (i = 1; i < num_key_slots; i++)
        fsring_enqueue(r, i);

	return h;
err_unlock:
err:
	fsring_free(r);
	rte_free(h);
	rte_free(buckets);
	rte_free(k);
	rte_free(tbl_chng_cnt);
	return NULL;
}

void
dpdk_hash_free(struct dpdk_hash *h)
{
	if (h == NULL)
		return;

	fsring_free(h->free_slots);
	rte_free(h->key_store);
	rte_free(h->buckets);
	rte_free(h->tbl_chng_cnt);
	rte_free(h);
}

hash_sig_t
dpdk_hash_hash(const struct dpdk_hash *h, const void *key)
{
	/* calc hash result by key */
	return h->hash_func(key, h->key_len, h->hash_func_init_val);
}

int32_t
dpdk_hash_max_key_id(const struct dpdk_hash *h)
{
	RETURN_IF_TRUE((h == NULL), -EINVAL);
	return h->entries;
}

int32_t
dpdk_hash_count(const struct dpdk_hash *h)
{
	uint32_t tot_ring_cnt;
	uint32_t ret;

	if (h == NULL)
		return -EINVAL;

    tot_ring_cnt = h->entries;

    ret = tot_ring_cnt - fsring_count(h->free_slots);
	return ret;
}

void
dpdk_hash_reset(struct dpdk_hash *h)
{
	uint32_t tot_ring_cnt, i;

	if (h == NULL)
		return;

	memset(h->buckets, 0, h->num_buckets * sizeof(struct dpdk_hash_bucket));
	memset(h->key_store, 0, h->key_entry_size * (h->entries + 1));
	*h->tbl_chng_cnt = 0;

	/* reset the free ring */
    fsring_reset(h->free_slots);

    tot_ring_cnt = h->entries;

	for (i = 1; i < tot_ring_cnt + 1; i++)
        fsring_enqueue(h->free_slots, i);
}

/*
 * Function called to enqueue back an index in the cache/ring,
 * as slot has not being used and it can be used in the
 * next addition attempt.
 */
static inline void
enqueue_slot_back(const struct dpdk_hash *h,
		uint32_t slot_id)
{
    fsring_enqueue(h->free_slots, slot_id);
}

/* Search a key from bucket and update its data.
 * Writer holds the lock before calling this.
 */
static inline int32_t
search_and_update(const struct dpdk_hash *h, void *data, const void *key,
	struct dpdk_hash_bucket *bkt, uint16_t sig)
{
	int i;
	struct dpdk_hash_key *k, *keys = h->key_store;

	for (i = 0; i < DPDK_HASH_BUCKET_ENTRIES; i++) {
		if (bkt->sig_current[i] == sig) {
			k = (struct dpdk_hash_key *) ((char *)keys +
					bkt->key_idx[i] * h->key_entry_size);
			if (dpdk_hash_cmp_eq(key, k->key, h) == 0) {
				/* The store to application data at *data
				 * should not leak after the store to pdata
				 * in the key store. i.e. pdata is the guard
				 * variable. Release the application data
				 * to the readers.
				 */
                k->pdata = data;
				// __atomic_store_n(&k->pdata,
				// 	data,
				// 	__ATOMIC_RELEASE);
				/*
				 * Return index where key is stored,
				 * subtracting the first dummy index
				 */
				return bkt->key_idx[i] - 1;
			}
		}
	}
	return -1;
}

/* Only tries to insert at one bucket (@prim_bkt) without trying to push
 * buckets around.
 * return 1 if matching existing key, return 0 if succeeds, return -1 for no
 * empty entry.
 */
static inline int32_t
dpdk_hash_cuckoo_insert_mw(const struct dpdk_hash *h,
		struct dpdk_hash_bucket *prim_bkt,
		struct dpdk_hash_bucket *sec_bkt,
		const struct dpdk_hash_key *key, void *data,
		uint16_t sig, uint32_t new_idx,
		int32_t *ret_val)
{
	unsigned int i;
	int32_t ret;

	/* Check if key was inserted after last check but before this
	 * protected region in case of inserting duplicated keys.
	 */
	ret = search_and_update(h, data, key, prim_bkt, sig);
	if (ret != -1) {
		*ret_val = ret;
		return 1;
	}

    ret = search_and_update(h, data, key, sec_bkt, sig);
    if (ret != -1) {
        *ret_val = ret;
        return 1;
    }

	/* Insert new entry if there is room in the primary
	 * bucket.
	 */
	for (i = 0; i < DPDK_HASH_BUCKET_ENTRIES; i++) {
		/* Check if slot is available */
		if (likely(prim_bkt->key_idx[i] == EMPTY_SLOT)) {
			prim_bkt->sig_current[i] = sig;
			/* Store to signature and key should not
			 * leak after the store to key_idx. i.e.
			 * key_idx is the guard variable for signature
			 * and key.
			 */
             prim_bkt->key_idx[i] = new_idx;
			// __atomic_store_n(&prim_bkt->key_idx[i],
			// 		 new_idx,
			// 		 __ATOMIC_RELEASE);
			break;
		}
	}

	if (i != DPDK_HASH_BUCKET_ENTRIES)
		return 0;

	/* no empty entry */
	return -1;
}

/* Shift buckets along provided cuckoo_path (@leaf and @leaf_slot) and fill
 * the path head with new entry (sig, alt_hash, new_idx)
 * return 1 if matched key found, return -1 if cuckoo path invalided and fail,
 * return 0 if succeeds.
 */
static inline int
dpdk_hash_cuckoo_move_insert_mw(const struct dpdk_hash *h,
			struct dpdk_hash_bucket *bkt,
			struct dpdk_hash_bucket *alt_bkt,
			const struct dpdk_hash_key *key, void *data,
			struct queue_node *leaf, uint32_t leaf_slot,
			uint16_t sig, uint32_t new_idx,
			int32_t *ret_val)
{
	uint32_t prev_alt_bkt_idx;
	struct queue_node *prev_node, *curr_node = leaf;
	struct dpdk_hash_bucket *prev_bkt, *curr_bkt = leaf->bkt;
	uint32_t prev_slot, curr_slot = leaf_slot;
	int32_t ret;

	/* In case empty slot was gone before entering protected region */
	if (curr_bkt->key_idx[curr_slot] != EMPTY_SLOT) {
		return -1;
	}

	/* Check if key was inserted after last check but before this
	 * protected region.
	 */
	ret = search_and_update(h, data, key, bkt, sig);
	if (ret != -1) {
		*ret_val = ret;
		return 1;
	}

    ret = search_and_update(h, data, key, alt_bkt, sig);
    if (ret != -1) {
        *ret_val = ret;
        return 1;
    }

	while (likely(curr_node->prev != NULL)) {
		prev_node = curr_node->prev;
		prev_bkt = prev_node->bkt;
		prev_slot = curr_node->prev_slot;

		prev_alt_bkt_idx = get_alt_bucket_index(h,
					prev_node->cur_bkt_idx,
					prev_bkt->sig_current[prev_slot]);

		if (unlikely(&h->buckets[prev_alt_bkt_idx]
				!= curr_bkt)) {
			/* revert it to empty, otherwise duplicated keys */
            curr_bkt->key_idx[curr_slot] = EMPTY_SLOT;
			// __atomic_store_n(&curr_bkt->key_idx[curr_slot],
			// 	EMPTY_SLOT,
			// 	__ATOMIC_RELEASE);
			return -1;
		}

		/* Need to swap current/alt sig to allow later
		 * Cuckoo insert to move elements back to its
		 * primary bucket if available
		 */
		curr_bkt->sig_current[curr_slot] =
			prev_bkt->sig_current[prev_slot];
		/* Release the updated bucket entry */
        curr_bkt->key_idx[curr_slot] = prev_bkt->key_idx[prev_slot];
		// __atomic_store_n(&curr_bkt->key_idx[curr_slot],
		// 	prev_bkt->key_idx[prev_slot],
		// 	__ATOMIC_RELEASE);

		curr_slot = prev_slot;
		curr_node = prev_node;
		curr_bkt = curr_node->bkt;
	}

	curr_bkt->sig_current[curr_slot] = sig;
	/* Release the new bucket entry */
    curr_bkt->key_idx[curr_slot] = new_idx;
	// __atomic_store_n(&curr_bkt->key_idx[curr_slot],
	// 		 new_idx,
	// 		 __ATOMIC_RELEASE);

	return 0;

}

/*
 * Make space for new key, using bfs Cuckoo Search and Multi-Writer safe
 * Cuckoo
 */
static inline int
dpdk_hash_cuckoo_make_space_mw(const struct dpdk_hash *h,
			struct dpdk_hash_bucket *bkt,
			struct dpdk_hash_bucket *sec_bkt,
			const struct dpdk_hash_key *key, void *data,
			uint16_t sig, uint32_t bucket_idx,
			uint32_t new_idx, int32_t *ret_val)
{
	unsigned int i;
	struct queue_node queue[DPDK_HASH_BFS_QUEUE_MAX_LEN];
	struct queue_node *tail, *head;
	struct dpdk_hash_bucket *curr_bkt, *alt_bkt;
	uint32_t cur_idx, alt_idx;

	tail = queue;
	head = queue + 1;
	tail->bkt = bkt;
	tail->prev = NULL;
	tail->prev_slot = -1;
	tail->cur_bkt_idx = bucket_idx;

	/* Cuckoo bfs Search */
	while (likely(tail != head && head <
					queue + DPDK_HASH_BFS_QUEUE_MAX_LEN -
					DPDK_HASH_BUCKET_ENTRIES)) {
		curr_bkt = tail->bkt;
		cur_idx = tail->cur_bkt_idx;
		for (i = 0; i < DPDK_HASH_BUCKET_ENTRIES; i++) {
			if (curr_bkt->key_idx[i] == EMPTY_SLOT) {
				int32_t ret = dpdk_hash_cuckoo_move_insert_mw(h,
						bkt, sec_bkt, key, data,
						tail, i, sig,
						new_idx, ret_val);
				if (likely(ret != -1))
					return ret;
			}

			/* Enqueue new node and keep prev node info */
			alt_idx = get_alt_bucket_index(h, cur_idx,
						curr_bkt->sig_current[i]);
			alt_bkt = &(h->buckets[alt_idx]);
			head->bkt = alt_bkt;
			head->cur_bkt_idx = alt_idx;
			head->prev = tail;
			head->prev_slot = i;
			head++;
		}
		tail++;
	}

	return -ENOSPC;
}

static inline uint32_t
alloc_slot(const struct dpdk_hash *h)
{
	uint32_t slot_id;
    
    if (fsring_dequeue(h->free_slots, &slot_id) != 0)
        return EMPTY_SLOT;

    return slot_id;
}

static inline int32_t
__dpdk_hash_add_key_with_hash(const struct dpdk_hash *h, const void *key,
						hash_sig_t sig, void *data)
{
	uint16_t short_sig;
	uint32_t prim_bucket_idx, sec_bucket_idx;
	struct dpdk_hash_bucket *prim_bkt, *sec_bkt;
	struct dpdk_hash_key *new_k, *keys = h->key_store;
	uint32_t slot_id;
	int ret;
	int32_t ret_val;

	short_sig = get_short_sig(sig);
	prim_bucket_idx = get_prim_bucket_index(h, sig);
	sec_bucket_idx = get_alt_bucket_index(h, prim_bucket_idx, short_sig);
	prim_bkt = &h->buckets[prim_bucket_idx];
	sec_bkt = &h->buckets[sec_bucket_idx];
	rte_prefetch0(prim_bkt);
	rte_prefetch0(sec_bkt);

	/* Check if key is already inserted in primary location */
	ret = search_and_update(h, data, key, prim_bkt, short_sig);
	if (ret != -1) {
		return ret;
	}

	/* Check if key is already inserted in secondary location */
    ret = search_and_update(h, data, key, sec_bkt, short_sig);
    if (ret != -1) {
        return ret;
    }

	/* Did not find a match, so get a new slot for storing the new key */

	slot_id = alloc_slot(h);
	if (slot_id == EMPTY_SLOT) {
		return -ENOSPC;
	}

	new_k = RTE_PTR_ADD(keys, slot_id * h->key_entry_size);
	/* The store to application data (by the application) at *data should
	 * not leak after the store of pdata in the key store. i.e. pdata is
	 * the guard variable. Release the application data to the readers.
	 */
    new_k->pdata = data;
	// __atomic_store_n(&new_k->pdata,
	// 	data,
	// 	__ATOMIC_RELEASE);
	/* Copy key */
	memcpy(new_k->key, key, h->key_len);

	/* Find an empty slot and insert */
	ret = dpdk_hash_cuckoo_insert_mw(h, prim_bkt, sec_bkt, key, data,
					short_sig, slot_id, &ret_val);
	if (ret == 0)
		return slot_id - 1;
	else if (ret == 1) {
		enqueue_slot_back(h, slot_id);
		return ret_val;
	}

	/* Primary bucket full, need to make space for new entry */
	ret = dpdk_hash_cuckoo_make_space_mw(h, prim_bkt, sec_bkt, key, data,
				short_sig, prim_bucket_idx, slot_id, &ret_val);
	if (ret == 0)
		return slot_id - 1;
	else if (ret == 1) {
		enqueue_slot_back(h, slot_id);
		return ret_val;
	}

	/* Also search secondary bucket to get better occupancy */
	ret = dpdk_hash_cuckoo_make_space_mw(h, sec_bkt, prim_bkt, key, data,
				short_sig, sec_bucket_idx, slot_id, &ret_val);

	if (ret == 0)
		return slot_id - 1;
	else if (ret == 1) {
		enqueue_slot_back(h, slot_id);
		return ret_val;
	}

    /* if ext table not enabled, we failed the insertion */
    enqueue_slot_back(h, slot_id);
    return ret;
}

int32_t
dpdk_hash_add_key_with_hash(const struct dpdk_hash *h,
			const void *key, hash_sig_t sig)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __dpdk_hash_add_key_with_hash(h, key, sig, 0);
}

int32_t
dpdk_hash_add_key(const struct dpdk_hash *h, const void *key)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __dpdk_hash_add_key_with_hash(h, key, dpdk_hash_hash(h, key), 0);
}

int
dpdk_hash_add_key_with_hash_data(const struct dpdk_hash *h,
			const void *key, hash_sig_t sig, void *data)
{
	int ret;

	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	ret = __dpdk_hash_add_key_with_hash(h, key, sig, data);
	if (ret >= 0)
		return 0;
	else
		return ret;
}

int
dpdk_hash_add_key_data(const struct dpdk_hash *h, const void *key, void *data)
{
	int ret;

	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	ret = __dpdk_hash_add_key_with_hash(h, key, dpdk_hash_hash(h, key), data);
	if (ret >= 0)
		return 0;
	else
		return ret;
}

/* Search one bucket to find the match key - uses rw lock */
static inline int32_t
search_one_bucket_l(const struct dpdk_hash *h, const void *key,
		uint16_t sig, void **data,
		const struct dpdk_hash_bucket *bkt)
{
	int i;
	struct dpdk_hash_key *k, *keys = h->key_store;

	for (i = 0; i < DPDK_HASH_BUCKET_ENTRIES; i++) {
		if (bkt->sig_current[i] == sig &&
				bkt->key_idx[i] != EMPTY_SLOT) {
			k = (struct dpdk_hash_key *) ((char *)keys +
					bkt->key_idx[i] * h->key_entry_size);

			if (dpdk_hash_cmp_eq(key, k->key, h) == 0) {
				if (data != NULL)
					*data = k->pdata;
				/*
				 * Return index where key is stored,
				 * subtracting the first dummy index
				 */
				return bkt->key_idx[i] - 1;
			}
		}
	}
	return -1;
}

static inline int32_t
__dpdk_hash_lookup_with_hash_l(const struct dpdk_hash *h, const void *key,
				hash_sig_t sig, void **data)
{
	uint32_t prim_bucket_idx, sec_bucket_idx;
	struct dpdk_hash_bucket *bkt;
	int ret;
	uint16_t short_sig;

	short_sig = get_short_sig(sig);
	prim_bucket_idx = get_prim_bucket_index(h, sig);
	sec_bucket_idx = get_alt_bucket_index(h, prim_bucket_idx, short_sig);

	bkt = &h->buckets[prim_bucket_idx];

	/* Check if key is in primary location */
	ret = search_one_bucket_l(h, key, short_sig, data, bkt);
	if (ret != -1) {
		return ret;
	}
	/* Calculate secondary hash */
	bkt = &h->buckets[sec_bucket_idx];

	/* Check if key is in secondary location */
    ret = search_one_bucket_l(h, key, short_sig,
                data, bkt);
    if (ret != -1) {
        return ret;
    }

	return -ENOENT;
}

static inline int32_t
__dpdk_hash_lookup_with_hash(const struct dpdk_hash *h, const void *key,
					hash_sig_t sig, void **data)
{
	return __dpdk_hash_lookup_with_hash_l(h, key, sig, data);
}

int32_t
dpdk_hash_lookup_with_hash(const struct dpdk_hash *h,
			const void *key, hash_sig_t sig)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __dpdk_hash_lookup_with_hash(h, key, sig, NULL);
}

int32_t
dpdk_hash_lookup(const struct dpdk_hash *h, const void *key)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __dpdk_hash_lookup_with_hash(h, key, dpdk_hash_hash(h, key), NULL);
}

int
dpdk_hash_lookup_with_hash_data(const struct dpdk_hash *h,
			const void *key, hash_sig_t sig, void **data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __dpdk_hash_lookup_with_hash(h, key, sig, data);
}

int
dpdk_hash_lookup_data(const struct dpdk_hash *h, const void *key, void **data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __dpdk_hash_lookup_with_hash(h, key, dpdk_hash_hash(h, key), data);
}

static int
free_slot(const struct dpdk_hash *h, uint32_t slot_id)
{
	enqueue_slot_back(h, slot_id);
	return 0;
}

static inline void
remove_entry(const struct dpdk_hash *h, struct dpdk_hash_bucket *bkt,
		unsigned int i)
{
	int ret = free_slot(h, bkt->key_idx[i]);

	if (ret < 0) {
		RTE_LOG(ERR, HASH,
			"%s: could not enqueue free slots in global ring\n",
				__func__);
	}
}

/* Search one bucket and remove the matched key.
 * Writer is expected to hold the lock while calling this
 * function.
 */
static inline int32_t
search_and_remove(const struct dpdk_hash *h, const void *key,
			struct dpdk_hash_bucket *bkt, uint16_t sig, int *pos)
{
	struct dpdk_hash_key *k, *keys = h->key_store;
	unsigned int i;
	uint32_t key_idx;

	/* Check if key is in bucket */
	for (i = 0; i < DPDK_HASH_BUCKET_ENTRIES; i++) {
        key_idx = bkt->key_idx[i];
		// key_idx = __atomic_load_n(&bkt->key_idx[i],
		// 			  __ATOMIC_ACQUIRE);
		if (bkt->sig_current[i] == sig && key_idx != EMPTY_SLOT) {
			k = (struct dpdk_hash_key *) ((char *)keys +
					key_idx * h->key_entry_size);
			if (dpdk_hash_cmp_eq(key, k->key, h) == 0) {
				bkt->sig_current[i] = NULL_SIGNATURE;
				/* Free the key store index if
				 * no_free_on_del is disabled.
				 */
                remove_entry(h, bkt, i);
                bkt->key_idx[i] = EMPTY_SLOT;
				// __atomic_store_n(&bkt->key_idx[i],
				// 		 EMPTY_SLOT,
				// 		 __ATOMIC_RELEASE);

				*pos = i;
				/*
				 * Return index where key is stored,
				 * subtracting the first dummy index
				 */
				return key_idx - 1;
			}
		}
	}
	return -1;
}

static inline int32_t
__dpdk_hash_del_key_with_hash(const struct dpdk_hash *h, const void *key,
						hash_sig_t sig)
{
	uint32_t prim_bucket_idx, sec_bucket_idx;
	struct dpdk_hash_bucket *prim_bkt, *sec_bkt;
	int pos;
	int32_t ret;
	uint16_t short_sig;

	short_sig = get_short_sig(sig);
	prim_bucket_idx = get_prim_bucket_index(h, sig);
	sec_bucket_idx = get_alt_bucket_index(h, prim_bucket_idx, short_sig);
	prim_bkt = &h->buckets[prim_bucket_idx];

	/* look for key in primary bucket */
	ret = search_and_remove(h, key, prim_bkt, short_sig, &pos);
	if (ret != -1) {
	    return ret;
	}

	/* Calculate secondary hash */
	sec_bkt = &h->buckets[sec_bucket_idx];

    ret = search_and_remove(h, key, sec_bkt, short_sig, &pos);
    if (ret != -1) {
	    return ret;
    }

	return -ENOENT;
}

int32_t
dpdk_hash_del_key_with_hash(const struct dpdk_hash *h,
			const void *key, hash_sig_t sig)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __dpdk_hash_del_key_with_hash(h, key, sig);
}

int32_t
dpdk_hash_del_key(const struct dpdk_hash *h, const void *key)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __dpdk_hash_del_key_with_hash(h, key, dpdk_hash_hash(h, key));
}

int
dpdk_hash_get_key_with_position(const struct dpdk_hash *h, const int32_t position,
			       void **key)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	struct dpdk_hash_key *k, *keys = h->key_store;
	k = (struct dpdk_hash_key *) ((char *) keys + (position + 1) *
				     h->key_entry_size);
	*key = k->key;

	if (position !=
	    __dpdk_hash_lookup_with_hash(h, *key, dpdk_hash_hash(h, *key),
					NULL)) {
		return -ENOENT;
	}

	return 0;
}

int
dpdk_hash_free_key_with_position(const struct dpdk_hash *h,
				const int32_t position)
{
	/* Key index where key is stored, adding the first dummy index */
	uint32_t key_idx = position + 1;

	RETURN_IF_TRUE(((h == NULL) || (key_idx == EMPTY_SLOT)), -EINVAL);

	const uint32_t total_entries = h->entries + 1;

	/* Out of bounds */
	if (key_idx >= total_entries)
		return -EINVAL;

	/* Enqueue slot to cache/ring of free slots. */
	return free_slot(h, key_idx);

}

static inline void
compare_signatures(uint32_t *prim_hash_matches, uint32_t *sec_hash_matches,
			const struct dpdk_hash_bucket *prim_bkt,
			const struct dpdk_hash_bucket *sec_bkt,
			uint16_t sig,
			enum dpdk_hash_sig_compare_function sig_cmp_fn)
{
	unsigned int i;

	/* For match mask the first bit of every two bits indicates the match */
	switch (sig_cmp_fn) {
#if defined(__SSE2__)
	case DPDK_HASH_COMPARE_SSE:
		/* Compare all signatures in the bucket */
		*prim_hash_matches = _mm_movemask_epi8(_mm_cmpeq_epi16(
				_mm_load_si128(
					(__m128i const *)prim_bkt->sig_current),
				_mm_set1_epi16(sig)));
		/* Compare all signatures in the bucket */
		*sec_hash_matches = _mm_movemask_epi8(_mm_cmpeq_epi16(
				_mm_load_si128(
					(__m128i const *)sec_bkt->sig_current),
				_mm_set1_epi16(sig)));
		break;
#elif defined(__ARM_NEON)
	case DPDK_HASH_COMPARE_NEON: {
		uint16x8_t vmat, vsig, x;
		int16x8_t shift = {-15, -13, -11, -9, -7, -5, -3, -1};

		vsig = vld1q_dup_u16((uint16_t const *)&sig);
		/* Compare all signatures in the primary bucket */
		vmat = vceqq_u16(vsig,
			vld1q_u16((uint16_t const *)prim_bkt->sig_current));
		x = vshlq_u16(vandq_u16(vmat, vdupq_n_u16(0x8000)), shift);
		*prim_hash_matches = (uint32_t)(vaddvq_u16(x));
		/* Compare all signatures in the secondary bucket */
		vmat = vceqq_u16(vsig,
			vld1q_u16((uint16_t const *)sec_bkt->sig_current));
		x = vshlq_u16(vandq_u16(vmat, vdupq_n_u16(0x8000)), shift);
		*sec_hash_matches = (uint32_t)(vaddvq_u16(x));
		}
		break;
#endif
	default:
		for (i = 0; i < DPDK_HASH_BUCKET_ENTRIES; i++) {
			*prim_hash_matches |=
				((sig == prim_bkt->sig_current[i]) << (i << 1));
			*sec_hash_matches |=
				((sig == sec_bkt->sig_current[i]) << (i << 1));
		}
	}
}

static inline void
__bulk_lookup_l(const struct dpdk_hash *h, const void **keys,
		const struct dpdk_hash_bucket **primary_bkt,
		const struct dpdk_hash_bucket **secondary_bkt,
		uint16_t *sig, int32_t num_keys, int32_t *positions,
		uint64_t *hit_mask, void *data[])
{
	uint64_t hits = 0;
	int32_t i;
	uint32_t prim_hitmask[DPDK_HASH_LOOKUP_BULK_MAX] = {0};
	uint32_t sec_hitmask[DPDK_HASH_LOOKUP_BULK_MAX] = {0};

	/* Compare signatures and prefetch key slot of first hit */
	for (i = 0; i < num_keys; i++) {
		compare_signatures(&prim_hitmask[i], &sec_hitmask[i],
			primary_bkt[i], secondary_bkt[i],
			sig[i], h->sig_cmp_fn);

		if (prim_hitmask[i]) {
			uint32_t first_hit =
					__builtin_ctzl(prim_hitmask[i])
					>> 1;
			uint32_t key_idx =
				primary_bkt[i]->key_idx[first_hit];
			const struct dpdk_hash_key *key_slot =
				(const struct dpdk_hash_key *)(
				(const char *)h->key_store +
				key_idx * h->key_entry_size);
			rte_prefetch0(key_slot);
			continue;
		}

		if (sec_hitmask[i]) {
			uint32_t first_hit =
					__builtin_ctzl(sec_hitmask[i])
					>> 1;
			uint32_t key_idx =
				secondary_bkt[i]->key_idx[first_hit];
			const struct dpdk_hash_key *key_slot =
				(const struct dpdk_hash_key *)(
				(const char *)h->key_store +
				key_idx * h->key_entry_size);
			rte_prefetch0(key_slot);
		}
	}

	/* Compare keys, first hits in primary first */
	for (i = 0; i < num_keys; i++) {
		positions[i] = -ENOENT;
		while (prim_hitmask[i]) {
			uint32_t hit_index =
					__builtin_ctzl(prim_hitmask[i])
					>> 1;
			uint32_t key_idx =
				primary_bkt[i]->key_idx[hit_index];
			const struct dpdk_hash_key *key_slot =
				(const struct dpdk_hash_key *)(
				(const char *)h->key_store +
				key_idx * h->key_entry_size);

			/*
			 * If key index is 0, do not compare key,
			 * as it is checking the dummy slot
			 */
			if (!!key_idx &
				!dpdk_hash_cmp_eq(
					key_slot->key, keys[i], h)) {
				if (data != NULL)
					data[i] = key_slot->pdata;

				hits |= 1ULL << i;
				positions[i] = key_idx - 1;
				goto next_key;
			}
			prim_hitmask[i] &= ~(3ULL << (hit_index << 1));
		}

		while (sec_hitmask[i]) {
			uint32_t hit_index =
					__builtin_ctzl(sec_hitmask[i])
					>> 1;
			uint32_t key_idx =
				secondary_bkt[i]->key_idx[hit_index];
			const struct dpdk_hash_key *key_slot =
				(const struct dpdk_hash_key *)(
				(const char *)h->key_store +
				key_idx * h->key_entry_size);

			/*
			 * If key index is 0, do not compare key,
			 * as it is checking the dummy slot
			 */

			if (!!key_idx &
				!dpdk_hash_cmp_eq(
					key_slot->key, keys[i], h)) {
				if (data != NULL)
					data[i] = key_slot->pdata;

				hits |= 1ULL << i;
				positions[i] = key_idx - 1;
				goto next_key;
			}
			sec_hitmask[i] &= ~(3ULL << (hit_index << 1));
		}
next_key:
		continue;
	}

    if (hit_mask != NULL)
        *hit_mask = hits;
}

#define PREFETCH_OFFSET 4
static inline void
__bulk_lookup_prefetching_loop(const struct dpdk_hash *h,
	const void **keys, int32_t num_keys,
	uint16_t *sig,
	const struct dpdk_hash_bucket **primary_bkt,
	const struct dpdk_hash_bucket **secondary_bkt)
{
	int32_t i;
	uint32_t prim_hash[DPDK_HASH_LOOKUP_BULK_MAX];
	uint32_t prim_index[DPDK_HASH_LOOKUP_BULK_MAX];
	uint32_t sec_index[DPDK_HASH_LOOKUP_BULK_MAX];

	/* Prefetch first keys */
	for (i = 0; i < PREFETCH_OFFSET && i < num_keys; i++)
		rte_prefetch0(keys[i]);

	/*
	 * Prefetch rest of the keys, calculate primary and
	 * secondary bucket and prefetch them
	 */
	for (i = 0; i < (num_keys - PREFETCH_OFFSET); i++) {
		rte_prefetch0(keys[i + PREFETCH_OFFSET]);

		prim_hash[i] = dpdk_hash_hash(h, keys[i]);

		sig[i] = get_short_sig(prim_hash[i]);
		prim_index[i] = get_prim_bucket_index(h, prim_hash[i]);
		sec_index[i] = get_alt_bucket_index(h, prim_index[i], sig[i]);

		primary_bkt[i] = &h->buckets[prim_index[i]];
		secondary_bkt[i] = &h->buckets[sec_index[i]];

		rte_prefetch0(primary_bkt[i]);
		rte_prefetch0(secondary_bkt[i]);
	}

	/* Calculate and prefetch rest of the buckets */
	for (; i < num_keys; i++) {
		prim_hash[i] = dpdk_hash_hash(h, keys[i]);

		sig[i] = get_short_sig(prim_hash[i]);
		prim_index[i] = get_prim_bucket_index(h, prim_hash[i]);
		sec_index[i] = get_alt_bucket_index(h, prim_index[i], sig[i]);

		primary_bkt[i] = &h->buckets[prim_index[i]];
		secondary_bkt[i] = &h->buckets[sec_index[i]];

		rte_prefetch0(primary_bkt[i]);
		rte_prefetch0(secondary_bkt[i]);
	}
}


static inline void
__dpdk_hash_lookup_bulk_l(const struct dpdk_hash *h, const void **keys,
			int32_t num_keys, int32_t *positions,
			uint64_t *hit_mask, void *data[])
{
	uint16_t sig[DPDK_HASH_LOOKUP_BULK_MAX];
	const struct dpdk_hash_bucket *primary_bkt[DPDK_HASH_LOOKUP_BULK_MAX];
	const struct dpdk_hash_bucket *secondary_bkt[DPDK_HASH_LOOKUP_BULK_MAX];

	__bulk_lookup_prefetching_loop(h, keys, num_keys, sig,
		primary_bkt, secondary_bkt);

	__bulk_lookup_l(h, keys, primary_bkt, secondary_bkt, sig, num_keys,
		positions, hit_mask, data);
}


static inline void
__dpdk_hash_lookup_bulk(const struct dpdk_hash *h, const void **keys,
			int32_t num_keys, int32_t *positions,
			uint64_t *hit_mask, void *data[])
{
    __dpdk_hash_lookup_bulk_l(h, keys, num_keys, positions,
                    hit_mask, data);
}

int
dpdk_hash_lookup_bulk(const struct dpdk_hash *h, const void **keys,
		      uint32_t num_keys, int32_t *positions)
{
	RETURN_IF_TRUE(((h == NULL) || (keys == NULL) || (num_keys == 0) ||
			(num_keys > DPDK_HASH_LOOKUP_BULK_MAX) ||
			(positions == NULL)), -EINVAL);

	__dpdk_hash_lookup_bulk(h, keys, num_keys, positions, NULL, NULL);
	return 0;
}

int
dpdk_hash_lookup_bulk_data(const struct dpdk_hash *h, const void **keys,
		      uint32_t num_keys, uint64_t *hit_mask, void *data[])
{
	RETURN_IF_TRUE(((h == NULL) || (keys == NULL) || (num_keys == 0) ||
			(num_keys > DPDK_HASH_LOOKUP_BULK_MAX) ||
			(hit_mask == NULL)), -EINVAL);

	int32_t positions[num_keys];

	__dpdk_hash_lookup_bulk(h, keys, num_keys, positions, hit_mask, data);

	/* Return number of hits */
	return __builtin_popcountl(*hit_mask);
}


static inline void
__dpdk_hash_lookup_with_hash_bulk_l(const struct dpdk_hash *h,
			const void **keys, hash_sig_t *prim_hash,
			int32_t num_keys, int32_t *positions,
			uint64_t *hit_mask, void *data[])
{
	int32_t i;
	uint32_t prim_index[DPDK_HASH_LOOKUP_BULK_MAX];
	uint32_t sec_index[DPDK_HASH_LOOKUP_BULK_MAX];
	uint16_t sig[DPDK_HASH_LOOKUP_BULK_MAX];
	const struct dpdk_hash_bucket *primary_bkt[DPDK_HASH_LOOKUP_BULK_MAX];
	const struct dpdk_hash_bucket *secondary_bkt[DPDK_HASH_LOOKUP_BULK_MAX];

	/*
	 * Prefetch keys, calculate primary and
	 * secondary bucket and prefetch them
	 */
	for (i = 0; i < num_keys; i++) {
		rte_prefetch0(keys[i]);

		sig[i] = get_short_sig(prim_hash[i]);
		prim_index[i] = get_prim_bucket_index(h, prim_hash[i]);
		sec_index[i] = get_alt_bucket_index(h, prim_index[i], sig[i]);

		primary_bkt[i] = &h->buckets[prim_index[i]];
		secondary_bkt[i] = &h->buckets[sec_index[i]];

		rte_prefetch0(primary_bkt[i]);
		rte_prefetch0(secondary_bkt[i]);
	}

	__bulk_lookup_l(h, keys, primary_bkt, secondary_bkt, sig, num_keys,
		positions, hit_mask, data);
}

static inline void
__dpdk_hash_lookup_with_hash_bulk(const struct dpdk_hash *h, const void **keys,
			hash_sig_t *prim_hash, int32_t num_keys,
			int32_t *positions, uint64_t *hit_mask, void *data[])
{
    __dpdk_hash_lookup_with_hash_bulk_l(h, keys, prim_hash,
            num_keys, positions, hit_mask, data);
}

int
dpdk_hash_lookup_with_hash_bulk(const struct dpdk_hash *h, const void **keys,
		hash_sig_t *sig, uint32_t num_keys, int32_t *positions)
{
	RETURN_IF_TRUE(((h == NULL) || (keys == NULL) ||
			(sig == NULL) || (num_keys == 0) ||
			(num_keys > DPDK_HASH_LOOKUP_BULK_MAX) ||
			(positions == NULL)), -EINVAL);

	__dpdk_hash_lookup_with_hash_bulk(h, keys, sig, num_keys,
		positions, NULL, NULL);
	return 0;
}

int
dpdk_hash_lookup_with_hash_bulk_data(const struct dpdk_hash *h,
		const void **keys, hash_sig_t *sig,
		uint32_t num_keys, uint64_t *hit_mask, void *data[])
{
	RETURN_IF_TRUE(((h == NULL) || (keys == NULL) ||
			(sig == NULL) || (num_keys == 0) ||
			(num_keys > DPDK_HASH_LOOKUP_BULK_MAX) ||
			(hit_mask == NULL)), -EINVAL);

	int32_t positions[num_keys];

	__dpdk_hash_lookup_with_hash_bulk(h, keys, sig, num_keys,
			positions, hit_mask, data);

	/* Return number of hits */
	return __builtin_popcountl(*hit_mask);
}

int32_t
dpdk_hash_iterate(const struct dpdk_hash *h, const void **key, void **data, uint32_t *next)
{
	uint32_t bucket_idx, idx, position;
	struct dpdk_hash_key *next_key;

	RETURN_IF_TRUE(((h == NULL) || (next == NULL)), -EINVAL);

	const uint32_t total_entries_main = h->num_buckets *
							DPDK_HASH_BUCKET_ENTRIES;

	/* Out of bounds of all buckets (both main table and ext table) */
	if (*next >= total_entries_main)
		goto extend_table;

	/* Calculate bucket and index of current iterator */
	bucket_idx = *next / DPDK_HASH_BUCKET_ENTRIES;
	idx = *next % DPDK_HASH_BUCKET_ENTRIES;

	/* If current position is empty, go to the next one */
    while ((position = h->buckets[bucket_idx].key_idx[idx])) {
	// while ((position = __atomic_load_n(&h->buckets[bucket_idx].key_idx[idx],
	// 				__ATOMIC_ACQUIRE)) == EMPTY_SLOT) {
		(*next)++;
		/* End of table */
		if (*next == total_entries_main)
			goto extend_table;
		bucket_idx = *next / DPDK_HASH_BUCKET_ENTRIES;
		idx = *next % DPDK_HASH_BUCKET_ENTRIES;
	}

	next_key = (struct dpdk_hash_key *) ((char *)h->key_store +
				position * h->key_entry_size);
	/* Return key and data */
	*key = next_key->key;
	*data = next_key->pdata;

	/* Increment iterator */
	(*next)++;

	return position - 1;

/* Begin to iterate extendable buckets */
extend_table:
	/* Out of total bound or if ext bucket feature is not enabled */
    return -ENOENT;
}
