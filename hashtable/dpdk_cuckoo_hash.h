/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016 Intel Corporation
 * Copyright(c) 2018 Arm Limited
 */

/* rte_cuckoo_hash.h
 * This file hold Cuckoo Hash private data structures to allows include from
 * platform specific files like rte_cuckoo_hash_x86.h
 */

#ifndef _DPDK_CUCKOO_HASH_H_
#define _DPDK_CUCKOO_HASH_H_

#include <rte_vect.h>

/* Functions to compare multiple of 16 byte keys (up to 128 bytes) */
static int
dpdk_hash_k16_cmp_eq(const void *key1, const void *key2, size_t key_len __rte_unused)
{
	const __m128i k1 = _mm_loadu_si128((const __m128i *) key1);
	const __m128i k2 = _mm_loadu_si128((const __m128i *) key2);
	const __m128i x = _mm_xor_si128(k1, k2);

	return !_mm_test_all_zeros(x, x);
}

static int
dpdk_hash_k32_cmp_eq(const void *key1, const void *key2, size_t key_len)
{
	return dpdk_hash_k16_cmp_eq(key1, key2, key_len) ||
		dpdk_hash_k16_cmp_eq((const char *) key1 + 16,
				(const char *) key2 + 16, key_len);
}

static int
dpdk_hash_k48_cmp_eq(const void *key1, const void *key2, size_t key_len)
{
	return dpdk_hash_k16_cmp_eq(key1, key2, key_len) ||
		dpdk_hash_k16_cmp_eq((const char *) key1 + 16,
				(const char *) key2 + 16, key_len) ||
		dpdk_hash_k16_cmp_eq((const char *) key1 + 32,
				(const char *) key2 + 32, key_len);
}

static int
dpdk_hash_k64_cmp_eq(const void *key1, const void *key2, size_t key_len)
{
	return dpdk_hash_k32_cmp_eq(key1, key2, key_len) ||
		dpdk_hash_k32_cmp_eq((const char *) key1 + 32,
				(const char *) key2 + 32, key_len);
}

static int
dpdk_hash_k80_cmp_eq(const void *key1, const void *key2, size_t key_len)
{
	return dpdk_hash_k64_cmp_eq(key1, key2, key_len) ||
		dpdk_hash_k16_cmp_eq((const char *) key1 + 64,
				(const char *) key2 + 64, key_len);
}

static int
dpdk_hash_k96_cmp_eq(const void *key1, const void *key2, size_t key_len)
{
	return dpdk_hash_k64_cmp_eq(key1, key2, key_len) ||
		dpdk_hash_k32_cmp_eq((const char *) key1 + 64,
				(const char *) key2 + 64, key_len);
}

static int
dpdk_hash_k112_cmp_eq(const void *key1, const void *key2, size_t key_len)
{
	return dpdk_hash_k64_cmp_eq(key1, key2, key_len) ||
		dpdk_hash_k32_cmp_eq((const char *) key1 + 64,
				(const char *) key2 + 64, key_len) ||
		dpdk_hash_k16_cmp_eq((const char *) key1 + 96,
				(const char *) key2 + 96, key_len);
}

static int
dpdk_hash_k128_cmp_eq(const void *key1, const void *key2, size_t key_len)
{
	return dpdk_hash_k64_cmp_eq(key1, key2, key_len) ||
		dpdk_hash_k64_cmp_eq((const char *) key1 + 64,
				(const char *) key2 + 64, key_len);
}

/* Macro to enable/disable run-time checking of function parameters */
#if defined(RTE_LIBDPDK_HASH_DEBUG)
#define RETURN_IF_TRUE(cond, retval) do { \
	if (cond) \
		return retval; \
} while (0)
#else
#define RETURN_IF_TRUE(cond, retval)
#endif

#if defined(RTE_LIBDPDK_HASH_DEBUG)
#define ERR_IF_TRUE(cond, fmt, args...) do { \
	if (cond) { \
		RTE_LOG(ERR, HASH, fmt, ##args); \
		return; \
	} \
} while (0)
#else
#define ERR_IF_TRUE(cond, fmt, args...)
#endif

#include <rte_hash_crc.h>
#include <rte_jhash.h>

#if defined(RTE_ARCH_X86) || defined(RTE_ARCH_ARM64)
/*
 * All different options to select a key compare function,
 * based on the key size and custom function.
 */
enum cmp_jump_table_case {
	KEY_CUSTOM = 0,
	KEY_16_BYTES,
	KEY_32_BYTES,
	KEY_48_BYTES,
	KEY_64_BYTES,
	KEY_80_BYTES,
	KEY_96_BYTES,
	KEY_112_BYTES,
	KEY_128_BYTES,
	KEY_OTHER_BYTES,
	NUM_KEY_CMP_CASES,
};

/*
 * Table storing all different key compare functions
 * (multi-process supported)
 */
const dpdk_hash_cmp_eq_t cmp_jump_table[NUM_KEY_CMP_CASES] = {
	NULL,
	dpdk_hash_k16_cmp_eq,
	dpdk_hash_k32_cmp_eq,
	dpdk_hash_k48_cmp_eq,
	dpdk_hash_k64_cmp_eq,
	dpdk_hash_k80_cmp_eq,
	dpdk_hash_k96_cmp_eq,
	dpdk_hash_k112_cmp_eq,
	dpdk_hash_k128_cmp_eq,
	memcmp
};
#else
/*
 * All different options to select a key compare function,
 * based on the key size and custom function.
 */
enum cmp_jump_table_case {
	KEY_CUSTOM = 0,
	KEY_OTHER_BYTES,
	NUM_KEY_CMP_CASES,
};

/*
 * Table storing all different key compare functions
 * (multi-process supported)
 */
const dpdk_hash_cmp_eq_t cmp_jump_table[NUM_KEY_CMP_CASES] = {
	NULL,
	memcmp
};

#endif


/** Number of items per bucket. */
#define DPDK_HASH_BUCKET_ENTRIES		8

#if !RTE_IS_POWER_OF_2(DPDK_HASH_BUCKET_ENTRIES)
#error DPDK_HASH_BUCKET_ENTRIES must be a power of 2
#endif

#define NULL_SIGNATURE			0

#define EMPTY_SLOT			0

#define KEY_ALIGNMENT			16

#define LCORE_CACHE_SIZE		64

#define DPDK_HASH_BFS_QUEUE_MAX_LEN       1000

#define RTE_XABORT_CUCKOO_PATH_INVALIDED 0x4

#define DPDK_HASH_TSX_MAX_RETRY  10

/* Structure that stores key-value pair */
struct dpdk_hash_key {
	union {
		uintptr_t idata;
		void *pdata;
	};
	/* Variable key size */
	char key[0];
};

/* All different signature compare functions */
enum dpdk_hash_sig_compare_function {
	DPDK_HASH_COMPARE_SCALAR = 0,
	DPDK_HASH_COMPARE_SSE,
	DPDK_HASH_COMPARE_NEON,
	DPDK_HASH_COMPARE_NUM
};

/** Bucket structure */
struct dpdk_hash_bucket {
	uint16_t sig_current[DPDK_HASH_BUCKET_ENTRIES];

	uint32_t key_idx[DPDK_HASH_BUCKET_ENTRIES];

	uint8_t flag[DPDK_HASH_BUCKET_ENTRIES];

	void *next;
} __rte_cache_aligned;

/** A hash table structure. */
struct dpdk_hash {
	char name[DPDK_HASH_NAMESIZE];   /**< Name of the hash. */
	uint32_t entries;               /**< Total table entries. */
	uint32_t num_buckets;           /**< Number of buckets in table. */

	struct rte_ring *free_slots;
	/**< Ring that stores all indexes of the free slots in the key table */

	/* Fields used in lookup */

	uint32_t key_len __rte_cache_aligned;
	/**< Length of hash key. */
	uint8_t ext_table_support;     /**< Enable extendable bucket table */
	uint8_t writer_takes_lock;
	/**< Indicates if the writer threads need to take lock */
	dpdk_hash_function hash_func;    /**< Function used to calculate hash. */
	uint32_t hash_func_init_val;    /**< Init value used by hash_func. */
	dpdk_hash_cmp_eq_t dpdk_hash_custom_cmp_eq;
	/**< Custom function used to compare keys. */
	enum cmp_jump_table_case cmp_jump_table_idx;
	/**< Indicates which compare function to use. */
	enum dpdk_hash_sig_compare_function sig_cmp_fn;
	/**< Indicates which signature compare function to use. */
	uint32_t bucket_bitmask;
	/**< Bitmask for getting bucket index from hash signature. */
	uint32_t key_entry_size;         /**< Size of each key entry. */

	void *key_store;                /**< Table storing all keys and data */
	struct dpdk_hash_bucket *buckets;
	/**< Table with buckets storing all the	hash values and key indexes
	 * to the key table.
	 */
	struct dpdk_hash_bucket *buckets_ext; /**< Extra buckets array */
	struct rte_ring *free_ext_bkts; /**< Ring of indexes of free buckets */
	/* Stores index of an empty ext bkt to be recycled on calling
	 * dpdk_hash_del_xxx APIs. When lock free read-write concurrency is
	 * enabled, an empty ext bkt cannot be put into free list immediately
	 * (as readers might be using it still). Hence freeing of the ext bkt
	 * is piggy-backed to freeing of the key index.
	 */
	uint32_t *ext_bkt_to_free;
	uint32_t *tbl_chng_cnt;
	/**< Indicates if the hash table changed from last read. */
} __rte_cache_aligned;

struct queue_node {
	struct dpdk_hash_bucket *bkt; /* Current bucket on the bfs search */
	uint32_t cur_bkt_idx;

	struct queue_node *prev;     /* Parent(bucket) in search path */
	int prev_slot;               /* Parent(slot) in search path */
};

/** @internal Default RCU defer queue entries to reclaim in one go. */
#define DPDK_HASH_RCU_DQ_RECLAIM_MAX	16

#endif
