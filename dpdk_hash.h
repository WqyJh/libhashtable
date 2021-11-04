/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#ifndef _DPDK_HASH_H_
#define _DPDK_HASH_H_

/**
 * @file
 *
 * DPDK Hash Table
 */

#include <stdint.h>
#include <stddef.h>

#include <rte_compat.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum size of hash table that can be created. */
#define DPDK_HASH_ENTRIES_MAX			(1 << 30)

/** Maximum number of characters in hash name.*/
#define DPDK_HASH_NAMESIZE			32

/** Maximum number of keys that can be searched for using dpdk_hash_lookup_bulk. */
#define DPDK_HASH_LOOKUP_BULK_MAX		64
#define DPDK_HASH_LOOKUP_MULTI_MAX		DPDK_HASH_LOOKUP_BULK_MAX

/** Flag to indicate the extendable bucket table feature should be used */
#define DPDK_HASH_EXTRA_FLAGS_EXT_TABLE 0x08

/**
 * The type of hash value of a key.
 * It should be a value of at least 32bit with fully random pattern.
 */
typedef uint32_t hash_sig_t;

/** Type of function that can be used for calculating the hash value. */
typedef uint32_t (*dpdk_hash_function)(const void *key, uint32_t key_len,
				      uint32_t init_val);

/** Type of function used to compare the hash key. */
typedef int (*dpdk_hash_cmp_eq_t)(const void *key1, const void *key2, size_t key_len);

/**
 * Type of function used to free data stored in the key.
 * Required when using internal RCU to allow application to free key-data once
 * the key is returned to the ring of free key-slots.
 */
typedef void (*dpdk_hash_free_key_data)(void *p, void *key_data);

/**
 * Parameters used when creating the hash table.
 */
struct dpdk_hash_parameters {
	const char *name;		/**< Name of the hash. */
	uint32_t entries;		/**< Total hash table entries. */
	uint32_t reserved;		/**< Unused field. Should be set to 0 */
	uint32_t key_len;		/**< Length of hash key. */
	dpdk_hash_function hash_func;	/**< Primary Hash function used to calculate hash. */
	uint32_t hash_func_init_val;	/**< Init value used by hash_func. */
	int socket_id;			/**< NUMA Socket ID for memory. */
	uint8_t extra_flag;		/**< Indicate if additional parameters are present. */
};

/** @internal A hash table structure. */
struct dpdk_hash;

/**
 * Create a new hash table.
 *
 * @param params
 *   Parameters used to create and initialise the hash table.
 * @return
 *   Pointer to hash table structure that is used in future hash table
 *   operations, or NULL on error, with error code set in rte_errno.
 *   Possible rte_errno errors include:
 *    - E_RTE_NO_CONFIG - function could not get pointer to rte_config structure
 *    - E_RTE_SECONDARY - function was called from a secondary process instance
 *    - ENOENT - missing entry
 *    - EINVAL - invalid parameter passed to function
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 */
struct dpdk_hash *
dpdk_hash_create(const struct dpdk_hash_parameters *params);

/**
 * Set a new hash compare function other than the default one.
 *
 * @note Function pointer does not work with multi-process, so do not use it
 * in multi-process mode.
 *
 * @param h
 *   Hash table for which the function is to be changed
 * @param func
 *   New compare function
 */
void dpdk_hash_set_cmp_func(struct dpdk_hash *h, dpdk_hash_cmp_eq_t func);

/**
 * Find an existing hash table object and return a pointer to it.
 *
 * @param name
 *   Name of the hash table as passed to dpdk_hash_create()
 * @return
 *   Pointer to hash table or NULL if object not found
 *   with rte_errno set appropriately. Possible rte_errno values include:
 *    - ENOENT - value not available for return
 */
struct dpdk_hash *
dpdk_hash_find_existing(const char *name);

/**
 * De-allocate all memory used by hash table.
 * @param h
 *   Hash table to free
 */
void
dpdk_hash_free(struct dpdk_hash *h);

/**
 * Reset all hash structure, by zeroing all entries.
 * When DPDK_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF is enabled,
 * it is application's responsibility to make sure that
 * none of the readers are referencing the hash table
 * while calling this API.
 *
 * @param h
 *   Hash table to reset
 */
void
dpdk_hash_reset(struct dpdk_hash *h);

/**
 * Return the number of keys in the hash table
 * @param h
 *  Hash table to query from
 * @return
 *   - -EINVAL if parameters are invalid
 *   - A value indicating how many keys were inserted in the table.
 */
int32_t
dpdk_hash_count(const struct dpdk_hash *h);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Return the maximum key value ID that could possibly be returned by
 * dpdk_hash_add_key function.
 *
 * @param h
 *  Hash table to query from
 * @return
 *   - -EINVAL if parameters are invalid
 *   - A value indicating the max key ID of key slots present in the table.
 */
__rte_experimental
int32_t
dpdk_hash_max_key_id(const struct dpdk_hash *h);

/**
 * Add a key-value pair to an existing hash table.
 * This operation is not multi-thread safe
 * and should only be called from one thread by default.
 * Thread safety can be enabled by setting flag during
 * table creation.
 * If the key exists already in the table, this API updates its value
 * with 'data' passed in this API. It is the responsibility of
 * the application to manage any memory associated with the old value.
 * The readers might still be using the old value even after this API
 * has returned.
 *
 * @param h
 *   Hash table to add the key to.
 * @param key
 *   Key to add to the hash table.
 * @param data
 *   Data to add to the hash table.
 * @return
 *   - 0 if added successfully
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOSPC if there is no space in the hash for this key.
 */
int
dpdk_hash_add_key_data(const struct dpdk_hash *h, const void *key, void *data);

/**
 * Add a key-value pair with a pre-computed hash value
 * to an existing hash table.
 * This operation is not multi-thread safe
 * and should only be called from one thread by default.
 * Thread safety can be enabled by setting flag during
 * table creation.
 * If the key exists already in the table, this API updates its value
 * with 'data' passed in this API. It is the responsibility of
 * the application to manage any memory associated with the old value.
 * The readers might still be using the old value even after this API
 * has returned.
 *
 * @param h
 *   Hash table to add the key to.
 * @param key
 *   Key to add to the hash table.
 * @param sig
 *   Precomputed hash value for 'key'
 * @param data
 *   Data to add to the hash table.
 * @return
 *   - 0 if added successfully
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOSPC if there is no space in the hash for this key.
 */
int32_t
dpdk_hash_add_key_with_hash_data(const struct dpdk_hash *h, const void *key,
						hash_sig_t sig, void *data);

/**
 * Add a key to an existing hash table. This operation is not multi-thread safe
 * and should only be called from one thread by default.
 * Thread safety can be enabled by setting flag during
 * table creation.
 *
 * @param h
 *   Hash table to add the key to.
 * @param key
 *   Key to add to the hash table.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOSPC if there is no space in the hash for this key.
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key. This
 *     unique key id may be larger than the user specified entry count
 *     when DPDK_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD flag is set.
 */
int32_t
dpdk_hash_add_key(const struct dpdk_hash *h, const void *key);

/**
 * Add a key to an existing hash table.
 * This operation is not multi-thread safe
 * and should only be called from one thread by default.
 * Thread safety can be enabled by setting flag during
 * table creation.
 *
 * @param h
 *   Hash table to add the key to.
 * @param key
 *   Key to add to the hash table.
 * @param sig
 *   Precomputed hash value for 'key'.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOSPC if there is no space in the hash for this key.
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key. This
 *     unique key ID may be larger than the user specified entry count
 *     when DPDK_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD flag is set.
 */
int32_t
dpdk_hash_add_key_with_hash(const struct dpdk_hash *h, const void *key, hash_sig_t sig);

/**
 * Remove a key from an existing hash table.
 * This operation is not multi-thread safe
 * and should only be called from one thread by default.
 * Thread safety can be enabled by setting flag during
 * table creation.
 * If DPDK_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL or
 * DPDK_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF is enabled and
 * internal RCU is NOT enabled,
 * the key index returned by dpdk_hash_add_key_xxx APIs will not be
 * freed by this API. dpdk_hash_free_key_with_position API must be called
 * additionally to free the index associated with the key.
 * dpdk_hash_free_key_with_position API should be called after all
 * the readers have stopped referencing the entry corresponding to
 * this key. RCU mechanisms could be used to determine such a state.
 *
 * @param h
 *   Hash table to remove the key from.
 * @param key
 *   Key to remove from the hash table.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if the key is not found.
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key, and is the same
 *     value that was returned when the key was added.
 */
int32_t
dpdk_hash_del_key(const struct dpdk_hash *h, const void *key);

/**
 * Remove a key from an existing hash table.
 * This operation is not multi-thread safe
 * and should only be called from one thread by default.
 * Thread safety can be enabled by setting flag during
 * table creation.
 * If DPDK_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL or
 * DPDK_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF is enabled and
 * internal RCU is NOT enabled,
 * the key index returned by dpdk_hash_add_key_xxx APIs will not be
 * freed by this API. dpdk_hash_free_key_with_position API must be called
 * additionally to free the index associated with the key.
 * dpdk_hash_free_key_with_position API should be called after all
 * the readers have stopped referencing the entry corresponding to
 * this key. RCU mechanisms could be used to determine such a state.
 *
 * @param h
 *   Hash table to remove the key from.
 * @param key
 *   Key to remove from the hash table.
 * @param sig
 *   Precomputed hash value for 'key'.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if the key is not found.
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key, and is the same
 *     value that was returned when the key was added.
 */
int32_t
dpdk_hash_del_key_with_hash(const struct dpdk_hash *h, const void *key, hash_sig_t sig);

/**
 * Find a key in the hash table given the position.
 * This operation is multi-thread safe with regarding to other lookup threads.
 * Read-write concurrency can be enabled by setting flag during
 * table creation.
 *
 * @param h
 *   Hash table to get the key from.
 * @param position
 *   Position returned when the key was inserted.
 * @param key
 *   Output containing a pointer to the key
 * @return
 *   - 0 if retrieved successfully
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if no valid key is found in the given position.
 */
int
dpdk_hash_get_key_with_position(const struct dpdk_hash *h, const int32_t position,
			       void **key);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Free a hash key in the hash table given the position
 * of the key. This operation is not multi-thread safe and should
 * only be called from one thread by default. Thread safety
 * can be enabled by setting flag during table creation.
 * If DPDK_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL or
 * DPDK_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF is enabled and
 * internal RCU is NOT enabled,
 * the key index returned by dpdk_hash_del_key_xxx APIs must be freed
 * using this API. This API should be called after all the readers
 * have stopped referencing the entry corresponding to this key.
 * RCU mechanisms could be used to determine such a state.
 * This API does not validate if the key is already freed.
 *
 * @param h
 *   Hash table to free the key from.
 * @param position
 *   Position returned when the key was deleted.
 * @return
 *   - 0 if freed successfully
 *   - -EINVAL if the parameters are invalid.
 */
__rte_experimental
int
dpdk_hash_free_key_with_position(const struct dpdk_hash *h,
				const int32_t position);

/**
 * Find a key-value pair in the hash table.
 * This operation is multi-thread safe with regarding to other lookup threads.
 * Read-write concurrency can be enabled by setting flag during
 * table creation.
 *
 * @param h
 *   Hash table to look in.
 * @param key
 *   Key to find.
 * @param data
 *   Output with pointer to data returned from the hash table.
 * @return
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key, and is the same
 *     value that was returned when the key was added.
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if the key is not found.
 */
int
dpdk_hash_lookup_data(const struct dpdk_hash *h, const void *key, void **data);

/**
 * Find a key-value pair with a pre-computed hash value
 * to an existing hash table.
 * This operation is multi-thread safe with regarding to other lookup threads.
 * Read-write concurrency can be enabled by setting flag during
 * table creation.
 *
 * @param h
 *   Hash table to look in.
 * @param key
 *   Key to find.
 * @param sig
 *   Precomputed hash value for 'key'
 * @param data
 *   Output with pointer to data returned from the hash table.
 * @return
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key, and is the same
 *     value that was returned when the key was added.
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if the key is not found.
 */
int
dpdk_hash_lookup_with_hash_data(const struct dpdk_hash *h, const void *key,
					hash_sig_t sig, void **data);

/**
 * Find a key in the hash table.
 * This operation is multi-thread safe with regarding to other lookup threads.
 * Read-write concurrency can be enabled by setting flag during
 * table creation.
 *
 * @param h
 *   Hash table to look in.
 * @param key
 *   Key to find.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if the key is not found.
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key, and is the same
 *     value that was returned when the key was added.
 */
int32_t
dpdk_hash_lookup(const struct dpdk_hash *h, const void *key);

/**
 * Find a key in the hash table.
 * This operation is multi-thread safe with regarding to other lookup threads.
 * Read-write concurrency can be enabled by setting flag during
 * table creation.
 *
 * @param h
 *   Hash table to look in.
 * @param key
 *   Key to find.
 * @param sig
 *   Precomputed hash value for 'key'.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if the key is not found.
 *   - A positive value that can be used by the caller as an offset into an
 *     array of user data. This value is unique for this key, and is the same
 *     value that was returned when the key was added.
 */
int32_t
dpdk_hash_lookup_with_hash(const struct dpdk_hash *h,
				const void *key, hash_sig_t sig);

/**
 * Calc a hash value by key.
 * This operation is not multi-process safe.
 *
 * @param h
 *   Hash table to look in.
 * @param key
 *   Key to find.
 * @return
 *   - hash value
 */
hash_sig_t
dpdk_hash_hash(const struct dpdk_hash *h, const void *key);

/**
 * Find multiple keys in the hash table.
 * This operation is multi-thread safe with regarding to other lookup threads.
 * Read-write concurrency can be enabled by setting flag during
 * table creation.
 *
 * @param h
 *   Hash table to look in.
 * @param keys
 *   A pointer to a list of keys to look for.
 * @param num_keys
 *   How many keys are in the keys list (less than DPDK_HASH_LOOKUP_BULK_MAX).
 * @param hit_mask
 *   Output containing a bitmask with all successful lookups.
 * @param data
 *   Output containing array of data returned from all the successful lookups.
 * @return
 *   -EINVAL if there's an error, otherwise number of successful lookups.
 */
int
dpdk_hash_lookup_bulk_data(const struct dpdk_hash *h, const void **keys,
		      uint32_t num_keys, uint64_t *hit_mask, void *data[]);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Find multiple keys in the hash table with precomputed hash value array.
 * This operation is multi-thread safe with regarding to other lookup threads.
 * Read-write concurrency can be enabled by setting flag during
 * table creation.
 *
 * @param h
 *   Hash table to look in.
 * @param keys
 *   A pointer to a list of keys to look for.
 * @param sig
 *   A pointer to a list of precomputed hash values for keys.
 * @param num_keys
 *   How many keys are in the keys list (less than DPDK_HASH_LOOKUP_BULK_MAX).
 * @param positions
 *   Output containing a list of values, corresponding to the list of keys that
 *   can be used by the caller as an offset into an array of user data. These
 *   values are unique for each key, and are the same values that were returned
 *   when each key was added. If a key in the list was not found, then -ENOENT
 *   will be the value.
 * @return
 *   -EINVAL if there's an error, otherwise 0.
 */
__rte_experimental
int
dpdk_hash_lookup_with_hash_bulk(const struct dpdk_hash *h, const void **keys,
		hash_sig_t *sig, uint32_t num_keys, int32_t *positions);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Find multiple keys in the hash table with precomputed hash value array.
 * This operation is multi-thread safe with regarding to other lookup threads.
 * Read-write concurrency can be enabled by setting flag during
 * table creation.
 *
 * @param h
 *   Hash table to look in.
 * @param keys
 *   A pointer to a list of keys to look for.
 * @param sig
 *   A pointer to a list of precomputed hash values for keys.
 * @param num_keys
 *   How many keys are in the keys list (less than DPDK_HASH_LOOKUP_BULK_MAX).
 * @param hit_mask
 *   Output containing a bitmask with all successful lookups.
 * @param data
 *   Output containing array of data returned from all the successful lookups.
 * @return
 *   -EINVAL if there's an error, otherwise number of successful lookups.
 */
__rte_experimental
int
dpdk_hash_lookup_with_hash_bulk_data(const struct dpdk_hash *h,
		const void **keys, hash_sig_t *sig,
		uint32_t num_keys, uint64_t *hit_mask, void *data[]);

/**
 * Find multiple keys in the hash table.
 * This operation is multi-thread safe with regarding to other lookup threads.
 * Read-write concurrency can be enabled by setting flag during
 * table creation.
 *
 * @param h
 *   Hash table to look in.
 * @param keys
 *   A pointer to a list of keys to look for.
 * @param num_keys
 *   How many keys are in the keys list (less than DPDK_HASH_LOOKUP_BULK_MAX).
 * @param positions
 *   Output containing a list of values, corresponding to the list of keys that
 *   can be used by the caller as an offset into an array of user data. These
 *   values are unique for each key, and are the same values that were returned
 *   when each key was added. If a key in the list was not found, then -ENOENT
 *   will be the value.
 * @return
 *   -EINVAL if there's an error, otherwise 0.
 */
int
dpdk_hash_lookup_bulk(const struct dpdk_hash *h, const void **keys,
		      uint32_t num_keys, int32_t *positions);

/**
 * Iterate through the hash table, returning key-value pairs.
 *
 * @param h
 *   Hash table to iterate
 * @param key
 *   Output containing the key where current iterator
 *   was pointing at
 * @param data
 *   Output containing the data associated with key.
 *   Returns NULL if data was not stored.
 * @param next
 *   Pointer to iterator. Should be 0 to start iterating the hash table.
 *   Iterator is incremented after each call of this function.
 * @return
 *   Position where key was stored, if successful.
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOENT if end of the hash table.
 */
int32_t
dpdk_hash_iterate(const struct dpdk_hash *h, const void **key, void **data, uint32_t *next);

#ifdef __cplusplus
}
#endif

#endif /* _DPDK_HASH_H_ */
