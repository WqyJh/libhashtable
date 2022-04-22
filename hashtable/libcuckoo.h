
#ifndef _LIBCUCKOO_HASH_H_
#define _LIBCUCKOO_HASH_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cuckoo_hash;

struct cuckoo_hash *cuckoo_hash_create(int capacity);

void cuckoo_hash_free(struct cuckoo_hash *h);

bool cuckoo_hash_insert(struct cuckoo_hash *h, const void *key, void *data);

bool cuckoo_hash_erase(struct cuckoo_hash *h, const void *key);

bool cuckoo_hash_find(struct cuckoo_hash *h, const void *key, void **data);

int32_t cuckoo_hash_iterate(struct cuckoo_hash *h, const void **key, void **data, uint32_t *next);

#ifdef __cplusplus
}
#endif

#endif // _LIBCUCKOO_HASH_H_
