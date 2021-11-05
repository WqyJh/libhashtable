
#ifndef _LIBCUCKOO_HASH_NOLOCK_H_
#define _LIBCUCKOO_HASH_NOLOCK_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cuckoo_hash_nolock;

struct cuckoo_hash_nolock *cuckoo_hash_nolock_create(int capacity);

void cuckoo_hash_nolock_free(struct cuckoo_hash_nolock *h);

bool cuckoo_hash_nolock_insert(struct cuckoo_hash_nolock *h, const void *key, void *data);

bool cuckoo_hash_nolock_erase(struct cuckoo_hash_nolock *h, const void *key);

bool cuckoo_hash_nolock_find(struct cuckoo_hash_nolock *h, const void *key, void **data);

#ifdef __cplusplus
}
#endif

#endif // _LIBCUCKOO_HASH_NOLOCK_H_
