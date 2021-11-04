
#ifndef _UNORDERED_MAP_HASH_H_
#define _UNORDERED_MAP_HASH_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct unordered_map_hash;

struct unordered_map_hash *unordered_map_hash_create(int capacity);

void unordered_map_hash_free(struct unordered_map_hash *h);

bool unordered_map_hash_insert(struct unordered_map_hash *h, const void *key, void *data);

bool unordered_map_hash_erase(struct unordered_map_hash *h, const void *key);

bool unordered_map_hash_find(struct unordered_map_hash *h, const void *key, void **data);

#ifdef __cplusplus
}
#endif

#endif // _UNORDERED_MAP_HASH_H_
