

#include <string.h>

#include <libcuckoo/cuckoohash_map.hh>

#include "libcuckoo.h"


typedef struct { char blob[16]; } key_blob;

typedef struct { char blob[8]; } value_blob;

#define CUCKOO_TABLE_NAME blob_blob_table
#define CUCKOO_KEY_TYPE key_blob
#define CUCKOO_MAPPED_TYPE value_blob

namespace std {
template <> struct hash<key_blob> {
  size_t operator()(const key_blob &kb) const { return *(size_t *)kb.blob; }
};

template <> struct equal_to<key_blob> {
  bool operator()(const key_blob &lhs, const key_blob &rhs) const {
    return memcmp(lhs.blob, rhs.blob, sizeof(lhs.blob)) == 0;
  }
};
}

#include <libcuckoo-c/cuckoo_table_template.cc>

#ifdef __cplusplus
extern "C" {
#endif

struct cuckoo_hash {
    blob_blob_table *tbl;
};

struct cuckoo_hash *cuckoo_hash_create(int capacity) {
    blob_blob_table *tbl = blob_blob_table_init(capacity);
    if (tbl == NULL) {
        return NULL;
    }

    struct cuckoo_hash *h = new struct cuckoo_hash;
    if (h == nullptr) {
        return NULL;
    }
    h->tbl = tbl;
    return h;
}

void cuckoo_hash_free(struct cuckoo_hash *h) {
    if (h == NULL) return;
    if (h->tbl != NULL) {
        blob_blob_table_free(h->tbl);
    }
    delete h;
}

bool cuckoo_hash_insert(struct cuckoo_hash *h, const void *key, void *data) {
    return blob_blob_table_insert(h->tbl, (key_blob*)key, (value_blob*)&data);
}

bool cuckoo_hash_erase(struct cuckoo_hash *h, const void *key) {
    return blob_blob_table_erase(h->tbl, (key_blob*)key);
}

bool cuckoo_hash_find(struct cuckoo_hash *h, const void *key, void **data) {
    return blob_blob_table_find(h->tbl, (key_blob*)key, (value_blob*)data);
}

#ifdef __cplusplus
}
#endif
