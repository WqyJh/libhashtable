

#include <string.h>

#include <libcuckoo/cuckoohash_map.hh>
#include <memory.h>

#include "common.h"
#include "libcuckoo.h"

typedef struct {
    char blob[16];
} key_blob;

typedef struct {
    char blob[8];
} value_blob;

#define CUCKOO_TABLE_NAME blob_blob_table
#define CUCKOO_KEY_TYPE key_blob
#define CUCKOO_MAPPED_TYPE value_blob

namespace std {
template <> struct hash<key_blob> {
    size_t operator()(const key_blob &kb) const {
        return FLOW_HASH_FUNC(kb.blob, sizeof(key_blob), 0);
    }
};

template <> struct equal_to<key_blob> {
    bool operator()(const key_blob &lhs, const key_blob &rhs) const {
        return memcmp(lhs.blob, rhs.blob, sizeof(lhs.blob)) == 0;
    }
};
} // namespace std

class cuckoo_hash_nolock {
  public:
    cuckoo_hash_nolock(size_t n) {
        map_ = map_type(n);
        holder_.push_back(map_.lock_table());
    }

    template <typename K, typename V> bool find(const K &k, V &v) const {
        auto ret = holder_[0].find(k);
        if (ret == holder_[0].end())
            return false;
        v = ret->second;
        return true;
    }

    template <typename K, typename V> bool insert(const K &k, const V &v) {
        auto ret = holder_[0].insert(k, v);
        return ret.second;
    }

    template <typename K> bool erase(const K &k) {
        auto &lt = holder_[0];
        auto ret = lt.erase(k);
        return ret > 0;
    }

  private:
    using map_type =
        libcuckoo::cuckoohash_map<key_blob, value_blob, std::hash<key_blob>,
                                  std::equal_to<key_blob>>;
    map_type map_;
    std::vector<map_type::locked_table> holder_;
};

#ifdef __cplusplus
extern "C" {
#endif

struct cuckoo_hash_nolock *cuckoo_hash_nolock_create(int capacity) {
    return new cuckoo_hash_nolock(capacity);
}

void cuckoo_hash_nolock_free(struct cuckoo_hash_nolock *h) { delete h; }

bool cuckoo_hash_nolock_insert(struct cuckoo_hash_nolock *h, const void *key,
                               void *data) {
    value_blob value;
    *(uint64_t *)value.blob = (uint64_t)data;
    return h->insert(*(key_blob *)key, value);
}

bool cuckoo_hash_nolock_erase(struct cuckoo_hash_nolock *h, const void *key) {
    return h->erase(*(key_blob *)key);
}

bool cuckoo_hash_nolock_find(struct cuckoo_hash_nolock *h, const void *key,
                             void **data) {
    value_blob value;
    auto found = h->find(*(key_blob *)key, value);
    if (found) {
        *(uint64_t *)data = *(uint64_t *)value.blob;
        return true;
    }
    return false;
}

#ifdef __cplusplus
}
#endif
