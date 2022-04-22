

#include <string.h>

#include <libcuckoo/cuckoohash_map.hh>
#include <memory.h>

#include "common.h"
#include "libcuckoo.h"

typedef struct {
    char blob[KEY_LEN];
} key_blob;

typedef struct {
    char blob[8];
} value_blob;

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

using map_type = libcuckoo::cuckoohash_map<key_blob, value_blob, std::hash<key_blob>,
                              std::equal_to<key_blob>>;

struct iterator_holder {
    int idx;
    map_type::locked_table& table;
    map_type::locked_table::const_iterator it;
    iterator_holder(int idx, map_type::locked_table&& table): idx(idx), table(table) {
        it = table.begin();
    };
};
class cuckoo_hash {
  public:
    cuckoo_hash(size_t n) : tbl(n), holder(nullptr) {}
    ~cuckoo_hash() {
        if (holder != nullptr) {
            delete holder;
        }
    }

    map_type tbl;
    iterator_holder *holder;
};

#ifdef __cplusplus
extern "C" {
#endif

struct cuckoo_hash *cuckoo_hash_create(int capacity) {
    return new cuckoo_hash(capacity);
}

void cuckoo_hash_free(struct cuckoo_hash *h) { delete h; }

bool cuckoo_hash_insert(struct cuckoo_hash *h, const void *key, void *data) {
    value_blob value;
    *(uint64_t*)value.blob = (uint64_t)data;
    return h->tbl.insert(*(key_blob*)key, value);
}

bool cuckoo_hash_erase(struct cuckoo_hash *h, const void *key) {
    return h->tbl.erase(*(key_blob*)key);
}

bool cuckoo_hash_find(struct cuckoo_hash *h, const void *key, void **data) {
    value_blob value;
    auto found = h->tbl.find(*(key_blob*)key, value);
    if (found) {
        *(uint64_t*)data = *(uint64_t*)value.blob;
        return true;
    }
    return false;
}

int32_t cuckoo_hash_iterate(struct cuckoo_hash *h, const void **key, void **data, uint32_t *next) {
    if (h->holder == nullptr) {
        h->holder = new iterator_holder(0, h->tbl.lock_table());
    }
    auto it = h->holder->it;
    if (it == h->holder->table.end()) {
        delete h->holder;
        h->holder = nullptr;
        return -ENOENT;
    }
    // auto lt = h->tbl.lock_table();
    // auto it = std::next(lt.begin(), *next);
    // if (it == lt.end()) {
    //     return -ENOENT;
    // }
    *key = &it->first;
    *(uint64_t*)data = *(uint64_t*)it->second.blob;
    h->holder->it++;
    *next = ++h->holder->idx;
    return 0;
}

#ifdef __cplusplus
}
#endif
