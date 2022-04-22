

#include <asm-generic/errno-base.h>
#include <cstdint>
#include <string.h>
#include <utility>
#include <functional>
#include <unordered_map>

#include "common.h"
#include "unordered_map.h"

typedef struct { char blob[KEY_LEN]; } key_blob;

typedef uint64_t value_blob;
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
}



#ifdef __cplusplus
extern "C" {
#endif

struct iterator_holder {
    using iterator_type = std::unordered_map<key_blob, value_blob>::const_iterator;
    iterator_type it;
    int idx;
    iterator_holder(iterator_type it, int idx): it(it), idx(idx) {};
};

struct unordered_map_hash {
    std::unordered_map<key_blob, value_blob> tbl;
    iterator_holder *holder;
};

struct unordered_map_hash *unordered_map_hash_create(int capacity) {
    struct unordered_map_hash *h = new struct unordered_map_hash;
    if (h == nullptr) {
        return NULL;
    }
    h->holder = nullptr;
    h->tbl.reserve(capacity);
    return h;
}

void unordered_map_hash_free(struct unordered_map_hash *h) {
    if (h == NULL) return;
    delete h;
}

bool unordered_map_hash_insert(struct unordered_map_hash *h, const void *key, void *data) {
    auto ret = h->tbl.insert(std::pair<key_blob, value_blob>(*(key_blob*)key, static_cast<value_blob>((uint64_t)data)));
    return ret.second;
}

bool unordered_map_hash_erase(struct unordered_map_hash *h, const void *key) {
    auto ret = h->tbl.erase(*(key_blob*)key);
    return ret > 0;
}

bool unordered_map_hash_find(struct unordered_map_hash *h, const void *key, void **data) {
    auto ret = h->tbl.find(*(key_blob*)key);
    if (ret == h->tbl.end()) return false;
    *(uint64_t*)data = ret->second;
    return true;
}

int32_t unordered_map_hash_iterate(struct unordered_map_hash *h, const void **key, void **data, uint32_t *next) {
    // uint32_t idx = 0;
    // for (int i = 0; i < h->tbl.bucket_count(); i++) {
    //     if (idx + h->tbl.bucket_size(i) > *next) {
    //         auto it = std::next(h->tbl.begin(i), (*next - idx));
    //         *key = &it->first;
    //         *data = (void*)it->second;
    //         (*next)++;
    //         return 0;
    //     }
    //     idx += h->tbl.bucket_size(i);
    // }
    // return -ENOENT;
    if (h->holder == nullptr) {
        h->holder = new iterator_holder(h->tbl.begin(), 0);
    }
    auto it = h->holder->it;
    if (it == h->tbl.end()) {
        delete h->holder;
        h->holder = nullptr;
        return -ENOENT;
    }
    *key = &it->first;
    *data = (void*)it->second;
    h->holder->it++;
    *next = ++h->holder->idx;
    return 0;
}

#ifdef __cplusplus
}
#endif
