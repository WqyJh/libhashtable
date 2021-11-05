

#include <cstdint>
#include <string.h>
#include <utility>
#include <functional>
#include <unordered_map>

#include "common.h"
#include "unordered_map.h"

typedef struct { char blob[16]; } key_blob;

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

struct unordered_map_hash {
    std::unordered_map<key_blob, value_blob> tbl;
};

struct unordered_map_hash *unordered_map_hash_create(int capacity) {
    struct unordered_map_hash *h = new struct unordered_map_hash;
    if (h == nullptr) {
        return NULL;
    }
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

#ifdef __cplusplus
}
#endif
