#include <cstdint>
#include <cstring>
#include <memory>
#include <functional>
#include <pthread.h>
#include <rte_cycles.h>
#include <rte_hash.h>
#include <stdlib.h> /* srand, rand */
#include <time.h>   /* time */
#include <chrono>
#include <unistd.h>

#include <benchmark/benchmark.h>

#include <rte_errno.h>
#include <rte_lcore.h>

#include <libcuckoo/cuckoohash_map.hh>
#include <unordered_map>
#include <dpdk_hash.h>

#ifdef ENABLE_XXH32
#include <xxhash.h>
static __rte_always_inline uint32_t xxh_hash(const void *data,
                                             uint32_t data_len,
                                             uint32_t init_val) {
    return XXH32(data, data_len, init_val);
}
#define FLOW_HASH_FUNC xxh_hash

#elif ENABLE_XXH3_64bits
#include <xxhash.h>
static __rte_always_inline uint32_t xxh_hash(const void *data,
                                             uint32_t data_len,
                                             uint32_t init_val) {
    return XXH3_64bits(data, data_len);
}
#define FLOW_HASH_FUNC xxh_hash

#elif RTE_ARCH_X86
#include <rte_hash_crc.h>
#define FLOW_HASH_FUNC rte_hash_crc

#else
#include <rte_jhash.h>
#define FLOW_HASH_FUNC rte_jhash
#endif

#define ITERATIONS 50000000
#define MAX_ENTRIES 1000000
#define LOAD_FACTOR 0.7

#define EXPECT_TRUE(v1) assert(v1)
#define EXPECT_EQ(v1, v2) assert((v1) == (v2))

#define HASH_NAME_LEN 64

struct __attribute__((__packed__)) flow_key {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint32_t proto;
};

static void BM_rte_hash_add(benchmark::State &state) {
    char hash_name[HASH_NAME_LEN];
    sprintf(hash_name, "hash_add");
    struct rte_hash_parameters hash_params = {
        .name = hash_name,
        .entries = MAX_ENTRIES,
        .reserved = 0,
        .key_len = sizeof(struct flow_key),
        .hash_func = FLOW_HASH_FUNC,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
        .extra_flag = 0,
    };
    struct rte_hash *hash = rte_hash_create(&hash_params);
    EXPECT_TRUE(hash != NULL);
    int n = MAX_ENTRIES * LOAD_FACTOR;

    struct flow_key *keys = new struct flow_key[n];
    for (int i = 0; i < n; i++) {
        // Don't use rand() to generate keys.
        // Make the keys identical when re-enter this func.
        uint8_t *a = (uint8_t *)&keys[i];
        *(uint64_t *)a = (uint64_t)i;
        *(uint64_t *)(a + 8) = !(uint64_t)i;
    }

    int items = 0;
    while (state.KeepRunningBatch(n)) {
        for (int i = 0; i < n; i++) {
            EXPECT_EQ(0, rte_hash_add_key_data(hash, &keys[i], (void *)(uint64_t)i));
        }

        state.PauseTiming(); // Stop timers. They will not count until they are
                             // resumed.
        for (int i = 0; i < n; i++) {
            int ret = rte_hash_del_key(hash, &keys[i]);
            EXPECT_TRUE(ret >= 0);
        }
        items += n;
        state.ResumeTiming(); // And resume timers. They are now counting again.
    }

    state.SetItemsProcessed(items);
    rte_hash_free(hash);
    delete[] keys;
}

static void BM_rte_hash_lookup(benchmark::State &state) {
    char hash_name[HASH_NAME_LEN];
    sprintf(hash_name, "hash_lookup");

    struct rte_hash_parameters hash_params = {
        .name = hash_name,
        .entries = MAX_ENTRIES,
        .reserved = 0,
        .key_len = sizeof(struct flow_key),
        .hash_func = FLOW_HASH_FUNC,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
        .extra_flag = 0,
    };
    struct rte_hash *hash = rte_hash_create(&hash_params);
    int n = MAX_ENTRIES * LOAD_FACTOR;

    struct flow_key *keys = new struct flow_key[n];
    for (int i = 0; i < n; i++) {
        // Don't use rand() to generate keys.
        // Make the keys identical when re-enter this func.
        uint8_t *a = (uint8_t *)&keys[i];
        *(uint64_t *)a = (uint64_t)i;
        *(uint64_t *)(a + 8) = !(uint64_t)i;
    }

    for (int i = 0; i < n; i++) {
        EXPECT_EQ(0, rte_hash_add_key_data(hash, &keys[i], (void *)(uintptr_t)i));
    }

    int items = 0;
    int idx = 0;
    while (state.KeepRunningBatch(n)) {
        for (int i = 0; i < n; i++) {
            uintptr_t data = 0;
            int ret = rte_hash_lookup_data(hash, &keys[i], (void **)&data);
            EXPECT_TRUE(ret >= 0);
            EXPECT_EQ((uint64_t)i, data);
        }
        items += n;
    }

    state.SetItemsProcessed(items);
    rte_hash_free(hash);
    delete[] keys;
}

static void BM_rte_hash_del(benchmark::State &state) {
    char hash_name[HASH_NAME_LEN];
    sprintf(hash_name, "hash_del");
    struct rte_hash_parameters hash_params = {
        .name = hash_name,
        .entries = MAX_ENTRIES,
        .reserved = 0,
        .key_len = sizeof(struct flow_key),
        .hash_func = FLOW_HASH_FUNC,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
        .extra_flag = 0,
    };
    struct rte_hash *hash = rte_hash_create(&hash_params);
    EXPECT_TRUE(hash != NULL);
    int n = MAX_ENTRIES * LOAD_FACTOR;

    struct flow_key *keys = new struct flow_key[n];
    for (int i = 0; i < n; i++) {
        // Don't use rand() to generate keys.
        // Make the keys identical when re-enter this func.
        uint8_t *a = (uint8_t *)&keys[i];
        *(uint64_t *)a = (uint64_t)i;
        *(uint64_t *)(a + 8) = !(uint64_t)i;
    }

    int items = 0;
    while (state.KeepRunningBatch(n)) {
        state.PauseTiming(); // Stop timers. They will not count until they are
                             // resumed.
        for (int i = 0; i < n; i++) {
            EXPECT_EQ(0, rte_hash_add_key_data(hash, &keys[i], (void *)(uint64_t)i));
        }
        items += n;
        state.ResumeTiming(); // And resume timers. They are now counting again.
        
        for (int i = 0; i < n; i++) {
            int ret = rte_hash_del_key(hash, &keys[i]);
            EXPECT_TRUE(ret >= 0);
        }
    }

    state.SetItemsProcessed(items);
    rte_hash_free(hash);
    delete[] keys;
}

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


static void BM_libcuckoo_add(benchmark::State &state) {
    blob_blob_table *tbl = blob_blob_table_init(MAX_ENTRIES);
    int n = MAX_ENTRIES * LOAD_FACTOR;

    struct flow_key *keys = new struct flow_key[n];
    for (int i = 0; i < n; i++) {
        // Don't use rand() to generate keys.
        // Make the keys identical when re-enter this func.
        uint8_t *a = (uint8_t *)&keys[i];
        *(uint64_t *)a = (uint64_t)i;
        *(uint64_t *)(a + 8) = !(uint64_t)i;
    }

    int items = 0;
    while (state.KeepRunningBatch(n)) {
        for (int i = 0; i < n; i++) {
            uintptr_t value = i;
            blob_blob_table_insert(tbl, (key_blob*)&keys[i], (value_blob*)&value);
            // EXPECT_TRUE(flow_table.insert(&keys[i], i));
        }

        state.PauseTiming(); // Stop timers. They will not count until they are
                             // resumed.
        for (int i = 0; i < n; i++) {
            // EXPECT_TRUE(flow_table.erase(&keys[i]));
            blob_blob_table_erase(tbl, (key_blob*)&keys[i]);
        }
        items += n;
        state.ResumeTiming(); // And resume timers. They are now counting again.
    }

    state.SetItemsProcessed(items);
    delete[] keys;
}


static void BM_unordered_map_add(benchmark::State &state) {
    std::unordered_map<key_blob, value_blob> tbl(MAX_ENTRIES);
    int n = MAX_ENTRIES * LOAD_FACTOR;

    struct flow_key *keys = new struct flow_key[n];
    for (int i = 0; i < n; i++) {
        // Don't use rand() to generate keys.
        // Make the keys identical when re-enter this func.
        uint8_t *a = (uint8_t *)&keys[i];
        *(uint64_t *)a = (uint64_t)i;
        *(uint64_t *)(a + 8) = !(uint64_t)i;
    }

    int items = 0;
    while (state.KeepRunningBatch(n)) {
        for (int i = 0; i < n; i++) {
            key_blob key;
            *(uint64_t *)&key.blob[0] = *(uint64_t *)&keys[i];
            *(uint64_t *)&key.blob[1] = *(uint64_t *)&keys[i + 1];
            value_blob value;
            *(uint64_t *)&value.blob[0] = (uint64_t)i;

            auto ret = tbl.insert(std::pair<key_blob, value_blob>(key, value));
            EXPECT_TRUE(ret.second);
        }

        state.PauseTiming(); // Stop timers. They will not count until they are
                             // resumed.
        for (int i = 0; i < n; i++) {
            key_blob key;
            *(uint64_t *)&key.blob[0] = *(uint64_t *)&keys[i];
            *(uint64_t *)&key.blob[1] = *(uint64_t *)&keys[i + 1];
            auto ret = tbl.erase(key);
            EXPECT_TRUE(ret > 0);
        }
        items += n;
        state.ResumeTiming(); // And resume timers. They are now counting again.
    }

    state.SetItemsProcessed(items);
    delete[] keys;
}


static void BM_dpdk_hash_add(benchmark::State &state) {
    char hash_name[HASH_NAME_LEN];
    sprintf(hash_name, "hash_add");
    struct dpdk_hash_parameters hash_params = {
        .name = hash_name,
        .entries = MAX_ENTRIES,
        .reserved = 0,
        .key_len = sizeof(struct flow_key),
        .hash_func = FLOW_HASH_FUNC,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
        .extra_flag = 0,
    };
    struct dpdk_hash *hash = dpdk_hash_create(&hash_params);
    EXPECT_TRUE(hash != NULL);
    int n = MAX_ENTRIES * LOAD_FACTOR;

    struct flow_key *keys = new struct flow_key[n];
    for (int i = 0; i < n; i++) {
        // Don't use rand() to generate keys.
        // Make the keys identical when re-enter this func.
        uint8_t *a = (uint8_t *)&keys[i];
        *(uint64_t *)a = (uint64_t)i;
        *(uint64_t *)(a + 8) = !(uint64_t)i;
    }

    int items = 0;
    while (state.KeepRunningBatch(n)) {
        for (int i = 0; i < n; i++) {
            EXPECT_EQ(0, dpdk_hash_add_key_data(hash, &keys[i], (void *)(uint64_t)i));
        }

        state.PauseTiming(); // Stop timers. They will not count until they are
                             // resumed.
        for (int i = 0; i < n; i++) {
            int ret = dpdk_hash_del_key(hash, &keys[i]);
            EXPECT_TRUE(ret >= 0);
        }
        items += n;
        state.ResumeTiming(); // And resume timers. They are now counting again.
    }

    state.SetItemsProcessed(items);
    dpdk_hash_free(hash);
    delete[] keys;
}

BENCHMARK(BM_rte_hash_add);
BENCHMARK(BM_rte_hash_lookup);
BENCHMARK(BM_rte_hash_del);
BENCHMARK(BM_libcuckoo_add);
BENCHMARK(BM_unordered_map_add);
BENCHMARK(BM_dpdk_hash_add);
