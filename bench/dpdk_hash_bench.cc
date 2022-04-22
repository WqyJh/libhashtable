#include <rte_hash.h>

#include <benchmark/benchmark.h>

#include <rte_errno.h>
#include <rte_lcore.h>

#include "hashtable/dpdk.h"
#include "hashtable/common.h"

#include "common.h"

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
        .tick_interval = 2,
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
            EXPECT_EQ(
                0, dpdk_hash_add_key_data(hash, &keys[i], (void *)(uint64_t)i));
        }

        state.PauseTiming(); // Stop timers. They will not count until they are
                             // resumed.
        for (int i = 0; i < n; i++) {
            int ret = dpdk_hash_del_key(hash, &keys[i]);
            EXPECT_TRUE(ret >= 0);
            EXPECT_EQ(n - i - 1, dpdk_hash_count(hash));
        }
        EXPECT_EQ(0, dpdk_hash_count(hash));
        items += n;
        state.ResumeTiming(); // And resume timers. They are now counting again.
    }

    state.SetItemsProcessed(items);
    dpdk_hash_free(hash);
    delete[] keys;
}

static void BM_dpdk_hash_lookup(benchmark::State &state) {
    char hash_name[HASH_NAME_LEN];
    sprintf(hash_name, "hash_lookup");
    struct dpdk_hash_parameters hash_params = {
        .name = hash_name,
        .entries = MAX_ENTRIES,
        .reserved = 0,
        .key_len = sizeof(struct flow_key),
        .hash_func = FLOW_HASH_FUNC,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
        .tick_interval = 2,
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
        EXPECT_EQ(0,
                  dpdk_hash_add_key_data(hash, &keys[i], (void *)(uint64_t)i));
    }

    int items = 0;
    while (state.KeepRunningBatch(n)) {
        for (int i = 0; i < n; i++) {
            uint64_t data;
            EXPECT_TRUE(dpdk_hash_lookup_data(hash, &keys[i], (void **)&data) >=
                        0);
            EXPECT_EQ((uint64_t)i, data);
        }
        items += n;
    }

    EXPECT_EQ(n, dpdk_hash_count(hash));
    state.SetItemsProcessed(items);
    dpdk_hash_free(hash);
    delete[] keys;
}

static void BM_dpdk_hash_del(benchmark::State &state) {
    char hash_name[HASH_NAME_LEN];
    sprintf(hash_name, "hash_del");
    struct dpdk_hash_parameters hash_params = {
        .name = hash_name,
        .entries = MAX_ENTRIES,
        .reserved = 0,
        .key_len = sizeof(struct flow_key),
        .hash_func = FLOW_HASH_FUNC,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
        .tick_interval = 2,
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
        state.PauseTiming(); // Stop timers. They will not count until they are
                             // resumed.
        for (int i = 0; i < n; i++) {
            EXPECT_EQ(
                0, dpdk_hash_add_key_data(hash, &keys[i], (void *)(uint64_t)i));
        }
        EXPECT_EQ(n, dpdk_hash_count(hash));
        items += n;
        state.ResumeTiming(); // And resume timers. They are now counting again.

        for (int i = 0; i < n; i++) {
            EXPECT_TRUE(dpdk_hash_del_key(hash, &keys[i]) >= 0);
        }
    }

    state.SetItemsProcessed(items);
    dpdk_hash_free(hash);
    delete[] keys;
}

void BM_dpdk_hash_iterate(benchmark::State &state) {
    char hash_name[HASH_NAME_LEN];
    sprintf(hash_name, "hash_iterate");
    struct dpdk_hash_parameters hash_params = {
        .name = hash_name,
        .entries = MAX_ENTRIES,
        .reserved = 0,
        .key_len = sizeof(struct flow_key),
        .hash_func = FLOW_HASH_FUNC,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
        .tick_interval = 2,
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
        EXPECT_EQ(0,
                  dpdk_hash_add_key_data(hash, &keys[i], (void *)(uint64_t)i));
    }

    int items = 0;
    uint32_t next = 0;
    while (state.KeepRunning()) {
        void *data;
        void *key;
        int ret = dpdk_hash_iterate(hash, (const void**)&key, &data, &next);
        if (ret == -ENOENT) {
            next = 0;
            continue;
        }

        state.PauseTiming(); // Stop timers. They will not count until they are
                            // resumed.
        items++;
        if (ret < 0) {
            printf("ret=%d\n", ret);
        }
        EXPECT_TRUE(ret >= 0);
        EXPECT_TRUE(memcmp(key, (void*)&keys[(uint64_t)data], sizeof(struct flow_key)) == 0);
        state.ResumeTiming(); // And resume timers. They are now counting again.
    }

    EXPECT_EQ(n, dpdk_hash_count(hash));
    state.SetItemsProcessed(items);
    dpdk_hash_free(hash);
    delete[] keys;
}

BENCHMARK(BM_dpdk_hash_add);
BENCHMARK(BM_dpdk_hash_del);
BENCHMARK(BM_dpdk_hash_lookup);
