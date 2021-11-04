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

#include <dpdk_hash.h>

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

BENCHMARK(BM_dpdk_hash_add);
