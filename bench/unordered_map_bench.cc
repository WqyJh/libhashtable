#include <benchmark/benchmark.h>

#include "common.h"

#include <unordered_map_hash.h>

static void BM_unordered_map_add(benchmark::State &state) {
    struct unordered_map_hash *tbl = unordered_map_hash_create(MAX_ENTRIES);
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
            EXPECT_TRUE(unordered_map_hash_insert(tbl, &keys[i], (void *)(uint64_t)i));
        }

        state.PauseTiming(); // Stop timers. They will not count until they are
                             // resumed.
        for (int i = 0; i < n; i++) {
            EXPECT_TRUE(unordered_map_hash_erase(tbl, &keys[i]));
        }
        items += n;
        state.ResumeTiming(); // And resume timers. They are now counting again.
    }

    state.SetItemsProcessed(items);
    delete[] keys;
}

BENCHMARK(BM_unordered_map_add);
