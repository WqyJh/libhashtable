#include <benchmark/benchmark.h>

#include <unordered_map>

#include "common.h"

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

BENCHMARK(BM_unordered_map_add);
