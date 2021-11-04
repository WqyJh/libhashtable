#include <benchmark/benchmark.h>

#include <rte_errno.h>
#include <rte_lcore.h>

#include "common.h"

#include <libcuckoo_hash.h>

static void BM_libcuckoo_add(benchmark::State &state) {
    struct cuckoo_hash *tbl = cuckoo_hash_create(MAX_ENTRIES);
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
            EXPECT_TRUE(cuckoo_hash_insert(tbl, &keys[i], (void*)(uintptr_t)i));
            // EXPECT_TRUE(flow_table.insert(&keys[i], i));
        }

        state.PauseTiming(); // Stop timers. They will not count until they are
                             // resumed.
        for (int i = 0; i < n; i++) {
            EXPECT_TRUE(cuckoo_hash_erase(tbl, &keys[i]));
        }
        items += n;
        state.ResumeTiming(); // And resume timers. They are now counting again.
    }

    state.SetItemsProcessed(items);
    cuckoo_hash_free(tbl);
    delete[] keys;
}

BENCHMARK(BM_libcuckoo_add);
