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

#include "common.h"

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


BENCHMARK(BM_libcuckoo_add);
