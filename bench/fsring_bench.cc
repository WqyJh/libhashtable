
#include <benchmark/benchmark.h>

#include <rte_lcore.h>

#include <hashtable/fsring.h>
#include "common.h"

static void BM_fsring_enqueue(benchmark::State &state) {
    struct fsring *r = fsring_create(MAX_ENTRIES, rte_socket_id());

    EXPECT_TRUE(r != NULL);
    int n = MAX_ENTRIES * LOAD_FACTOR;

    int items = 0;
    while (state.KeepRunningBatch(n)) {
        for (int i = 0; i < n; i++) {
            EXPECT_EQ(0, fsring_enqueue(r, i));
        }

        state.PauseTiming(); // Stop timers. They will not count until they are
                             // resumed.
        for (int i = 0; i < n; i++) {
            uint32_t value;
            EXPECT_EQ(0, fsring_dequeue(r, &value));
            EXPECT_EQ(value, i);
        }
        items += n;
        state.ResumeTiming(); // And resume timers. They are now counting again.
    }

    state.SetItemsProcessed(items);
}

BENCHMARK(BM_fsring_enqueue);
