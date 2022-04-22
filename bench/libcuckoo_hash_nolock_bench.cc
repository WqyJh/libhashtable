#include <benchmark/benchmark.h>

#include <rte_errno.h>
#include <rte_lcore.h>

#include "common.h"

#include "hashtable/libcuckoo_nolock.h"

static void BM_libcuckoo_add_nolock(benchmark::State &state) {
    struct cuckoo_hash_nolock *tbl = cuckoo_hash_nolock_create(MAX_ENTRIES);
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
            EXPECT_TRUE(cuckoo_hash_nolock_insert(tbl, &keys[i], (void*)(uintptr_t)i));
            // EXPECT_TRUE(flow_table.insert(&keys[i], i));
        }

        state.PauseTiming(); // Stop timers. They will not count until they are
                             // resumed.
        for (int i = 0; i < n; i++) {
            EXPECT_TRUE(cuckoo_hash_nolock_erase(tbl, &keys[i]));
        }
        items += n;
        state.ResumeTiming(); // And resume timers. They are now counting again.
    }

    state.SetItemsProcessed(items);
    cuckoo_hash_nolock_free(tbl);
    delete[] keys;
}

static void BM_libcuckoo_lookup_nolock(benchmark::State &state) {
    struct cuckoo_hash_nolock *tbl = cuckoo_hash_nolock_create(MAX_ENTRIES);
    int n = MAX_ENTRIES * LOAD_FACTOR;

    struct flow_key *keys = new struct flow_key[n];
    for (int i = 0; i < n; i++) {
        // Don't use rand() to generate keys.
        // Make the keys identical when re-enter this func.
        uint8_t *a = (uint8_t *)&keys[i];
        *(uint64_t *)a = (uint64_t)i;
        *(uint64_t *)(a + 8) = !(uint64_t)i;
        EXPECT_TRUE(cuckoo_hash_nolock_insert(tbl, &keys[i], (void*)(uintptr_t)i));
    }

    int items = 0;
    while (state.KeepRunningBatch(n)) {
            uint64_t data;
        for (int i = 0; i < n; i++) {
            EXPECT_TRUE(cuckoo_hash_nolock_find(tbl, &keys[i], (void **)&data));
            EXPECT_EQ((uint64_t)i, data);
        }
        items += n;
    }

    state.SetItemsProcessed(items);
    cuckoo_hash_nolock_free(tbl);
    delete[] keys;
}

static void BM_libcuckoo_del_nolock(benchmark::State &state) {
    struct cuckoo_hash_nolock *tbl = cuckoo_hash_nolock_create(MAX_ENTRIES);
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
            EXPECT_TRUE(cuckoo_hash_nolock_insert(tbl, &keys[i], (void*)(uintptr_t)i));
        }
        items += n;
        state.ResumeTiming(); // And resume timers. They are now counting again.

        for (int i = 0; i < n; i++) {
            EXPECT_TRUE(cuckoo_hash_nolock_erase(tbl, &keys[i]));
        }
    }

    state.SetItemsProcessed(items);
    cuckoo_hash_nolock_free(tbl);
    delete[] keys;
}

void BM_libcuckoo_iterate_nolock(benchmark::State &state) {
    struct cuckoo_hash_nolock *tbl = cuckoo_hash_nolock_create(MAX_ENTRIES);
    int n = MAX_ENTRIES * LOAD_FACTOR;

    struct flow_key *keys = new struct flow_key[n];
    for (int i = 0; i < n; i++) {
        // Don't use rand() to generate keys.
        // Make the keys identical when re-enter this func.
        uint8_t *a = (uint8_t *)&keys[i];
        *(uint64_t *)a = (uint64_t)i;
        *(uint64_t *)(a + 8) = !(uint64_t)i;
        EXPECT_TRUE(cuckoo_hash_nolock_insert(tbl, &keys[i], (void*)(uintptr_t)i));
    }

    int items = 0;
    uint32_t next = 0;
    while (state.KeepRunning()) {
        void *data;
        void *key;
        int ret = cuckoo_hash_nolock_iterate(tbl, (const void**)&key, &data, &next);
        if (ret == -ENOENT) {
            next = 0;
            continue;
        }

        state.PauseTiming(); // Stop timers. They will not count until they are
                            // resumed.
        items++;
        EXPECT_EQ(0, ret);
        EXPECT_TRUE(memcmp(key, (void*)&keys[(uint64_t)data], sizeof(struct flow_key)) == 0);
        state.ResumeTiming(); // And resume timers. They are now counting again.
    }

    state.SetItemsProcessed(items);
    cuckoo_hash_nolock_free(tbl);
    delete[] keys;
}

BENCHMARK(BM_libcuckoo_add_nolock);
BENCHMARK(BM_libcuckoo_del_nolock);
BENCHMARK(BM_libcuckoo_lookup_nolock);
