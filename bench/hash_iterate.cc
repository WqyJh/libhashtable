#include <benchmark/benchmark.h>

extern void BM_dpdk_hash_iterate(benchmark::State &state);
extern void BM_rte_hash_iterate(benchmark::State &state);
extern void BM_libcuckoo_iterate(benchmark::State &state);
extern void BM_libcuckoo_iterate_nolock(benchmark::State &state);
extern void BM_unordered_map_iterate(benchmark::State &state);

BENCHMARK(BM_libcuckoo_iterate);
BENCHMARK(BM_libcuckoo_iterate_nolock);
BENCHMARK(BM_dpdk_hash_iterate);
BENCHMARK(BM_rte_hash_iterate);
BENCHMARK(BM_unordered_map_iterate);

