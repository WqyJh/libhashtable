#ifndef FLOW_DIRECTOR_COMMON_H
#define FLOW_DIRECTOR_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BENCH_ALWAYS_INLINE
#define bench_always_inline inline __attribute__((always_inline))
#endif // BENCH_ALWAYS_INLINE

#ifdef ENABLE_XXH32
#include <xxhash.h>
static bench_always_inline uint32_t xxh_hash(const void *data,
                                             uint32_t data_len,
                                             uint32_t init_val) {
    return XXH32(data, data_len, init_val);
}
#define FLOW_HASH_FUNC xxh_hash

#elif ENABLE_XXH3_64bits
#include <xxhash.h>
static bench_always_inline uint32_t xxh_hash(const void *data,
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

#ifdef __cplusplus
}
#endif

#endif // FLOW_DIRECTOR_COMMON_H
