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

#ifdef __cplusplus
}
#endif

#endif // FLOW_DIRECTOR_COMMON_H
