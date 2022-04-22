#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define ITERATIONS 50000000
#define MAX_ENTRIES 10000000
#define LOAD_FACTOR 0.7

#define EXPECT_TRUE(v1) assert(v1)
#define EXPECT_EQ(v1, v2) assert((v1) == (v2))

#define HASH_NAME_LEN 64

struct __attribute__((__packed__)) flow_key {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;
};

#ifdef __cplusplus
}
#endif

#endif // BENCH_COMMON_H
