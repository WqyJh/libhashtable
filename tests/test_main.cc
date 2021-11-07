#include <cstdint>
#include <stdint.h>
#include <thread>
#include <atomic>
#include <stdlib.h>
#include <time.h>

#include <gtest/gtest.h>

#include "../hashtable/bloom_filter.h"

// TEST(main, hash_by_hash) {
//     for (uint32_t i = 0; i < 1000; i++) {
//         printf("%u:%u ", i, (i | (i << 16)));
//     }
// }

TEST(main, bloom) {
    uint64_t filter = 0;

    srand(time(NULL));
    uint32_t hash1 = rand();
    uint32_t hash2 = rand();
    uint32_t hash3 = rand();
    uint32_t hash4 = rand();

    bloom_reset(&filter);
    EXPECT_FALSE(bloom_test(&filter, hash1, hash2));

    bloom_set(&filter, hash1, hash2);
    EXPECT_TRUE(bloom_test(&filter, hash1, hash2));

    bloom_set(&filter, hash1, hash3);
    EXPECT_TRUE(bloom_test(&filter, hash1, hash2));
    EXPECT_TRUE(bloom_test(&filter, hash1, hash3));
    EXPECT_TRUE(bloom_test(&filter, hash2, hash3));
}

TEST(main, bloom64) {
    uint64_t filter = 0;

    srand(time(NULL));
    uint32_t hash1 = rand();
    uint32_t hash2 = rand();
    uint32_t hash3 = rand();
    uint32_t hash4 = rand();

    bloom_reset64(filter);
    EXPECT_FALSE(bloom_test64(filter, hash1, hash2));

    bloom_set64(filter, hash1, hash2);
    EXPECT_TRUE(bloom_test64(filter, hash1, hash2));

    bloom_set64(filter, hash1, hash3);
    EXPECT_TRUE(bloom_test64(filter, hash1, hash2));
    EXPECT_TRUE(bloom_test64(filter, hash1, hash3));
    EXPECT_TRUE(bloom_test64(filter, hash2, hash3));
}
