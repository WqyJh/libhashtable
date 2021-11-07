
#ifndef BLOOM_FILTER_H
#define BLOOM_FILTER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define bitmask64(n) (((uint64_t)1) << (n))

#define hashbit64(hash) (hash % (sizeof(uint64_t) * 8))

#define hashmask64(hash) bitmask64(hashbit64(hash))

#define hashtest64(n, hash) (n & hashmask64(hash))

#define bloom_set64(n, hash1, hash2) ((n) |= (hashmask64(hash1) | hashmask64(hash2)))

#define bloom_test64(n, hash1, hash2) hashtest64(n, hash1) && hashtest64(n, hash2)

#define bloom_reset64(n) (n = 0)

uint64_t bitmask(uint32_t b) {
    return (((uint64_t)1) << b);
}

void bitset(uint64_t *n, uint32_t b) {
    *n |= bitmask(b);
}

bool bittest(uint64_t *n, uint32_t b) {
    return *n & bitmask(b);
}

uint32_t hashbit(uint32_t hash) {
    return hash % (sizeof(uint64_t) * 8);
}

void bloom_set(uint64_t *filter, uint32_t hash1, uint32_t hash2) {
    bitset(filter, hashbit(hash1));
    bitset(filter, hashbit(hash2));
}

bool bloom_test(uint64_t *filter, uint32_t hash1, uint32_t hash2) {
    return bittest(filter, hashbit(hash1)) && bittest(filter, hashbit(hash2));
}

void bloom_reset(uint64_t *filter) {
    *filter = 0;
}

#ifdef __cplusplus
}
#endif

#endif // BLOOM_FILTER_H
