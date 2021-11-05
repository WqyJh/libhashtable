#ifndef _FIXED_RING_INLINE_H
#define _FIXED_RING_INLINE_H

#include <stdint.h>
#include <errno.h>
#include <rte_malloc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define POWEROF2(x) ((((x)-1) & (x)) == 0)
#define RTE_ALIGN_FLOOR(val, align) \
	(typeof(val))((val) & (~((typeof(val))((align) - 1))))
#define RTE_ALIGN_CEIL(val, align) \
	RTE_ALIGN_FLOOR(((val) + ((typeof(val)) (align) - 1)), align)
#define RTE_ALIGN(val, align) RTE_ALIGN_CEIL(val, align)

#define RTE_RING_SZ_MASK  (0x7fffffffU) /**< Ring size mask */

struct fsring {
    uint32_t head;
    uint32_t tail;
    uint32_t size;
    uint32_t mask;
    uint32_t capacity;
    uint32_t data[0];
};

static inline unsigned int fsring_get_data_memsize(unsigned int n)
{
    return sizeof(uint32_t *) * n;
}

static inline unsigned int fsring_get_actual_count(unsigned int n) {
    uint32_t count;
	if (!POWEROF2(n)) {
        count = rte_align32pow2(n + 1);
	} else {
        count = n;
    }
    return count;
}

static inline unsigned int fsring_get_memsize(unsigned int n)
{
    /* count must be a power of 2 */
    uint32_t count = fsring_get_actual_count(n);
    ssize_t sz = sizeof(struct fsring) + fsring_get_data_memsize(count);
    return RTE_ALIGN(sz, RTE_CACHE_LINE_SIZE);
}

static inline void fsring_free(struct fsring *s) {
    if (s == NULL) return;
    rte_free(s);
}

static inline void fsring_init(struct fsring *s, unsigned int n)
{
    uint32_t count = fsring_get_actual_count(n);

    s->size = count;
    s->mask = count - 1;
    s->capacity = n;

    s->head = 0;
    s->tail = 0;
}

static inline void fsring_reset(struct fsring *s)
{
    s->head = 0;
    s->tail = 0;
}

static inline unsigned int fsring_count(struct fsring *s)
{
	return (s->tail - s->head) & s->mask;
}

static inline int fsring_enqueue(struct fsring *s, uint32_t obj) {
    // uint32_t entries = (prod_tail - cons_head);
    // uint32_t free_entries = (mask + cons_tail -prod_head);
    uint32_t free_entries = s->capacity + s->head - s->tail;
    if (free_entries < 1) {
        return -ENOSPC;
    }

    s->data[s->tail & s->mask] = obj;
    ++s->tail;
    return 0;
}

static inline int fsring_dequeue(struct fsring *s, uint32_t *obj) {
    uint32_t entries = s->tail - s->head;
    if (entries < 1) {
        return -ENOENT;
    }
    *obj = s->data[s->head & s->mask];
    ++s->head;
    return 0;
}

static inline struct fsring *fsring_create(unsigned int capacity, int socket_id) {
    unsigned int mem_size = fsring_get_memsize(capacity);
    struct fsring *s = (struct fsring *)rte_zmalloc_socket(NULL, mem_size,
					RTE_CACHE_LINE_SIZE, socket_id);
    fsring_init(s, capacity);
    return s;
}

#ifdef __cplusplus
}
#endif

#endif // _FIXED_RING_INLINE_H
