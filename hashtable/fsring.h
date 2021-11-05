#ifndef _FIXED_RING_H
#define _FIXED_RING_H

#include <stdint.h>

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

struct fsring;

unsigned int fsring_get_memsize(unsigned int n);

void fsring_free(struct fsring *s);

void fsring_init(struct fsring *s, unsigned int n);

void fsring_reset(struct fsring *s);

unsigned int fsring_count(struct fsring *s);

int fsring_enqueue(struct fsring *s, uint32_t obj);

int fsring_dequeue(struct fsring *s, uint32_t *obj);

struct fsring *fsring_create(unsigned int capacity, int socket_id);

#ifdef __cplusplus
}
#endif

#endif // _FIXED_RING_H
