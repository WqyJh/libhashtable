#ifndef _FIXED_STACK_H
#define _FIXED_STACK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <errno.h>


struct fixed_stack {
    uint32_t pos;
    uint32_t capacity;
    uint32_t data[0];
};

static inline unsigned int fixed_stack_get_data_memsize(unsigned int n)
{
    return sizeof(uint32_t *) * n;
}

static inline unsigned int fixed_stack_get_memsize(unsigned int n)
{
    return sizeof(struct fixed_stack) + fixed_stack_get_data_memsize(n);
}

static inline void fixed_stack_init(struct fixed_stack *s, unsigned int n)
{
    s->capacity = n;
    s->pos = 0;
}

static inline void fixed_stack_reset(struct fixed_stack *s)
{
    s->pos = 0;
}

static inline unsigned int fixed_stack_size(struct fixed_stack *s)
{
    return s->pos;
}

static inline int fixed_stack_push(struct fixed_stack *s, uint32_t obj) {
    if (s->pos == s->capacity) {
        return -ENOSPC;
    }
    s->data[s->pos++] = obj;
    return 0;
}

static inline int fixed_stack_pop(struct fixed_stack *s, uint32_t *obj) {
    if (s->pos == 0) {
        return -ENOENT;
    }
    *obj = s->data[--s->pos];
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif // _FIXED_STACK_H
