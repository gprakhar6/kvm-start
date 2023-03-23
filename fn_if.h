#ifndef __FN_IF_H__
#define __FN_IF_H__

#include <stdint.h>

struct __attribute__((packed, aligned(8))) t_shm {
    struct t_shm *next;
    uint16_t flags; // because packet start has to be 4 byte aligned minus 2
};

#endif
