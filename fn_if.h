#ifndef __FN_IF_H__
#define __FN_IF_H__

#include <stdint.h>

struct __attribute__((packed, aligned(8))) t_shm {
    struct t_shm *next;
    uint64_t fndt[3];
    uint16_t flags;
};

#endif
