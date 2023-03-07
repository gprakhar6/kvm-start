#ifndef __TYPEDEF_H__
#define __TYPEDEF_H__

#include <stdint.h>

struct func_prop {
    uint64_t entry;
    uint64_t stack_load_addr;
    uint64_t min_addr;
    uint64_t max_addr;    
};

#endif
