#ifndef __RUNTIME_IF_H__
#define __RUNTIME_IF_H__

#define MAX_FUNC      (64)
struct t_func_info {
    uint64_t pt_addr;
    uint64_t entry_addr;
    uint64_t stack_load_addr;
};

struct t_metadata {
    struct t_func_info func_info[MAX_FUNC];
};
    
#endif
