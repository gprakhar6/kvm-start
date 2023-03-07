#ifndef __RESOLVE_DEPS_H__
#define __RESOLVE_DEPS_H__

#include "../elf-reader/elf-reader.h"
#include "globvar.h"
#include "typedef.h"

struct exec_info {
    char filename[MAX_NAME_LEN+1];
    char name[MAX_NAME_LEN+1];
    uint16_t p3e;
    int dep_list[MAX_DEPS];
    int num_dep;
    struct elf64_file elf;
    uint8_t *mm;
    uint32_t mm_size;
    struct func_prop func_prop;
};

struct lib_deps {
    struct exec_info exec[MAX_DEPS];
    int num_exec;
};

int gen_deps(struct lib_deps *deps, char *name);

#endif
