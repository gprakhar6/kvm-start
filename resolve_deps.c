#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
 #include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "resolve_deps.h"
#include "../elf-reader/elf-reader.h"
#include "globvar.h"

#define fatal(s, ...) do {                              \
        printf("%s.%04d: %s :",__FILE__,__LINE__, strerror(errno));     \
        printf(s, ##__VA_ARGS__);                       \
        exit(1);                                        \
    } while(0)

struct lib_queue {
    int *queue;
    int start, end;
    int total_sz;
    int cur_sz;
};

extern char *ATARU_LD_FUNC_PATH;

// queue funcs
static void init_queue(struct lib_queue *q, int *q_arr, int sz);
static void push_q(struct lib_queue *q, int e);
static int pop_q(struct lib_queue *q);

static char* iterate_deps(struct exec_info *e, int *i);
static int in_exec_info(struct lib_deps *deps, char *dep_name);

void init_queue(struct lib_queue *q, int *q_arr, int sz)
{
    q->queue = q_arr;
    q->total_sz = sz;
    q->cur_sz = 0;
    q->start = 0;
    q->end = 0;
}

void push_q(struct lib_queue *q, int e)
{
    if(q->cur_sz >= q->total_sz)
	fatal("exceeding q_len\n");
    q->queue[q->start] = e;
    q->start += 1;
    q->cur_sz += 1;
    if(q->start >= q->total_sz)
	q->start = 0;
}

int pop_q(struct lib_queue *q)
{
    int ret;
    if(q->cur_sz <= 0)
	ret = -1;
    else {
	ret  = q->queue[q->end];
	q->end += 1;
	if(q->end >= q->total_sz)
	    q->end = 0;
	q->cur_sz -= 1;
    }

    return ret;
}

// unused as of now. I wanted to have multiple paths to search from
// will see later how to do this gracefully
int get_path(char all_paths[], int all_paths_sz, char path[],
	     int path_sz, int i) {
    int ret = -1, j;
    if(i >= all_paths_sz)
	return ret;

    j = 0;
    while(i < all_paths_sz && \
	  all_paths[i] != '\0' && all_paths[i] != ':') {
	path[j]= all_paths[i];
	j++; i++;
	if(j >= path_sz)
	    fatal("too big of a path\n");
    }
    path[j] = '\0';

    return i;
}

void init_exec(struct exec_info *e, char *name, uint64_t base_addr)
{
    int fd;
    char name_mapped[MAX_NAME_LEN + 1];
    struct stat stat;
    printf("name = %s, %s\n", name, ATARU_LD_FUNC_PATH);
    strcpy(e->name, ATARU_LD_FUNC_PATH);
    strcat(e->name, name);
    strcpy(name_mapped, e->name);
    strcat(name_mapped, STR_MAPPED); // TBD safety check later
    e->base_addr = base_addr;
    e->num_dep = 0;
    fd = open(name_mapped, O_RDWR);
    if(fd == -1)
	fatal("cant open %s\n", name_mapped);
    fstat(fd, &stat);
    if(stat.st_size > GB_1)
	fatal("too big of a library %s\n", name_mapped);
    // replace this with mmap
    init_elf64_file(e->name, &(e->elf));
    e->mm =							    \
        (uint8_t *)mmap(NULL, stat.st_size, PROT_READ | PROT_WRITE, \
                        MAP_PRIVATE, fd, 0);
    e->mm_size = stat.st_size;
    close(fd);
}

void add_deps(struct exec_info *e, int idx)
{
    if(e->num_dep >= MAX_DEPS)
	fatal("%s: cant have more than %d deps\n", e->name, MAX_DEPS);
    e->dep_list[e->num_dep] = idx;
    (e->num_dep)++;
}

void print_deps(struct lib_deps *deps, struct exec_info *e) {
    int i, idx;
    for(i = 0; i < e->num_dep; i++) {
	idx = e->dep_list[i];
	printf("    %s\n", deps->exec[idx].name);
    }
}

int gen_deps(struct lib_deps *deps, char *name)
{
#define Q_SZ (128)
    int idx, jdx, i;
    int q_arr[Q_SZ];
    struct exec_info *e;
    char *dep_name;
    struct lib_queue q;
    FILE *fp;
    char buf[MAX_NAME_LEN+1];
    //init_limits(limit_file);
    deps->num_exec = 1;
    init_exec(&(deps->exec[0]), name, 0x80400000);
    strcpy(buf, ATARU_LD_FUNC_PATH);
    strcat(buf, name);
    strcat(buf, STR_MAPPED);
    strcat(buf, STR_PROP);
    fp = fopen(buf, "r");
    if(fp == NULL)
	fatal("cannot open %s\n", buf);
    fread(&deps->func_prop, sizeof(deps->func_prop), 1, fp);
    fclose(fp);
    
    init_queue(&q, q_arr, Q_SZ);
    push_q(&q, 0);
    while((idx = pop_q(&q)) >= 0) {
	e = &(deps->exec[idx]);
	i = 0;
	while((dep_name = iterate_deps(e, &i)) != NULL) {
	    if((jdx = in_exec_info(deps, dep_name)) == -1) {
		if(idx == jdx)
		    fatal("This is bad circular dep %d\n", idx);
		jdx = (deps->num_exec)++;
		init_exec(&(deps->exec[jdx]), dep_name, (jdx+4)*(0x40000000));
		push_q(&q, jdx);
	    }
	    printf("Adding %s as dep of %s\n", dep_name, e->name);
	    add_deps(e, jdx);
	}
    }

    for(i = 0; i < deps->num_exec; i++) {
	printf("%02d: %s\n", i, deps->exec[i].name);
	print_deps(deps, &deps->exec[i]);
    }
#undef Q_SZ    
}


char* iterate_deps(struct exec_info *e, int *i) {
    char *ret;
    if(iterate_needed_libs(&e->elf, &ret, i) == -1)
	ret = NULL;
    return ret;
}

//char* iterate_deps(struct exec_info *e, int *i) {
//
//    int lib_i, j, nidx;
//    int max_deps, dep_tree_sz;
//    char *ret, *n_lib;
//    
//    max_deps = sizeof(dep_tree[0]) / (sizeof(dep_tree[0][0]));
//    dep_tree_sz  = sizeof(dep_tree) / (sizeof(dep_tree[0]));
//    for(j = 0; j < dep_tree_sz; j++) {
//	if(strcmp(&dep_tree[j][0][0], e->name) == 0)
//	    break;
//    }
//    if(j == dep_tree_sz)
//	fatal("no %s found\n", e->name);
//
//    lib_i = j;
//    nidx = *i+1;
//    if((nidx >= max_deps))
//	ret = NULL;
//    else {
//	n_lib = &dep_tree[lib_i][nidx][0];
//	if(strcmp(n_lib, "") == 0)
//	    ret = NULL;
//	else {
//	    ret = n_lib;
//	    (*i)++;
//	}
//    }
//    return ret;
//}

int in_exec_info(struct lib_deps *deps, char *dep_name)
{
    int ret, i;
    ret = -1;
    for(i = 0; i < deps->num_exec; i++) {
	if(strcmp(deps->exec[i].name, dep_name) == 0) {
	    ret = i;
	}
    }
    return ret;
}
