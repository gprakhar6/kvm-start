#ifndef __RUNTIME_IF_H__
#define __RUNTIME_IF_H__

#define MAX_FUNC       (64)
#define MAX_DAG_ARR_SZ (256)

struct t_func_info {
    uint64_t pt_addr;
    uint64_t entry_addr;
    uint64_t stack_load_addr;
};

// POI zero it is assumed
typedef struct  {
    union {
	uint64_t R;
	struct {
	    uint8_t sched_init : 1;
	    /* state machine, 00 -> start,
	    / 11 -> fin */
	    uint8_t sched_sm   : 2;
	    uint8_t active_cpus : 8;
	};
    };
} t_sched_status;

struct t_metadata {
    struct t_func_info func_info[MAX_FUNC];
    t_sched_status sched_status;
    uint8_t node_nums;
    uint16_t dag[MAX_DAG_ARR_SZ];
};
    
#endif
