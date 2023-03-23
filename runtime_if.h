#ifndef __RUNTIME_IF_H__
#define __RUNTIME_IF_H__

#define MAX_FUNC       (64)
#define MAX_DAG_ARR_SZ (256)

struct t_func_info {
    uint64_t pt_addr;
    uint64_t entry_addr;
    uint64_t stack_load_addr;
    uint32_t inp_off;
    uint32_t out_off;
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
	};
    };
} t_sched_status;

struct t_metadata {
    struct t_func_info func_info[MAX_FUNC];
    volatile uint64_t bit_map_inactive_cpus;
    uint64_t num_active_cpus;
    uint8_t current[64];
    t_sched_status sched_status;
    uint64_t dag_ts, dag_n;
    uint64_t dag_tot_tsc_time, dag_tot_proc_inp;
    uint8_t num_nodes;
    uint8_t start_func;
    uint16_t spare;
    uint16_t dag[MAX_DAG_ARR_SZ];
    uint16_t dag_in_count[MAX_FUNC]; // used by runtime
    uint32_t dag_func_time[MAX_FUNC];
};

#endif
