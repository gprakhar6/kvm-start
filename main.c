#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <fcntl.h>
#include <time.h>
#include <sched.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <errno.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <semaphore.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include "globvar.h"
#include "bits.h"
#include "../elf-reader/elf-reader.h"
#include "runtime_if.h"
#include "fn_if.h"
#include "sock_flow.h"
#include "typedef.h"
#include "resolve_deps.h"
#include "app_defn.h"

#define __IRQCHIP__

#define fatal(s, ...) do {						\
	printf("%s.%04d: %s :",__FILE__,__LINE__, strerror(errno));	\
	printf(s, ##__VA_ARGS__);					\
	exit(1);							\
    } while(0)

#define ONE_PAGE (0x1000)

#define PAGE_MASK (0x1FFFFF)

#define SHM_SIZE (MB_2 * SHARED_PAGES)
#define SHARED_RO_SIZE (MB_2 * PAGES_SHARED_RO)

#define SZ2PAGES(x) (((x) + MB_2 - 1) / MB_2)
#define ROUND2PAGE(x) (SZ2PAGES(x) * MB_2)
#define H2G(h,g) ((h) + (uint64_t)&(g))
#define ARR_SZ_1D(x) (sizeof(x)/sizeof(x[0]))
#define ts(x) (gettimeofday(&x, NULL))
#define dt(t2, t1) ((t2.tv_sec - t1.tv_sec)*1000000 + (t2.tv_usec - t1.tv_usec))
#define pdt() printf("dt = %ld us\n", dt(t2,t1))
#define pts(ts) {printf("ts = %ld us\n", (ts.tv_sec*1000000 + ts.tv_usec))}
#define tr_result(s, b, ...) do {write(s, b, sprintf(b, ##__VA_ARGS__));} while(0)
#define vcpumeta(v) ((*(vcpu->metadata))->v)
#define declobj(type, var_name) type var_name = type ## _ ## constructor()
#define	update_stat(o, v) (o)->update_stat(o, v)

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

enum {
    eboot_time = 0,
    edag_tot_t,
    enet_time,
    efunc0,
    efunc_maxfunc = efunc0 + MAX_FUNC,
    etot_stat
};
typedef enum {
    eraw,
    etcp
} conn_t;
typedef struct t_pstat {
    double cur;
    uint64_t n;
    double max;
    double min;
    double Ex1;
    double Ex2;
    double Ex3;
    double Ex4;
    double std;
    double skw;
    double kurt;
    void (*update_stat)(struct t_pstat *stat, double cur);
} t_pstat;

struct t_page_table {
    uint64_t e[512];
};

struct t_pg_tbls {
    struct t_page_table tbl[2];
};

struct vm;
typedef struct
{
    struct vm *vm;
    int vcpufd;
    uint8_t id;
    uint8_t pool_size;
    pthread_t tid;
    struct kvm_run *run;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    struct kvm_debugregs dregs;
    struct kvm_cpuid2 *cpuid2;
    uint64_t entry;
    uint64_t stack_start;
    struct t_metadata **metadata;
    uint8_t **shared_mem;
    int *clifd;
    int *sock_f, *sockaddr_f_len, *buflen;
    struct sockaddr *saddr_f;
    sem_t *sem_vcpu_init;
} t_vcpu;

enum elf_type {
    elf_lib = 1,
    elf_uc
};

struct exec_path_name {
    char path[128];
    char name[64];
    uint64_t inp_off;
    uint64_t out_off;
};
struct executable {
    char name[MAX_NAME_LEN+1];
    enum elf_type type;
    unsigned char *mm;
    uint32_t mm_size;
    struct elf64_file elf;
};

struct vm {
    pid_t pid;
    int fd;
    int ncpu;
    int slot_no;
    t_vcpu *vcpu;
    int rand_num;
    uint64_t entry;
    struct func_prop kprop;
    uint64_t stack_start;
    uint64_t kern_end;
    uint64_t paging;
    struct t_pg_tbls *tbls;
    struct kvm_cpuid2 *cpuid2;
    int mmap_size;
    uint8_t *kmem;
    unsigned int kphy_mem_size;
    uint8_t *umem;
    unsigned int uphy_mem_size;
    pthread_t tid_tmr, tid_sock;
    int tmr_eventfd;
    uint8_t *shared_mem;
    uint8_t *shared_user_code;
    uint8_t *shared_ro;
    int clifd;
    int sock_f, sockaddr_f_len;
    struct sockaddr saddr_f;
    struct lib_deps exec_deps[MAX_FUNC];
    int num_exec;
    struct t_metadata *metadata;
};

const char limit_file[] = "../elf-reader/limits.txt";
const char smap_file_name[] = "smap_dump.txt";
static int pktcnt = 0;
static struct timeval t1, t2;
static struct timeval t1_net, t2_net;
static uint64_t tsc_t1, tsc_t2;
static double tsc2ts;
static sem_t vcpu_init_barrier, sem_vcpu_init[MAX_VCPUS];
static sem_t sem_booted, sem_usercode_loaded, sem_work_wait, sem_work_fin;
static uint64_t boot_time;
// currently each function resides on one folder
// with library maybe softlinked in that folder
char *ATARU_LD_FUNC_PATH;
int isol_core_start = 12;
int runtime_vcpus = 1, runtime_pcpus = 1;
int out_off_print = 0, num_out_print = 0;
static char str_sys_cmd[1024];
static char result_buf[1024];
static char file_buf[sizeof(result_buf)-1];
static t_pstat pstats[etot_stat];
static uint64_t gp2hv[NR_GP2HV];
static conn_t conn_type;
static int result_sock, wait_s, tcp_server_sock;
#define GP2HV(x)  (gp2hv[((x) >> 21)] + ((x) & (MB_2 - 1)))
static struct app_defn_t app;

static const char sprintf_cmd_private_page[] = "cat %s | grep -i -E '^Private_.*:' | awk '//{s+=$2}END{print s}' > tmp/private%d.txt";
static const char sprintf_cmd_pss[] = "cat %s | grep -i '^pss' | awk '//{s+=$2}END{print s}' > tmp/pss%d.txt";
static struct sock_filter code[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 4, 0x00000800 },
    { 0x20, 0, 0, 0x0000001a },
    { 0x15, 8, 0, 0x0a1046f0 },
    { 0x20, 0, 0, 0x0000001e },
    { 0x15, 6, 7, 0x0a1046f0 },
    { 0x15, 1, 0, 0x00000806 },
    { 0x15, 0, 5, 0x00008035 },
    { 0x20, 0, 0, 0x0000001c },
    { 0x15, 2, 0, 0x0a1046f0 },
    { 0x20, 0, 0, 0x00000026 },
    { 0x15, 0, 1, 0x0a1046f0 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
};

int tcp_listen_on(int *port, int max_listen);
void fin_sock(int sock);
int getinp_raw(t_vcpu *vcpu);
int getinp_tcp(t_vcpu *vcpu, int len);

static inline int handle_io_port(t_vcpu *vcpu);
int get_vm(struct vm *vm);
void register_mem(struct vm *vm, void *hva, uint64_t *gpa,
		  uint64_t sz);
void setup_vcpus(struct vm *vm);
int setup_bootcode_mmap(struct vm *vm);
void snapshot_vm(struct vm *vm);
int setup_usercode_mmap(struct vm *vm);
void resolve_dynsyms(struct vm *vm);
void register_umem_mmap(struct vm *vm);
void setup_irqfd(struct vm *vm, uint32_t gsi);
void setup_device_loop(struct vm *vm);
int print_regs(t_vcpu *vcpu);
void install_signal_handlers();
void print_cpuid_output(struct kvm_cpuid2 *cpuid2);
void print_lapic_state(struct kvm_lapic_state *lapic);
Elf64_Shdr* get_shdr(struct elf64_file *elf, char *name);
void print_hex(uint8_t *a, int sz);
void dump_self_smaps();
uint64_t guest2host(uint64_t cr3, uint64_t addr);
int connect_to(int sock, char ip[], int port);
int read_file(char b[], int bs, const char fname[]);


// struct t_pstat member functions
struct t_pstat t_pstat_constructor();
void t_pstat_update_stat(t_pstat *stat, double cur);

static inline uint64_t tsc()
{
    uint32_t eax, edx;
    asm volatile("rdtscp\n": "=a"(eax),"=d"(edx));
    return (uint64_t)eax | (((uint64_t)edx) << 32);
}

struct vm vm;
int main(int argc, char *argv[])
{
    int i, ret;
    uint64_t gpa;
    for(i = 1; i < argc;) {
	if(strcmp(argv[i], "vcpu") == 0) {
	    if(i+1 >= argc)
		fatal("provide option for %s\n", argv[i]);
	    if(sscanf(argv[i+1], "%d", &runtime_vcpus) != 1) {
		printf("provide numeric argument to %s\n", argv[i]);
		exit(-1);
	    }
	    printf("%s num = %d\n", argv[i], runtime_vcpus);
	    i+=2;
	    continue;
	}
	if(strcmp(argv[i], "pcpu") == 0) {
	    if(i+1 >= argc)
		fatal("provide option for %s\n", argv[i]);
	    if(sscanf(argv[i+1], "%d", &runtime_pcpus) != 1) {
		printf("provide numeric argument to %s\n", argv[i]);
		exit(-1);
	    }
	    printf("%s num = %d\n", argv[i], runtime_pcpus);
	    i+=2;
	    continue;
	}
	if(strcmp(argv[i], "parg") == 0) {
	    if(i+2 >= argc)
		fatal("provide option for %s\n", argv[i]);

	    if(sscanf(argv[i+1], "%d", &out_off_print) != 1) {
		printf("provide numeric argument to %s\n", argv[i]);
		exit(-1);
	    }
	    if(sscanf(argv[i+2], "%d", &num_out_print) != 1) {
		printf("provide numeric argument to %s\n", argv[i]);
		exit(-1);
	    }
	    if(out_off_print > SHM_SIZE || num_out_print > 128) {
		fatal("bad:out_off_print=%d,num_out_print=%d",
		      out_off_print, num_out_print);
	    }
	    printf("%s,offset=%d,num2print=%d\n", argv[i],out_off_print, num_out_print);
	    i+=3;
	    continue;
	}
    }

    init_limits(limit_file);
    setup_bootcode_mmap(&vm); // 750 us
    setup_usercode_mmap(&vm); // 290 us
    resolve_dynsyms(&vm);
    //printf("(after funcs mmap)\nprivate_clean + private_dirty + private_hugetlb(kB):\n");
    //fflush(stdout);
    dump_self_smaps();
    sprintf(str_sys_cmd, sprintf_cmd_private_page, smap_file_name, vm.pid);
    system(str_sys_cmd);
    // wait for client app connection here
    get_vm(&vm); // 500 us
    gpa = 0;
    register_mem(&vm, vm.kmem, &gpa, vm.kphy_mem_size);
    vm.ncpu = runtime_vcpus;
    setup_vcpus(&vm); // 200 us    (2500 for 64 vcpus)
    register_umem_mmap(&vm);
    sem_post(&sem_usercode_loaded);
    //snapshot_vm(&vm);
    //setup_irqfd(&vm, 1);
    setup_device_loop(&vm); // start device thread

    //pthread_join(vm.tid_tmr, NULL);
    //printf("Timer thread joined\n");

    //printf("Installing signal handler\n");
    //install_signal_handlers();
    for(i = 0; i < vm.ncpu; i++)
	pthread_join(vm.vcpu[i].tid, NULL);
    printf("All cpu thread joined\n");

    return 0;
}
int decode_msg(t_vcpu *vcpu, uint16_t msg)
{
    int i;
    int ret = 0, len, fn;
    int buflen = 0;
    static double net_time = 0.0, cold_dag_tsc_time;
    static uint64_t cold_req_time;
    struct sockaddr_in cli;
    switch(msg) {
    case 1: // init sent to all guest vcpu by vcpu 0
	for(i = 1; i < vcpu->pool_size; i++)
	    sem_post(&sem_vcpu_init[i]);
	break;
    case 2: // MSG_BOOTED
	//ts(t2);
	//tsc_t2 = tsc();
	//printf("boot time = %ld, tsc_time = %ld\n", dt(t2, t1), (tsc_t2 - tsc_t1) / 3400);
	//printf("Booted = %d\n", vcpu->id);
	sem_post(&sem_booted);
	// TBD required or not? seems not
	sem_wait(&sem_usercode_loaded);
	break;

    case 3: // MSG_WAITING_FOR_WORK
	//pts(t2);
	if(pktcnt == 0) {
	    ts(t2);
	    boot_time = dt(t2,t1);
	    //exit(-1);
	    //printf("private_clean + private_dirty + private_hugetlb(kB):\n");
	    fflush(stdout);
	    dump_self_smaps();
	    sprintf(str_sys_cmd, sprintf_cmd_private_page, smap_file_name, vcpu->vm->pid);
	    system(str_sys_cmd);
	    //printf("pss(kB):\n");
	    fflush(stdout);
	    sprintf(str_sys_cmd, sprintf_cmd_pss, smap_file_name, vcpu->vm->pid);
	    system(str_sys_cmd);
	    tsc_t1 = tsc();
	    //printf("ts(t1)\n");
	    ts(t1);
	}
	// cold start times
	if(pktcnt == 1) {
	    ts(t2);
	    cold_dag_tsc_time = (double)vcpumeta(dag_tot_tsc_time);
	    cold_req_time = dt(t2,t1);
	}
	if(pktcnt > 1) {
	    for(i = efunc0; i < efunc_maxfunc; i++) {
		fn = i - (int)efunc0;
		update_stat(&pstats[i],					\
			    (double)vcpumeta(dag_func_time[fn]));
	    }
	    update_stat(&pstats[edag_tot_t],
			(double)vcpumeta(dag_tot_tsc_time));
	    update_stat(&pstats[enet_time], (double)net_time);
	    /*
	    if(((pktcnt-1) % 1000 == 0) ||
	       ((pktcnt-2) % 1000 == 0) ||
		((pktcnt-3) % 1000 == 0)) {
		printf("min = %lf\n", pstats[eboot_time].min);
		printf("max = %lf\n", pstats[eboot_time].max);
		printf("avg = %lf\n", pstats[eboot_time].Ex1);
	    }
	    */
	}
	//printf("%d: %d\n",buflen,pktcnt);
	if(pktcnt >= app.pktcnt) {
	    ts(t2);
	    tsc_t2 = tsc();
	    //printf("Sched_getcpu = %d\n", sched_getcpu());
	    tsc2ts = (double)(dt(t2, t1)) / (double)(tsc_t2 - tsc_t1);
#define TR(...)	tr_result(result_sock, result_buf, ##__VA_ARGS__)
	    // boot time is us
	    TR("%-10ld ", boot_time);
	    TR("%-10ld ", dt(t2, t1));
	    //printf("tsc2ts = %lf, tsc_t1 = %lu, ts_t2 = %lu, sub=%lu\n", tsc2ts, tsc_t1, tsc_t2, tsc_t2 - tsc_t1);
	    // tsc difference
	    TR("%-16lu ", tsc_t2 - tsc_t1);
	    TR("%-10d ", app.pktcnt);
	    TR("%-10d ", buflen);
	    // private_mem
	    read_file(file_buf, sizeof(file_buf), "tmp/private.txt");
	    TR("%-12s ", file_buf);
	    // pss
	    read_file(file_buf, sizeof(file_buf), "tmp/pss.txt");
	    TR("%-12s ", file_buf);
	    //printf("avg dag_ts = %lf us, %ld\n", (*(vcpu->metadata))->dag_ts * tsc2ts, (*(vcpu->metadata))->dag_n);
	    /*
	      printf("avg dag_ts = %lf us\n",
	      ((*(vcpu->metadata))->dag_ts /
	      (*(vcpu->metadata))->dag_n) * tsc2ts);
	    */
	    /*
	    TR("%-16.5lf ",
	       ((*(vcpu->metadata))->dag_tot_tsc_time /
		(*(vcpu->metadata))->dag_tot_proc_inp) * tsc2ts);
	    */
	    TR("%-10d ", vcpumeta(num_nodes));
	    TR("%-15lu ", cold_req_time);
	    TR("%-15lf ", cold_dag_tsc_time * tsc2ts);
	    TR("%-15lf %-15lf %-15lf %-15lf %-15lf %-15lf %-15lf ",
	       pstats[edag_tot_t].min * tsc2ts,
	       pstats[edag_tot_t].Ex1 * tsc2ts,
	       pstats[edag_tot_t].max * tsc2ts,
	       pstats[edag_tot_t].std * tsc2ts,
	       pstats[edag_tot_t].skw * tsc2ts * tsc2ts * tsc2ts,
	       pstats[edag_tot_t].kurt * tsc2ts * tsc2ts * tsc2ts * tsc2ts,
	       pstats[edag_tot_t].Ex1 * pstats[edag_tot_t].n * tsc2ts);

	    TR("%-16lf ",
	       ((*(vcpu->metadata))->dag_ts) * tsc2ts);

	    TR("%-8lf ",
	       ((*(vcpu->metadata))->dag_ts /
		(*(vcpu->metadata))->dag_n) * tsc2ts);
	    TR("%-15lf ", net_time);
	    for(i = 0; i < app.num_nodes; i++) {
		TR("%-15lf %-15lf %-15lf %-15lf %-15lf %-15lf %-15lf ",
		   pstats[efunc0+i].min * tsc2ts,
		   pstats[efunc0+i].Ex1 * tsc2ts,
		   pstats[efunc0+i].max * tsc2ts,
		   pstats[efunc0+i].std * tsc2ts,
		   pstats[efunc0+i].skw * tsc2ts * tsc2ts * tsc2ts,
		   pstats[efunc0+i].kurt * tsc2ts * tsc2ts * tsc2ts * tsc2ts,
		   pstats[efunc0+i].Ex1 * pstats[efunc0+i].n * tsc2ts);
		/*
		TR("%-15lf ", ((double)vcpumeta(dag_func_time[i]) /
			       vcpumeta(dag_tot_proc_inp)) * tsc2ts);
		*/
	    }
	    //printf("net_time = %lf\n", net_time);
	    //printf("num dag invocations = %lu\n", (*(vcpu->metadata))->dag_tot_proc_inp);
	    TR("\n");
#undef TR
	    if(num_out_print != 0)
	    {
		uint64_t *paddr;
		paddr = (typeof(paddr))((uint8_t*)*(vcpu->shared_mem) + out_off_print);
		printf("out: ");
		for(i = 0; i < num_out_print; i++) {
		    printf("%15.3lf ", ((double)(paddr[i*4+2] / paddr[i*4+3]))*tsc2ts);
		}
		printf("\n");
	    }
	    //printf("FIN\n");
	    fin_sock(*(vcpu->sock_f));
	    if(*(vcpu->sock_f) != result_sock)
		close(result_sock);
	    exit(-1);
	}

	ts(t1_net);
	switch(conn_type) {
	case eraw:
	    getinp_raw(vcpu);
	    break;
	case etcp:
	    getinp_tcp(vcpu, app.msg_len);
	    break;
	default:
	    fatal("Unknown conn_type = %d\n", conn_type);
	    break;
	}
	//print_hex(addr, 64);
	//printf("buflen = %d\n", buflen);
	ts(t2_net);
	net_time += dt(t2_net, t1_net);
	pktcnt++;

	break;
    default:
	fatal("Unknown msg from the guest");
	break;
    }

    return ret;
}

// takes guest physica cr3, guest virt addr
// returns hv address
void* pt_walk(uint64_t cr3, uint64_t addr)
{
    uint64_t off, p4e, p3e, p2e, e;

    //printf("cr3 = %016lX\n", (uint64_t)cr3);
    //printf("hv-cr3 = %016lX\n", (uint64_t)GP2HV(cr3));
    off = (addr >> 39) & 0x1FF;
    p4e = *((uint64_t *)GP2HV(cr3) + off);
    //printf("p4e = %016lX, off = %ld\n", p4e, off);
    p4e = p4e & (~(KB_4-1));

    off = (addr >> 30) & 0x1FF;
    p3e = *((uint64_t *)GP2HV(p4e) + off);
    //printf("p3e = %016lX, off = %ld\n", p3e, off);
    p3e = p3e & (~(KB_4-1));

    off = (addr >> 21) & 0x1FF;
    p2e = *((uint64_t *)GP2HV(p3e) + off);
    //printf("p2e = %016lX, off = %ld\n", p2e, off);
    p2e = p2e & (~(KB_4-1));

    e = GP2HV(p2e);
    return (void *)(e + (addr & (MB_2-1)));

}
void handle_syscall(t_vcpu *vcpu, uint16_t nr)
{
    int ret;
    uint64_t rax, rdi, rsi, rcx, rdx, r8, r9;
    uint64_t cr3, cr3_hv;
    ret = ioctl(vcpu->vcpufd, KVM_GET_REGS, &vcpu->regs);
    if(ret == -1)
	fatal("cant read regs\n");
    ret = ioctl(vcpu->vcpufd, KVM_GET_SREGS, &vcpu->sregs);
    if(ret == -1)
	fatal("cant read sregs\n");

    rdi = vcpu->regs.rdi;
    rsi = vcpu->regs.rsi;
    rcx = vcpu->regs.rcx;
    rdx = vcpu->regs.rdx;
    r8  = vcpu->regs.r8;
    r9  = vcpu->regs.r9;
    cr3 = vcpu->sregs.cr3;

    switch(nr) {
    case 11:
	rax = printf((char *)pt_walk(cr3, rdi),
		     (char *)pt_walk(cr3, rsi));
	break;
    default:
	fatal("Unsupported system call %d\n", nr);
	break;
    }
    vcpu->regs.rax = rax;
    ret = ioctl(vcpu->vcpufd, KVM_SET_REGS, &vcpu->regs);
    if(ret == 1)
	fatal("error setting regs");
    //printf("syscall nr:%d\n", nr);
    //printf("rdi    = 0x%016lx\n", rdi);
    //printf("rsi    = 0x%016lx\n", rsi);
    //printf("rcx    = 0x%016lx\n", rdx);
    //printf("rdx    = 0x%016lx\n", rcx);
    //printf("r8     = 0x%016lx\n", r8);
    //printf("r9     = 0x%016lx\n", r9);
}

static inline int handle_io_port(t_vcpu *vcpu)
{
    char c;
    int ret;
    uint16_t nr;

    switch(vcpu->run->io.port) {
    case PORT_SYSCALL:
	if (vcpu->run->io.direction == KVM_EXIT_IO_OUT &&
	    vcpu->run->io.size == 2 && vcpu->run->io.count == 1) {
	    nr = *(uint16_t *)(((uint8_t *)vcpu->run) + vcpu->run->io.data_offset);
	    handle_syscall(vcpu, nr);
	}
	break;
    case PORT_SERIAL: /* for the printf function */
	if (vcpu->run->io.direction == KVM_EXIT_IO_OUT &&
	    vcpu->run->io.size == 1 && vcpu->run->io.count == 1) {
	    c = *(((char *)vcpu->run) + vcpu->run->io.data_offset);
	    printf("%c", c);
	}
	break;
    case PORT_WAIT_USER_CODE_MAPPING: /* For waiting for user code creation thread */
	sem_wait(&vcpu_init_barrier);
	//printf("Joined\n");
	break;
    case PORT_HLT:
	tsc_t2 = tsc();
	ts(t2);
	printf("time = %ld, tsc_time = %ld\n", dt(t2, t1), (tsc_t2 - tsc_t1) / 3400);
	printf("Halt port IO\n");
	    printf("pktcnt = %d\n", pktcnt);
	print_regs(vcpu);
	exit(-1);
	return 1;
	break;
    case PORT_PRINT_REGS:
	printf("PORT_PRINT_REGS IO:\n");
	print_regs(vcpu);
	break;
    case PORT_MY_ID: // POOL_SZ << 8 | CPU_ID
	if(vcpu->run->io.direction == KVM_EXIT_IO_IN) {
	    if (vcpu->run->io.size == 2 && vcpu->run->io.count == 1) {
		*(uint16_t *)(((uint8_t *)vcpu->run) + vcpu->run->io.data_offset) =
		    ((uint16_t)(vcpu->pool_size) << 8) | (uint16_t)vcpu->id;
	    }
	}
	else {
	    uint8_t v;
	    // out direction
	    if (vcpu->run->io.size == 1 && vcpu->run->io.count == 1) {
		v = *(((uint8_t *)vcpu->run) + vcpu->run->io.data_offset);
	    }
	}
	break;

    case PORT_MSG: // 0x3fe-0x3ff
	if(vcpu->run->io.direction == KVM_EXIT_IO_OUT) {
	    if (vcpu->run->io.size == 2 && vcpu->run->io.count == 1) {
		uint16_t msg;
		msg = *(uint16_t *)(((uint8_t *)vcpu->run) + vcpu->run->io.data_offset);
		ret = decode_msg(vcpu, msg);
	    }
	}
	break;
    default:
	print_regs(vcpu);
	fatal("unhandled KVM_EXIT_IO, %X\n", vcpu->run->io.port);
	break;
    }

    return 0;
}

int get_vm(struct vm *vm)
{
    int i;
    int kvm, ret;
    int err, nent;

    err = 0;
    kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if(kvm == -1) {
	printf("Unable to open kvm\n");
	exit(1);
    }

    ret = ioctl(kvm, KVM_GET_API_VERSION, NULL);
    if(ret == -1)
	fatal("API error\n");


    vm->fd = ioctl(kvm, KVM_CREATE_VM, (unsigned long)0);
    if(vm->fd == -1)
	fatal("cant create VM\n");
    ret = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if(ret == -1)
	fatal("kvm mmap size error\n");
    vm->mmap_size = ret;
    if(vm->mmap_size < sizeof(struct kvm_run))
	fatal("really! mmap_size < run. Why?\n");

    nent = 128;
    vm->cpuid2 =
	(struct kvm_cpuid2 *)
	malloc(sizeof(struct kvm_cpuid2)
	       + nent * sizeof(struct kvm_cpuid_entry2));
    vm->cpuid2->nent = nent;
    if(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, vm->cpuid2) < 0)
	fatal("cant get cpuid");
    // all future vcpus will now have irqchip
    //print_cpuid_output(vm->cpuid2);
#ifdef __IRQCHIP__
    if(ioctl(vm->fd, KVM_CREATE_IRQCHIP, 0))
	fatal("Unable to create IRQCHIP\n");
#endif
    // not sure about its correctness
    //ret = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_NR_VCPUS);
    //printf("nr_vcpus = %d\n", ret);
    //ret = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_MAX_VCPUS);
    //printf("max_vcpus = %d\n", ret);
    //ret = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_NR_MEMSLOTS);
    //printf("max_memslots = %d\n", ret);

    sem_init(&sem_booted, 0, 0);
    sem_init(&sem_usercode_loaded, 0, 0);
    sem_init(&sem_work_wait, 0, 0);
    sem_init(&sem_work_fin, 0, 0);

    vm->sockaddr_f_len = sizeof(vm->saddr_f);

    vm->metadata->bit_map_inactive_cpus = ~0;
    vm->metadata->num_active_cpus = 0;
    vm->slot_no = 0;
    for(i = 0; i < ARR_SZ_1D(pstats); i++)
	pstats[i] = t_pstat_constructor();
    return err;
}

void *create_vcpu(void *vvcpu)
{
    int i;
    t_vcpu *vcpu = vvcpu;
    int ret;
    struct kvm_lapic_state lapic_state;
    struct kvm_mp_state mp_state;
    pthread_t pid;
    int core_id;
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    /*
    // depend on linux sched for affinity within pcpus
    core_id = isol_core_start;
    for(i = 0; i < runtime_pcpus; i++) {
    CPU_SET(core_id, &cpuset);
    //printf("core_id = %d\n", core_id);
    core_id += 1;
    }
    */

    // distribute eventy, 1 core per pcpu
    core_id = isol_core_start + (vcpu->id + vcpu->vm->rand_num) % runtime_pcpus;
    CPU_SET(core_id, &cpuset);
    // pin cpu thread to a cpu set
    if(pthread_setaffinity_np(vcpu->tid, sizeof(cpuset), &cpuset))
	fatal("pthread_setaffinity_np failed, pinning\n");

    //ts(t1);
#ifdef __IRQCHIP__
    if(ioctl(vcpu->vcpufd, KVM_GET_LAPIC, &lapic_state)) {
	fatal("Could not get the lapic state");
    }
#endif
    //print_lapic_state(&lapic_state);
    mp_state.mp_state = 1;
    sem_wait(vcpu->sem_vcpu_init);
    while(mp_state.mp_state != 0) {

	//while(0 && (vcpu->id != 0)) {
	if(ioctl(vcpu->vcpufd, KVM_GET_MP_STATE, &mp_state)) {
	    fatal("Cannot fetch MP_STATE");
	}
	//printf("MP_STATE for %d = %d\n", vcpu->id, mp_state.mp_state);
	//sleep(1);
    }

    //printf("In vcpu thread %ld\n", vcpu->tid);
    if(ioctl(vcpu->vcpufd, KVM_SET_CPUID2, vcpu->cpuid2) < 0)
	fatal("cannot set cpuid things\n");
    // to get the real mode running
    if(ioctl(vcpu->vcpufd, KVM_GET_SREGS, &(vcpu->sregs)) < 0)
	fatal("cant set get sregs tid = %ld\n", vcpu->tid);

    //printf("cs.base = %llX\n",vcpu->sregs.cs.base);
    //printf("cs.selector = %llX\n",vcpu->sregs.cs.selector);
    vcpu->sregs.cs.base = 0;
    vcpu->sregs.cs.selector = 0;
    vcpu->sregs.gs.base = 0;
    vcpu->sregs.gs.selector = 0;
    if(ioctl(vcpu->vcpufd, KVM_SET_SREGS, &(vcpu->sregs)) < 0)
	fatal("cant set seg sregs tid = %ld\n", vcpu->tid);

    {
	struct kvm_regs regs = {
	    .rip = vcpu->entry,
	    .rax = 2,
	    .rbx = 2,
	    .rcx = (uint64_t)vcpu->id, // saves a vm exit, used in real mode
	    .rsp = vcpu->stack_start,
	    .rdi = vcpu->stack_start,
	    .rsi = 0,
	    .rflags = 0x2,
	    .r10 = (uint64_t)vcpu->id, // saves a vm exit
	    .r11 = (uint64_t)vcpu->pool_size
	};
	ret = ioctl(vcpu->vcpufd, KVM_SET_REGS, &regs);
	if(ret == -1)
	    fatal("Cannot set regs in vcpu thread");

	//printf("entry = %lx, stack_start = %lx\n", vcpu->entry, vcpu->stack_start);
    }

    //printf("before run vcpu %ld\n", vcpu->tid);
    //tsc_t1 = tsc();
    //ts(t1);
    //ts(t2);
    //pdt();
    while(1) {
	ret = ioctl(vcpu->vcpufd, KVM_RUN, NULL);
	if(ret == -1)
	    fatal("KVM_RUN ERROR\n");

	//printf("exit reason = %d\n", vcpu->run->exit_reason);
	//print_regs(&vm);
	switch(vcpu->run->exit_reason) {
	case KVM_EXIT_HLT:
	    goto finish;
	    break;
	case KVM_EXIT_IO:
	    if(handle_io_port(vcpu))
		return NULL;
	    break;
	case KVM_EXIT_SHUTDOWN:
	    printf("pktcnt = %d\n", pktcnt);
	    print_regs(vcpu);
	    fatal("KVM_EXIT_SHUTDOWN\n");
	    break;
	case KVM_EXIT_INTERNAL_ERROR:
	    fatal("KVM_EXIT_INTERNAL_ERROR\n");
	    break;
	case KVM_EXIT_FAIL_ENTRY:
	    fatal("KVM_EXIT_FAIL_ENTRY\n");
	    break;
	default:
	    print_regs(vcpu);
	    fatal("exit_reason = %d\n, exiting\n", vcpu->run->exit_reason);
	    break;
	}
    }

finish:
    print_regs(vcpu);
    return NULL;
}

void setup_vcpus(struct vm *vm)
{
    uint8_t start_id;
    int i;
    unsigned long vcpu_id;
    vm->vcpu = calloc(vm->ncpu, sizeof(*(vm->vcpu)));
    if(vm->vcpu == NULL)
	fatal("Cannot allocate vm->vcpu");

    for(i = 0; i < vm->ncpu; i++) {
	vm->vcpu[i].vm = vm;
	vcpu_id = i;
	vm->vcpu[i].vcpufd = ioctl(vm->fd, KVM_CREATE_VCPU, vcpu_id);
	//printf("vcpufd = %d\n", vm->vcpu[i].vcpufd);
	if(vm->vcpu[i].vcpufd == -1)
	    fatal("Cannot create vcpu\n");

	vm->vcpu[i].run = \
	    mmap(NULL, vm->mmap_size, PROT_READ | PROT_WRITE,
		 MAP_SHARED, vm->vcpu[i].vcpufd, 0);
	if(!vm->vcpu[i].run)
	    fatal("run error\n");

	vm->vcpu[i].cpuid2 = vm->cpuid2;
	vm->vcpu[i].entry = vm->entry;
	// give 1 page for stack for the runtime
	// I hope i never need more than this
	// also stack_start has my_id, it will break if stack size changes
	// more than one page.
	vm->vcpu[i].stack_start = vm->stack_start - ((i) * PAGE_SIZE);
	vm->vcpu[i].pool_size = vm->ncpu;
	vm->vcpu[i].shared_mem = &(vm->shared_mem);
	vm->vcpu[i].metadata = &(vm->metadata);
	vm->vcpu[i].clifd = &(vm->clifd);
	vm->vcpu[i].sock_f = &(vm->sock_f);
	vm->vcpu[i].saddr_f = &(vm->saddr_f);
	vm->vcpu[i].sockaddr_f_len = &(vm->sockaddr_f_len);
    }
    start_id = 0;
    // start all the vcpu threads
    for(i = 0; i < vm->ncpu; i++) {
	sem_init(&sem_vcpu_init[i], 0, 0);
	vm->vcpu[i].sem_vcpu_init = &sem_vcpu_init[i];
	vm->vcpu[i].tid = -1;
	vm->vcpu[i].id = start_id++;
	if(pthread_create(&(vm->vcpu[i].tid), NULL, create_vcpu, &(vm->vcpu[i]))) {
	    fatal("Couldnt create thread for user code creation\n");
	}
	else {
	    //printf("Created vcpu thread with tid  = %ld\n", vm->vcpu[i].tid);
	}
    }
    // only after all vcpus are created
    sem_post(&sem_vcpu_init[0]); // make sure cpu id zero starts

}

int setup_bootcode_mmap(struct vm *vm)
{
    int fd; struct stat stat;
    const char kernel_code[MAX_NAME_LEN+1] = "../boot/bin/main_mapped";
    const char kernel_prop[MAX_NAME_LEN+1] = "../boot/bin/main_mapped_prop";
    const char kernel_elf[MAX_NAME_LEN+1] = "../boot/bin/main";
    struct elf64_file elf;
    Elf64_Shdr *shdr;
    FILE *fp;

    init_elf64_file(kernel_elf, &elf);

    fd = open(kernel_code, O_RDWR);
    if(fd == -1)
	fatal("Unable to open kernel code\n");
    fstat(fd, &stat);
    if((vm->kmem = mmap(NULL, stat.st_size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE, fd, 0)) == MAP_FAILED)
	fatal("mmap failed for kmem\n");
    close(fd);
    vm->kphy_mem_size = stat.st_size;

    fp = fopen(kernel_prop, "r");
    if(fp == NULL)
	fatal("unable to open kernel code properties\n");

    fread(&(vm->kprop), sizeof(vm->kprop), 1, fp);
    fclose(fp);


    vm->metadata = (struct t_metadata *)&(vm->kmem[0x0008]);
    // TBD Compatibility
    vm->entry = vm->kprop.entry;
    vm->stack_start = vm->kprop.stack_load_addr;
    shdr = get_shdr(&elf, ".kfree_space");
    if(shdr == NULL)
	fatal("no .kfree_space section found");
    vm->kern_end = shdr->sh_addr; // this better be alined to 4KB
    //printf("kern_end = %ld\n", vm->kern_end / KB_1);
    shdr = get_shdr(&elf, ".paging");
    if(shdr == NULL)
	fatal("no .paging section found");
    vm->paging = shdr->sh_addr;
    //printf("paging section start = %08lX\n", vm->paging);
    //vm->tbls = (typeof(vm->tbls))(vm->kern_end - MAX_VCPUS * sizeof(struct t_pg_tbls));
    //printf("tbls test: %08lX\n", vm->tbls[0].tbl[1].e[3]);
    fini_elf64_file(&elf);
}

void snapshot_vm(struct vm *vm)
{
}

int tcp_listen_on(int *port, int max_listen)
{
    int sockfd, itrue;
    struct sockaddr_in servaddr;
    socklen_t len;
    if(port == NULL)
	fatal("port is NULL\n");
    sockfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if(sockfd == -1)
	fatal("Unable to get a socket");
    itrue = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &itrue, sizeof(int));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if(*port != 0)
	servaddr.sin_port = htons(*port);
    else
	servaddr.sin_port = 0; // auto assign port
    if(bind(sockfd, (struct sockaddr *)&servaddr,
            sizeof(servaddr)) != 0) {
	fatal("Unable to bind the socket on %d\n", *port);
    }
    if(port != NULL) {
	len = sizeof(servaddr);
	if (getsockname(sockfd, (struct sockaddr *)&servaddr,
			&len) == -1) {
	    fatal("getsockname error\n");
	}
	// get port number
	*port = ntohs(servaddr.sin_port);
    }

    if(listen(sockfd, max_listen) != 0) {
        fatal("listen failed max_liste = %d\n", max_listen);
    }

    return sockfd;
}

int setup_usercode_mmap(struct vm *vm)
{
    int i;
    uint32_t inp_off, out_off;
    int sockfd, clifd, len;
    char buf[128], *tcpbuf;
    int n, tot;
    struct sockaddr_in cli;
    pid_t c_pid;
    struct rt_exec_path_name *u_exec = app.exec;
    int server_port;
    server_port = SERVER_PORT;
    sockfd = tcp_listen_on(&server_port, MAX_LISTEN_APP);
    fflush(stdout);
look_for_new_app:
    clifd = accept(sockfd, (struct sockaddr *)&cli, &len);
    if((c_pid = fork()) != 0) {
	close(clifd);
	goto look_for_new_app;
    }
    else
	close(sockfd);

    tcpbuf = (typeof(tcpbuf))&app;
    // big packet, read till you get everything!
    tot = 0;
    while((n = read(clifd, &tcpbuf[tot], sizeof(app) - tot)) >= 0) {
	tot += n;
	if(tot >= sizeof(app))
	    break;
    }
    printf("Rxed app defn\n");
    /*
    {
        int sockfd_fin;
        char done_str[] = "Done";
        if((sockfd_fin = socket(AF_INET, SOCK_STREAM, 0)) == -1)
            fatal("Unable to open fin socket\n");
        connect_to(sockfd_fin,
                   app.result_ip,
                   APP_FIN_PORT);
        write(sockfd_fin, done_str, sizeof(done_str)+1);
        close(sockfd_fin);
    }
    */
    if(strcmp(app.conn_type, "raw") == 0) {
	conn_type = eraw;
    }
    else if (strcmp(app.conn_type, "tcp") == 0) {
	conn_type = etcp;
	if(app.conn_port < 0)
	    fatal("bad conn_port %d\n", app.conn_port);
	tcp_server_sock = tcp_listen_on(&app.conn_port, MAX_LISTEN_CLIENT);
	printf("Listening on port %d\n", app.conn_port);
    }
    
    {
	uint16_t ns_port = htons(app.conn_port);
	write(clifd, &ns_port, sizeof(ns_port));
    }
    close(clifd);
new_client_for_app:
    if(conn_type == eraw) {
	vm->sock_f = get_sock_for_flow(code, ARR_SZ_1D(code), "br0");
	printf("sock listening on br0\n");
    }
    else if (conn_type = etcp) {
	//printf("accepting the connection\n");
	len = sizeof(cli);
	vm->sock_f = accept(tcp_server_sock, (struct sockaddr *)&cli, &len);
	if(vm->sock_f <= 0)
	    fatal("Cannot accept the socket connection\n");
	//printf("Rxed connection\n");
    }
    else
	fatal("Unknown conn_type");

    if((vm->sock_f) <= 0)
	fatal("cannot create sock for the flow\n");
    vm->sockaddr_f_len = sizeof(vm->saddr_f);

    if(conn_type == etcp) 
	result_sock = vm->sock_f;
    else if(conn_type == eraw) {
	if((result_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	    fatal("unable to open result socket\n");
	if(app.result_port <= 0)
	    fatal("result port is less than 0\n");
	printf("Connecting to %s ip, at port %d\n", app.result_ip,
	       app.result_port);
	wait_s = 2;
	while(connect_to(result_sock,
			 app.result_ip,
			 app.result_port)) {
	    sleep(1);
	    wait_s--;
	    if(wait_s < 0)
		fatal("timeout for connecting to result socket\n");
	}
    }

    fflush(stdout);
    ts(t1);
    if(conn_type == etcp) {
	if((c_pid = fork()) != 0) {
	    close(result_sock);
	    goto new_client_for_app;
	}
	else
	    vm->pid = getpid();
    }
    else
	vm->pid = getpid();

    {
	time_t t;
	srand((unsigned) time(&t));
    }
    vm->rand_num = rand();
    vm->metadata->num_nodes = app.num_nodes;

    memcpy(vm->metadata->dag, app.dag, sizeof(app.dag));
    memset(vm->metadata->current, NULL_FUNC, sizeof(vm->metadata->current));
    vm->metadata->start_func = 0;

    vm->shared_mem =						\
	(uint8_t *)mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, \
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(vm->shared_mem == MAP_FAILED)
	fatal("shared mapping failed\n");

    vm->shared_ro =						\
	(uint8_t *)mmap(NULL, SHARED_RO_SIZE, PROT_READ | PROT_WRITE,	\
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(vm->shared_ro == MAP_FAILED)
	fatal("shared ro mapping failed\n");

    for(i = 0; i < 1024; i++) {
	if(i%2 == 0)
	    vm->shared_ro[i] = 0xaa;
	if(i%2 == 1)
	    vm->shared_ro[i] = 0x55;
    }
    if(mprotect(vm->shared_ro, SHARED_RO_SIZE, PROT_READ))
	fatal("unable to update shared_ro PROT bits\n");

    vm->num_exec = 0;
    for(i = 0; i < ARR_SZ_1D(vm->exec_deps); i++) {
	if(u_exec[i].name[0] == '\0' || i > app.num_nodes)
	    break;
	// TBD where to call fin
	ATARU_LD_FUNC_PATH = u_exec[i].path;
	gen_deps(&vm->exec_deps[i], u_exec[i].name);
	inp_off = u_exec[i].inp_off;
	out_off = u_exec[i].out_off;
	if(inp_off >= SHM_SIZE
	   || out_off >= SHM_SIZE)
	    fatal("The inp(%d) or out(%d) offsets are beyond %d",
		  inp_off, out_off, SHM_SIZE);
	vm->exec_deps[i].exec[0].func_prop.inp_off = inp_off;
	vm->exec_deps[i].exec[0].func_prop.out_off = out_off;
	vm->num_exec++;
    }
}

void register_mem(struct vm *vm, void *hva, uint64_t *gpa,
		  uint64_t sz)
{
    int idx, idx_e;
    struct kvm_userspace_memory_region region = {
	.slot = vm->slot_no++,
	.flags = 0,
	.guest_phys_addr = *gpa,
	.memory_size = sz,
	.userspace_addr = (size_t) hva
    };
    if(ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
	printf("slot = %d, addr = %016lX, sz = %ld, uaddr = %016lX\n",
	       vm->slot_no-1, *gpa, sz, (uint64_t)hva);
	if(sz % PAGE_SIZE != 0)
	    printf("The page size for the exec must be 4k aligned\n");
	fatal("ioctl(KVM_SET_USER_MEMORY_REGION)\n");
    }
    //printf("%016lX -> %016lX\n", (uint64_t)*gpa, (uint64_t)hva);
    idx = *gpa / MB_2;
    *gpa += sz;
    *gpa = ROUND2PAGE(*gpa);
    idx_e = *gpa / MB_2;
    if(idx_e >= NR_GP2HV)
	fatal("Crossed physical possible size for guest\n");
    gp2hv[idx] = (uint64_t)hva;
    idx++;
    for(;idx < idx_e; idx++) {
	gp2hv[idx] = MB_2 + gp2hv[idx-1];
    }
}

void cont_map_p2(uint64_t *pt, uint64_t start_addr, int num_entries,
		 uint64_t pg_flags)
{
    int i;
    for(i = 0; i < num_entries; i++) {
	pt[i] = start_addr | pg_flags;
	start_addr + MB_2;
    }
}
// call after copying user data and kern data
void register_umem_mmap(struct vm *vm)
{
    int i, j, init_pt, fni, init_i, p3i;
    uint64_t *gp_pt; // guest physical page table
    uint64_t gp_mem, gp_shm, gp_shc, gp_shro;
    uint64_t hv_kmem, templ_boot_p3, shared_ro_page;
    struct lib_deps *dep;

    gp_mem = vm->kphy_mem_size; // end of k pages
    gp_pt = (uint64_t *)vm->kern_end;
    hv_kmem = (uint64_t)vm->kmem;
    // shared memory below kmem end page
    gp_shm = gp_mem;
    register_mem(vm, vm->shared_mem, &gp_mem, SHM_SIZE);
    // register the shared user code
    gp_shc = gp_mem;
    register_mem(vm, vm->exec_deps[0].exec[0].mm, &gp_mem,
		 vm->exec_deps[0].exec[0].mm_size);
    gp_shro = gp_mem; // shared read only data
    register_mem(vm, vm->shared_ro, &gp_mem, SHARED_RO_SIZE);
    templ_boot_p3 = hv_kmem + vm->paging + 2 * 512 * sizeof(uint64_t);
    shared_ro_page = templ_boot_p3 - 512 * sizeof(uint64_t);
    // presesent, user, big, 1 GB ro mapping
    // 4 GB area
    cont_map_p2((uint64_t *)shared_ro_page, gp_shro,
		PAGES_SHARED_RO, 0x85);
    //printf("boot_p4 = %016lX\n",templ_boot_p3+512 * sizeof(uint64_t));
    // i = 0 is the shared_user_code
    init_i = 1;
    for(i = init_i; i < vm->num_exec; i++) {
	int num_pages;
	uint64_t gp_area;
	uint64_t *p3, *p2;
	// copy first 4 entries
	// templ_boot_p3 is after apic page
	p3 = (typeof(p3))H2G(hv_kmem, gp_pt[0]);
	memcpy((void *)p3, (void *)templ_boot_p3, 4*sizeof(uint64_t));
	fni = i - init_i;
	dep = &(vm->exec_deps[i]);
	//printf("%08lX\n", *(uint64_t *)vm->mm[i]);
	vm->metadata->func_info[fni].pt_addr = \
	    (typeof(vm->metadata->func_info[i].pt_addr))gp_pt;
	//printf("pt_addr = %016lX\n", vm->metadata->func_info[fni].pt_addr);
	vm->metadata->func_info[fni].stack_load_addr =			\
	    (typeof(vm->metadata->func_info[fni].stack_load_addr))\
	    dep->exec[0].func_prop.stack_load_addr;
	vm->metadata->func_info[fni].entry_addr				\
	    = (typeof(vm->metadata->func_info[fni].entry_addr))\
	    dep->exec[0].func_prop.entry;

	vm->metadata->func_info[fni].inp_off =
	    (uint64_t)dep->exec[0].func_prop.inp_off;
	vm->metadata->func_info[fni].out_off =
	    (uint64_t)dep->exec[0].func_prop.out_off;

	for(j = 0; j < dep->num_exec; j++) {
	    gp_area = gp_mem;
	    //printf("registering %s\n", dep->exec[j].name);
	    //printf("    %016lX, %d\n", gp_mem, dep->exec[j].mm_size);
	    register_mem(vm, dep->exec[j].mm, &gp_mem,
			 dep->exec[j].mm_size);
	    gp_pt += 512;
	    p2 = (typeof(p2))H2G(hv_kmem, gp_pt[0]);
	    num_pages = SZ2PAGES(dep->exec[j].mm_size);
	    if(j == 0) { //for the main function
		p2[0] = gp_shm | 0x087;
		// TBD based on SHARED_PAGES & PAGES_SHARED_CODE
		p2[1] = gp_shc | 0x087;
		init_pt = 2;
	    }
	    else { // for its dependent libraries
		init_pt = 0;
	    }
	    p3i = dep->exec[j].p3e; // p3 entry index
	    if(p3i >= 512)
		fatal("Crossing the p3 num entires\n");
	    //printf("Mapping %s to p3i=%d\n", dep->exec[j].name, p3i);
	    p3[p3i] = (uint64_t)gp_pt | 0x07;
	    cont_map_p2(&p2[init_pt], gp_area, num_pages, 0x087);
	}
	gp_pt += 512;
    }
}

// resolve rel with sym in mm, whereas sym belongs to lib
// mapped at index p3e in p3 page table
void resolve_this(uint8_t *mm, relocs_t *rel, int mm_p3e,
		  uint64_t e_start,
		  uint8_t *mm_sym, Elf64_Sym *sym, int sym_p3e,
		  uint64_t sym_e_start)
{
    uint64_t offset, dep_lib_start;
    void *src, *dst;
    int copy_sz;
    uint64_t value, value_va;

#if 0
    if(mm_p3e == 2)// func special handling than lib
	e_start = FUNC_VA_START;
    else
	e_start = LIB_VA_START;

    if(sym_p3e == 2) {
	sym_e_start = FUNC_VA_START;
	dep_lib_start = FUNC_VA_START;
    }
    else {
	sym_e_start = LIB_VA_START;
	dep_lib_start = (uint64_t)sym_p3e * (uint64_t)GB_1;
    }
#endif
    dep_lib_start = (uint64_t)sym_p3e * (uint64_t)GB_1;
    offset = rel->offset;
    //printf("act e_start = %016lX\n", e_start);
    //printf("act sym_e_start = %016lX\n", sym_e_start);

    //printf("%s, mm_p3e = %d,dep_lib_start = %016lX\n", rel->name, mm_p3e, dep_lib_start);
    /*
      printf("0:offset = %016lX\nvalue = %016lX\ne_start=%016lX\n",
      offset, sym->st_value, e_start);
    */
    offset = rel->offset - e_start;
    value = sym->st_value - sym_e_start;
    //printf("dep_lib_start: %016lX, %d\n", dep_lib_start, sym_p3e);
    value_va = value + dep_lib_start;
/*
  printf("1:offset = %016lX\nvalue = %016lX\nvalue_va=%016lX\n",
  offset, value, value_va);
*/


    //printf("sym_p3e = %d\n", sym_p3e);
    dst = (typeof(dst))(&mm[offset]);

    // only global and default i can understand
    if((ELF64_ST_BIND(sym->st_info) == STB_GLOBAL ||
	ELF64_ST_BIND(sym->st_info) == STB_WEAK ||
	ELF64_ST_BIND(sym->st_info) == 0) &&
       (ELF64_ST_VISIBILITY(sym->st_other) == STV_DEFAULT ||
	ELF64_ST_VISIBILITY(sym->st_other) == 0)) {
	switch(ELF64_ST_TYPE(sym->st_info)) {
	case STT_FUNC:
	    switch(rel->type) {
		// SERIOUSLY THIS IS MESS, TBD
	    case 6: // R_X86_64_GLOB_DAT
		value_va += rel->addend;
		src = (typeof(src))&value_va;
		copy_sz = 8;
		//printf("R_X86_64_GLOB_DAT: value_va = %016lX\n", value_va);
		break;
	    case 7: // R_X86_64_JUMP_SLOT
		value_va += rel->addend;
		src = (typeof(src))&(value_va);
		copy_sz = 8;
		//printf("R_X86_64_JUMP_SLOT: value_va = %016lX\n", value_va);
		break;
	    default:
		fatal("Unknown rel->type %d,%s\n", rel->type, rel->name);
	    }
	    break;
	case 0:
	case STT_OBJECT:
	    switch(rel->type) {
	    case 1: // R_X86_64_64
		value_va += rel->addend;
		src = &value_va;
		copy_sz = 8;
		break;
	    case 5: // R_X86_64_COPY
		value += rel->addend;
		src = (typeof(src))&(mm_sym[value]);
		copy_sz = sym->st_size;
		//printf("R_X86_64_COPY: copy_sz = %d\n", copy_sz);
		//print_hex(&mm_sym[value], copy_sz);
		break;
	    case 6: // R_X86_64_GLOB_DAT
		value_va += rel->addend;
		src = (typeof(src))&value_va;
		copy_sz = 8;
		//printf("R_X86_64_GLOB_DAT: value_va = %016lX\n", value_va);
		break;
	    case 8: // R_X86_64_RELATIVE
		value_va = dep_lib_start + *(uint64_t *)dst;
		src = &value_va;
		copy_sz = 8;
		break;
	    default:
		fatal("Unknown rel->type %d\n", rel->type);
	    }
	    //printf("st_value = %016lX\n", value);
	    break;
	default:
	    fatal("Unkown type for sym st_info = %d",
		  ELF64_ST_TYPE(sym->st_info));
	}
    }
    else {
	fatal("Unknown bind or vis type for sym:st_info = %d st_other = %d, %016lX\n",
	      ELF64_ST_BIND(sym->st_info),
	      ELF64_ST_VISIBILITY(sym->st_other),
	      rel->offset);
    }
    // this resolves ultimately
    memcpy(dst, src, copy_sz);
}
void resolve_dynsyms(struct vm *vm)
{
    int i, j, k, idx, dep_idx, dep_p3e;
    uint64_t dep_min_addr;
    Elf64_Sym *sym;
    uint8_t *mm_sym;
    struct elf64_file *elf, *elfd;
    struct exec_info *e;
    struct lib_deps *dep;
    relocs_t rel;

    for(i = 0; i < vm->num_exec; i++) {
	dep = &(vm->exec_deps[i]);
	//printf("Resolving: %s\n", dep->exec[0].name);
	for(j = 0; j < dep->num_exec; j++) {
	    e = &(dep->exec[j]);
	    //printf("    resolving %s\n", e->name);
	    elf = &(e->elf);
	    //print_relocs(elf);
	    idx = 0;
	    while(iterate_rel(elf, &rel, &idx) != -1) {
		//printf("idx = %d, %016lX\n", idx, rel.addend);
		if(rel.type == 6) { // R_X86_64_GLOB_DAT
		    /* this type requires that, first search
		       in the parent exec, if it has the symbol
		       in the dynsym resolve with that
		       else resolve with the st_value within
		       its own dynsym. wierd. but thats how it
		       works
		    */
		    // consider main exec as dep and search for sym
		    elfd = &(dep->exec[0].elf);
		    sym = dynsym(elfd, rel.name);
		    if(sym == (typeof(sym))-1) {
			dep_p3e = e->p3e;
			sym = rel.dynsym; // resolve with itself
			mm_sym = e->mm;
		    }
		    else {
			dep_p3e = 2;
			mm_sym = dep->exec[0].mm;
		    }
		    //printf("resolve_glob\n");
		    resolve_this(e->mm, &rel, e->p3e,
				 e->func_prop.min_addr,
				 mm_sym, sym, dep_p3e,
				 e->func_prop.min_addr);
		    continue; // check next rel
		}
		// TBD perhaps R_X86_64_64 too should be here
#if 1
		if(rel.type == 8) { // R_X86_64_RELATIVE
		    dep_p3e = e->p3e;
		    sym = rel.dynsym; // resolve with itself
		    mm_sym = e->mm;
		    resolve_this(e->mm, &rel, e->p3e,
				 e->func_prop.min_addr,
				 mm_sym, sym, dep_p3e,
				 e->func_prop.min_addr);
		    continue;
		}
#endif
		for(k = -1; k < e->num_dep; k++) {
		    if(k == -1) { // check myself first
			elfd = elf;
			mm_sym = e->mm;
			dep_min_addr = e->func_prop.min_addr;
			dep_p3e = e->p3e;
		    }
		    else {
			dep_idx = e->dep_list[k];
			elfd = &(dep->exec[dep_idx].elf);
			mm_sym = dep->exec[dep_idx].mm;
			dep_min_addr = dep->exec[dep_idx].func_prop.min_addr;
			dep_p3e = dep->exec[dep_idx].p3e;
		    }
		    sym = dynsym(elfd, rel.name);
		    if(sym == (typeof(sym))-1)
			continue;
		    // this dep may be also referring to the rel
		    // check next dep if it has the appropriate symbol
		    if(sym->st_value == 0)
			continue;
		    //printf("resolv gen\n");
		    resolve_this(e->mm, &rel, e->p3e,
				 e->func_prop.min_addr,
				 mm_sym, sym, dep_p3e,
				 dep_min_addr);
		    goto next_sym;
		}
		fatal("symbol %s of %s not found in any dep\n", rel.name, e->name);
	    next_sym:
		continue;
	    }
	}
    }
#if 0
    //printf("%016lX\n", dynsym(&vm->exec[1].elf, "myfunc")->st_value);
    for(i = 0; i < vm->num_exec; i++) {
	//print_relocs(&(vm->exec[i].elf));
	print_needed_libs(&(vm->exec[i].elf));
	continue;
	elf = &(vm->exec[i].elf);
	if(elf->dynsyms != NULL) {
	    syms = elf->dynsyms;
	    syms_sz = elf->dynsyms_size;
	    for(j = 0; j < syms_sz; j++) {
		idx = syms[j].st_name;
		if(idx != 0) {
		    printf("%d,%d,%d: %s,%016lX,%02X-%02X, %d\n", i, j, idx, &(elf->dynstrtbl[idx]), syms[j].st_value, syms[j].st_info,syms[j].st_other, syms[j].st_shndx);
		    if((ELF64_ST_TYPE(syms[j].st_info) == STT_FUNC) &&
		       (ELF64_ST_BIND(syms[j].st_info) == STB_GLOBAL) &&
		       (ELF64_ST_VISIBILITY(syms[j].st_other) == STV_DEFAULT)) {
			printf("match\n");
		    }
		}
	    }
	}
    }
#endif
}

void* timer_event_loop(void *vvm)
{
    struct kvm_irq_level irq;
    struct vm *vm = vvm;
    uint64_t u64;

#if 0
    while(1) {
	printf("Writing to irqfd\n");
	u64 = 1;
	//write(vm->tmr_eventfd, &u64, sizeof(u64));
	sleep(1);
    }
#endif
#if 0
    sleep(5);
    printf("Inserting irq\n");
    irq.irq = 1;
    irq.level = 1;
    if(ioctl(vm->fd, KVM_IRQ_LINE, &irq))
	fatal("Unable to set irq line");
    sleep(2);
    printf("Inserting irq\n");
    irq.irq = 1;
    irq.level = 0;
    if(ioctl(vm->fd, KVM_IRQ_LINE, &irq))
	fatal("Unable to set irq line");
    sleep(2);
    printf("Inserting irq\n");
    irq.irq = 1;
    irq.level = 1;
    if(ioctl(vm->fd, KVM_IRQ_LINE, &irq))
	fatal("Unable to set irq line");
#endif
    return NULL;
}

// to send interrupt from host to guest
// irqfd is a lazy sort of mechanism
void setup_irqfd(struct vm *vm, uint32_t gsi)
{
    struct kvm_irqfd irqfd;
    memset(&irqfd, 0, sizeof(irqfd));
    if((irqfd.fd = eventfd(0, 0)) == -1)
	fatal("Unable to set the eventfd\n");
    irqfd.gsi = gsi;

    if(ioctl(vm->fd, KVM_IRQFD, &irqfd))
	fatal("Unable to set the irqfd for the gsi = %d\n", gsi);

    vm->tmr_eventfd = irqfd.fd;
}

void* sock_loop(void *vvm)
{
    struct vm *vm = vvm;
    int sock;
    int buflen, sockaddr_len;
    struct sockaddr saddr;
    char *buffer;
    /*
      sock = get_sock_for_flow(code, ARR_SZ_1D(code), "br0");
      if(sock < 0)
      fatal("cannot create sock for the flow\n");
      sockaddr_len = sizeof(saddr);
      printf("sock listening on br0\n");
      buffer = vm->shared_mem;
    */
    /*
      buffer = mmap(NULL, MB_2, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    */
    /*
      while(1) {
      buflen = recvfrom(sock, buffer, MB_2, 0, &saddr,
      (socklen_t *)&sockaddr_len);
      if(buflen <= 0)
      fatal("buflen <= 0");
      //printf("buflen = %d, buf = %d\n", buflen, *(int *)buffer);
      sem_post(&sem_work_wait);
      sem_wait(&sem_work_fin);
      //sendto(sock, buffer, buflen, 0, &saddr, (socklen_t)sockaddr_len);
      }
    */
    return NULL;
}

void setup_device_loop(struct vm *vm)
{
    if(pthread_create(&vm->tid_tmr, NULL, timer_event_loop, vm))
	fatal("Count create thread for timer\n");
    if(pthread_create(&vm->tid_sock, NULL, sock_loop, vm))
	fatal("Count create thread for timer\n");
}

void print_segment(struct kvm_segment *seg)
{
    printf("Base  : 0x%llx\n", seg->base);
    printf("Limit : 0x%x\n", seg->limit);
}

void print_cpuid_output(struct kvm_cpuid2 *cpuid2)
{
    int i;
    for(i = 0; i < cpuid2->nent; i++) {
	printf("----------------%03d----------------\n", i);
	printf("function    = 0x%08x\n", cpuid2->entries[i].function);
	printf("index       = 0x%08x\n", cpuid2->entries[i].index   );
	printf("flags       = 0x%08x\n", cpuid2->entries[i].flags   );
	printf("eax         = 0x%08x\n", cpuid2->entries[i].eax     );
	printf("ebx         = 0x%08x\n", cpuid2->entries[i].ebx     );
	printf("ecx         = 0x%08x\n", cpuid2->entries[i].ecx     );
	printf("edx         = 0x%08x\n", cpuid2->entries[i].edx     );
    }
}
int print_regs(t_vcpu *vcpu)
{
    int ret, i;

    ret = ioctl(vcpu->vcpufd, KVM_GET_REGS, &vcpu->regs);
    if(ret == -1)
	fatal("cant get regs\n");
    ret = ioctl(vcpu->vcpufd, KVM_GET_SREGS, &vcpu->sregs);
    if(ret == -1)
	fatal("cant get regs\n");
    ret = ioctl(vcpu->vcpufd, KVM_GET_DEBUGREGS, &vcpu->dregs);
    if(ret == -1)
	fatal("cant get debug regs\n");
    printf("--------------------------------\n");
    printf("id     = %d\n", vcpu->id);
    printf("rip    = 0x%016llx\t", vcpu->regs.rip);
    printf("rax    = 0x%016llx\t", vcpu->regs.rax);
    printf("rbx    = 0x%016llx\n", vcpu->regs.rbx);
    printf("rcx    = 0x%016llx\t", vcpu->regs.rcx);
    printf("rdx    = 0x%016llx\t", vcpu->regs.rdx);
    printf("rsp    = 0x%016llx\n", vcpu->regs.rsp);
    printf("rbp    = 0x%016llx\t", vcpu->regs.rbp);
    printf("rdi    = 0x%016llx\t", vcpu->regs.rdi);
    printf("rsi    = 0x%016llx\n", vcpu->regs.rsi);
#define RECUR_CALL(x) printf("r[%02d]    = 0x%016llx\n", x, vcpu->regs.r ## x)
    RECUR_CALL(8);
    RECUR_CALL(9);
    RECUR_CALL(10);
    RECUR_CALL(11);
    RECUR_CALL(12);
    RECUR_CALL(13);
    RECUR_CALL(14);
    RECUR_CALL(15);


    printf("rflags = 0x%016llx\t", vcpu->regs.rflags);
    printf("efer   = 0x%016llx\t", vcpu->sregs.efer);
    printf("cr0    = 0x%016llx\n", vcpu->sregs.cr0);
    printf("cr2    = 0x%016llx\t", vcpu->sregs.cr2);
    printf("cr3    = 0x%016llx\t", vcpu->sregs.cr3);
    printf("cr4    = 0x%016llx\n", vcpu->sregs.cr4);
    printf("gs     = 0x%016llx\t", vcpu->sregs.gs.base);
    printf("fs     = 0x%016llx\n", vcpu->sregs.fs.base);
    for(i = 0; i < 4; i++)
	printf("db[%d]  = 0x%016llx\n", i, vcpu->dregs.db[i]);
    printf("dr6    = 0x%016llx\t", vcpu->dregs.dr6);
    printf("dr7    = 0x%016llx\t", vcpu->dregs.dr7);
    printf("flags  = 0x%016llx\n", vcpu->dregs.flags);
    print_segment(&vcpu->sregs.cs);
    printf("--------------------------------\n");
}

void print_lapic_state(struct kvm_lapic_state *lapic)
{
    int i;
    for(i = 0; i < 0x40; i++)
	printf("[%03X] = %08X\n", i << 4, *(uint32_t *)&lapic->regs[i << 4]);
}

void sigint_handler(int signum)
{
    int i;
    for(i = 0; i < vm.ncpu; i++)
    {
	print_regs(&(vm.vcpu[i]));
    }
    signal(SIGINT, SIG_DFL);
}

void install_signal_handlers()
{
    struct sigaction new_action, old_action;

    new_action.sa_handler = sigint_handler;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = 0;
    sigaction(SIGINT, NULL, &old_action);
    sigaction(SIGINT, &new_action, NULL);

}

void print_hex(uint8_t *a, int sz)
{
    int i;
    for(i = 0; i < sz; i++) {
	if(i % 8 == 0)
	    printf("%04X: ", i);
	printf("%02X ", a[i]);
	if((i+1)%8 == 0)
	    printf("\n");
    }
    if(!((i % 8) == 0))
	printf("\n");
}

void dump_self_smaps()
{
    int by;
    FILE *fp, *fpw;
    char line[1024];
    fp = fopen("/proc/self/smaps", "r");
    if(fp == NULL)
	fatal("cant open smaps\n");

    fpw = fopen(smap_file_name, "w");
    if(fpw == NULL)
	fatal("cant write smap dump\n");

    while((by = fread(line, 1, sizeof(line), fp)) > 0) {
	fwrite(line, 1, by, fpw);
    }
    fclose(fp);
    fclose(fpw);

}

int connect_to(int sockfd, char ip[], int port)
{
    struct sockaddr_in servaddr;
    int itrue, ret = 0;
    itrue = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
               &itrue, sizeof(int));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ip);
    servaddr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *)&servaddr,
                sizeof(servaddr)) != 0) {
	//fatal("connfd failed\n");
	ret = -1;
    }

    return ret;
}

void fin_sock(int sock)
{
    char done[8];
    shutdown(sock, SHUT_WR);
    while(read(sock, done, 1) > 0);
    close(sock);
}
int getinp_raw(t_vcpu *vcpu) {
    struct iovec iovec[2];
    struct msghdr msg;
    uint64_t addr = (uint64_t)*(vcpu->shared_mem);
    ((struct t_shm *)addr)->next = NULL;
    int buflen;
    buflen = MB_1 - sizeof(struct t_shm);
    iovec[0].iov_base =				   \
	(typeof(iovec[0].iov_base))(addr +				\
				    sizeof(struct t_shm));

    iovec[0].iov_len = buflen;
    msg.msg_name = vcpu->saddr_f;
    msg.msg_namelen = (socklen_t )*(vcpu->sockaddr_f_len);
    msg.msg_iov = iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    buflen = recvmsg(*(vcpu->sock_f), &msg, 0);
    if(buflen <= 0)
	fatal("recvmsg returns error: %d\n", buflen);

    return 0;
}

int getinp_tcp(t_vcpu *vcpu, int len) {
    int tot, n;
    uint8_t *tcpbuf;
    uint64_t addr = (uint64_t)*(vcpu->shared_mem);
    //((struct t_shm *)addr)->next = NULL;
    // big packet, read till you get everything!
    tcpbuf = (typeof(tcpbuf))(addr);
    tot = 0;
    while((n = read(*(vcpu->sock_f), &tcpbuf[tot], len - tot)) >= 0) {
	tot += n;
	if(tot >= len)
	    break;
    }

    return 0;
}

int read_file(char b[], int bs, const char fname[]) {
    int i, rd, n;
    FILE *fp;
    if((fp = fopen(fname, "r")) == NULL)
	fatal("cannot open %s\n", fname);

    i = n = 0;
    do {
	rd = bs - i;
	i += n;
    }
    while((rd > 0) && ((n = fread(&b[i], 1, rd, fp)) > 0));
    if(b[i-1] == '\n')
	b[i-1] = '\0';
    fclose(fp);
    return i;
}

t_pstat t_pstat_constructor()
{
    t_pstat s;
    s.cur = 0;
    s.n = 0;
    s.max = 0;
    s.min = INFINITY;
    s.Ex1 = 0;
    s.Ex2 = 0;
    s.Ex3 = 0;
    s.Ex4 = 0;
    s.std = 0;
    s.skw = 0;
    s.kurt = 0;
    s.update_stat = t_pstat_update_stat;

    return s;
}
void t_pstat_update_stat(t_pstat *stat, double cur)
{
    double cur2, cur3, cur4;
    double np1, np1_2, s1, s2, s3, s4;
    double sig2, sig3, sig4, nEx1, nEx2, nEx3, nEx4;
    double nEx1_2, nEx1_3, nEx1_4;
    cur2 = cur*cur;
    cur3 = cur2*cur;
    cur4 = cur3*cur;
    np1 = stat->n + 1;
    np1_2 = np1*np1;
    stat->cur = cur;
    stat->max = max(stat->max, stat->cur);
    stat->min = min(stat->min, stat->cur);
#define Ex(n) (stat->Ex ## n)

    Ex(1) = Ex(1) - Ex(1)/np1 + cur/np1;
    Ex(2) = Ex(2) - Ex(2)/np1 + cur2/np1;
    Ex(3) = Ex(3) - Ex(3)/np1 + cur3/np1;
    Ex(4) = Ex(4) - Ex(4)/np1 + cur4/np1;

    sig2 = Ex(2) - Ex(1);
    stat->std = sqrt(sig2);
#define sig (stat->std)
    sig3 = sig2 * stat->std;
    sig4 = sig2 * sig2;

    nEx1 = Ex(1) / sig;
    nEx2 = Ex(2) / sig2;
    nEx3 = Ex(3) / sig3;
    nEx4 = Ex(4) / sig4;
    nEx1_2 = nEx1 * nEx1;
    nEx1_3 = nEx1_2 * nEx1;
    nEx1_4 = nEx1_2 * nEx1_2;
    stat->skw = nEx3 - 3.0*nEx1 - nEx1_3;
    stat->kurt = nEx4 - 4.0*nEx1*nEx3 +
	6.0*nEx1_2 + 3.0*nEx1_4;
    stat->n = np1;

#undef Ex
#undef sig
}
/*
  dag repr:
  num_nodes
  in_vertex_count_per_node
  start_of_out_vertex_idxes

  1
  /   \
  0     3
  \   /
  2

  output repr:
  4  // num_nodes
  0  // 0 in count dag[] starts here
  1  // 1 in count
  1  // 2 in count
  2  // 3 in count
  0  // 0 start_idx
  2  // 1 start_idx
  3  // 2 start_idx
  4  // 3 start_idx  (no out edge so same idxes)
  4  // 3 end_idx
  1  // out_edge 0
  2
  3  // out_edge 1
  3  // out_edge 2
*/

/*
  1
  /   \
  0     3
  \   /
  2
*/
