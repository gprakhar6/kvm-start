#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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

#define __IRQCHIP__

#define fatal(s, ...) do {				\
	printf("%s.%04d: %s :",__FILE__,__LINE__, strerror(errno));	\
	printf(s, ##__VA_ARGS__);			\
	exit(1);					\
    } while(0)

#define ONE_PAGE (0x1000)

#define PAGE_MASK (0x1FFFFF)

#define SHM_SIZE (MB_2 * SHARED_PAGES)

#define SZ2PAGES(x) (((x) + MB_2 - 1) / MB_2)
#define ROUND2PAGE(x) (SZ2PAGES(x) * MB_2)
#define H2G(h,g) ((h) + (uint64_t)&(g))
#define ARR_SZ_1D(x) (sizeof(x)/sizeof(x[0]))
#define ts(x) (gettimeofday(&x, NULL))
#define dt(t2, t1) ((t2.tv_sec - t1.tv_sec)*1000000 + (t2.tv_usec - t1.tv_usec))
#define dtsc(y,x) ((y-x)%())
#define pdt() printf("dt = %ld us\n", dt(t2,t1));
#define pts(ts) printf("ts = %ld us\n", (ts.tv_sec*1000000 + ts.tv_usec));

struct t_page_table {
    uint64_t e[512];
};

struct t_pg_tbls {
    struct t_page_table tbl[2];
};

typedef struct
{
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
    char path[MAX_NAME_LEN + 1];
    char name[MAX_NAME_LEN + 1];
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
char *ATARU_LD_FUNC_PATH;
int isol_core_start = 12;
int runtime_vcpus = 1, runtime_pcpus = 1;
static char str_sys_cmd[1024];

static const char sprintf_cmd_private_page[] = "cat %s | grep -i -E '^Private_.*:' | awk '//{s+=$2}END{print s}'";
static const char sprintf_cmd_pss[] = "cat %s | grep -i '^pss' | awk '//{s+=$2}END{print s}'";

static inline int handle_io_port(t_vcpu *vcpu);
int get_vm(struct vm *vm);
void register_kmem(struct vm *vm);
void setup_vcpus(struct vm *vm);
int setup_bootcode_mmap(struct vm *vm);
void snapshot_vm(struct vm *vm);
int setup_usercode_mmap(struct vm *vm);
void resolve_dynsyms(struct vm *vm);
void register_umem_mmap(struct vm *vm);
void setup_irqfd(struct vm *vm, uint32_t gsi);
void setup_device_loop(struct vm *vm);
int print_regs(t_vcpu *vm);
void install_signal_handlers();
void print_cpuid_output(struct kvm_cpuid2 *cpuid2);
void print_lapic_state(struct kvm_lapic_state *lapic);
Elf64_Shdr* get_shdr(struct elf64_file *elf, char *name);
void print_hex(uint8_t *a, int sz);
void dump_self_smaps();

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
    int sockfd, itrue, clifd, len;
    struct sockaddr_in servaddr, cli;
    int server_port = SERVER_PORT, max_listen = MAX_LISTEN;
    char buf[128];
    
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
    }
    
    init_limits(limit_file);
    setup_bootcode_mmap(&vm); // 750 us
    setup_usercode_mmap(&vm); // 290 us
    resolve_dynsyms(&vm);    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1)
	fatal("Unable to get a socket");

    itrue = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &itrue, sizeof(int));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(server_port);
    if(bind(sockfd, (struct sockaddr *)&servaddr,
            sizeof(servaddr)) != 0) {
	fatal("Unable to bind the socket\n");
    }
    if(listen(sockfd, max_listen) != 0) {
        fatal("listen failed\n");
    }
    printf("(after funcs mmap)\nprivate_clean + private_dirty + private_hugetlb(kB):\n");
    fflush(stdout);
    dump_self_smaps();
    sprintf(str_sys_cmd, sprintf_cmd_private_page, smap_file_name);
    system(str_sys_cmd);
read_again:
    clifd = accept(sockfd, (struct sockaddr *)&cli, &len);
    len = 100;
    while(read(clifd, buf, len) <= 0);
    ts(t1);
    if(fork() != 0) {
	close(clifd);
	goto read_again;
    }
    else {
	close(sockfd);
	vm.pid = getpid();
	//printf("pid = %d\n", vm.pid);
    }
    get_vm(&vm); // 500 us    
    register_kmem(&vm);
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
    int ret = 0, len;
    int buflen;
    static double net_time = 0.0;
    switch(msg) {
    case 1: // init sent to all guest vcpu by vcpu 0
	for(i = 1; i < vcpu->pool_size; i++)
	    sem_post(&sem_vcpu_init[i]);
	break;
    case 2: // MSG_BOOTED
	//ts(t2);
	//tsc_t2 = tsc();
	//printf("boot time = %ld, tsc_time = %ld\n", dt(t2, t1), (tsc_t2 - tsc_t1) / 3400);
	sem_post(&sem_booted);
	// TBD required or not? seems not
	sem_wait(&sem_usercode_loaded);
	break;

    case 3: // MSG_WAITING_FOR_WORK
	//pts(t2);
	if(pktcnt == 0) {
	    ts(t2);
	    printf("Boot time = %lu us\n", dt(t2,t1));
	    //exit(-1);
	    printf("private_clean + private_dirty + private_hugetlb(kB):\n");
	    fflush(stdout);
	    dump_self_smaps();
	    sprintf(str_sys_cmd, sprintf_cmd_private_page, smap_file_name);
	    system(str_sys_cmd);
	    printf("pss(kB):\n");
	    fflush(stdout);
	    sprintf(str_sys_cmd, sprintf_cmd_pss, smap_file_name);
	    system(str_sys_cmd);
	    tsc_t1 = tsc();
	    //printf("ts(t1)\n");
	    ts(t1);
	}
	//printf("shm = %d\n", *(int *)*(vcpu->shared_mem));
	*(int *)*(vcpu->shared_mem) = 1;
	buflen = MB_1;
	{
	    struct iovec iovec[2];
	    struct msghdr msg;
	    uint64_t addr = (uint64_t)*(vcpu->shared_mem);
	    ((struct t_shm *)addr)->next = NULL;
	    iovec[0].iov_base = \
		(typeof(iovec[0].iov_base))(addr + \
					    sizeof(struct t_shm));
	    iovec[0].iov_len = buflen;
	    msg.msg_name = vcpu->saddr_f;
	    msg.msg_namelen = (socklen_t )*(vcpu->sockaddr_f_len);
	    msg.msg_iov = iovec;
	    msg.msg_iovlen = 1;
	    msg.msg_control = NULL;
	    msg.msg_controllen = 0;
	    msg.msg_flags = 0;

	    ts(t1_net);
	    buflen = recvmsg(*(vcpu->sock_f), &msg, 0);
	    ts(t2_net);
	    net_time += dt(t2_net, t1_net);
	    //printf("buflen = %d\n", buflen);
	    /*
	    printf("shm: ");
	    {
		int h;
		for(h = 0; h < 64; h++) {
		    printf("%02X(%d,%c) ",((unsigned char *)(iovec[0].iov_base))[h],h,((char *)(iovec[0].iov_base))[h]);
		    if((h-1) % 4 == 0)
			printf("\n");
		}
	    }
	    printf("\n");
	    */
	    
	}
	if(buflen <= 0)
	    printf("bad buflen %d\n", buflen);
	/*
	if((buflen = recvfrom(*(vcpu->sock_f), *(vcpu->shared_mem), buflen,
			      0, vcpu->saddr_f, (socklen_t *)vcpu->sockaddr_f_len)) <= 0)
	    fatal("bad buflen\n");
	*/
	//sem_post(&sem_work_fin);
	//sem_wait(&sem_work_wait);
	//exit(-1);
	//printf("Waiting for work\n");
	
	pktcnt++;
	//printf("%d: %d\n",buflen,pktcnt);
	if(pktcnt >= 1000000) {
	    ts(t2);
	    //printf("ts(t1)\n");
	    tsc_t2 = tsc();
	    tsc2ts = (double)(dt(t2, t1)) / (double)(tsc_t2 - tsc_t1);
	    pdt();
	    //printf("tsc2ts = %lf, tsc_t1 = %lu, ts_t2 = %lu, sub=%lu\n", tsc2ts, tsc_t1, tsc_t2, tsc_t2 - tsc_t1);
	    printf("avg dag_ts = %lf us, %ld\n", (*(vcpu->metadata))->dag_ts * tsc2ts, (*(vcpu->metadata))->dag_n);
	    printf("avg dag_ts = %lf us\n",
		   ((*(vcpu->metadata))->dag_ts /
		    (*(vcpu->metadata))->dag_n) * tsc2ts);
	    for(i = 0; i < 3; i++) {
		struct t_shm *shm = (struct t_shm *)(*(vcpu->shared_mem));
		printf("fndt[%d] = %lf\n", i, ((double)shm->fndt[i]) * tsc2ts);
	    }
	    printf("net_time = %lf\n", net_time);
	    exit(-1);
	}
	/*
	if(pktcnt % 1000 == 0)
	    printf("%d:smem = %08X,cnt=%d\n", vcpu->id, **(uint32_t **)vcpu->shared_mem, pktcnt);
	*/
	break;
    default:
	fatal("Unknown msg from the guest");
	break;
    }

    return ret;
}

static inline int handle_io_port(t_vcpu *vcpu)
{
    char c;
    int ret;

    switch(vcpu->run->io.port) {
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

int get_vm(struct vm *vm)
{
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

    vm->sock_f = get_sock_for_flow(code, ARR_SZ_1D(code), "br0");
    if(vm->sock_f < 0)
	fatal("cannot create sock for the flow\n");
    vm->sockaddr_f_len = sizeof(vm->saddr_f);
    printf("sock listening on br0\n");    
    
    vm->metadata->bit_map_inactive_cpus = ~0;
    vm->metadata->num_active_cpus = 0;
    vm->slot_no = 0;
    return err;
}

void register_kmem(struct vm *vm)
{
    struct kvm_userspace_memory_region region = {
	.slot = vm->slot_no++,
	.flags = 0,
	.guest_phys_addr = 0,
	.memory_size = vm->kphy_mem_size,
	.userspace_addr = (size_t) vm->kmem
    };
    if(ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
	fatal("ioctl(KVM_SET_USER_MEMORY_REGION)");
    }    
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
    core_id = isol_core_start + (vcpu->id) % runtime_pcpus;
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
    vm->kmem = mmap(NULL, stat.st_size, PROT_READ | PROT_WRITE, \
		    MAP_PRIVATE, fd, 0);
    close(fd);
    vm->kphy_mem_size = stat.st_size;
    if(vm->kmem == MAP_FAILED)
	fatal("mmap of kernel code failed\n");

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

#if 0
// not used this function
int setup_usercode_mmap(struct vm *vm)
{
    int i, j, num_pages;
    uint64_t gp_pt; // guest physical, page table start for funcs
    char buf[MAX_NAME_LEN+1];
    {
	struct executable u_exec[] = {
	    {.name = "/home/prakhar/data/code/shared_user_code/shared_user_code",
	     .type = elf_uc},
	    {.name = "/home/prakhar/data/code/nfvs/firewall/main",
	     .type = elf_uc},
	    {.name = "/home/prakhar/data/code/nfvs/ids/main",
	     .type = elf_uc},
	    {.name = "/home/prakhar/data/code/nfvs/encrypt/main",
	     .type = elf_uc},
	    {.name = ""}, // end of executables
	};
	assert(sizeof(u_exec) < sizeof(vm->exec));
	memcpy(vm->exec, u_exec, sizeof(u_exec));
    }
    vm->start_lib_idx = 1;
    vm->start_user_func_idx = 2;
    vm->shared_mem = \
	(uint8_t *)mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, \
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(vm->shared_mem == MAP_FAILED)
	fatal("shared mapping failed\n");
    vm->num_exec = 0;
    for(i = 0; i < ARR_SZ_1D(vm->exec); i++) {
	int fd;
	struct stat stat;
	FILE *fp;
	if(vm->exec[i].name[0] == '\0')
	    break;
	// TBD where to call fin
	init_elf64_file(vm->exec[i].name, &(vm->exec[i].elf));
	strncpy(buf, vm->exec[i].name, MAX_NAME_LEN);
	strncat(buf, STR_MAPPED, MAX_NAME_LEN - strnlen(buf, MAX_NAME_LEN));
	fd = open(buf, O_RDWR);
	if(fd == -1)
	    fatal("unable to open %s\n", buf);
	strncat(buf, STR_PROP, MAX_NAME_LEN - strnlen(buf, MAX_NAME_LEN));
	fp = fopen(buf, "r");
	if(fp == NULL)
	    fatal("cannot open %s\n", buf);

	fread(&vm->func_prop[i], sizeof(vm->func_prop[i]), 1, fp);
	fstat(fd, &stat);
	vm->exec[i].mm = (uint8_t *)mmap(NULL, stat.st_size,	\
				    PROT_READ | PROT_WRITE, \
				    MAP_PRIVATE,fd, 0);
	if(vm->exec[i].mm == MAP_FAILED)
	    fatal("mmap of %s failed\n", vm->exec[i].name);
	close(fd);
	fclose(fp);
	if(stat.st_size > GB_1)
	    fatal("too big of a memory image\n");
        vm->exec[i].mm_size = (uint32_t)stat.st_size;
	if((vm->exec[i].mm_size) == 0)
	    fatal("vm->exec[%d].mm_size = 0\n", i);
	vm->num_exec++;
    }
}

#endif
int setup_usercode_mmap(struct vm *vm)
{
    int i;

    /*
    struct exec_path_name u_exec[] = {
	{.path = "/home/prakhar/data/code/shared_user_code/",
	 .name = "shared_user_code"
	},
	{.path = "/home/prakhar/data/code/nfvs/firewall/",
	 .name = "main"
	},
	{.path = "/home/prakhar/data/code/nfvs/ids/",
	 .name = "main"
	},
	{.path = "/home/prakhar/data/code/nfvs/encrypt/",
	 .name = "main"
	},
	{.path = "",
	 .name = ""
	}
    };
    */
    
    struct exec_path_name u_exec[] = {
	{.path = "/home/prakhar/data/code/shared_user_code/",
	 .name = "shared_user_code"
	},
	{.path = "/home/prakhar/data/code/null_fn/",
	 .name = "main"
	},
	{.path = "/home/prakhar/data/code/null_fn/",
	 .name = "main"
	},
	{.path = "/home/prakhar/data/code/null_fn/",
	 .name = "main"
	},
	{.path = "/home/prakhar/data/code/null_fn/",
	 .name = "main"
	},
	{.path = "/home/prakhar/data/code/null_fn/",
	 .name = "main"
	},
	{.path = "/home/prakhar/data/code/null_fn/",
	 .name = "main"
	},
	{.path = "/home/prakhar/data/code/null_fn/",
	 .name = "main"
	},
	{.path = "/home/prakhar/data/code/null_fn/",
	 .name = "main"
	},
	{.path = "/home/prakhar/data/code/null_fn/",
	 .name = "main"
	},
	{.path = "/home/prakhar/data/code/null_fn/",
	 .name = "main"
	},
	{.path = "/home/prakhar/data/code/null_fn/",
	 .name = "main"
	},	
	{.path = "",
	 .name = ""
	}
    };
    
    assert(sizeof(u_exec) < sizeof(vm->exec_deps));
    vm->shared_mem =						\
	(uint8_t *)mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, \
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(vm->shared_mem == MAP_FAILED)
	fatal("shared mapping failed\n");
    vm->num_exec = 0;
    for(i = 0; i < ARR_SZ_1D(vm->exec_deps); i++) {
	if(u_exec[i].name[0] == '\0')
	    break;
	// TBD where to call fin
	ATARU_LD_FUNC_PATH = u_exec[i].path;
	gen_deps(&vm->exec_deps[i], u_exec[i].name);
	vm->num_exec++;
    }
}

void register_mem(struct vm *vm, void *hva, uint64_t *gpa,
		  uint64_t sz)
{
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
    *gpa += sz;
    *gpa = ROUND2PAGE(*gpa);
}

void cont_map_p2(uint64_t *pt, uint64_t start_addr, int num_entries)
{
    int i;
    for(i = 0; i < num_entries; i++) {
	pt[i] = start_addr | 0x087;
	start_addr + MB_2;
    }
}
// call after copying user data and kern data
void register_umem_mmap(struct vm *vm)
{
    int i, j, init_pt, fni, init_i, p3i;
    uint64_t *gp_pt; // guest physical page table
    uint64_t gp_mem, gp_shm, gp_shc;
    uint64_t hv_kmem, templ_boot_p3;
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
    // i = 0 is the shared_user_code
    init_i = 1;
    for(i = init_i; i < vm->num_exec; i++) {
	int num_pages;
	uint64_t gp_area;
	uint64_t *p3, *p2;
	// copy first 4 entries
	// templ_boot_p3 is after apic page
	templ_boot_p3 = hv_kmem + vm->paging + 512 * sizeof(uint64_t);
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
	    dep->func_prop.stack_load_addr;
	vm->metadata->func_info[fni].entry_addr				\
	    = (typeof(vm->metadata->func_info[fni].entry_addr))\
	    dep->func_prop.entry;

	for(j = 0; j < dep->num_exec; j++) {
	    gp_area = gp_mem;
	    //printf("registering %s\n", dep->exec[j].name);
	    //printf("    %016lX, %ld\n", gp_mem, dep->exec[j].mm_size);
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
	    cont_map_p2(&p2[init_pt], gp_area, num_pages);
	}
	gp_pt += 512;
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
    vm->metadata->num_nodes = 11;
    {

	/*
	uint16_t tmp_arr[] = {
	    0,1,1,0,1,2,2,1,2,
	};
	*/
	
	uint16_t tmp_arr[] = {
	    0,1,1,1,2,3,1,2,1,1,3,0,3,4,6,8,9,10,13,14,15,16,16,1,2,3,4,4,5,5,6,7,7,5,8,9,10,10,10,
	};
	
	memcpy(vm->metadata->dag, tmp_arr, sizeof(tmp_arr));
    }
    memset(vm->metadata->current, NULL_FUNC, sizeof(vm->metadata->current));
    vm->metadata->start_func = 0;
}

// resolve rel with sym in mm, whereas sym belongs to lib
// mapped at index p3e in p3 page table
void resolve_this(uint8_t *mm, relocs_t *rel, int mm_p3e,
		  uint8_t *mm_sym, Elf64_Sym *sym, int sym_p3e)
{
    uint64_t offset, dep_lib_start;
    void *src, *dst;
    int copy_sz;
    uint64_t value, e_start, sym_e_start, value_va;

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
	dep_lib_start = (uint64_t)sym_p3e * (uint64_t)0x40000000;
    }
    offset = rel->offset;

    /*
    printf("%s, mm_p3e = %d,dep_lib_start = %016lX\n", rel->name, mm_p3e, dep_lib_start);
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
    if((ELF64_ST_BIND(sym->st_info) == STB_GLOBAL) &&
       (ELF64_ST_VISIBILITY(sym->st_other) == STV_DEFAULT)) {
	switch(ELF64_ST_TYPE(sym->st_info)) {
	case STT_FUNC:
	    switch(rel->type) {
	    case 7: // R_X86_64_JUMP_SLOT
		src = (typeof(src))&(value_va);
		copy_sz = 8;
		//printf("R_X86_64_JUMP_SLOT: value_va = %016lX\n", value_va);
		break;
	    default:
		fatal("Unknown rel->type %d\n", rel->type);
	    }
	    break;
	case STT_OBJECT:
	    switch(rel->type) {
	    case 5: // R_X86_64_COPY
		src = (typeof(src))&(mm_sym[value]);
		copy_sz = sym->st_size;
		//printf("R_X86_64_COPY: copy_sz = %d\n", copy_sz);
		//print_hex(&mm_sym[value], copy_sz);
		break;
	    case 6: // R_X86_64_GLOB_DAT
		src = (typeof(src))&value_va;
		copy_sz = 8;
		//printf("R_X86_64_GLOB_DAT: value_va = %016lX\n", value_va);
		break;
	    default:
		fatal("Unknown rel->type %d\n", rel->type);
	    }
	    //printf("st_value = %016lX\n", value);
	    break;
	default:
	    fatal("Unkown type for sym");
	}
    }
    else {
	fatal("Unknown bind or vis type for sym\n");
    }
    // this resolves ultimately
    memcpy(dst, src, copy_sz);
}
void resolve_dynsyms(struct vm *vm)
{
    int i, j, k, idx, dep_idx, dep_p3e;
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
	    idx = 0;
	    while(iterate_rel(elf, &rel, &idx) != -1) {
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
		    resolve_this(e->mm, &rel, e->p3e, mm_sym,
				 sym, dep_p3e);
		    continue; // check next rel
		}
		for(k = 0; k < e->num_dep; k++) {
		    dep_idx = e->dep_list[k];
		    elfd = &(dep->exec[dep_idx].elf);
		    mm_sym = dep->exec[dep_idx].mm;
		    sym = dynsym(elfd, rel.name);
		    if(sym == (typeof(sym))-1)
			continue;
		    // this dep may be also referring to the rel
		    // check next dep if it has the appropriate symbol
		    if(sym->st_value == 0)
			continue;
		    //printf("resolv gen\n");
		    resolve_this(e->mm, &rel, e->p3e, mm_sym, sym,
				 dep->exec[dep_idx].p3e);
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
	    printf("%04X: ", 0);
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
