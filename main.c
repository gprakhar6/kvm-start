#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>
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
#include "globvar.h"
#include "bits.h"
#include "../elf-reader/elf-reader.h"
#include "runtime_if.h"
#include "fn_if.h"
#include "sock_flow.h"

#define __IRQCHIP__

#define fatal(s, ...) do {				\
	printf("%04d: %s :",__LINE__, strerror(errno));	\
	printf(s, ##__VA_ARGS__);			\
	exit(1);					\
    } while(0)

#define KB_1 (1024)
#define KB_2 (2 * 1024)
#define KB_4 (4 * 1024)
#define MB_1 (1024 * KB_1)
#define MB_2 (2 * MB_1)
#define MB_512 (512 * MB_1)

#define ONE_PAGE (0x1000)
#define GUEST_MEMORY (4 * 1024 * 1024)
#define PAGE_MASK (0x1FFFFF)

#define SZ2PAGES(x) (((x) + MB_2 - 1) / MB_2)
#define ROUND2PAGE(x) (SZ2PAGES(x) * MB_2)
#define H2G(h,g) ((h) + (uint64_t)&(g))
#define ARR_SZ_1D(x) (sizeof(x)/sizeof(x[0]))
#define ts(x) (gettimeofday(&x, NULL))
#define dt(t2, t1) ((t2.tv_sec - t1.tv_sec)*1000000 + (t2.tv_usec - t1.tv_usec))
#define dtsc(y,x) ((y-x)%())
#define pdt() printf("dt = %ld us\n", dt(t2,t1));
#define pts(ts) printf("ts = %ld us\n", (ts.tv_sec*1000000 + ts.tv_usec));
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
    uint8_t **shared_mem;
    int *clifd;
    int *sock_f, *sockaddr_f_len, *buflen;
    struct sockaddr *saddr_f;
    sem_t *sem_vcpu_init;
} t_vcpu;

struct func_prop {
    uint64_t entry;
    uint64_t stack_load_addr;
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
    struct kvm_cpuid2 *cpuid2;
    int mmap_size;
    uint8_t *kmem;
    unsigned int kphy_mem_size;
    uint8_t *umem;
    unsigned int uphy_mem_size;
    pthread_t tid_tmr, tid_sock;
    int tmr_eventfd;
    uint8_t *shared_mem;
    int clifd;
    int sock_f, sockaddr_f_len;
    struct sockaddr saddr_f;
    int num_mm;
    void *mm[MAX_FUNC];
    int mm_size[MAX_FUNC];
    struct func_prop func_prop[MAX_FUNC];
    struct t_metadata *metadata;
};

int pktcnt = 0;
struct timeval t1, t2;
uint64_t tsc_t1, tsc_t2;
double tsc2ts;
sem_t vcpu_init_barrier, sem_vcpu_init[MAX_VCPUS];
sem_t sem_booted, sem_usercode_loaded, sem_work_wait, sem_work_fin;

static inline int handle_io_port(t_vcpu *vcpu);
int get_vm(struct vm *vm);
void register_kmem(struct vm *vm);
void setup_vcpus(struct vm *vm);
int setup_guest_phy2_host_virt_map(struct vm *vm);
int setup_bootcode(struct vm *vm);
int setup_bootcode_mmap(struct vm *vm);
void snapshot_vm(struct vm *vm);
int setup_usercode(struct vm *vm);
int setup_usercode_mmap(struct vm *vm);
void register_umem(struct vm *vm);
void register_umem_mmap(struct vm *vm);
void setup_irqfd(struct vm *vm, uint32_t gsi);
void setup_device_loop(struct vm *vm);
int print_regs(t_vcpu *vm);
void install_signal_handlers();
void print_cpuid_output(struct kvm_cpuid2 *cpuid2);
void print_lapic_state(struct kvm_lapic_state *lapic);
Elf64_Shdr* get_shdr(struct elf64_file *elf, char *name);

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
    int time_the_fork = 0;
    int sockfd, itrue, clifd, len;
    struct sockaddr_in servaddr, cli;
    int server_port = 9988, max_listen = 4;
    char buf[128];
    switch(argc) {
    case 0:
    case 1:
	break;
    default:
	if(strcmp(argv[1], "timeit") == 0) {
	    printf("Timing the fork to boot time\n");
	    time_the_fork = 1;
	}
	break;
    }

    if(time_the_fork == 1) {
	ts(t1);
	if(fork() != 0) {
	    wait(&ret);
	    pts(t1);
	    //ts(t2);
	    //pdt();
	    exit(-1);
	}
    }
    //setup_guest_phy2_host_virt_map(&vm); // 50 us
    //setup_bootcode(&vm); // 750 us
    setup_bootcode_mmap(&vm); // 750 us
    //setup_usercode(&vm); // 290 us
    setup_usercode_mmap(&vm); // 290 us
    
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
read_again:
    clifd = accept(sockfd, (struct sockaddr *)&cli, &len);
    len = 100;
    while(read(clifd, buf, len) <= 0);
    ts(t1);
    if(fork() != 0) {
	//close(clifd);
	//while(1);
	goto read_again;
    }
    else {
	vm.pid = getpid();
	printf("pid = %d\n", vm.pid);
	close(sockfd);
    }

    get_vm(&vm); // 500 us    
    register_kmem(&vm);
    vm.ncpu = 1;
    setup_vcpus(&vm); // 200 us    (2500 for 64 vcpus)
    //register_umem(&vm);
    register_umem_mmap(&vm);
    sem_post(&sem_usercode_loaded);    
    //snapshot_vm(&vm);
    //setup_irqfd(&vm, 1);
    setup_device_loop(&vm); // start device thread

    //pthread_join(vm.tid_tmr, NULL);
    //printf("Timer thread joined\n");

    install_signal_handlers();
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
	    printf("private_clean + private_dirty + private_hugetlb:\n");
	    system("cat /proc/self/smaps  | grep -i -E '^Private_.*:' | awk '//{s+=$2}END{print s}'");
	    printf("pss:\n");
	    system("cat /proc/self/smaps | grep -i '^pss' | awk '//{s+=$2}END{print s}'");
	    tsc_t1 = tsc();
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
	    iovec[0].iov_base = addr + sizeof(struct t_shm);
	    iovec[0].iov_len = buflen;
	    msg.msg_name = vcpu->saddr_f;
	    msg.msg_namelen = (socklen_t )*(vcpu->sockaddr_f_len);
	    msg.msg_iov = iovec;
	    msg.msg_iovlen = 1;
	    msg.msg_control = NULL;
	    msg.msg_controllen = 0;
	    msg.msg_flags = 0;
	    buflen = recvmsg(*(vcpu->sock_f), &msg, 0);

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
	    tsc_t2 = tsc();
	    tsc2ts = (double)(dt(t2, t1)) / (double)(tsc_t2 - tsc_t1);
	    pdt();
	    //printf("tsc2ts = %lf, tsc_t1 = %lu, ts_t2 = %lu, sub=%lu\n", tsc2ts, tsc_t1, tsc_t2, tsc_t2 - tsc_t1);
	    for(i = 0; i < 3; i++) {
		struct t_shm *shm = (struct t_shm *)(*(vcpu->shared_mem));
		printf("fndt[%d] = %lf\n", i, ((double)shm->fndt[i]) * tsc2ts);
	    }
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

int setup_guest_phy2_host_virt_map(struct vm *vm)
{
    int err;
    err = 0;
    vm->kphy_mem_size = GUEST_MEMORY;
    vm->kmem = mmap(NULL, vm->kphy_mem_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1 , 0);

    // should check MAP_FAILED TBD
    if(!vm->kmem)
	fatal("cant mmap\n");

    //mlock(vm->kmem, vm->kphy_mem_size);
    // TBD hopefully zero at init, cant have state machine with junk state
    vm->metadata = (struct t_metadata *)&(vm->kmem[0x0008]);

    return err;
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
    t_vcpu *vcpu = vvcpu;
    int ret;
    struct kvm_lapic_state lapic_state;
    struct kvm_mp_state mp_state;

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
		return;
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
    return;
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

const char limit_file[] = "../elf-reader/limits.txt";
const char executable[] = "../boot/bin/main";
int setup_bootcode(struct vm *vm)
{
    int ret;
    int i, sz;
    void *saddr;
    Elf64_Addr daddr;
    struct elf64_file elf;
    Elf64_Shdr* shdr;
    // to make all vcpu wait at barrier
    sem_init(&vcpu_init_barrier, 0, 0);

    init_limits(limit_file);
    init_elf64_file(executable, &elf);

    for(i = 0; i < elf.num_regions; i++) {
	daddr = elf.prog_regions[i]->vaddr;
	saddr = elf.prog_regions[i]->addr;
	sz = elf.prog_regions[i]->filesz;
	memcpy(&(vm->kmem[daddr]), saddr, sz);
	printf("vaddr = %08lX saddr = %08lX\n",(uint64_t)daddr, (uint64_t)saddr);
    }

    vm->entry = elf.ehdr->e_entry;
    shdr = get_shdr(&elf, ".stack");
    if(shdr == NULL)
	fatal("no stack section found for boot\n");
    vm->stack_start = shdr->sh_addr + shdr->sh_size;
    shdr = get_shdr(&elf, ".paging");
    vm->kern_end = shdr->sh_addr + shdr->sh_size;
    //printf("kern_end = %016lX\n", vm->kern_end);
    //printf("stack for boot = %016lX\n", vm->stack_start);
    //exit(1);
    fini_elf64_file(&elf);

    // tell all cpu code is ready and mapped
    for(i = 0; i < vm->ncpu; i++)
	sem_post(&vcpu_init_barrier);

    return 0;
}

int setup_bootcode_mmap(struct vm *vm)
{
    int fd; struct stat stat;
    const char kernel_code[1024] = "../boot/bin/main_mapped";
    const char kernel_prop[1024] = "../boot/bin/main_mapped_prop";
    FILE *fp;
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
    vm->kern_end = MB_1; // TBD putting hard limit
}

void snapshot_vm(struct vm *vm)
{
}

int setup_usercode(struct vm *vm)
{
    int ret;
    int i, j, fsz, msz;
    void *saddr;
    Elf64_Addr daddr;
    const char u_object_file[] = "tmp/main.o";
    const char u_executable[][128] = {
	"tmp/main",
	"tmp/main",
	"tmp/main",
	"tmp/main",
	"tmp/main",
    };
    char cmd[1024] = "bash create_executable.sh ";
    struct elf64_file elf;
    struct kvm_mp_state mp_state;
    uint64_t vaddr;
    uint8_t *hmem;
    uint8_t *umem, *umem_s, *smem;
    uint64_t kmem;
    uint64_t *upt;
    uint64_t ptidx, hudiff;
    Elf64_Shdr* shdr;
    //sem_wait(&sem_booted);

    // TBD proper allocation of phy memory
    vm->uphy_mem_size = MB_2 + MB_2 * ARR_SZ_1D(u_executable);
    vm->umem = mmap(NULL, vm->uphy_mem_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1 , 0);

    // should check MAP_FAILED TBD
    if(!vm->umem)
	fatal("cant mmap\n");

    //printf("slot 1 userspace now has memory\n");
    //return;
    //printf("Creating usercode\n");
    //strncat(cmd, u_object_file, sizeof(cmd)-1);
    //printf("executing cmd: %s\n",cmd);
    /*
      if(system(cmd))
      fatal("linking user code failed\n");
    */
    init_limits(limit_file);
    smem = (uint8_t *)((uint64_t)vm->kphy_mem_size);
    umem = (uint8_t *)((uint64_t)vm->kphy_mem_size + MB_2);
    vm->shared_mem = vm->umem;
    umem_s = umem;	
    hmem = (uint8_t *)((uint64_t)(vm->umem) + MB_2); // host virt addr
    kmem = vm->kern_end; // guest physical addr
    hudiff = (uint64_t)hmem - (uint64_t)umem;
    for(j = 0; j < ARR_SZ_1D(u_executable); j++) {
    // guest phy addrthis is the end of kern 2MB
	upt  = (typeof(upt))(&(vm->kmem[kmem]));
	init_elf64_file(&u_executable[j][0], &elf);
	memset(upt, 0, 512 * 8); // page table zeroing TBD, probably already zero
	upt[0] = ((uint64_t)smem & (~PAGE_MASK)) |	\
	    0x087; // big,X,X,X,X,user,writable,present
	vm->metadata->func_info[j].pt_addr = kmem;
	shdr = get_shdr(&elf, ".stack");
	vm->metadata->func_info[j].stack_load_addr = \
	    shdr->sh_addr + shdr->sh_size;
	vm->metadata->func_info[j].entry_addr = elf.ehdr->e_entry;
	for(i = 0; i < elf.num_regions; i++) {
	    vaddr = elf.prog_regions[i]->vaddr;
	    saddr = elf.prog_regions[i]->addr;
	    ptidx = (vaddr & 0x3FE00000) >> 21;
	    if(upt[ptidx] == 0) {
		//printf("umem = %016lX\n", (uint64_t)umem);
		//printf("ptidx = %ld\n", ptidx);
		upt[ptidx] = ((uint64_t)umem & (~PAGE_MASK)) |	\
		    0x087; // big,X,X,X,X,user,writable,present
		umem = (typeof(umem))((uint64_t)umem + MB_2);
		//printf("Increased umem\n");
	    }
	    daddr = (Elf64_Addr)(((upt[ptidx] & (~PAGE_MASK)) |		\
				  (vaddr & PAGE_MASK)) + hudiff);
	    /*
	      printf("ptidx = %ld, vaddr = %016lX\n",
	      ptidx, vaddr);
	    */
	    fsz = elf.prog_regions[i]->filesz;
	    msz = elf.prog_regions[i]->memsz;
	    //printf("%02d: %016lx %016lx %04d %04d\n\n", i, daddr, (uint64_t)saddr, fsz, msz);
	    memcpy((void *)daddr, saddr, fsz);
	}
	kmem += 512*8;
	if(kmem > (MB_2)) {
	    fatal("Crossed kernel 2MB for page tables");
	}
	if((uint64_t)umem - (uint64_t)umem_s > vm->uphy_mem_size) {
	    fatal("Functions need more memory than allocated\n");
	}
	fini_elf64_file(&elf);
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
    vm->metadata->num_nodes = 2;
    {
	/*
	uint16_t tmp_arr[] = {
	    0,1,1,2,1,0,2,4,5,5,5,1,2,3,4,3,
	};
	*/
	uint16_t tmp_arr[] = {
	    0,1,0,1,1,1,
	};	
	memcpy(vm->metadata->dag, tmp_arr, sizeof(tmp_arr));
    }
    /*
    vm->metadata->dag[0] = 0; // in nodes 0
    vm->metadata->dag[1] = 1; // in nodes 1
    vm->metadata->dag[2] = 1; // in nodes 2
    vm->metadata->dag[3] = 2; // in nodes 3
    vm->metadata->dag[4] = 0;
    vm->metadata->dag[5] = 2;
    vm->metadata->dag[6] = 3;
    vm->metadata->dag[7] = 4;
    vm->metadata->dag[8] = 4;
    vm->metadata->dag[9] = 1; // out 0
    vm->metadata->dag[10] = 2;
    vm->metadata->dag[11] = 3; // out 1
    vm->metadata->dag[12] = 3; // out 2
    vm->metadata->dag[13] = 0; // out 3
    */
    memset(vm->metadata->current, NULL_FUNC, sizeof(vm->metadata->current));
    vm->metadata->start_func = 0;
    //printf("Completed user code creation\n");

}

int setup_usercode_mmap(struct vm *vm)
{
    int i, j, num_pages;
    uint64_t gp_pt; // guest physical, page table start for funcs
    const char u_executable[][1024] = {
	"/home/prakhar/data/code/nfvs/firewall/main_mapped",
	"/home/prakhar/data/code/nfvs/ids/main_mapped",
	"/home/prakhar/data/code/nfvs/encrypt/main_mapped",
    };
    char u_executable_prop[ARR_SZ_1D(u_executable)][1024];
    for(i = 0; i < ARR_SZ_1D(u_executable); i++) {
	strcpy(&u_executable_prop[i][0], &u_executable[i][0]);
	strcat(&u_executable_prop[i][0], "_prop");
    }
    
    vm->shared_mem = \
	(uint8_t *)mmap(NULL, MB_2, PROT_READ | PROT_WRITE, \
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(vm->shared_mem == MAP_FAILED)
	fatal("shared mapping failed\n");
    vm->num_mm = 0;
    for(i = 0; i < ARR_SZ_1D(u_executable); i++) {
	
	int fd;
	struct stat stat;
	FILE *fp;
	fd = open(&u_executable[i][0], O_RDWR);
	if(fd == -1)
	    fatal("unable to open %s\n", &u_executable[i][0]);
	fp = fopen(&u_executable_prop[i][0], "r");
	if(fp == NULL)
	    fatal("cannot open %s\n", &u_executable_prop[i][0]);

	fread(&vm->func_prop[i], sizeof(vm->func_prop[i]), 1, fp);
	fstat(fd, &stat);
	vm->mm[i] = (uint8_t *)mmap(NULL, stat.st_size, \
				    PROT_READ | PROT_WRITE, \
				    MAP_PRIVATE,fd, 0);
	if(vm->mm[i] == MAP_FAILED)
	    fatal("mmap of %s failed\n", &u_executable[i][0]);
	close(fd);
	fclose(fp);
        vm->mm_size[i] = stat.st_size;
	vm->num_mm++;
    }
}
// call after copying user data
void register_umem(struct vm *vm)
{
    struct kvm_userspace_memory_region region = {
	.slot = vm->slot_no++,
	.flags = 0,
	.guest_phys_addr = vm->kphy_mem_size,
	.memory_size = vm->uphy_mem_size,
	.userspace_addr = (size_t) vm->umem
    };
    if(ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
	fatal("ioctl(KVM_SET_USER_MEMORY_REGION)\n");
    }
}

// call after copying user data and kern data
void register_umem_mmap(struct vm *vm)
{
    int i, j;
    uint64_t *gp_pt; // guest physical page table
    uint64_t gp_mem, gp_shm;
    uint64_t hv_kmem;
    gp_mem = vm->kphy_mem_size; // end of k pages
    gp_pt = (uint64_t *)vm->kern_end;
    hv_kmem = (uint64_t)vm->kmem;
    // shared memory below kmem end page
    {
	struct kvm_userspace_memory_region region = {
	    .slot = vm->slot_no++,
	    .flags = 0,
	    .guest_phys_addr = gp_mem,
	    .memory_size = MB_2, // shm is 2mb
	    .userspace_addr = (size_t) vm->shared_mem
	};
	//printf("registering shared mem\n");
	//printf("%d, %08llX, %08llX\n", region.slot, region.guest_phys_addr, region.userspace_addr);
	if(ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
	    fatal("ioctl(KVM_SET_USER_MEMORY_REGION)\n");
	}
	//printf("registered shared mem\n");
	gp_shm = region.guest_phys_addr;
	gp_mem += region.memory_size;
	gp_mem = ROUND2PAGE(gp_mem);
    }

    for(i = 0; i < vm->num_mm; i++) {
	int num_pages;
	uint64_t gp_area;
	{
	    struct kvm_userspace_memory_region region = {
		.slot = vm->slot_no++,
		.flags = 0,
		.guest_phys_addr = gp_mem,
		.memory_size = vm->mm_size[i],
		.userspace_addr = (size_t) vm->mm[i]
	    };
	    //printf("%d, %08llX, %08llX\n", region.slot, region.guest_phys_addr, region.userspace_addr);
	    if(ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
		fatal("ioctl(KVM_SET_USER_MEMORY_REGION)\n");
	    }
	    gp_area = region.guest_phys_addr;
	    gp_mem += region.memory_size;
	    gp_mem = ROUND2PAGE(gp_mem);
	}
	//printf("%08lX\n", *(uint64_t *)vm->mm[i]);
	vm->metadata->func_info[i].pt_addr = (typeof(vm->metadata->func_info[i].pt_addr))gp_pt;
	vm->metadata->func_info[i].stack_load_addr = \
	    (typeof(vm->metadata->func_info[i].stack_load_addr))vm->func_prop[i].stack_load_addr;
	vm->metadata->func_info[i].entry_addr \
	    = (typeof(vm->metadata->func_info[i].entry_addr))vm->func_prop[i].entry;
	
	num_pages = SZ2PAGES(vm->mm_size[i]);
	*(uint64_t *)H2G(hv_kmem, gp_pt[0]) = gp_shm | 0x087;
	for(j = 1; j <= num_pages; j++) {
	    *(uint64_t *)H2G(hv_kmem, gp_pt[j]) = gp_area | \
		0x087; // big,X,X,X,X,user,writable,present
	    //printf("func %d:num_pages=%d:pt[%d] %08lX\n", i, num_pages, j, *(uint64_t *)H2G(hv_kmem, gp_pt[j]));
	    gp_area += MB_2;

	}
	gp_pt += 512; // one page table
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
    vm->metadata->num_nodes = 3;
    {
	/*
	uint16_t tmp_arr[] = {
	    0,1,1,2,1,0,2,4,5,5,5,1,2,3,4,3,
	};
	*/
	uint16_t tmp_arr[] = {
	    0,1,1,0,1,2,2,1,2,
	};		
	memcpy(vm->metadata->dag, tmp_arr, sizeof(tmp_arr));
    }
    /*
    vm->metadata->dag[0] = 0; // in nodes 0
    vm->metadata->dag[1] = 1; // in nodes 1
    vm->metadata->dag[2] = 1; // in nodes 2
    vm->metadata->dag[3] = 2; // in nodes 3
    vm->metadata->dag[4] = 0;
    vm->metadata->dag[5] = 2;
    vm->metadata->dag[6] = 3;
    vm->metadata->dag[7] = 4;
    vm->metadata->dag[8] = 4;
    vm->metadata->dag[9] = 1; // out 0
    vm->metadata->dag[10] = 2;
    vm->metadata->dag[11] = 3; // out 1
    vm->metadata->dag[12] = 3; // out 2
    vm->metadata->dag[13] = 0; // out 3
    */
    memset(vm->metadata->current, NULL_FUNC, sizeof(vm->metadata->current));
    vm->metadata->start_func = 0;    
    //exit(-1);
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
    /*
    new_action.sa_handler = sigint_handler;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = 0;
    sigaction(SIGINT, NULL, &old_action);
    sigaction(SIGINT, &new_action, NULL);
    */
}
