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
#include <sys/mman.h>
#include <errno.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <semaphore.h>
#include <elf.h>
#include "globvar.h"
#include "bits.h"
#include "../elf-reader/elf-reader.h"

#define __IRQCHIP__

#define fatal(s, ...) do {\
	printf("%04d: %s :",__LINE__, strerror(errno));			\
	printf(s, ##__VA_ARGS__);					\
	exit(1);							\
    } while(0)
#define ONE_PAGE (0x1000)
#define GUEST_MEMORY (1024 * ONE_PAGE) // 4 mb
#define ts(x) (gettimeofday(&x, NULL))
#define dt(t2, t1) ((t2.tv_sec - t1.tv_sec)*1000000 + (t2.tv_usec - t1.tv_usec))

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
    sem_t *sem_vcpu_init;
} t_vcpu;

struct vm {
    int fd;
    int ncpu;
    t_vcpu *vcpu;
    uint64_t entry;
    uint64_t stack_start;
    struct kvm_cpuid2 *cpuid2;
    int mmap_size;
    uint8_t *mem;
    unsigned int phy_mem_size;
    pthread_t tid_tmr, tid_ucc;
    int tmr_eventfd;
};

struct timeval t1, t2;
sem_t vcpu_init_barrier, sem_vcpu_init[MAX_VCPUS];

static inline int handle_io_port(t_vcpu *vcpu);
int get_vm(struct vm *vm);
void setup_vcpus(struct vm *vm);
int setup_guest_phy2_host_virt_map(struct vm *vm);
int setup_bootcode(struct vm *vm);
int setup_usercode(struct vm *vm);
void setup_irqfd(struct vm *vm, uint32_t gsi);
void setup_device_loop(struct vm *vm);
int print_regs(t_vcpu *vm);
void print_cpuid_output(struct kvm_cpuid2 *cpuid2);
void print_lapic_state(struct kvm_lapic_state *lapic);
Elf64_Shdr* get_shdr(struct elf64_file *elf, char *name);
uint8_t report[256] = {0};
int main()
{
    int i, ret;
    struct vm vm;

    get_vm(&vm);
    setup_guest_phy2_host_virt_map(&vm);
    setup_bootcode(&vm);
    vm.ncpu = 63;
    setup_vcpus(&vm);
    //setup_irqfd(&vm, 1);
    setup_device_loop(&vm); // start device thread

    pthread_join(vm.tid_tmr, NULL);
    printf("Timer thread joined\n");
    for(i = 0; i < vm.ncpu; i++)
	pthread_join(vm.vcpu[i].tid, NULL);
    printf("All cpu thread joined\n");

    for(i = 0; i < vm.ncpu; i++)
	if(report[i] == 0) {
	    printf("%d did not report\n", i);
	}
    
    return 0;
}
void decode_msg(t_vcpu *vcpu, uint16_t msg)
{
    int i;
    switch(msg) {
    case '1': // init sent to all guest vcpu by vcpu 0
	for(i = 1; i < vcpu->pool_size; i++)
	    sem_post(&sem_vcpu_init[i]);
	break;
    default:
	fatal("Unknown msg from the guest");
	break;
    }
}

static inline int handle_io_port(t_vcpu *vcpu)
{
    char c;
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
	printf("Joined\n");
	break;
    case PORT_HLT:
	exit(-1);
	printf("Halt port IO\n");
	print_regs(vcpu);
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
		report[v] = 1;
	    }	    
	}
	break;
	
    case PORT_MSG: // 0x3fe-0x3ff
	if(vcpu->run->io.direction == KVM_EXIT_IO_OUT) {
	    if (vcpu->run->io.size == 2 && vcpu->run->io.count == 1) {
		uint16_t msg;
		msg = *(uint16_t *)(((uint8_t *)vcpu->run) + vcpu->run->io.data_offset);
		decode_msg(vcpu, msg);
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
    vm->phy_mem_size = GUEST_MEMORY;
    vm->mem = mmap(NULL, vm->phy_mem_size, PROT_READ | PROT_WRITE,
	       MAP_SHARED | MAP_ANONYMOUS, -1 , 0);

    // should check MAP_FAILED TBD
    if(!vm->mem)
	fatal("cant mmap\n");
    // set up memory mapping
    {
	struct kvm_userspace_memory_region region = {
	    .slot = 0,
	    .flags = 0,
	    .guest_phys_addr = 0,
	    .memory_size = vm->phy_mem_size,
	    .userspace_addr = (size_t) vm->mem
	};
	if(ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
	    fatal("ioctl(KVM_SET_USER_MEMORY_REGION)");
	}
    }

    return err;
}

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
    ret = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_NR_VCPUS);
    //printf("nr_vcpus = %d\n", ret);
    ret = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_MAX_VCPUS);
    //printf("max_vcpus = %d\n", ret);
    
    return err;
}

void *create_vcpu(void *vvcpu)
{
    t_vcpu *vcpu = vvcpu;
    int ret;
    struct kvm_lapic_state lapic_state;
    struct kvm_mp_state mp_state;
    
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
    while(1) {
	ret = ioctl(vcpu->vcpufd, KVM_RUN, NULL);
	if(ret == -1)
	    fatal("KVM_RUN ERROR\n");

	//printf("exit reason = %d\n", vm.run->exit_reason);
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

	vm->vcpu[i].run = mmap(NULL, vm->mmap_size, PROT_READ | PROT_WRITE,
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
	memcpy(&vm->mem[daddr], saddr, sz);
    }

    vm->entry = elf.ehdr.e_entry;
    shdr = get_shdr(&elf, ".stack");
    if(shdr == NULL)
	fatal("no stack section found for boot\n");
    vm->stack_start = shdr->sh_addr + shdr->sh_size;
    //printf("stack for boot = %016lX\n", vm->stack_start);
    //exit(1);
    fini_elf64_file(&elf);

    // tell all cpu code is ready and mapped
    for(i = 0; i < vm->ncpu; i++)
	sem_post(&vcpu_init_barrier);

    return 0;
}

int setup_usercode(struct vm *vm)
{
    int ret;
    int i, fsz, msz;
    void *saddr;
    Elf64_Addr daddr;
    const char u_object_file[] = "tmp/main.o";
    const char u_executable[] = "tmp/main.elf";
    char cmd[1024] = "bash create_executable.sh ";
    struct elf64_file elf;

    printf("Creating usercode\n");
    strncat(cmd, u_object_file, sizeof(cmd)-1);
    printf("executing cmd: %s\n",cmd);
    if(system(cmd))
	fatal("linking user code failed\n");

    init_limits(limit_file);
    init_elf64_file(u_executable, &elf);

    for(i = 0; i < elf.num_regions; i++) {
	daddr = elf.prog_regions[i]->vaddr;
	saddr = elf.prog_regions[i]->addr;
	fsz = elf.prog_regions[i]->filesz;
	msz = elf.prog_regions[i]->memsz;
	printf("%02d: %016lx %016lx %04d %04d\n", i, daddr, (uint64_t)saddr, fsz, msz);
	//memcpy(&vm->mem[daddr], saddr, sz);
    }
    printf("Completed user code creation\n");
    fini_elf64_file(&elf);
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

void setup_device_loop(struct vm *vm)
{
    if(pthread_create(&vm->tid_tmr, NULL, timer_event_loop, vm))
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

Elf64_Shdr* get_shdr(struct elf64_file *elf, char *name)
{
    int i;
    Elf64_Shdr *ret = NULL;
    
    for(i = 0; i < elf->ehdr.e_shnum; i++) {
	int idx;
	idx = elf->shdr[i].sh_name;
	if(strcmp(&(elf->shstrtbl[idx]), name) == 0) {
	    //printf("idx = %d\n", i);
	    ret = &(elf->shdr[i]);
	    break;
	}
    }

    return ret;
}
