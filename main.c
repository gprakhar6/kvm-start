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
#include "bits.h"
#include "../elf-reader/elf-reader.h"

#define fatal(s, ...) do {\
	printf("%04d: %s :",__LINE__, strerror(errno));			\
	printf(s, ##__VA_ARGS__);					\
	exit(1);							\
    } while(0)
#define ONE_PAGE (0x1000)
#define MAX_KERN_SIZE (16 * ONE_PAGE)
#define CODE_START (0x1000)
#define STACK_START (0xA000)

#define ts(x) (gettimeofday(&x, NULL))
#define dt(t2, t1) ((t2.tv_sec - t1.tv_sec)*1000000 + (t2.tv_usec - t1.tv_usec))

struct vm {
    int fd;
    int vcpufd;
    uint8_t *mem;
    unsigned int phy_mem_size;
    struct kvm_run *run;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    struct kvm_debugregs dregs;
};

const char bootfile[] = "../boot/main.bin";

struct timeval t1, t2;

int get_vm(struct vm *vm);
int get_regs_sregs(struct vm *vm);
int setup_guest_phy2_host_virt_map(struct vm *vm);
int setup_vm_long_mode(struct vm *vm);
int setup_seg_real_mode(struct vm *vm);
int setup_seg(struct vm *vm);
int setup_bootcode(struct vm *vm);
int setup_code(struct vm *vm);
int print_regs(struct vm *vm);
void print_cpuid_output(struct kvm_cpuid2 *cpuid2);
int main()
{
    int ret;
    struct vm vm;
    char c;
    static uint32_t pcnt = 0;
    
    ts(t1);
    get_vm(&vm);
    setup_guest_phy2_host_virt_map(&vm);    
    get_regs_sregs(&vm);
    setup_seg_real_mode(&vm);    
    setup_bootcode(&vm);
    //setup_vm_long_mode(&vm);
    //ts(t2);
    //printf("setuptime = %ld us\n", dt(t2,t1));
    //setup_code(&vm);
    ts(t1);
    while(1) {
	ret = ioctl(vm.vcpufd, KVM_RUN, NULL);
	if(ret == -1)
	    fatal("KVM_RUN ERROR\n");

	//printf("exit reason = %d\n", vm.run->exit_reason);
	//print_regs(&vm);	
	switch(vm.run->exit_reason) {
	case KVM_EXIT_HLT:
	    ts(t2);
	    printf("time = %ld\n", dt(t2, t1));
	    goto finish;
	    break;
	case KVM_EXIT_IO:
	    if (vm.run->io.direction == KVM_EXIT_IO_OUT &&
		vm.run->io.size == 1 && vm.run->io.port == 0x3f8 &&
		vm.run->io.count == 1) {
		c = *(((char *)vm.run) + vm.run->io.data_offset);
		printf("%02x", (unsigned char)c);
		pcnt++;
		if(pcnt%4 == 0) printf(" ");
		    
		if(pcnt%8 == 0) printf("\n");
	    }
	    else {
		print_regs(&vm);
		fatal("unhandled KVM_EXIT_IO, %X\n", vm.run->io.port);
	    }
	    break;	    
	case KVM_EXIT_SHUTDOWN:
	    fatal("KVM_EXIT_SHUTDOWN\n");
	    break;
	case KVM_EXIT_INTERNAL_ERROR:
	    fatal("KVM_EXIT_INTERNAL_ERROR\n");
	    break;
	case KVM_EXIT_FAIL_ENTRY:
	    fatal("KVM_EXIT_FAIL_ENTRY\n");
	    break;
	default:
	    break;   
	}
    }

finish:

    print_regs(&vm);
    printf("got halt?\n");
    return 0;
}

int setup_guest_phy2_host_virt_map(struct vm *vm)
{
    int err;
    err = 0;
    vm->phy_mem_size = 1024 * ONE_PAGE;
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
    int kvm, ret, mmap_size;
    int err, nent;
    struct kvm_cpuid2 *cpuid2;
    
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
    mmap_size = ret;
    if(mmap_size < sizeof(*vm->run))
	fatal("really! mmap_size < run. Why?\n");

    nent = 128;
    cpuid2 =
	(struct kvm_cpuid2 *)
	malloc(sizeof(struct kvm_cpuid2)
	       + nent * sizeof(struct kvm_cpuid_entry2));
    cpuid2->nent = nent;
    if(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, cpuid2) < 0)
	fatal("cant get cpuid");
    
    //print_cpuid_output(cpuid2);
    
    vm->vcpufd = ioctl(vm->fd, KVM_CREATE_VCPU, (unsigned long)0);
    if(vm->vcpufd == -1)
	fatal("Cannot create vcpu\n");

    if(ioctl(vm->vcpufd, KVM_SET_CPUID2, cpuid2) < 0)
	fatal("cannot set cpuid things\n");
    
    vm->run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
		  MAP_SHARED, vm->vcpufd, 0);
    if(!vm->run)
	fatal("run error\n");

    return err;
}

int get_regs_sregs(struct vm *vm)
{
    int ret;
    ret = ioctl(vm->vcpufd, KVM_GET_SREGS, &vm->sregs);
    if(ret == -1)
	fatal("Cant get sregs\n");
    
    ret = ioctl(vm->vcpufd, KVM_GET_REGS, &vm->regs);
    if(ret == -1)
	fatal("cant get regs\n");;
    return ret;
}

void setup_paging(struct vm *vm)
{
    uint64_t pml4_addr = MAX_KERN_SIZE;
    uint64_t *pml4 = (void*) (vm->mem + pml4_addr);
    
    uint64_t pdp_addr = pml4_addr + 0x1000;
    uint64_t *pdp = (void*) (vm->mem + pdp_addr);
    
    uint64_t pd_addr = pdp_addr + 0x1000;
    uint64_t *pd = (void*) (vm->mem + pd_addr);
    int ret;
    
//    ret = ioctl(vm->vcpufd, KVM_GET_SREGS, &vm->sregs);
//    if(ret == -1)
//	fatal("Cant get sregs\n");
    
    pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdp_addr;
    pdp[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
    /* kernel only, no PED64_USER */
    pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_PS;
    
    vm->sregs.cr3 = pml4_addr;
    vm->sregs.cr4 = CR4_PAE;
    vm->sregs.cr4 |= CR4_OSFXSR | CR4_OSXMMEXCPT; /* enable SSE instruction */
    vm->sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | \
	CR0_AM | CR0_PG;
    vm->sregs.efer = EFER_LME | EFER_LMA;
    vm->sregs.efer |= EFER_SCE; /* enable syscall instruction */
    if(ioctl(vm->vcpufd, KVM_SET_SREGS, &vm->sregs) < 0)
	fatal("cant set sregs\n");
    
}
int setup_seg_real_mode(struct vm *vm)
{
    int ret;
    vm->sregs.cs.base = 0;
    //vm->sregs.cs.limit = 0xffffffff;    
    vm->sregs.cs.selector = 0;
    if(ioctl(vm->vcpufd, KVM_SET_SREGS, &vm->sregs) < 0)
	fatal("cant set seg sregs");
}

int setup_seg(struct vm *vm)
{
    int ret;
    struct kvm_segment seg = {
	.base = 0,
	.limit = 0xffffffff,
	.selector = 1 << 3,
	.present = 1,
	.type = 0xb, /* Code segment */
	.dpl = 0, /* Kernel: level 0 */
	.db = 0,
	.s = 1,
	.l = 1, /* long mode */
	.g = 1
    };
//    ret = ioctl(vm->vcpufd, KVM_GET_SREGS, &vm->sregs);
//    if(ret == -1)
//	fatal("Cant get sregs\n");    
    vm->sregs.cs = seg;
    seg.type = 0x3; /* Data segment */
    seg.selector = 2 << 3;
    vm->sregs.ds = vm->sregs.es = vm->sregs.fs = \
	vm->sregs.gs = vm->sregs.ss = seg;
    if(ioctl(vm->vcpufd, KVM_SET_SREGS, &vm->sregs) < 0)
	fatal("cant set seg sregs");
}

int setup_vm_long_mode(struct vm *vm)
{
    int ret;

    setup_paging(vm);
    setup_seg(vm);
    
}

const char limit_file[] = "../elf-reader/limits.txt";
const char executable[] = "../test/main";
int setup_bootcode(struct vm *vm)
{
    int ret, i, filesz;
    FILE *fp;

    fp = fopen(bootfile, "r");
    if(fp == NULL)
	fatal("cant open %s\n", bootfile);

    fseek(fp, 0, SEEK_END);
    filesz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if(fread(&vm->mem[0x1000], filesz, 1, fp) != 1)
	fatal("cant read %s file\n", bootfile);
    {
	struct kvm_regs regs = {
	    .rip = 0x1000,
	    .rax = 2,
	    .rbx = 2,
	    .rsp = STACK_START, /* temporary stack */
	    .rbp = STACK_START,
	    .rdi = 0,
	    .rsi = 0,	    
	    .rflags = 0x2
	};    
	ret = ioctl(vm->vcpufd, KVM_SET_REGS, &regs);
	if(ret == -1)
	    fatal("cant set regs\n");
    }    
}

int setup_code(struct vm *vm)
{
    int ret;
    int i, sz;
    void *saddr;
    Elf64_Addr daddr;
    
    struct elf64_file elf;
    if(ret == -1)
	fatal("cant set regs\n");

    init_limits(limit_file);
    init_elf64_file(executable, &elf);

    for(i = 0; i < elf.num_regions; i++) {
	daddr = elf.prog_regions[i]->vaddr;
	saddr = elf.prog_regions[i]->addr;
	sz = elf.prog_regions[i]->filesz;
	memcpy(&vm->mem[daddr], saddr, sz);
    }
    
    {
	struct kvm_regs regs = {
	    .rip = elf.ehdr.e_entry,
	    .rax = 2,
	    .rbx = 2,
	    .rsp = STACK_START, /* temporary stack */
	    .rdi = STACK_START,
	    .rsi = 0,
	    .rflags = 0x2
	};    
	ret = ioctl(vm->vcpufd, KVM_SET_REGS, &regs);
    }
    
    fini_elf64_file(&elf);
    return 0;
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
int print_regs(struct vm *vm)
{
    int ret, i;
    
    ret = ioctl(vm->vcpufd, KVM_GET_REGS, &vm->regs);
    if(ret == -1)
	fatal("cant get regs\n");
    ret = ioctl(vm->vcpufd, KVM_GET_SREGS, &vm->sregs);
    if(ret == -1)
	fatal("cant get regs\n");
    ret = ioctl(vm->vcpufd, KVM_GET_DEBUGREGS, &vm->dregs);
    if(ret == -1)
	fatal("cant get debug regs\n");    
    printf("--------------------------------\n");
    printf("rip    = 0x%016llx\n", vm->regs.rip);
    printf("rax    = 0x%016llx\n", vm->regs.rax);
    printf("rbx    = 0x%016llx\n", vm->regs.rbx);
    printf("rcx    = 0x%016llx\n", vm->regs.rcx);
    printf("rdx    = 0x%016llx\n", vm->regs.rdx);    
    printf("rsp    = 0x%016llx\n", vm->regs.rsp);
    printf("rbp    = 0x%016llx\n", vm->regs.rbp);
    printf("rdi    = 0x%016llx\n", vm->regs.rdi);
    printf("rsi    = 0x%016llx\n", vm->regs.rsi);
#define RECUR_CALL(x) printf("r[%02d]    = 0x%016llx\n", x, vm->regs.r ## x)
    RECUR_CALL(8);
    RECUR_CALL(9);
    RECUR_CALL(10);
    RECUR_CALL(11);
    RECUR_CALL(12);
    RECUR_CALL(13);
    RECUR_CALL(14);
    RECUR_CALL(15);
	
	
    printf("rflags = 0x%016llx\n", vm->regs.rflags);
    printf("efer   = 0x%016llx\n", vm->sregs.efer);
    printf("cr0    = 0x%016llx\n", vm->sregs.cr0);
    printf("cr2    = 0x%016llx\n", vm->sregs.cr2);
    printf("cr3    = 0x%016llx\n", vm->sregs.cr3);        
    printf("cr4    = 0x%016llx\n", vm->sregs.cr4);
    for(i = 0; i < 4; i++)
	printf("db[%d]  = 0x%016llx\n", i, vm->dregs.db[i]);
    printf("dr6    = 0x%016llx\n", vm->dregs.dr6);
    printf("dr7    = 0x%016llx\n", vm->dregs.dr7);
    printf("flags  = 0x%016llx\n", vm->dregs.flags);
    print_segment(&vm->sregs.cs);
    printf("--------------------------------\n");    
}
