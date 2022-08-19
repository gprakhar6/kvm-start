#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include "bits.h"
#include "../elf-reader/elf-reader.h"

#define fatal(s, ...) do {printf("%04d: %s : %s\n",__LINE__, strerror(errno), s, ##__VA_ARGS__); \
	exit(1);} while(0)
#define ONE_PAGE (0x1000)
#define MAX_KERN_SIZE (16 * ONE_PAGE)
#define CODE_START (0x1000)
#define STACK_START (0xA000)

struct vm {
    int fd;
    int vcpufd;
    uint8_t *mem;
    unsigned int phy_mem_size;
    struct kvm_run *run;
    struct kvm_sregs sregs;
    struct kvm_regs regs;    
};

int get_vm(struct vm *vm);
int setup_guest_phy2_host_virt_map(struct vm *vm);
int setup_vm_long_mode(struct vm *vm);
int setup_code(struct vm *vm);
int print_regs(struct vm *vm);

int main()
{
    int ret;
    struct vm vm;
    
    get_vm(&vm);
    setup_guest_phy2_host_virt_map(&vm);
    setup_vm_long_mode(&vm);
    setup_code(&vm);
    while(1) {
	ret = ioctl(vm.vcpufd, KVM_RUN, NULL);
	if(ret == -1)
	    fatal("KVM_RUN ERROR\n");

	printf("exit reason = %d\n", vm.run->exit_reason);
	switch(vm.run->exit_reason) {
	case KVM_EXIT_HLT:
	    goto finish;
	    break;
	case KVM_EXIT_IO:
	    break;
	case KVM_EXIT_FAIL_ENTRY:
	    break;
	case KVM_EXIT_INTERNAL_ERROR:
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
    int err;

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

    vm->vcpufd = ioctl(vm->fd, KVM_CREATE_VCPU, (unsigned long)0);
    if(vm->vcpufd == -1)
	fatal("Cannot create vcpu\n");
    
    vm->run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
		  MAP_SHARED, vm->vcpufd, 0);
    if(!vm->run)
	fatal("run error\n");

    return err;
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
  
    ret = ioctl(vm->vcpufd, KVM_GET_SREGS, &vm->sregs);
    if(ret == -1)
	fatal("Cant get sregs\n");
    
    ret = ioctl(vm->vcpufd, KVM_GET_REGS, &vm->regs);
    if(ret == -1)
	fatal("cant get regs\n");

    setup_paging(vm);
    setup_seg(vm);
    
}

uint8_t code[] =
{
#include "code.h"
};

const char limit_file[] = "../elf-reader/limits.txt";
const char executable[] = "../test/main";

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

int print_regs(struct vm *vm)
{
    int ret;
    ret = ioctl(vm->vcpufd, KVM_GET_REGS, &vm->regs);
    if(ret == -1)
	fatal("cant get regs\n");    
    printf("rip = %llx\n", vm->regs.rip);
    printf("rax = %llx\n", vm->regs.rax);
    printf("rbx = %llx\n", vm->regs.rbx);
    printf("rsp = %llx\n", vm->regs.rsp);
    printf("rdi = %llx\n", vm->regs.rdi);
    printf("rsi = %llx\n", vm->regs.rsi);
    printf("rfl = %llx\n", vm->regs.rflags);
    
}
