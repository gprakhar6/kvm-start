#ifndef __GLOBVAR_H__
#define __GLOBVAR_H__

#define KB_1 (1024)
#define KB_2 (2 * 1024)
#define KB_4 (4 * 1024)
#define MB_1 (1024 * KB_1)
#define MB_2 (2 * MB_1)
#define MB_512 (512 * MB_1)
#define GB_1 (1024 * MB_1)

#define MAX_GUEST_PHYSICAL_SIZE_MB       (1024)
#define NR_GP2HV                         (MAX_GUEST_PHYSICAL_SIZE_MB+1)/2
#define MAX_VCPUS                        (64) // because uint64_t
#define MAX_DEPS                         (16)
#define SERVER_PORT                      (9988)
#define MAX_LISTEN                       (4)
#define MAX_NAME_LEN                     (1023)
#define STR_MAPPED                       ("_mapped")
#define STR_PROP                         ("_prop")
#define NULL_FUNC                        (255)
#define SHARED_PAGES                     (1)
#define PAGES_SHARED_CODE                (1)
#define FUNC_VA_START                    (0x80000000 + \
					  (SHARED_PAGES+PAGES_SHARED_CODE)*MB_2) 
#define LIB_VA_START                     (0x80000000)

#define  PORT_SYSCALL                    (0xfe)  // 0xff
#define	 PORT_SERIAL			 (0x3f8)
#define	 PORT_WAIT_USER_CODE_MAPPING	 (0x3f9)
#define	 PORT_HLT			 (0x3fa)
#define	 PORT_PRINT_REGS		 (0x3fb)
#define  PORT_MY_ID                      (0x3fc) // 0x3fd
#define  PORT_MSG                        (0x3fe) // 0x3ff
#endif
