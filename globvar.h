#ifndef __GLOBVAR_H__
#define __GLOBVAR_H__

#define MAX_VCPUS                        (64) // because uint64_t

#define NULL_FUNC  (255)


#define	 PORT_SERIAL			 (0x3f8)
#define	 PORT_WAIT_USER_CODE_MAPPING	 (0x3f9)
#define	 PORT_HLT			 (0x3fa)
#define	 PORT_PRINT_REGS		 (0x3fb)
#define  PORT_MY_ID                      (0x3fc) // 0x3fd
#define  PORT_MSG                        (0x3fe) // 0x3ff
#endif
