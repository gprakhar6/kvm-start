#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/filter.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <linux/if_ether.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/time.h>

#define fatal(fmt, ...) do{ printf("%04d fatal: ", __LINE__); \
	printf(fmt, ##__VA_ARGS__); printf("\nerr: %s", strerror(errno)); exit(0);} while(0)

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

int get_sock_for_flow(struct sock_filter code[], int code_size, char ifname[])
{
    int sock, ret;
    struct ifreq ifreq;
    struct sock_fprog bpf = {
        .len = code_size,
        .filter = code,
    };
    ret = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(sock < 0) {
	printf("%s-%d : Failure sock open\n", __FUNCTION__, __LINE__);
	goto fail_sock;
    }
    sock = ret;

    if((strlen(ifname) > 0) || (code == NULL)) {
	ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname,
			 strlen(ifname));
	if(ret < 0) {
	    printf("%s-%d : Failure setsockopt bind device\n", __FUNCTION__, __LINE__);
	    goto fail_setsockopt_bind_device;
	}
	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, ifname, strlen(ifname));
	ret = ioctl(sock, SIOCGIFFLAGS, &ifreq);
	if (ret == -1) {
	    printf("%s-%d : Failure ioctl SIOCGIFFLAGS, ifname=%s\n", __FUNCTION__, __LINE__, ifname);
	    goto ioctl_fail;
	}
	ifreq.ifr_flags |= IFF_PROMISC;
	ret = ioctl(sock, SIOCSIFFLAGS, &ifreq);
	if (ret == -1) {
	    printf("%s-%d : Failure ioctl SIOCSIFFLAGS\n", __FUNCTION__, __LINE__);
	    goto ioctl_fail;
	}	
    }

    if(code_size > 0) {
	ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf,
			 sizeof(bpf));
	if(ret < 0) {
	    printf("%s-%d : Failure setsockopt attach bpf\n", __FUNCTION__, __LINE__);    
	    goto fail_setsockopt_attach_bpf;
	}
    }    
succ:
    return sock;
fail_setsockopt_attach_bpf:
    if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "", 0) < 0)
	fatal("Unable to unbind socket now. Wierd.\n");
ioctl_fail:    
fail_setsockopt_bind_device:
    close(sock);
fail_sock:
    return ret;
}

