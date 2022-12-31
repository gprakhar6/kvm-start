#ifndef __SOCK_FLOW_H__
#define __SOCK_FLOW_H__
#include <linux/filter.h>
int get_sock_for_flow(struct sock_filter code[], int code_size, char ifname[]);

#endif
