#ifndef __RTABLE_H__
#define __RTABLE_H__

#include "base.h"
#include "types.h"

#include "list.h"

// structure of ip forwarding table
// note: 1, the table supports only ipv4 address;
// 		 2, addresses are stored in host byte order.
typedef struct // 一个路由表项
{
	struct list_head list;
	u32 dest;			 // destination ip address (could be network or host)
	u32 mask;			 // network mask of dest
	u32 gw;				 // ip address of next hop (will be 0 if dest is in网关ip地址
						 // the same network with iface)
	int flags;			 // flags (could be omitted here)路由标志
	char if_name[16];	 // name of the interface网络端口名称
	iface_info_t *iface; // pointer to the interface structure指向的实际网络接口的信息
} rt_entry_t;

extern struct list_head rtable;

void init_rtable();		   // 初始化路由表
void load_static_rtable(); // 加载静态路由
void clear_rtable();
void add_rt_entry(rt_entry_t *entry);
void remove_rt_entry(rt_entry_t *entry);
void print_rtable();
rt_entry_t *new_rt_entry(u32 dest, u32 mask, u32 gw, iface_info_t *iface); // 创建新的路由表项

rt_entry_t *longest_prefix_match(u32 ip);	  // 查找和ip匹配的最佳路由匹配项
u32 get_next_hop(rt_entry_t *entry, u32 dst); // 获取数据包的吓一跳地址

void load_rtable_from_kernel(); // 从操作系统内核获取当前的路由表信息

#endif
