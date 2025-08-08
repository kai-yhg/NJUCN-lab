#ifndef __ARPCACHE_H__
#define __ARPCACHE_H__
// ARP 缓存（ARP Cache）管理
#include "base.h"
#include "types.h"
#include "list.h"

#include <pthread.h>

#define MAX_ARP_SIZE 32			  // ARP 缓存最大存储 32 个 IP -> MAC 映射
#define ARP_ENTRY_TIMEOUT 15	  // ARP 表项超时时间 15 秒
#define ARP_REQUEST_MAX_RETRIES 5 // ARP 请求最多重试 5 次

// pending packet, waiting for arp reply
struct cached_pkt
{
	struct list_head list;
	char *packet; // 等待发送的数据包
	int len;	  // 数据包长度
};

// list of pending packets, with the same iface and destination ip address
struct arp_req
{
	struct list_head list;			 // 通过链表管理多个等待的 ARP 请求
	iface_info_t *iface;			 // 发送该请求的网卡
	u32 ip4;						 // 目标 IP 地址
	time_t sent;					 // 上次发送 ARP 请求的时间
	int retries;					 // 已重试次数
	struct list_head cached_packets; // 等待解析的数据包列表
};
struct arp_cache_entry // ARP 缓存表项
{
	u32 ip4;		  // IP 地址（主机字节序）
	u8 mac[ETH_ALEN]; // MAC 地址（6 字节）
	time_t added;	  // 记录 ARP 条目加入时间
	int valid;		  // 是否有效（未超时）
};

typedef struct // ARP 缓存管理
{
	struct arp_cache_entry entries[MAX_ARP_SIZE]; // ARP 缓存表
	struct list_head req_list;					  // 等待解析的 ARP 请求
	pthread_mutex_t lock;						  // 访问 ARP 缓存的互斥锁
	pthread_t thread;							  // 后台线程，定期清理超时条目
} arpcache_t;

void arpcache_init();
void arpcache_destroy();

int arpcache_lookup(u32 ip4, u8 mac[]);
void arpcache_insert(u32 ip4, u8 mac[]);
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len);
void *arpcache_sweep(void *arg);
#endif
