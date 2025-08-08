// （地址解析协议）的数据结构和相关函数接口
#ifndef __ARP_H__
#define __ARP_H__

#include "base.h"
#include "ether.h"
#include "types.h"

#define ARPHRD_ETHER 1 // 硬件地址类型，1 代表以太网（Ethernet）。

#define ARPOP_REQUEST 1 // ARP 请求操作码，表示发送一个请求来获取 IP 地址对应的 MAC 地址。
#define ARPOP_REPLY 2   // ARP 回复操作码，表示对请求进行回应，提供 MAC 地址。

struct ether_arp
{
    u16 arp_hrd;          // 硬件地址格式（Ethernet = 0x01）
    u16 arp_pro;          // 协议地址格式（IPv4 = 0x0800）
    u8 arp_hln;           // 硬件地址长度（Ethernet = 6）
    u8 arp_pln;           // 协议地址长度（IPv4 = 4）
    u16 arp_op;           // ARP 操作码（请求/应答）
    u8 arp_sha[ETH_ALEN]; // 发送方硬件地址（MAC 地址）
    u32 arp_spa;          // 发送方协议地址（IP 地址）
    u8 arp_tha[ETH_ALEN]; // 目标硬件地址（MAC 地址）
    u32 arp_tpa;          // 目标协议地址（IP 地址）
} __attribute__((packed));

// get the arp header of the packet
static inline struct ether_arp *packet_to_ether_arp(const char *packet)
{
    return (struct ether_arp *)(packet + ETHER_HDR_SIZE);
} // 该函数用于 获取 ARP 头部指针，跳过以太网帧头 ETHER_HDR_SIZE（通常为 14 字节）。

void handle_arp_packet(iface_info_t *info, char *packet, int len);                     // 处理收到的 ARP 数据包，可能是 ARP 请求 或 ARP 回复，并进行相应处理。
void arp_send_request(iface_info_t *iface, u32 dst_ip);                                // 发送 ARP 请求，用于获取 dst_ip 的 MAC 地址。
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len); // 通过 ARP 获取目标 MAC 地址 并发送数据包。

#endif
