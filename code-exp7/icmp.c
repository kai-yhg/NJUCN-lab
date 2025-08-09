// 该文件不存在问题
#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

// icmp_send_packet has two main functions:
// 1.handle icmp packets sent to the router itself (ICMP ECHO REPLY).
// 2.when an error occurs, send icmp error packets.
// Note that the structure of these two icmp packets is different, you need to malloc different sizes of memory.
// Some function and macro definitions in ip.h/icmp.h can help you.

void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	// assert(0 && "TODO: function icmp_send_packet not implemented!");
	// log(DEBUG, "icmp_send_packet");
	struct iphdr *in_ip = packet_to_ip_hdr(in_pkt);
	int icmp_len;
	char *packet;

	if (type == ICMP_ECHOREPLY)
	{
		// EchoReply 情况：拷贝整个原始的 ICMP 请求部分（从 IP payload 开始）
		icmp_len = len - ETHER_HDR_SIZE - IP_HDR_SIZE(in_ip);
		packet = (char *)malloc(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_len);
	}
	else
	{
		// 错误消息：仅拷贝原始 IP 报文头部 + 前 8 字节
		icmp_len = ICMP_HDR_SIZE + IP_HDR_SIZE(in_ip) + ICMP_COPIED_DATA_LEN;
		packet = (char *)malloc(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_len);
	} // 包的大小没问题

	// 设置以太网头部
	struct ether_header *eh = (struct ether_header *)packet;
	memset(eh, 0, ETHER_HDR_SIZE);
	eh->ether_type = htons(ETH_P_IP); // 以太网头部没问题

	// 获取目的 IP（即原包的源 IP）
	u32 dst_ip = ntohl(in_ip->saddr);

	// 最长前缀匹配，确定下一跳
	rt_entry_t *entry = longest_prefix_match(dst_ip); // 下一跳地址没问题
	if (!entry)
	{
		log(ERROR, "No route found for ICMP reply to %x\n", dst_ip);
		free(packet);
		return;
	}

	// 设置 IP 头部
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	ip_init_hdr(ip, entry->iface->ip, dst_ip, IP_BASE_HDR_SIZE + icmp_len, IPPROTO_ICMP);

	// 设置 ICMP 头部
	struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
	icmp->type = type;
	icmp->code = code;
	icmp->checksum = 0;

	if (type == ICMP_ECHOREPLY)
	{
		// 拷贝 EchoRequest 中的 Identifier 和 Sequence 字段及 Payload
		const char *in_icmp_data = (char *)IP_DATA(in_ip);
		memcpy(icmp, in_icmp_data, icmp_len);
		icmp->type = ICMP_ECHOREPLY;
		icmp->code = 0;
	}
	else
	{
		// 拷贝原始 IP 报文头和其后 8 字节
		memcpy((char *)icmp + ICMP_HDR_SIZE, in_ip, IP_HDR_SIZE(in_ip) + ICMP_COPIED_DATA_LEN);

		// Identifier 和 Sequence置为 0
		icmp->icmp_identifier = 0;
		icmp->icmp_sequence = 0;
	}

	// 计算 ICMP 校验和
	icmp->checksum = icmp_checksum(icmp, icmp_len);

	// 发送 IP 包（注意总长度：以太网头 + IP头 + ICMP体）
	ip_send_packet(packet, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_len);
}
