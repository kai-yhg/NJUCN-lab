#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// handle arp packet
// If the dest ip address of this arp packet is not equal to the ip address of the incoming iface, drop it.
// If it is an arp request packet, send arp reply to the destination, insert the ip->mac mapping into arpcache.
// If it is an arp reply packet, insert the ip->mac mapping into arpcache.
// Tips:
// You can use functions: htons, htonl, ntohs, ntohl to convert host byte order and network byte order (16 bits use ntohs/htons, 32 bits use ntohl/htonl).
// You can use function: packet_to_ether_arp() in arp.h to get the ethernet header in a packet.
void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	// assert(0 && "TODO: function handle_arp_packet not implemented!");
	// log(DEBUG, "handle_arp_packet");
	struct ether_header *eth_hdr = (struct ether_header *)packet;
	struct ether_arp *arp_hdr = packet_to_ether_arp(packet);

	// 检查ARP数据包目标IP是否等于本接口IP（都应为主机序）
	if (ntohl(arp_hdr->arp_tpa) != iface->ip)
	{
		free(packet);
		return; // 丢弃不是发给本路由器的ARP包
	}

	if (ntohs(arp_hdr->arp_op) == ARPOP_REQUEST)
	{
		// 插入IP->MAC映射
		// log(DEBUG, "ARP request received from IP: %x\n", arp_hdr->arp_spa);
		arpcache_insert(ntohl(arp_hdr->arp_spa), arp_hdr->arp_sha);

		// 回复ARP请求
		arp_send_reply(iface, arp_hdr);
	}
	else if (ntohs(arp_hdr->arp_op) == ARPOP_REPLY)
	{
		// 插入IP->MAC映射
		// log(DEBUG, "ARP reply received from IP: %x\n", arp_hdr->arp_spa);
		arpcache_insert(ntohl(arp_hdr->arp_spa), arp_hdr->arp_sha);
	}
}

// send an arp reply packet
// Encapsulate an arp reply packet, send it out through iface_send_packet.
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	// assert(0 && "TODO: function arp_send_reply not implemented!");
	// log(DEBUG, "arp_send_reply");
	char *packet = malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_header *eth_hdr = (struct ether_header *)packet;
	struct ether_arp *arp_hdr = (struct ether_arp *)(packet + ETHER_HDR_SIZE);

	// 构造以太网头
	memcpy(eth_hdr->ether_dhost, req_hdr->arp_sha, ETH_ALEN); // 对方MAC
	memcpy(eth_hdr->ether_shost, iface->mac, ETH_ALEN);		  // 本接口MAC
	eth_hdr->ether_type = htons(ETH_P_ARP);

	// 构造ARP头
	arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
	arp_hdr->arp_pro = htons(ETH_P_IP);
	arp_hdr->arp_hln = ETH_ALEN;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(ARPOP_REPLY);

	memcpy(arp_hdr->arp_sha, iface->mac, ETH_ALEN);		  // 本接口MAC
	arp_hdr->arp_spa = htonl(iface->ip);				  // 本接口IP,question:是否需要htons
	memcpy(arp_hdr->arp_tha, req_hdr->arp_sha, ETH_ALEN); // 目标MAC（请求者）
	arp_hdr->arp_tpa = req_hdr->arp_spa;				  // 目标IP（请求者IP）
	// log(DEBUG, "ARP reply: src_ip=%x, dst_ip=%x\n", ntohl(arp_hdr->arp_spa), ntohl(arp_hdr->arp_tpa));
	iface_send_packet(iface, packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
	free(packet);
}

// send an arp request
// Encapsulate an arp request packet, send it out through iface_send_packet.
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	// assert(0 && "TODO: function arp_send_request not implemented!");
	// log(DEBUG, "arp_send_request");
	char *packet = malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_header *eth_hdr = (struct ether_header *)packet;
	struct ether_arp *arp_hdr = (struct ether_arp *)(packet + ETHER_HDR_SIZE);

	// 以太网头
	memset(eth_hdr->ether_dhost, 0xff, ETH_ALEN); // 广播地址
	memcpy(eth_hdr->ether_shost, iface->mac, ETH_ALEN);
	eth_hdr->ether_type = htons(ETH_P_ARP);

	// ARP头
	arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
	arp_hdr->arp_pro = htons(ETH_P_IP);
	arp_hdr->arp_hln = ETH_ALEN;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(ARPOP_REQUEST);

	memcpy(arp_hdr->arp_sha, iface->mac, ETH_ALEN); // 本接口MAC
	arp_hdr->arp_spa = htonl(iface->ip);			// 本接口IP
	memset(arp_hdr->arp_tha, 0x00, ETH_ALEN);		// 目标MAC未知
	arp_hdr->arp_tpa = htonl(dst_ip);				// 目标IP

	iface_send_packet(iface, packet, sizeof(struct ether_header) + sizeof(struct ether_arp));

	free(packet);
}

// send (IP) packet through arpcache lookup
// Lookup the mac address of dst_ip in arpcache.
// If it is found, fill the ethernet header and emit the packet by iface_send_packet.
// Otherwise, pending this packet into arpcache and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	// assert(0 && "TODO: function iface_send_packet_by_arp not implemented!");
	// log(DEBUG, "iface_send_packet_by_arp");
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	u8 mac[ETH_ALEN];
	if (arpcache_lookup(dst_ip, mac))
	{
		// log(DEBUG, "MAC address found in arpcache, sending packet immediately\n");
		memcpy(eh->ether_dhost, mac, ETH_ALEN);
		eh->ether_type = htons(ETH_P_IP);
		iface_send_packet(iface, packet, len);
	}
	else
	{
		// log(DEBUG, "MAC address not found, packet queued and ARP request sent\n");
		arpcache_append_packet(iface, dst_ip, packet, len);
		arp_send_request(iface, dst_ip);
	}
}
