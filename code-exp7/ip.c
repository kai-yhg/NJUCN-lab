#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

#include "mospf_proto.h"
#include "mospf_daemon.h"

#include "log.h"

#include <stdlib.h>
#include <assert.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);

	if (ip->ttl <= 1)
	{
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, 0);
		return;
	}

	ip->ttl -= 1;
	ip->checksum = ip_checksum(ip);

	rt_entry_t *entry = longest_prefix_match(ip_dst);
	if (!entry)
	{
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, 0);
		return;
	}

	u32 next_hop_ip = (entry->gw != 0) ? entry->gw : ip_dst;

	iface_send_packet_by_arp(entry->iface, next_hop_ip, packet, len);
	// assert(0 && "TODO: function ip_forward_packet not implemented!");
}
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);
	if (daddr == iface->ip)
	{
		if (ip->protocol == IPPROTO_ICMP)
		{
			struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
			if (icmp->type == ICMP_ECHOREQUEST)
			{
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
			}
		}
		else if (ip->protocol == IPPROTO_MOSPF)
		{
			handle_mospf_packet(iface, packet, len);
		}

		free(packet);
	}
	else if (ip->daddr == htonl(MOSPF_ALLSPFRouters))
	{
		assert(ip->protocol == IPPROTO_MOSPF);
		handle_mospf_packet(iface, packet, len);

		free(packet);
	}
	else
	{
		ip_forward_packet(daddr, packet, len);
	}
}
