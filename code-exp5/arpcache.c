#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "icmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include "log.h"
static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweep thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list)
	{
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list)
		{
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// look up the IP->mac mapping, need pthread_mutex_lock/unlock
// Traverse the table to find whether there is an entry with the same IP and mac address with the given arguments.
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	// assert(0 && "TODO: function arpcache_lookup not implemented!");
	log(DEBUG, "arpcache_lookup");
	pthread_mutex_lock(&arpcache.lock);
	for (int i = 0; i < MAX_ARP_SIZE; i++)
	{
		if (arpcache.entries[i].valid && arpcache.entries[i].ip4 == ip4)
		{
			memcpy(mac, arpcache.entries[i].mac, ETH_ALEN);
			pthread_mutex_unlock(&arpcache.lock);
			return 1;
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
	return 0;
}

// insert the IP->mac mapping into arpcache, need pthread_mutex_lock/unlock
// If there is a timeout entry (attribute valid in struct) in arpcache, replace it.
// If there isn't a timeout entry in arpcache, randomly replace one.
// If there are pending packets waiting for this mapping, fill the ethernet header for each of them, and send them out.
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(用arp_req结构体封装)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	// assert(0 && "TODO: function arpcache_insert not implemented!");
	log(DEBUG, "arpcache_insert");
	pthread_mutex_lock(&arpcache.lock);
	int index = 0;
	for (; index < MAX_ARP_SIZE; index++)
	{
		if (!arpcache.entries[index].valid)
		{
			break;
		}
	}
	if (index == MAX_ARP_SIZE)
		index = rand() % MAX_ARP_SIZE;
	arpcache.entries[index].ip4 = ip4;
	arpcache.entries[index].added = time(NULL);
	arpcache.entries[index].valid = 1;
	memcpy(arpcache.entries[index].mac, mac, ETH_ALEN); // 插入映射
	// 寻找等待这个映射的待发射数据包
	struct arp_req *req, *temp;
	list_for_each_entry_safe(req, temp, &arpcache.req_list, list)
	{
		if (req->ip4 == ip4)
		{
			log(DEBUG, "found pending packets for ip %x\n", ip4);
			struct cached_pkt *cpkt, *tmp;
			list_for_each_entry_safe(cpkt, tmp, &req->cached_packets, list)
			{
				struct ether_header *eth_hdr = (struct ether_header *)cpkt->packet;
				memcpy(eth_hdr->ether_dhost, mac, ETH_ALEN); // 1？
				iface_send_packet(req->iface, cpkt->packet, cpkt->len);
				list_delete_entry(&cpkt->list);
				free(cpkt);
			}
			log(DEBUG, "delete pending packets for ip %x\n", ip4);
			list_delete_entry(&req->list);
			free(req);
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
}

// append the packet to arpcache
// Look up in the list which stores pending packets, if there is already an entry with the same IP address and iface,
// which means the corresponding arp request has been sent out, just append this packet at the tail of that entry (The entry may contain more than one packet).
// Otherwise, malloc a new entry with the given IP address and iface, append the packet, and send arp request.
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{

	// assert(0 && "TODO: function arpcache_append_packet not implemented!");
	log(DEBUG, "arpcache_append_packet");

	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req, *temp;
	struct cached_pkt *pkt = malloc(sizeof(struct cached_pkt));
	pkt->packet = packet;
	pkt->len = len;
	list_for_each_entry_safe(req, temp, &arpcache.req_list, list)
	{
		if (req->ip4 == ip4 && req->iface == iface)
		{
			list_add_tail(&pkt->list, &req->cached_packets);
			pthread_mutex_unlock(&arpcache.lock);
			return;
		}
	}
	struct arp_req *new_req = (struct arp_req *)malloc(sizeof(struct arp_req));
	new_req->iface = iface;
	new_req->ip4 = ip4;
	new_req->sent = time(NULL);
	new_req->retries = 1;
	init_list_head(&new_req->cached_packets);
	list_add_tail(&pkt->list, &new_req->cached_packets);
	list_add_tail(&new_req->list, &arpcache.req_list);
	arp_send_request(iface, ip4);
	pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
// for IP->mac entry, if the entry has been in the table for more than 15 seconds, remove it from the table
// for pending packets, if the arp request is sent out 1 second ago, while the reply has not been received, retransmit the arp request
// If the arp request has been sent 5 times without receiving arp reply, for each pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these packets
// tips
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void *arpcache_sweep(void *arg)
{
	while (1)
	{
		sleep(1);
		// assert(0 && "TODO: function arpcache_sweep not implemented!");
		time_t now = time(NULL);
		pthread_mutex_lock(&arpcache.lock);
		for (int index = 0; index < MAX_ARP_SIZE; index++)
		{

			if (arpcache.entries[index].valid && (now - arpcache.entries[index].added > 15))
				arpcache.entries[index].valid = 0;
		}
		struct arp_req *req, *temp;
		list_for_each_entry_safe(req, temp, &arpcache.req_list, list)
		{
			if (now - req->sent >= 1)
			{
				if (req->retries < ARP_REQUEST_MAX_RETRIES)
				{
					arp_send_request(req->iface, req->ip4);
					req->sent = now;
					req->retries++;
				}
				else
				{
					struct cached_pkt *pkt, *pkt_tmp;
					pthread_mutex_unlock(&arpcache.lock);
					list_for_each_entry_safe(pkt, pkt_tmp, &req->cached_packets, list)
					{
						list_delete_entry(&pkt->list);
						icmp_send_packet(pkt->packet, pkt->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
						free(pkt->packet);
						free(pkt);
					}
					list_delete_entry(&req->list);
					free(req);
					pthread_mutex_lock(&arpcache.lock);
				}
			}
		}
		pthread_mutex_unlock(&arpcache.lock);
	}
	return NULL;
}