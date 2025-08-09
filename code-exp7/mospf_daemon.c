#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <rtable.h>
#define INT_MAX 2147483647
extern ustack_t *instance;

pthread_mutex_t mospf_lock;
typedef struct dijkstra_node
{
	u32 rid;			   // Router ID
	int cost;			   // 距离
	u32 pre;			   // 上一个节点（用于追踪路径）
	int visited;		   // 是否访问过
	struct list_head list; // 用于构建图结构或临时链表
} dijkstra_node_t;
void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list)
	{
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_database_thread(void *param);

void mospf_run()
{
	pthread_t hello, lsu, nbr, db;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_database_thread, NULL);
}
void send_mospf_hello(iface_info_t *iface)
{
	// 1. 计算总长度
	int len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;
	char *packet = malloc(len);
	memset(packet, 0, len);
	// 2. 构造以太网头部
	struct ether_header *eth = (struct ether_header *)packet;
	memset(eth->ether_dhost, 0xff, ETH_ALEN);
	memcpy(eth->ether_shost, iface->mac, ETH_ALEN);
	eth->ether_type = htons(ETH_P_IP);
	// 3. 构造 IP 头部
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	ip_init_hdr(ip, iface->ip, MOSPF_ALLSPFRouters, len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
	// 4. 构造 MOSPF 头部
	struct mospf_hdr *mospf = (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	mospf_init_hdr(mospf, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, instance->area_id);
	// 5. 构造 Hello 报文
	struct mospf_hello *hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);
	mospf_init_hello(hello, iface->mask);
	// 6. 校验和
	mospf->checksum = mospf_checksum(mospf);
	// 7. 发送数据包
	// log(DEBUG, "Send mospf hello packet from %s (IP: %x) to all SPF routers",
	// iface->name, iface->ip); // 记录发送源和目标
	iface_send_packet(iface, packet, len);
	// 8. 释放
	// free(packet);
}
void *sending_mospf_hello_thread(void *param)
{
	// fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");
	while (1)
	{
		sleep(1);
		pthread_mutex_lock(&mospf_lock);
		// log(DEBUG, "send mospf hello packet periodically.");
		iface_info_t *iface, *next;
		list_for_each_entry_safe(iface, next, &instance->iface_list, list)
		{
			iface->helloint--;
			if (iface->helloint <= 0) // 发送hello报文
			{
				//	log(DEBUG, "Interface %s helloint timeout, send Hello", iface->name); // 记录超时发送
				send_mospf_hello(iface);
				iface->helloint = MOSPF_DEFAULT_HELLOINT;
			}
		}
		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void *checking_nbr_thread(void *param)
{
	// fprintf(stdout, "TODO: neighbor list timeout operation.\n");
	while (1)
	{
		sleep(1);
		// log(DEBUG, "Checking neighbor list for timeouts.\n");
		//  创建临时链表存储要删除的邻居
		struct list_head delete_list;
		init_list_head(&delete_list);

		int updated = 0; // 标记是否发生了邻居变化

		pthread_mutex_lock(&mospf_lock);

		// 遍历所有接口
		iface_info_t *iface;
		list_for_each_entry(iface, &instance->iface_list, list)
		{
			mospf_nbr_t *nbr, *q;
			list_for_each_entry_safe(nbr, q, &iface->nbr_list, list)
			{
				if (nbr->alive <= 0)
				{
					// log(DEBUG, "Neighbor timeout: remove neighbor %x from iface %s\n", nbr->nbr_ip, iface->name);

					// 从邻居列表中移除，放入待删除列表
					list_delete_entry(&nbr->list);
					list_add_tail(&nbr->list, &delete_list);
					iface->num_nbr--;

					updated = 1; // 有邻居变动
				}
				else
				{
					nbr->alive--;
				}
			}
		}

		pthread_mutex_unlock(&mospf_lock);

		// 释放所有待删除的邻居节点
		mospf_nbr_t *nbr, *q;
		list_for_each_entry_safe(nbr, q, &delete_list, list)
		{
			list_delete_entry(&nbr->list);
			free(nbr);
		}

		// 如果邻居发生变化，更新序列号并发送LSU
		if (updated)
		{
			send_mospf_lsu();
		}
	}

	return NULL;
}

void mospf_dijkstra(struct list_head *routing_table)
{
	// log(DEBUG, "Running Dijkstra's algorithm to compute shortest paths.");

	struct list_head all_nodes;
	init_list_head(&all_nodes);

	// 1. 加入 LSDB 中的所有节点
	mospf_db_entry_t *db_entry;
	list_for_each_entry(db_entry, &mospf_db, list)
	{
		dijkstra_node_t *node = malloc(sizeof(dijkstra_node_t));
		node->rid = db_entry->rid;
		node->cost = (node->rid == instance->router_id) ? 0 : INT_MAX;
		node->pre = 0;
		node->visited = 0;
		init_list_head(&node->list);
		list_add_tail(&node->list, &all_nodes);
	}

	// 2. 加入自己（如果不在 LSDB 中）
	int self_found = 0;
	list_for_each_entry(db_entry, &mospf_db, list)
	{
		if (db_entry->rid == instance->router_id)
		{
			self_found = 1;
			break;
		}
	}
	if (!self_found)
	{
		dijkstra_node_t *self_node = malloc(sizeof(dijkstra_node_t));
		self_node->rid = instance->router_id;
		self_node->cost = 0;
		self_node->pre = 0;
		self_node->visited = 0;
		init_list_head(&self_node->list);
		list_add_tail(&self_node->list, &all_nodes);
	}
	// 打印所有邻居节点
	// log(DEBUG, "All neighbors:");
	/*
	iface_info_t *iface1;
	list_for_each_entry(iface1, &instance->iface_list, list)
	{
		mospf_nbr_t *nbr;
		list_for_each_entry(nbr, &iface1->nbr_list, list)
		{
			//log(DEBUG, "Neighbor RID: " IP_FMT ", IP: " IP_FMT ", Mask: " IP_FMT ", on iface: %s", HOST_IP_FMT_STR(nbr->nbr_id), HOST_IP_FMT_STR(nbr->nbr_ip), HOST_IP_FMT_STR(nbr->nbr_mask), iface1->name);
		}
	}*/
	// 3. 加入邻居（如果不在 LSDB 中）
	iface_info_t *iface;
	list_for_each_entry(iface, &instance->iface_list, list)
	{
		mospf_nbr_t *nbr;
		list_for_each_entry(nbr, &iface->nbr_list, list)
		{
			int exist = 0;
			dijkstra_node_t *iter;
			list_for_each_entry(iter, &all_nodes, list)
			{
				if (iter->rid == nbr->nbr_id)
				{
					// 更新 cost 和 pre 如有必要
					if (iter->cost > 1)
					{
						iter->cost = 1;
						iter->pre = instance->router_id;
					}
					exist = 1;
					break;
				}
			}
			if (!exist)
			{
				dijkstra_node_t *nbr_node = malloc(sizeof(dijkstra_node_t));
				nbr_node->rid = nbr->nbr_id;
				nbr_node->cost = 1;
				nbr_node->pre = instance->router_id;
				nbr_node->visited = 0;
				init_list_head(&nbr_node->list);
				list_add_tail(&nbr_node->list, &all_nodes);
			}
		}
	}

	// 打印所有节点
	/*
	//log(DEBUG, "All nodes:");
	dijkstra_node_t *print_node;
	list_for_each_entry(print_node, &all_nodes, list)
	{
		if (print_node->pre == -1)
			//log(DEBUG, "RID: " IP_FMT ", cost: %d, pre: -1, visited: %d", HOST_IP_FMT_STR(print_node->rid), print_node->cost, print_node->visited);
		else
			//log(DEBUG, "RID: " IP_FMT ", cost: %d, pre: " IP_FMT ", visited: %d", HOST_IP_FMT_STR(print_node->rid), print_node->cost, print_node->pre, HOST_IP_FMT_STR(print_node->visited));
	}*/

	// 4. Dijkstra 算法
	while (1)
	{
		dijkstra_node_t *u = NULL, *iter;
		int min_cost = INT_MAX;
		list_for_each_entry(iter, &all_nodes, list)
		{
			if (!iter->visited && iter->cost < min_cost)
			{
				min_cost = iter->cost;
				u = iter;
			}
		}
		if (!u)
			break;
		u->visited = 1;

		// 查找 RID 为 u 的 LSDB 条目
		mospf_db_entry_t *db = NULL;
		list_for_each_entry(db_entry, &mospf_db, list)
		{
			if (db_entry->rid == u->rid)
			{
				db = db_entry;
				break;
			}
		}
		if (!db)
			continue;

		// 遍历 LSA，更新邻居的 cost 和 pre
		for (int i = 0; i < db->nadv; i++)
		{
			u32 adj_rid = db->array[i].rid;
			dijkstra_node_t *v = NULL;
			list_for_each_entry(iter, &all_nodes, list)
			{
				if (iter->rid == adj_rid)
				{
					v = iter;
					break;
				}
			}
			if (v && !v->visited && u->cost + 1 < v->cost)
			{
				v->cost = u->cost + 1;
				v->pre = u->rid;
			}
		}
	}

	// 打印 prev 路径数组
	/*
	//log(DEBUG, "prev array:");
	list_for_each_entry(print_node, &all_nodes, list)
	{
		if (print_node->pre == 0)
			//log(DEBUG, IP_FMT " -> -1", HOST_IP_FMT_STR(print_node->rid));
		else
			//log(DEBUG, IP_FMT " -> " IP_FMT, HOST_IP_FMT_STR(print_node->rid), HOST_IP_FMT_STR(print_node->pre));
	}*/

	// 5. 生成 routing table
	// log(DEBUG, "calculated routing table entries:");
	list_for_each_entry(db_entry, &mospf_db, list)
	{
		if (db_entry->rid == instance->router_id)
			continue;
		for (int i = 0; i < db_entry->nadv; i++)
		{
			u32 dst_subnet = db_entry->array[i].network;
			u32 mask = db_entry->array[i].mask;

			// 回溯路径，找出直连的下一跳 RID
			u32 curr = db_entry->rid;
			u32 prev = 0;
			while (1)
			{
				dijkstra_node_t *print_node = NULL;
				dijkstra_node_t *node = NULL;
				list_for_each_entry(print_node, &all_nodes, list)
				{
					if (print_node->rid == curr)
					{
						node = print_node;
						break;
					}
				}
				if (!node || node->pre == instance->router_id || node->pre == -1)
				{
					prev = curr;
					break;
				}
				curr = node->pre;
			}

			// 从邻居中找到 prev 对应的 IP 和 iface
			iface_info_t *iface;
			list_for_each_entry(iface, &instance->iface_list, list)
			{
				mospf_nbr_t *nbr;
				list_for_each_entry(nbr, &iface->nbr_list, list)
				{
					if (nbr->nbr_id == prev)
					{
						int exists = 0;
						rt_entry_t *e;
						list_for_each_entry(e, routing_table, list)
						{
							if (e->dest == dst_subnet && e->mask == mask)
							{
								exists = 1;
								break;
							}
						}
						if (!exists)
						{
							rt_entry_t *entry = new_rt_entry(dst_subnet, mask, nbr->nbr_ip, iface);
							list_add_tail(&entry->list, routing_table);
						}
						goto next_entry;
					}
				}
			}
			// log(WARNING, "could not find the ip address according to neighbor router id (%x).", prev);
		next_entry:;
		}
	}

	// 6. 清理节点
	dijkstra_node_t *node, *tmp;
	list_for_each_entry_safe(node, tmp, &all_nodes, list)
	{
		list_delete_entry(&node->list);
		free(node);
	}
}

void spf_run()
{
	// pthread_mutex_lock(&mospf_lock);
	// log(DEBUG, "Running SPF algorithm to update routing table.");
	// 1. 构造Dijkstra算法的图结构
	struct list_head routing_table;
	init_list_head(&routing_table);
	read_kernel_rtable(&routing_table);
	mospf_dijkstra(&routing_table);

	// 2. 清除旧的路由表
	clear_rtable();

	// 3. 加载新的路由表
	load_rtable(&routing_table);
	print_rtable();
	// 4. 释放临时路由表中的内存
	rt_entry_t *entry, *q;
	list_for_each_entry_safe(entry, q, &routing_table, list)
	{
		list_delete_entry(&entry->list);
		free(entry);
	}

	// pthread_mutex_unlock(&mospf_lock);
}

void *checking_database_thread(void *param)
{
	// fprintf(stdout, "TODO: link state database timeout operation.\n");
	while (1)
	{
		sleep(1);
		// log(DEBUG, "Checking link state database for timeouts.");
		int changed = 0;

		pthread_mutex_lock(&mospf_lock);

		mospf_db_entry_t *entry, *q;
		list_for_each_entry_safe(entry, q, &mospf_db, list)
		{
			entry->alive--;
			if (entry->alive <= 0)
			{
				// log(DEBUG, "Database entry timeout, remove rid: %x", entry->rid);
				list_delete_entry(&entry->list);
				free(entry->array);
				free(entry);
				changed = 1;
			}
		}

		pthread_mutex_unlock(&mospf_lock);

		if (changed)
		{
			spf_run(); // 运行SPF算法更新路由表
		}
	}

	return NULL;
}

void update_nbr_list_via_hello(iface_info_t *iface, u32 rid, u32 ip, u32 mask, int helloint)
{
	// log(DEBUG, "Updating neighbor list via Hello: RID %x, IP %x, Mask %x on %s",rid, ip, mask, iface->name); // 新增：详细更新日志
	//  1. 查找是否已有该邻居（按 Router ID 匹配）
	mospf_nbr_t *nbr;
	list_for_each_entry(nbr, &iface->nbr_list, list)
	{
		if (nbr->nbr_id == rid)
		{
			// 已存在该邻居，刷新 alive 计数器
			nbr->alive = MOSPF_DATABASE_TIMEOUT;
			return;
		}
	}

	// 2. 检查子网掩码是否匹配
	if ((iface->mask != mask))
	{
		// log(DEBUG, "Mask mismatch, ignore new neighbor.");
		return;
	}

	// 3. 检查子网是否匹配（同一子网才添加为邻居）
	if ((iface->ip & iface->mask) != (ip & mask))
	{
		// log(DEBUG, "Subnet mismatch, ignore new neighbor.");
		return;
	}

	// 4. 创建新邻居节点
	mospf_nbr_t *new_nbr = malloc(sizeof(mospf_nbr_t));
	memset(new_nbr, 0, sizeof(mospf_nbr_t));
	new_nbr->nbr_id = rid;
	new_nbr->nbr_ip = ip;
	new_nbr->nbr_mask = mask;
	new_nbr->alive = MOSPF_DATABASE_TIMEOUT;
	init_list_head(&new_nbr->list);

	// 5. 添加到接口的邻居列表中
	list_add_tail(&new_nbr->list, &iface->nbr_list);
	iface->num_nbr++;

	// 6. 更新本地序列号 & 发送新的 LSU 报文
	send_mospf_lsu();
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{

	// fprintf(stdout, "TODO: handle mOSPF Hello message.\n");
	//  1. 获取 IP、mOSPF 和 Hello 报文头部
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct mospf_hdr *mospf = (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(ip));
	struct mospf_hello *hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);
	// log(DEBUG, "Handling mOSPF Hello message on interface %s from IP %x",iface->name, ntohl(ip->saddr)); // 新增：记录接收源IP
	//  2. 获取发送方的 IP 地址（即源 IP）
	u32 src_ip = ntohl(ip->saddr);

	// 3. 校验 mOSPF 检验和
	u16 original_cksum = mospf->checksum;
	mospf->checksum = 0;
	if (mospf_checksum(mospf) != original_cksum)
	{
		// log(WARN, "Invalid mOSPF Hello checksum.");
		return;
	}
	mospf->checksum = original_cksum;

	// 4. 检查子网掩码是否匹配（与本接口地址掩码比较）
	if (ntohl(hello->mask) != iface->mask)
	{
		// log(DEBUG, "Hello mask mismatch. Ignored.");
		return;
	}

	// 5. 检查 Hello 间隔是否为默认值
	if (ntohs(hello->helloint) != MOSPF_DEFAULT_HELLOINT)
	{
		// log(DEBUG, "Hello interval not default. Ignored.");
		return;
	}
	// 6.
	pthread_mutex_lock(&mospf_lock);
	update_nbr_list_via_hello(iface, ntohl(mospf->rid), ntohl(ip->saddr), ntohl(hello->mask), ntohs(hello->helloint));
	pthread_mutex_unlock(&mospf_lock);
}

char *generate_mospf_lsu(int *len)
{
	// log(DEBUG, "Generating mOSPF LSU message.");
	int lsa_num = 0;

	// 计算总 LSA 数量（每个接口至少一个：无邻居或有若干邻居）
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list)
	{
		if (iface->num_nbr == 0)
			lsa_num++;
		else
		{
			mospf_nbr_t *nbr = NULL;
			list_for_each_entry(nbr, &iface->nbr_list, list)
			{
				lsa_num++;
			}
		}
	}

	*len = MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + lsa_num * MOSPF_LSA_SIZE;
	char *buffer = malloc(*len);
	memset(buffer, 0, *len);

	// 初始化 mospf_hdr
	struct mospf_hdr *mospf = (struct mospf_hdr *)buffer;
	mospf_init_hdr(mospf, MOSPF_TYPE_LSU, *len, instance->router_id, instance->area_id);

	// 初始化 mospf_lsu
	struct mospf_lsu *lsu = (struct mospf_lsu *)(buffer + MOSPF_HDR_SIZE);

	lsu->seq = htons(instance->sequence_num); // 不在此函数内加1，由调用者控制
	// log(DEBUG, "LSU sequence number: %d", lsu->seq); // 新增：记录序列号
	lsu->ttl = MOSPF_MAX_LSU_TTL;
	lsu->nadv = htonl(lsa_num);

	// 填充 LSA 项
	struct mospf_lsa *lsa = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);
	list_for_each_entry(iface, &instance->iface_list, list)
	{
		if (iface->num_nbr == 0)
		{
			// 无邻居，填充空 LSA（只包含自己）
			lsa->network = iface->ip & iface->mask;
			lsa->mask = iface->mask;
			lsa->rid = instance->router_id;
			lsa++;
		}
		else
		{
			mospf_nbr_t *nbr = NULL;
			list_for_each_entry(nbr, &iface->nbr_list, list)
			{
				lsa->network = nbr->nbr_ip & nbr->nbr_mask;
				lsa->mask = nbr->nbr_mask;
				lsa->rid = nbr->nbr_id;
				lsa++;
			}
		}
	}

	// 校验和
	mospf->checksum = mospf_checksum(mospf);

	return buffer;
}

void send_mospf_lsu()
{
	// 生成LSU消息
	int mospf_len;
	char *mospf_msg = generate_mospf_lsu(&mospf_len);
	if (!mospf_msg)
	{
		return;
	}

	iface_info_t *iface;
	list_for_each_entry(iface, &instance->iface_list, list)
	{
		mospf_nbr_t *nbr;
		list_for_each_entry(nbr, &iface->nbr_list, list)
		{
			// 计算总包长：Ethernet + IP + MOSPF_LSU
			int pkt_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + mospf_len;
			char *packet = malloc(pkt_len);
			memset(packet, 0, pkt_len);

			// Ethernet头
			struct ether_header *eth = (struct ether_header *)packet;
			memcpy(eth->ether_shost, iface->mac, ETH_ALEN);
			memset(eth->ether_dhost, 0xff, ETH_ALEN); // 广播MAC
			eth->ether_type = htons(ETH_P_IP);

			// IP头
			struct iphdr *ip = packet_to_ip_hdr(packet);
			ip_init_hdr(ip, iface->ip, nbr->nbr_ip, pkt_len - ETHER_HDR_SIZE, IPPROTO_MOSPF);

			// 拷贝MOSPF消息内容
			memcpy(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE, mospf_msg, mospf_len);

			// 发送数据包
			// log(DEBUG, "Send LSU from %s (IP %x) to neighbor %x (IP %x),with sequence %d",iface->name, iface->ip, nbr->nbr_id, nbr->nbr_ip, instance->sequence_num); // 新增：记录转发路径
			instance->sequence_num++;
			ip_send_packet(packet, pkt_len);
		}
	}

	// 释放LSU消息缓冲区
	free(mospf_msg);
}

void *sending_mospf_lsu_thread(void *param)
{
	// fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");
	while (1)
	{
		sleep(1);
		pthread_mutex_lock(&mospf_lock);
		// log(DEBUG, "send mospf lsu packet periodically.\n");
		instance->lsuint--;
		if (instance->lsuint <= 0)
		{
			// 发送LSU报文
			send_mospf_lsu();
			// 更新序列号
			// 重置计时器
			instance->lsuint = MOSPF_DEFAULT_LSUINT;
		}
		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	// fprintf(stdout, "TODO: handle mOSPF LSU message.\n");

	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct mospf_hdr *mospf = (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(ip));
	struct mospf_lsu *lsu = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
	struct mospf_lsa *lsa_array = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);
	u32 saddr = ntohl(ip->saddr);
	// log(DEBUG, "Received LSU with %d LSAs from router %08x (IP " IP_FMT ") on %s",ntohl(lsu->nadv), ntohl(mospf->rid), HOST_IP_FMT_STR(saddr), iface->name);

	// 1. 校验检验和
	u16 checksum = mospf->checksum;
	mospf->checksum = 0;
	if (mospf_checksum(mospf) != checksum)
	{
		// log(ERROR, "LSU checksum invalid");
		return;
	}
	mospf->checksum = checksum;

	u32 rid = ntohl(mospf->rid); // 发送者 router ID
	u16 seq = ntohs(lsu->seq);	 // 序列号

	// 2. 忽略自己发的 LSU
	if (rid == instance->router_id)
		return;

	pthread_mutex_lock(&mospf_lock);

	// 3. 查找现有 LSDB 中是否已有该 router id
	mospf_db_entry_t *entry = NULL;
	list_for_each_entry(entry, &mospf_db, list)
	{
		if (entry->rid == rid)
			break;
	}

	// 4. 如果未找到 or 序列号更大，则更新数据库
	// log(DEBUG, "Processing LSU for RID %x with sequence %d", rid, seq); // 新增：记录处理信息
	if (&entry->list == &mospf_db || seq > entry->seq)
	{
		if (&entry->list == &mospf_db)
		{
			// 新建 LSDB 项
			entry = (mospf_db_entry_t *)malloc(sizeof(mospf_db_entry_t));
			memset(entry, 0, sizeof(mospf_db_entry_t));
			entry->rid = rid;
			entry->seq = seq;
			entry->nadv = ntohl(lsu->nadv);
			entry->alive = MOSPF_DATABASE_TIMEOUT;
			int size = sizeof(struct mospf_lsa) * entry->nadv;
			entry->array = malloc(size);
			memcpy(entry->array, lsa_array, size);
			// log(DEBUG, "Updated LSDB for RID %x with sequence %d", rid, seq); // 新增：记录数据库更新
			list_add_tail(&entry->list, &mospf_db);
		}
		else
		{
			// 释放旧 LSA
			if (entry->array)
				free(entry->array);
		}

		// 更新 LSDB 内容
		entry->seq = seq;
		entry->nadv = ntohl(lsu->nadv);
		entry->alive = MOSPF_DATABASE_TIMEOUT;
		int size = sizeof(struct mospf_lsa) * entry->nadv;
		entry->array = malloc(size);
		memcpy(entry->array, lsa_array, size);
		print_lsdb();
		// 路由拓扑变化，更新路由表

		spf_run();
	}

	// 5. 如果找到但不是更新（序列号不大），也刷新 alive 倒计时
	else
	{
		entry->alive = MOSPF_DATABASE_TIMEOUT;
	}

	// 6. 减少TTL，转发 LSU 给其它邻居
	lsu->ttl--;
	mospf->checksum = 0;
	mospf->checksum = mospf_checksum(mospf);

	if (lsu->ttl > 0)
	{
		iface_info_t *iface_iter;
		list_for_each_entry(iface_iter, &instance->iface_list, list)
		{
			// 不向收到该 LSU 的接口转发
			if (iface_iter == iface)
				continue;

			mospf_nbr_t *nbr;
			list_for_each_entry(nbr, &iface_iter->nbr_list, list)
			{
				char *packet_copy = malloc(len);
				memcpy(packet_copy, packet, len);

				// 修改 IP 目的地址为邻居 IP
				struct iphdr *ip_copy = packet_to_ip_hdr(packet_copy);
				ip_copy->daddr = htonl(nbr->nbr_ip);
				ip_copy->checksum = ip_checksum(ip_copy);

				// 修改 LSU TTL & 校验和
				struct mospf_hdr *mospf_copy = (struct mospf_hdr *)(packet_copy + ETHER_HDR_SIZE + IP_HDR_SIZE(ip_copy));
				struct mospf_lsu *lsu_copy = (struct mospf_lsu *)((char *)mospf_copy + MOSPF_HDR_SIZE);
				lsu_copy->ttl = lsu->ttl;
				mospf_copy->checksum = 0;
				mospf_copy->checksum = mospf_checksum(mospf_copy);

				// log(DEBUG, "Forwarding LSU (TTL %d) from %x to neighbor " IP_FMT,lsu_copy->ttl, rid, HOST_IP_FMT_STR(nbr->nbr_ip));

				ip_send_packet(packet_copy, len);
			}
		}
	}

	pthread_mutex_unlock(&mospf_lock);
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	// log(DEBUG, "handle_mospf_packet on interface %s", iface->name);
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	if (mospf->version != MOSPF_VERSION)
	{
		// log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return;
	}
	if (mospf->checksum != mospf_checksum(mospf))
	{
		// log(ERROR, "received mospf packet with incorrect checksum");
		return;
	}
	if (ntohl(mospf->aid) != instance->area_id)
	{
		// log(ERROR, "received mospf packet with incorrect area id");
		return;
	}

	switch (mospf->type)
	{
	case MOSPF_TYPE_HELLO:
		handle_mospf_hello(iface, packet, len);
		break;
	case MOSPF_TYPE_LSU:
		handle_mospf_lsu(iface, packet, len);
		break;
	default:
		// log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
		break;
	}
}
