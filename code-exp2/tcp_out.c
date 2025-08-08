#include "tcp.h"
#include "tcp_sock.h"
#include "ip.h"
#include "ether.h"

#include "log.h"
#include "list.h"

#include <stdlib.h>
#include <string.h>

// initialize tcp header according to the arguments
static void tcp_init_hdr(struct tcphdr *tcp, u16 sport, u16 dport, u32 seq, u32 ack,
						 u8 flags, u16 rwnd)
{
	memset((char *)tcp, 0, TCP_BASE_HDR_SIZE);

	tcp->sport = htons(sport);
	tcp->dport = htons(dport);
	tcp->seq = htonl(seq);
	tcp->ack = htonl(ack);
	tcp->off = TCP_HDR_OFFSET;
	tcp->flags = flags;
	tcp->rwnd = htons(rwnd);
}

// send a tcp packet
//
// Given that the payload of the tcp packet has been filled, initialize the tcp
// header and ip header (remember to set the checksum in both header), and emit
// the packet by calling ip_send_packet.

void tcp_send_packet(struct tcp_sock *tsk, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	int ip_tot_len = len - ETHER_HDR_SIZE;
	int tcp_data_len = ip_tot_len - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;

	u32 saddr = tsk->sk_sip;
	u32 daddr = tsk->sk_dip;
	u16 sport = tsk->sk_sport;
	u16 dport = tsk->sk_dport;

	u32 seq = tsk->snd_nxt;
	u32 ack = tsk->rcv_nxt;
	u16 rwnd = tsk->rcv_wnd;
	log(DEBUG, "tcp_send_packet:seq=%u,ack=%u, rwnd =%u", seq, ack, rwnd);
	tcp_init_hdr(tcp, sport, dport, seq, ack, TCP_PSH | TCP_ACK, rwnd);
	ip_init_hdr(ip, saddr, daddr, ip_tot_len, IPPROTO_TCP);

	tcp->checksum = tcp_checksum(ip, tcp);

	ip->checksum = ip_checksum(ip);

	tsk->snd_nxt += tcp_data_len;
	// tcp_send_buffer_add_packet(tsk, packet, len);
	ip_send_packet(packet, len);
}

void tcp_send_probe_packet(struct tcp_sock *tsk)
{
	int pkt_size = 1 + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	char *packet = malloc(pkt_size);
	packet[pkt_size - 1] = 'X';
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);
	// char *payload = (char *)tcp + TCP_BASE_HDR_SIZE;

	int tcp_data_len = 1;
	int ip_tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + tcp_data_len;
	int pkt_len = ETHER_HDR_SIZE + ip_tot_len;

	u32 saddr = tsk->sk_sip;
	u32 daddr = tsk->sk_dip;
	u16 sport = tsk->sk_sport;
	u16 dport = tsk->sk_dport;

	u32 seq = tsk->snd_una - 1; // 使用旧的、已确认的序列号
	u32 ack = tsk->rcv_nxt;
	u16 rwnd = tsk->rcv_wnd;

	tcp_init_hdr(tcp, sport, dport, seq, ack, TCP_PSH | TCP_ACK, rwnd);
	ip_init_hdr(ip, saddr, daddr, ip_tot_len, IPPROTO_TCP);

	tcp->checksum = tcp_checksum(ip, tcp);
	ip->checksum = ip_checksum(ip);

	ip_send_packet(packet, pkt_len);
}
// send a tcp control packet
//
// The control packet is like TCP_ACK, TCP_SYN, TCP_FIN (excluding TCP_RST).
// All these packets do not have payload and the only difference among these is
// the flags.
void tcp_send_control_packet(struct tcp_sock *tsk, u8 flags)
{
	int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	char *packet = malloc(pkt_size);
	if (!packet)
	{
		log(ERROR, "malloc tcp control packet failed.");
		return;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	u16 tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;

	ip_init_hdr(ip, tsk->sk_sip, tsk->sk_dip, tot_len, IPPROTO_TCP);
	tcp_init_hdr(tcp, tsk->sk_sport, tsk->sk_dport, tsk->snd_nxt,
				 tsk->rcv_nxt, flags, tsk->rcv_wnd);

	tcp->checksum = tcp_checksum(ip, tcp);

	if (flags & (TCP_SYN | TCP_FIN))
		tsk->snd_nxt += 1;
	// log(DEBUG, "de9 control packet");
	// tcp_send_buffer_add_packet(tsk, packet, pkt_size);
	ip_send_packet(packet, pkt_size);
}

// send tcp reset packet
//
// Different from tcp_send_control_packet, the fields of reset packet is
// from tcp_cb instead of tcp_sock.
void tcp_send_reset(struct tcp_cb *cb)
{
	int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	char *packet = malloc(pkt_size);
	if (!packet)
	{
		log(ERROR, "malloc tcp control packet failed.");
		return;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	u16 tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	ip_init_hdr(ip, cb->daddr, cb->saddr, tot_len, IPPROTO_TCP);
	tcp_init_hdr(tcp, cb->dport, cb->sport, 0, cb->seq_end, TCP_RST | TCP_ACK, 0);
	tcp->checksum = tcp_checksum(ip, tcp);

	ip_send_packet(packet, pkt_size);
}
void tcp_send_buffer_add_packet(struct tcp_sock *tsk, char *packet, int len)
{
	log(DEBUG, "tcp_send_buffer_add_packet:len=%d", len);

	struct send_buffer_entry *new_entry = malloc(sizeof(struct send_buffer_entry));
	new_entry->length = len;
	new_entry->packet = malloc(len);
	memcpy(new_entry->packet, packet, len);
	new_entry->seq = tsk->snd_nxt;
	// 1.创建新的发送缓冲区条目
	// 2.获取报文序号
	list_add_tail(&new_entry->node, &tsk->send_buf);
	// 3.添加到发送队列尾部
	// 4.设置重传定时器，可以写在这里也可以不写外面调用
	pthread_mutex_lock(&tsk->send_buf_lock);
	tcp_set_retrans_timer(tsk);

	pthread_mutex_unlock(&tsk->send_buf_lock);
}

int tcp_update_send_buffer(struct tcp_sock *tsk, u32 ack)
{
	log(DEBUG, "tcp_update_send_buffer:ack=%u", ack);

	struct send_buffer_entry *entry, *next;
	int updated = 0;

	list_for_each_entry_safe(entry, next, &tsk->send_buf, node)
	{
		if (less_than_32b(entry->seq, ack))
		{
			// 2.数据已被确认，移除该条目
			list_delete_entry(&entry->node);
			free(entry->packet);
			updated = 1;
		}
		else
			break;
	}
	// 3.如果队列为空，取消重传定时器
	if (list_empty(&tsk->send_buf))
	{
		log(DEBUG, "empty send buffer");
		tcp_unset_retrans_timer(tsk);
	}
	log(DEBUG, "update snd_una");
	pthread_mutex_lock(&tsk->send_buf_lock);
	tcp_update_retrans_timer(tsk);
	pthread_mutex_unlock(&tsk->send_buf_lock);
	return updated;
}

int tcp_retrans_send_buffer(struct tcp_sock *tsk)
{
	log(DEBUG, "tcp_retrans_send_buffer");
	// pthread_mutex_lock(&tsk->send_buf_lock);
	if (list_empty(&tsk->send_buf))
	{
		log(DEBUG, "wake up send");
		wake_up(tsk->wait_send);
		pthread_mutex_unlock(&tsk->send_buf_lock);
		return -1;
	}
	//  log(DEBUG, "1");
	struct send_buffer_entry *entry = list_entry((&tsk->send_buf)->next, typeof(*entry), node);
	// log(DEBUG, "2");
	int pkt_len = entry->length + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	// log(DEBUG, "3");
	char *new_packet = malloc(pkt_len);
	// log(DEBUG, "5");
	memcpy(new_packet + pkt_len - entry->length, entry->packet, entry->length);
	// 1.获取队列头部的数据包
	// log(DEBUG, "4");
	struct iphdr *ip = packet_to_ip_hdr(new_packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);
	// log(DEBUG, "3");
	int tcp_data_len = entry->length;
	int ip_tot_len = entry->length + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;

	u32 saddr = tsk->sk_sip;
	u32 daddr = tsk->sk_dip;
	u16 sport = tsk->sk_sport;
	u16 dport = tsk->sk_dport;

	u32 seq = entry->seq; // 使用旧的、已确认的序列号
	u32 ack = tsk->rcv_nxt;
	u16 rwnd = tsk->rcv_wnd;

	tcp_init_hdr(tcp, sport, dport, seq, ack, TCP_PSH | TCP_ACK, rwnd);
	ip_init_hdr(ip, saddr, daddr, ip_tot_len, IPPROTO_TCP);

	tcp->checksum = tcp_checksum(ip, tcp);
	ip->checksum = ip_checksum(ip);
	// 2.创建新的数据包用于重传

	// 3. 更新TCP头部

	// 4.发送重传包
	// log(DEBUG, "4");
	ip_send_packet(new_packet, pkt_len);
	// log(DEBUG, "5");
	//  pthread_mutex_unlock(&tsk->send_buf_lock);
	return 0;
}