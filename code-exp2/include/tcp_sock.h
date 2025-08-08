#ifndef __TCP_SOCK_H__
#define __TCP_SOCK_H__

#include "types.h"
#include "list.h"
#include "tcp.h"
#include "tcp_timer.h"
#include "ring_buffer.h"

#include "synch_wait.h"

#include <pthread.h>

#define PORT_MIN 12345
#define PORT_MAX 23456
#define TCP_MSS (ETH_FRAME_LEN - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE)
struct sock_addr
{
	u32 ip;
	u16 port;
} __attribute__((packed));
struct recv_ofo_buf_entry
{
	struct list_head node;
	u32 length;
	u32 seq;
	u32 seq_end;
	char *packet;
};
struct send_buffer_entry
{
	struct list_head node;
	u32 length;
	u32 seq;
	char *packet;
};
// the main structure that manages a connection locally
struct tcp_sock
{
	// sk_ip, sk_sport, sk_sip, sk_dport are the 4-tuple that represents a
	// connection
	struct sock_addr local;
	struct sock_addr peer;
#define sk_sip local.ip
#define sk_sport local.port
#define sk_dip peer.ip
#define sk_dport peer.port // 四元组

	// 连接管理
	//  pointer to parent tcp sock, a tcp sock which bind and listen to a port
	//  is the parent of tcp socks when *accept* a connection request
	struct tcp_sock *parent;

	// represents the number that the tcp sock is referred, if this number
	// decreased to zero, the tcp sock should be released
	int ref_cnt; // 引用次数，减到0就释放

	// hash_list is used to hash tcp sock into listen_table or established_table,
	// bind_hash_list is used to hash into bind_table
	struct list_head hash_list;		 // 已建立连接表
	struct list_head bind_hash_list; // 储存在bind端口的哈希表

	// struct list_head {
	// struct list_head *next, *prev;
	//};

	// 监听队列
	//  when a passively opened tcp sock receives a SYN packet, it mallocs a child
	//  tcp sock to serve the incoming connection, which is pending in the
	//  listen_queue of parent tcp sock
	struct list_head listen_queue; // 监听队列，收到SYN后新分配的tcp_sock放入监听队列
	// when receiving the last packet (ACK) of the 3-way handshake, the tcp sock
	// in listen_queue will be moved into accept_queue, waiting for *accept* by
	// parent tcp sock
	struct list_head accept_queue; // 完成三次握手后放在接受队列等待accept取出

#define TCP_MAX_BACKLOG 128
	// the number of pending tcp sock in accept_queue
	int accept_backlog;
	// the maximum number of pending tcp sock in accept_queue
	int backlog;

	// the list node used to link listen_queue or accept_queue of parent tcp sock
	struct list_head list;
	// tcp timer used during TCP_TIME_WAIT state

	// TCP 状态管理
	struct tcp_timer timewait;

	// used for timeout retransmission
	struct tcp_timer retrans_timer;
	struct tcp_timer persist_timer;
	// 同步等待机制
	//  synch waiting structure of *connect*, *accept*, *recv*, and *send*
	struct synch_wait *wait_connect;
	struct synch_wait *wait_accept; // 等待客户端连接
	struct synch_wait *wait_recv;
	struct synch_wait *wait_send;
	struct synch_wait *wait_wnd;
	/*
		struct synch_wait {
		pthread_mutex_t lock;		// mutex lock
		pthread_cond_t cond;		// condition variable to synch
		int notified;				// whether ready to read/write
		int dead;					// whether dead
		int sleep;					// whether others are waiting
	};
	*/

	// 发送和接收缓冲区
	//  receiving buffer
	struct ring_buffer *rcv_buf; // 接受缓冲区
	// used to pend unacked packets
	struct list_head send_buf; // 储存等待确认的TCP报文
	// used to pend out-of-order packets
	struct list_head rcv_ofo_buf; // 乱序到达的TCP报文

	// tcp state, see enum tcp_state in tcp.h
	int state;
	int cc_state; // 拥塞控制状态
	// 发送和接收序列号
	//  initial sending sequence number
	u32 iss; // 初始发送序列号
	// the highest byte that is ACKed by peer
	u32 snd_una; // 最早未被对方确认的序列号
	// the highest byte sent
	u32 snd_nxt; // 下一个要发送的序列号
	// the highest byte ACKed by itself (i.e. the byte expected to receive next)
	u32 rcv_nxt; // 期望接收的下一个字节的序列号

	// 拥塞控制
	//  used to indicate the end of fast recovery
	u32 recovery_point;
	// 快速恢复结束点
	//  min(adv_wnd, cwnd)
	u32 snd_wnd; // 发送窗口
	// the receiving window advertised by peer
	u16 adv_wnd; // 对方通告的窗口大小

	// the size of receiving window (advertised by tcp sock itself)
	u16 rcv_wnd; // 本地通告的接收窗口大小

	// congestion window
	float cwnd;
	u32 dup_ack_count; // duplicate ACK count
	// slow start threshold
	u32 ssthresh;
	pthread_mutex_t timer_list_lock; // 保护定时器链表
	pthread_mutex_t sk_lock;		 // 保护核心参数
	pthread_mutex_t rcv_buf_lock;	 // 保护接收缓冲区
	pthread_mutex_t send_buf_lock;	 // 保护发送缓冲区
};

void tcp_set_state(struct tcp_sock *tsk, int state);

int tcp_sock_accept_queue_full(struct tcp_sock *tsk);
void tcp_sock_accept_enqueue(struct tcp_sock *tsk);
struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk);

int tcp_hash(struct tcp_sock *tsk);
void tcp_unhash(struct tcp_sock *tsk);
void tcp_bind_unhash(struct tcp_sock *tsk);
struct tcp_sock *alloc_tcp_sock();
void free_tcp_sock(struct tcp_sock *tsk);
struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb);

u32 tcp_new_iss();

void tcp_send_reset(struct tcp_cb *cb);

void tcp_send_control_packet(struct tcp_sock *tsk, u8 flags);
void tcp_send_packet(struct tcp_sock *tsk, char *packet, int len);
void tcp_send_probe_packet(struct tcp_sock *tsk);
int tcp_send_data(struct tcp_sock *tsk, char *buf, int len);

void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_congestion_control(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void init_tcp_stack();

int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr);
int tcp_sock_listen(struct tcp_sock *tsk, int backlog);
int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr);
struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk);
void tcp_sock_close(struct tcp_sock *tsk);

int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len);

int tcp_sock_write(struct tcp_sock *tsk, char *buf, int len);

int tcp_tx_window_test(struct tcp_sock *tsk);

int tcp_recv_ofo_buffer_add_packet(struct tcp_sock *tsk, struct tcp_cb *cb);
int tcp_move_recv_ofo_buffer(struct tcp_sock *tsk);
int tcp_retrans_send_buffer(struct tcp_sock *tsk);
int tcp_update_send_buffer(struct tcp_sock *tsk, u32 ack);
void tcp_send_buffer_add_packet(struct tcp_sock *tsk, char *packet, int len);
#endif
