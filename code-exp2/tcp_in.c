#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>

// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
void *tcp_cwnd_thread(void *arg)
{
	struct tcp_sock *tsk = (struct tcp_sock *)arg;
	FILE *fp = fopen("cwnd.txt", "w");

	int time_us = 0;
	while (tsk->state == TCP_ESTABLISHED)
	{
		usleep(10); // 每500us唤醒一次，按需更改
		time_us += 10;
		fprintf(fp, "%d %f %u %u %d\n", time_us, tsk->cwnd, tsk->ssthresh, tsk->adv_wnd, tsk->cc_state);
	}
	fclose(fp);
	return NULL;
}
void tcp_congestion_control(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{

	if (tsk->cc_state == TCP_FAST_RECOVER)
	{
		log(DEBUG, "in recovery");
		if (cb->ack >= tsk->recovery_point)
		{
			tsk->cc_state = TCP_SLOW_START;
			tsk->cwnd = tsk->ssthresh;
			log(DEBUG, "exit recovery");
		}
		else
		{
			tsk->cwnd += (float)(1 * TCP_MSS);
		}
	}
	else if (tsk->cc_state == TCP_SLOW_START)
	{
		if (cb->ack < tsk->snd_una) // 接收到重复的ack
		{
			tsk->dup_ack_count++;
		}
		else // 接收到新的ack
		{
			tsk->cwnd += (float)(1 * TCP_MSS);
			tsk->dup_ack_count = 0;
		}
		if (tsk->cwnd > tsk->ssthresh)
		{
			tsk->cc_state = TCP_CONGESTION_AVOIDANCE;
			log(DEBUG, "enter disorder");
		}
	}
	else if (tsk->cc_state == TCP_CONGESTION_AVOIDANCE) // 拥塞避免状态
	{
		if (cb->ack > tsk->snd_una)
		{
			tsk->cwnd += (float)((float)(TCP_MSS * TCP_MSS) / (float)tsk->cwnd);
			tsk->dup_ack_count = 0;
		}
		else
		{
			tsk->dup_ack_count++;
		}
	}
	if (tsk->dup_ack_count >= 3) // 快速重传
	{
		log(DEBUG, "fast retransmit");
		tsk->cc_state = TCP_FAST_RECOVER;
		tsk->ssthresh = tsk->cwnd / 2;
		tsk->cwnd = (float)(tsk->ssthresh + 3 * TCP_MSS);

		tsk->dup_ack_count = 0;
		tsk->recovery_point = tsk->snd_nxt;
		tcp_retrans_send_buffer(tsk);
	}

	static FILE *fp = NULL;
	static int time_us = 0;

	if (!fp)
	{
		fp = fopen("cwnd1.txt", "w");
		if (!fp)
		{
			log(ERROR, "Failed to open cwnd.txt");
			return;
		}
	}
	if (tsk->state == TCP_ESTABLISHED && less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
	{
		// 记录当前拥塞控制参数
		time_us += 1000; // 假设每个ACK间隔1ms
		fprintf(fp, "%d %f %u %u %d\n", time_us, tsk->cwnd, tsk->ssthresh, tsk->adv_wnd, tsk->cc_state);
		fflush(fp);
	}
}

static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	int old_window_test = tcp_tx_window_test(tsk);
	log(DEBUG, "tcp_update_window: snd_una=%u, snd_nxt=%u, rwnd=%u",
		tsk->snd_una, tsk->snd_nxt, cb->rwnd);

	// 拥塞控制

	tsk->snd_una = cb->ack;	 // 更新未确认的发送序列号
	tsk->adv_wnd = cb->rwnd; // 更新接收方的通告窗口

	// tsk->cwnd = 0x7f7f7f7f;					 // 设置一个较大的值，拥塞控制后续会用到
	tsk->snd_wnd = min(cb->rwnd, tsk->cwnd); // 更新发送窗口
	int new_window_test = tcp_tx_window_test(tsk);
	if (new_window_test)
	{
		tcp_unset_persist_timer(tsk);
	}
	else
	{
		log(DEBUG, "set persist timer");
		tcp_set_persist_timer(tsk);
	}

	log(DEBUG, "old_window_test = %d, new_window_test = %d", old_window_test, new_window_test);
	if (new_window_test)
	{
		log(DEBUG, "wake up send");
		wake_up(tsk->wait_send);
	}
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

// check whether the sequence number of the incoming packet is in the receiving
// window

// Process the incoming packet according to TCP state machine.
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	// log(DEBUG, "process");
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	// log(DEBUG, "start to process");

	// 握手过程
	// 服务器
	if (!tsk)
	{
		log(ERROR, "not such socket, sending RST.");
		tcp_send_reset(cb);
		return;
	}
	switch (tsk->state)
	{
	case TCP_LISTEN: // 处于监听状态的服务器
					 // tcp_state_listen_handle_packet(tsk, cb, packet);//has ack inside it
		// 处于监听状态下，如果监听对象不存在，就返回；
		//                如果收到的包不是SYN，就返回RST
		if (tsk == NULL)
		{
			tcp_send_reset(cb);
			return;
		}
		// else if ((cb->flags & TCP_SYN) == 0)
		//{
		// if (cb->flags & TCP_RST)
		// return;
		// else
		//{
		// tcp_send_control_packet(tsk, TCP_RST);
		// return;
		//}
		//}

		// 如果收到的包是SYN，就准备建立连接
		// 新建一个子sock，初始化好对应的数据，并把它插入父sock的listen_sock上
		if (cb->flags & TCP_SYN)
		{
			struct tcp_sock *child_sk = alloc_tcp_sock();
			child_sk->sk_sip = cb->daddr;
			child_sk->sk_sport = cb->dport;
			child_sk->sk_dip = cb->saddr;
			child_sk->sk_dport = cb->sport;
			child_sk->iss = tcp_new_iss();
			child_sk->snd_nxt = child_sk->iss;
			child_sk->rcv_nxt = cb->seq + 1;
			child_sk->parent = tsk;
			// list_add_tail(&child_sk->list, &tsk->listen_queue);
			//  修改子sock的状态为SYN_RECV，发送SYN|ACK报文，并把子sock添加到tcp_established_sock_table
			tcp_set_state(child_sk, TCP_SYN_RECV);
			tcp_hash(child_sk);
			tcp_send_control_packet(child_sk, TCP_SYN | TCP_ACK);
			tcp_sock_accept_enqueue(child_sk);

			wake_up(tsk->wait_accept);
		}
		break;
	case TCP_SYN_RECV: // 服务器收到SYN，进入established状态

		if (cb->flags & TCP_ACK)
		{

			// struct tcp_sock *child_tsk = alloc_tcp_sock(); // 分配新的子套接字
			// child_tsk = tsk;							   // 设置父套接字
			// tcp_sock_accept_enqueue(child_tsk);			   // 将子套接字加入 accept_queue

			// child_tsk->rcv_nxt = cb->seq;			   // 更新接收窗口
			// tsk->snd_una = cb->ack;					   // 更新发送窗口
			// tcp_set_state(child_tsk, TCP_ESTABLISHED); // 设置子套接字状态为 ESTABLISHED

			// wake_up((child_tsk->parent)->wait_accept); // 唤醒阻塞在 accept 的线程

			tcp_set_state(tsk, TCP_ESTABLISHED);
			tcp_update_window_safe(tsk, cb);
			tcp_unset_retrans_timer(tsk);
			wake_up(tsk->wait_recv);
		}
		break;

	case TCP_SYN_SENT:
		if (cb->flags & (TCP_SYN | TCP_ACK))
		{
			tsk->rcv_nxt = cb->seq + 1;
			// tsk->snd_nxt += 1;
			tcp_set_state(tsk, TCP_ESTABLISHED);

			tcp_hash(tsk);
			tcp_update_send_buffer(tsk, cb->ack);
			tcp_update_window_safe(tsk, cb);
			tcp_unset_retrans_timer(tsk);
			// tsk->snd_nxt = tsk->snd_una;
			tcp_send_control_packet(tsk, TCP_ACK);
			tsk->cwnd = (float)TCP_MSS;
			tsk->ssthresh = (u32)64 * 1024;
			tsk->dup_ack_count = 0;
			tsk->cc_state = TCP_SLOW_START;
			log(DEBUG, "slow start");
			pthread_t cwnd_record;
			pthread_create(&cwnd_record, NULL, tcp_cwnd_thread, (void *)tsk);
			wake_up(tsk->wait_connect);
		}
		else
		{
			tcp_send_reset(cb);
			log(ERROR, "when in SYN_SENT, received a packet which is not SYN|ACK");
		}
		break;

	case TCP_ESTABLISHED:
		if (cb->flags & TCP_FIN)
		{
			tsk->rcv_nxt = cb->seq + 1;
			tcp_set_state(tsk, TCP_CLOSE_WAIT);
			wake_up(tsk->wait_recv);
			tcp_send_control_packet(tsk, TCP_ACK);
		}
		else if (cb->flags & TCP_ACK)
		{ // receive
			log(DEBUG, "cb->seq = %u, cb->ack= %u, tsk->rcv_nxt = %u", cb->seq, cb->ack, tsk->rcv_nxt);
			if (cb->seq < tsk->rcv_nxt)
			{
				tcp_send_control_packet(tsk, TCP_ACK);
			}
			if (cb->pl_len == 0)
			{
				log(DEBUG, "receive empty packet");
				tcp_update_send_buffer(tsk, cb->ack);
				tcp_congestion_control(tsk, cb, packet);
				tcp_update_window_safe(tsk, cb);
			}
			else
			{
				log(DEBUG, "receive data");
				pthread_mutex_lock(&tsk->rcv_buf_lock);
				tcp_recv_ofo_buffer_add_packet(tsk, cb);
				tcp_move_recv_ofo_buffer(tsk);
				pthread_mutex_unlock(&tsk->rcv_buf_lock);

				//  log(DEBUG, "receive length is %d", cb->pl_len);
				//  tsk->rcv_nxt = cb->seq + data_len;
				//  tcp_send_control_packet(tsk, TCP_ACK);
			}
		}
		break;
		/*
		else if ((cb->flags & TCP_ACK) && (cb->flags & TCP_PSH))
		{
			// 检查序号范
			if (less_or_equal_32b(cb->seq, tsk->rcv_nxt))
			{
				// 收到了之前确认过的报文，直接回复ACK
				tcp_send_control_packet(tsk, TCP_ACK);
			}
			else if (tsk->rcv_nxt == cb->seq)
			{
				// 刚好是自己希望收到的报文，将数据写入接收缓冲区
				int data_len = cb->pl_len;
				if (data_len != 0)
				{
					pthread_mutex_lock(&tsk->rcv_buf_lock);
					write_ring_buffer(tsk->rcv_buf, cb->payload, data_len);
					tsk->rcv_wnd -= data_len; // 更新接收窗口
					tsk->rcv_nxt += data_len; // 更新期望的接收序号

					tcp_send_control_packet(tsk, TCP_ACK);
					pthread_mutex_unlock(&tsk->rcv_buf_lock);
					log(DEBUG, "send ack, snd_nxt = %u, snd_una = %u", tsk->snd_nxt, tsk->snd_una);
					wake_up(tsk->wait_recv); // 唤醒阻塞在 recv 的线程
				}
				else
					tcp_update_window_safe(tsk, cb); // 终于找到了错误
			}
			else if (less_than_32b(tsk->rcv_nxt, cb->seq))
			{
				// 收了乱序报文，直接回复ACK，丢弃数据
				tcp_send_control_packet(tsk, TCP_ACK);
			}
		}
		else if (cb->flags & TCP_ACK)
		{
			if (less_or_equal_32b(cb->seq, tsk->rcv_nxt))
			{
				// 收到了之前确认过的报文，直接回复ACK
				tcp_send_control_packet(tsk, TCP_ACK);
			}
			else if (less_than_32b(tsk->rcv_nxt, cb->seq))
			{
				// 收了乱序报文，直接回复ACK，丢弃数据
				tcp_send_control_packet(tsk, TCP_ACK);
			}
			else
				tcp_update_window_safe(tsk, cb);
		}*/

	// 四次挥手
	// 服务器
	case TCP_CLOSE_WAIT:
		tcp_set_state(tsk, TCP_LAST_ACK);
		tsk->rcv_nxt = cb->seq + 1;
		tcp_send_control_packet(tsk, TCP_ACK | TCP_FIN);
		break;
	case TCP_LAST_ACK:
		if (cb->flags & (TCP_ACK | TCP_FIN))
		{
			tcp_update_send_buffer(tsk, cb->ack);
			tcp_set_state(tsk, TCP_CLOSED);
			tcp_bind_unhash(tsk);
			// free_tcp_sock(tsk);
		}
		break;
	// 客户端
	case TCP_FIN_WAIT_1:
		if ((cb->flags & TCP_FIN) && (cb->flags & TCP_ACK))
		{
			tsk->rcv_nxt = cb->seq + 1;
			tcp_update_send_buffer(tsk, cb->ack);
			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_set_state(tsk, TCP_TIME_WAIT);
			tcp_set_timewait_timer(tsk);
		}
		if (cb->flags & TCP_FIN)
		{
			tcp_set_state(tsk, TCP_CLOSING);
			tcp_send_control_packet(tsk, TCP_ACK);
		}
		else if (cb->flags & TCP_ACK)
		{
			tcp_set_state(tsk, TCP_FIN_WAIT_2);
		}

		break;

	case TCP_FIN_WAIT_2:
		if (cb->flags & TCP_FIN)
		{
			tsk->rcv_nxt = cb->seq + 1;
			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_set_state(tsk, TCP_TIME_WAIT);
			tcp_set_timewait_timer(tsk);
		}
		break;

	case TCP_TIME_WAIT:
		break;

	default:
		log(ERROR, "wrong state %d", tsk->state);
		break;
		return;
	}
}
int tcp_recv_ofo_buffer_add_packet(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	log(DEBUG, "tcp_recv_ofo_buffer_add_packet");
	if (less_or_equal_32b(cb->seq_end, tsk->rcv_nxt))
	{
		// 1.这是一个重复的包，直接丢弃
		pthread_mutex_unlock(&tsk->rcv_buf_lock);
		printf("duplicate packet: seq_end=%u, rcv_nxt=%u\n", cb->seq_end, tsk->rcv_nxt);
		return -1;
	}
	// 2.创建新的队列项
	struct recv_ofo_buf_entry *new_entry = malloc(sizeof(struct recv_ofo_buf_entry));
	new_entry->seq = cb->seq;
	new_entry->seq_end = cb->seq_end;
	new_entry->length = cb->pl_len;
	new_entry->packet = malloc(cb->pl_len);
	memcpy(new_entry->packet, cb->payload, cb->pl_len);
	struct recv_ofo_buf_entry *entry, *next;
	// 3.遍历乱序队列找到合适的位置插入
	if (list_empty(&tsk->rcv_ofo_buf))
	{
		log(DEBUG, "empty list");
		list_add_tail(&new_entry->node, &tsk->rcv_ofo_buf);
		return 0;
	}
	list_for_each_entry_safe(entry, next, &tsk->rcv_ofo_buf, node)
	{
		// 3.1检查是否有重复数据
		if (cb->seq == entry->seq)
		{
			log(ERROR, "duplicate packet");
			free(new_entry);
			return -1;
		}
		if (less_than_32b(cb->seq, entry->seq))
		{
			// 3.2找到合适的插入位置
			list_add_tail(&new_entry->node, &entry->node);
			log(DEBUG, "have_inserted");
			return 0;
		}
	}
	list_add_tail(&new_entry->node, &tsk->rcv_ofo_buf);
	// 4.如果遍历完还没插入，则添加到末尾
	log(DEBUG, "insert to tail");
	return 0;
}
int tcp_move_recv_ofo_buffer(struct tcp_sock *tsk)
{
	struct recv_ofo_buf_entry *entry, *next;
	int moved = 0;

	list_for_each_entry_safe(entry, next, &tsk->rcv_ofo_buf, node)
	{
		if (entry->seq != tsk->rcv_nxt)
		{
			log(DEBUG, "not in order");
			break;
		}
		// 1.检查是否有序
		if (ring_buffer_free(tsk->rcv_buf) < entry->length)
		{
			log(ERROR, "recv buffer is full");
			break;
		}
		// 1.1写入接收缓冲区
		log(DEBUG, "write to buffer");
		write_ring_buffer(tsk->rcv_buf, entry->packet, entry->length);
		tsk->rcv_nxt += entry->length;
		tsk->rcv_wnd -= entry->length;
		moved += entry->length;
		list_delete_entry(&entry->node);
		log(DEBUG, "rcv_next=%u, seq=%u,seq_end=%u", tsk->rcv_nxt, entry->seq, entry->seq_end);
		// 2.唤醒阻塞在recv的线程
		// 3.从乱序队列中移除
		// 4.遇到乱序报文就退出
	}
	tcp_send_control_packet(tsk, TCP_ACK);
	if (moved)
	{
		wake_up(tsk->wait_recv);
		log(DEBUG, "moved=%d", moved);
	}
	else
	{
		log(DEBUG, "no data moved");
	}

	return moved;
}