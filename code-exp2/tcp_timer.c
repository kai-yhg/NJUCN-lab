#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"
#include "log.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
static struct list_head timer_list;

static pthread_mutex_t timer_list_lock = PTHREAD_MUTEX_INITIALIZER;
// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	struct tcp_timer *timer, *next;
	pthread_mutex_lock(&timer_list_lock);
	list_for_each_entry_safe(timer, next, &timer_list, list)
	{
		if (timer->enable)
		{
			struct tcp_sock *tsk;
			switch (timer->type)
			{
			case 0:
				tsk = list_entry(timer, struct tcp_sock, timewait);
				break;
			case 1:
				tsk = list_entry(timer, struct tcp_sock, retrans_timer);
				log(DEBUG, "scan retrans_timer list");
				break;
			case 2:
				tsk = list_entry(timer, struct tcp_sock, persist_timer);
				break;
			}
			timer->timeout -= TCP_TIMER_SCAN_INTERVAL;
			if (timer->timeout <= 0)
			{
				// log(DEBUG, "tcp sock is in TIME_WAIT, free it.");
				if (timer->type == 2 && tsk->state != TCP_CLOSED)
				{
					log(DEBUG, "tcp persist timer timeout");
					tcp_send_probe_packet(tsk);
					timer->timeout = TCP_RETRANS_INTERVAL_INITIAL;
				}
				else if (timer->type == 1 && tsk->state != TCP_CLOSED)
				{
					log(DEBUG, "scan retrans_timer list");
					if (timer->retrans_cnt >= 3 && tsk->state != TCP_CLOSED)
					{
						log(DEBUG, "tcp sock is in TIME_WAIT, free it.");
						tcp_unset_retrans_timer(tsk);
						list_delete_entry(&timer->list);
						tcp_bind_unhash(tsk);
						wait_exit(tsk->wait_connect);
						wait_exit(tsk->wait_accept);
						wait_exit(tsk->wait_recv);
						wait_exit(tsk->wait_send);
						tcp_set_state(tsk, TCP_CLOSED);
						free_tcp_sock(tsk);
					}
					else
					{
						log(DEBUG, "tcp retrans timer timeout");
						timer->retrans_cnt++;
						timer->timeout = (TCP_RETRANS_INTERVAL_INITIAL << timer->retrans_cnt);
						tsk->ssthresh = tsk->cwnd / 2;
						tsk->cwnd = (float)TCP_MSS;
						tsk->dup_ack_count = 0;
						tsk->cc_state = TCP_SLOW_START;
						tcp_retrans_send_buffer(tsk);
					}
				}
				else
				{
					list_delete_entry(&timer->list);
					timer->enable = 0;
					tcp_set_state(tsk, TCP_CLOSED);
					tcp_sock_close(tsk);
				}
			}
		}
	}
	pthread_mutex_unlock(&timer_list_lock);
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	pthread_mutex_lock(&tsk->timer_list_lock);
	log(DEBUG, "set timer");
	tsk->ref_cnt++;
	struct tcp_timer *timer = &tsk->timewait;
	tsk->timewait.type = 0;
	tsk->timewait.timeout = 2 * TCP_MSL;
	tsk->timewait.enable = 1;
	list_add_tail(&tsk->timewait.list, &timer_list);
	pthread_mutex_unlock(&tsk->timer_list_lock);
}

void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1)
	{
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
void tcp_set_persist_timer(struct tcp_sock *tsk)
{

	if (tsk->persist_timer.enable)
	{
		return;
	}
	tsk->ref_cnt++;
	pthread_mutex_lock(&tsk->timer_list_lock);
	tsk->persist_timer.type = 2;

	tsk->persist_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	tsk->persist_timer.enable = 1;
	list_add_tail(&tsk->persist_timer.list, &timer_list);
	pthread_mutex_unlock(&tsk->timer_list_lock);
}

void tcp_unset_persist_timer(struct tcp_sock *tsk)
{
	if (!tsk->persist_timer.enable)
	{
		return;
	}
	tsk->persist_timer.enable = 0;
	tsk->ref_cnt--;
	list_delete_entry(&tsk->persist_timer.list);
}

void tcp_set_retrans_timer(struct tcp_sock *tsk)
{
	log(DEBUG, "set retrans timer");
	if (tsk->retrans_timer.enable)
	{
		pthread_mutex_lock(&tsk->timer_list_lock);
		tsk->retrans_timer.timeout = (TCP_RETRANS_INTERVAL_INITIAL << tsk->retrans_timer.retrans_cnt);
		pthread_mutex_unlock(&tsk->timer_list_lock);
		return;
	}
	tsk->ref_cnt++;
	pthread_mutex_lock(&tsk->timer_list_lock);
	tsk->retrans_timer.type = 1;
	tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	tsk->retrans_timer.enable = 1;
	list_add_tail(&tsk->retrans_timer.list, &timer_list);
	pthread_mutex_unlock(&tsk->timer_list_lock);
}
void tcp_unset_retrans_timer(struct tcp_sock *tsk)
{
	log(DEBUG, "unset retrans timer");
	if (!tsk->retrans_timer.enable)
	{
		return;
	}
	tsk->retrans_timer.enable = 0;
	tsk->ref_cnt--;
	list_delete_entry(&tsk->retrans_timer.list);
}
void tcp_update_retrans_timer(struct tcp_sock *tsk)
{
	log(DEBUG, "update retrans timer");
	if (!tsk->retrans_timer.enable)
	{
		return;
	}
	else
	{
		if (list_empty(&tsk->send_buf))
		{
			tcp_unset_retrans_timer(tsk);
			log(DEBUG, "wake up send");
			wake_up(tsk->wait_send);
		}
		else
		{
			tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
			tsk->retrans_timer.retrans_cnt = 0;
		}
	}
}