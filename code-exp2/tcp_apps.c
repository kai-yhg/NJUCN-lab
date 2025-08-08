#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>
// tcp server application, listens to port (specified by arg) and serves only one
// connection request

void *tcp_server(void *arg)
{
	// log(DEBUG, "server started.");
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0)
	{
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0)
	{
		log(ERROR, "tcp_sock listen ");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	int rbuf_size = 1000;
	// log(DEBUG, "receive buffer size: %d", rbuf_size);
	FILE *f = fopen("./server-output.dat", "w");
	if (f == NULL)
	{
		log(ERROR, "open file failed.");
		exit(1);
	}
	char *rbuf[rbuf_size];
	int rlen = 0;
	int total_recv = 0;
	while (1)
	{
		// log(DEBUG, "start to read");
		memset(rbuf, 0, rbuf_size);
		rlen = tcp_sock_read(csk, rbuf, rbuf_size);
		// log(DEBUG, "tcp_sock_read %d bytes.", rlen);
		if (rlen <= 0)
		{
			log(DEBUG, "tcp_sock_read return 0 value, finish transmission.");
			break;
		}
		else
		{
			rbuf[rlen] = '\0';
			// log(DEBUG, "tcp_sock_read %d bytes.", rlen);
			fwrite(rbuf, 1, rlen, f);
			total_recv += rlen;
			fprintf(stdout, "totally receive data: %d B\n", total_recv);
		}
	}
	fclose(f);

	// char buf[1460] = {0};
	// char response[1460] = {0};
	// while (1)
	//{
	//  接收客户端发送的数据
	//	int len = tcp_sock_read(csk, buf, sizeof(buf));
	//	if (len <= 0)
	//	break; // 客户端关闭连接

	//	buf[len] = '\0';
	// sprintf(response, "server echoes: %s", buf);
	//	tcp_sock_write(csk, response, strlen(response));
	//}

	tcp_sock_close(csk);

	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;
	struct tcp_sock *tsk = alloc_tcp_sock();
	if (tcp_sock_connect(tsk, skaddr) < 0)
	{
		log(ERROR, "tcp_sock connect to server (" IP_FMT ":%hu)failed.",
			NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}
	FILE *f = fopen("./client-input.dat", "r");
	char *wbuf = (char *)malloc(1000);
	int wlen = 0;
	while (1)
	{
		wlen = fread(wbuf, sizeof(char), 1000, f);
		if (wlen > 0)
		{
			tcp_sock_write(tsk, wbuf, wlen);
		}
		else
			break;
		if (wlen < 1000)
			break;
	}
	fclose(f);
	sleep(5);
	// char *data = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	// int data_len = strlen(data);
	// char buf[1460] = {0};
	// int len = 0;
	//  循环发送字符串 5 到 10 次
	// for (int i = 0; i < 10; i++)
	//{
	//  发送数据
	//	char new_data[1460];
	//	int tail_len = data_len - i;

	//	memcpy(new_data, data + i, tail_len);
	//	memcpy(new_data + tail_len, data, i);
	//	new_data[data_len] = '\0';
	//	tcp_sock_write(tsk, new_data, strlen(new_data));

	// 接收服务器的响应
	//	len = tcp_sock_read(tsk, buf, 1460);
	//	if (len > 0)
	//	{
	//		printf("%s\n", buf);
	//	}
	//	sleep(1);
	//	}
	log(DEBUG, "client finished.");
	tcp_sock_close(tsk);

	return NULL;
}
