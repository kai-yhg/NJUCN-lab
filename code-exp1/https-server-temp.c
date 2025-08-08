#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <pthread.h>
#include <stdlib.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

void handle_http_request(int client_sock)
{
    char buffer[4096] = {0};
    int bytes = read(client_sock, buffer, sizeof(buffer));
    if (bytes < 0)
    {
        perror("Read failed");
        // close(client_sock);
        return;
    }
    buffer[bytes] = '\0';
    printf("Received request:\n%s\n", buffer);
    char response[] = "HTTP/1.1 301 Moved Permanently\r\n"
                      "Location: https://localhost/\r\n"
                      "Content-Length: 0\r\n\r\n";
    write(client_sock, response, strlen(response));
    close(client_sock);
}

void *http_execute(void *arg)
{
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        perror("Opening socket failed");
        exit(1);
    }
    int enable = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(1);
    }

    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(80); // 将电话机和本地地址绑定

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Bind failed");
        exit(1);
    }
    listen(server_sock, 10); // 准备开始连接，监听队列长度为10

    while (1)
    {
        struct sockaddr_in caddr;
        socklen_t len;
        int client_sock = accept(server_sock, (struct sockaddr *)&caddr, &len); // 接受连接，返回一个新的进行通讯的socket
        if (client_sock < 0)
        {
            perror("Accept failed");
            exit(1);
            pthread_t thread;
            pthread_create(&thread, NULL, (void *)handle_http_request, (void *)(intptr_t)client_sock);
            pthread_detach(thread);
        }
    }
}
void *https_execute(void *arg)
{
}
int main()
{
    printf("running\n");
    // init SSL Library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    printf("running");
    // enable TLS method
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    // load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0)
    {
        perror("load cert failed");
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0)
    {
        perror("load prikey failed");
        exit(1);
    }

    // 前面的不知道有啥用
    // 创造http和https两个线程
    pthread_t http_thread;
    //, https_thread;
    pthread_create(&http_thread, NULL, http_execute, NULL);
    // pthread_create(&https_thread, NULL, https_execute, NULL);
    pthread_join(http_thread, NULL);
    // pthread_join(https_thread, NULL);
    SSL_CTX_free(ctx);
    return 0;
}