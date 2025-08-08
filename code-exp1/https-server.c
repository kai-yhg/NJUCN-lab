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
#include "openssl/ssl.h"
#include "openssl/err.h"

#define HTTP_PORT 80
#define HTTPS_PORT 443
#define BUFFER_SIZE 1024
void handle_http_request(int client_sock)
{
    // printf("request\n");
    char buffer[1024] = {0};
    read(client_sock, buffer, sizeof(buffer));

    // 解析请求的路径
    char method[10], path[256], protocol[20];
    sscanf(buffer, "%s %255s %s", method, path, protocol);

    // 构造 301 重定向响应，保留路径，只修改端口
    char redirect_response[1024];
    snprintf(redirect_response, sizeof(redirect_response),
             "HTTP/1.1 301 Moved Permanently\r\n"
             "Location: https://10.0.0.1%s\r\n"
             "Content-Length: 0\r\n\r\n",
             path);

    write(client_sock, redirect_response, strlen(redirect_response));
    close(client_sock);
}

void handle_https_request(SSL *ssl)
{
    // printf("requests\n");

    if (SSL_accept(ssl) == -1)
    {
        perror("SSL_accept failed");
        int sock = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(sock);
        return;
    }

    char buf[1024] = {0};
    int bytes = SSL_read(ssl, buf, sizeof(buf));
    if (bytes <= 0)
    {
        SSL_free(ssl);
        return;
    }
    // printf("Received request:\n%s\n", buf);
    char method[10], path[256], protocol[20];
    sscanf(buf, "%s %255s %s", method, path, protocol);
    // printf("methos:%s path:%s protocol:%s", method, path, protocol);
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "./%.250s", path);
    // 把相对路径转换为本地路径

    FILE *file = fopen(filepath, "rb");
    if (!file) // 如果打不开文件就404
    {
        const char *not_found_response =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 13\r\n"
            "Connection: close\r\n\r\n"
            "404 Not Found";
        int sent = SSL_write(ssl, not_found_response, strlen(not_found_response));
        if (sent <= 0)
        {
            perror("SSL_write failed");
        }
    }
    else
    {
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);
        char *range_header = strstr(buf, "Range: bytes=");
        // 解析range_header，判断是否存在
        if (range_header)
        {
            long start, end;
            start = 0;
            end = file_size - 1; // 初始化以应对从头开始或者到最后结束的情况
            sscanf(range_header, "Range: bytes=%ld-%ld", &start, &end);
            // printf("%d %d\n", start, end);
            if (end >= file_size || end < start)
                end = file_size - 1;

            fseek(file, start, SEEK_SET);
            long content_length = end - start + 1;

            char header[256];
            snprintf(header, sizeof(header),
                     "HTTP/1.1 206 Partial Content\r\n"
                     "Content-Range: bytes %ld-%ld/%ld\r\n"
                     "Content-Length: %ld\r\n"
                     "Content-Type: text/html\r\n"
                     "Connection: close\r\n\r\n",
                     start, end, file_size, content_length);
            SSL_write(ssl, header, strlen(header));

            char buffer[1024];
            size_t bytes_read, remaining = content_length;
            while (remaining > 0 && (bytes_read = fread(buffer, 1, remaining > 1024 ? 1024 : remaining, file)) > 0)
            {
                SSL_write(ssl, buffer, bytes_read);
                remaining -= bytes_read;
            } // 防止读取超过最大限度
        }

        else // 没范围的情况
        {
            char header[1024];
            snprintf(header, sizeof(header),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Length: %ld\r\n"
                     "Content-Type: text/html\r\n"
                     "Connection: close\r\n\r\n",
                     file_size);
            SSL_write(ssl, header, strlen(header));

            char buffer[1024];
            size_t bytes_read;
            while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
            {
                SSL_write(ssl, buffer, bytes_read);
            }
        }
        fclose(file);
    }

    int sock = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sock);
}

void *start_http_server(void *arg)
{
    // printf("start\n");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(HTTP_PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Bind failed");
        exit(1);
    }
    listen(sock, 10);
    while (1)
    {
        // printf("while\n");
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0)
        {
            perror("HTTP Accept failed");
            continue;
        }

        handle_http_request(client_sock);
    }

    close(sock);
    return NULL;
}

void *start_https_server(void *arg)
{
    // printf("starts\n");
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(HTTPS_PORT);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Bind failed");
        exit(1);
    }
    listen(sock, 10);
    while (1)
    {

        // printf("whiles\n");
        int client_sock = accept(sock, NULL, NULL);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        handle_https_request(ssl);
    }
    close(sock);
    SSL_CTX_free(ctx);
    return NULL;
}

int main()
{
    SSL_library_init();
    pthread_t http_thread, https_thread;
    pthread_create(&http_thread, NULL, start_http_server, NULL);
    pthread_create(&https_thread, NULL, start_https_server, NULL);
    pthread_join(http_thread, NULL);
    pthread_join(https_thread, NULL);
    return 0;
}