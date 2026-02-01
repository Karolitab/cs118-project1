#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024
#define LOCAL_PORT_TO_CLIENT 8443
#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT 5001

void handle_request(SSL *ssl);
void send_local_file(SSL *ssl, const char *path);
void proxy_remote_file(SSL *ssl, const char *request);
int file_exists(const char *filename);

static int send_all_ssl(SSL *ssl, const void *buf, int len)
{
    const unsigned char *p = (const unsigned char *)buf;
    int sent = 0;
    while (sent < len)
    {
        int n = SSL_write(ssl, p + sent, len - sent);
        if (n <= 0)
            return 0;
        sent += n;
    }
    return 1;
}

static void url_decode_inplace(char *s)
{
    char *dst = s;
    for (char *src = s; *src; src++)
    {
        if (*src == '+')
        {
            *dst++ = ' ';
        }
        else if (*src == '%' &&
                 isxdigit((unsigned char)src[1]) &&
                 isxdigit((unsigned char)src[2]))
        {
            char hex[3] = {src[1], src[2], 0};
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 2;
        }
        else
        {
            *dst++ = *src;
        }
    }
    *dst = '\0';
}

static const char *content_type_for_path(const char *path)
{
    const char *ext = strrchr(path, '.');
    if (!ext)
        return "application/octet-stream";
    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0)
        return "text/html; charset=UTF-8";
    if (strcmp(ext, ".txt") == 0)
        return "text/plain; charset=UTF-8";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0)
        return "image/jpeg";
    if (strcmp(ext, ".m3u8") == 0)
        return "application/vnd.apple.mpegurl";
    return "application/octet-stream";
}

static int read_request_headers(SSL *ssl, char *buf, size_t cap, size_t *out_len)
{
    size_t used = 0;
    buf[0] = '\0';
    while (used + 1 < cap)
    {
        int n = SSL_read(ssl, buf + used, (int)(cap - used - 1));
        if (n <= 0)
            return 0;
        used += (size_t)n;
        buf[used] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL)
            break;
        if (used + 1 >= cap)
            break;
    }
    *out_len = used;
    return 1;
}

// TODO: Parse command-line arguments (-b/-r/-p) and override defaults.
// Keep behavior consistent with the project spec.
void parse_args(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
}

int main(int argc, char *argv[])
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    parse_args(argc, argv);

    // TODO: Initialize OpenSSL library
    SSL_library_init();
    // or for newer OPENSSL_init_ssl(0, NULL);
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // TODO: Create SSL context and load certificate/private key files
    // Files: "server.crt" and "server.key"

    // SSL_CTX *ssl_ctx;

    // For a server:
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "Error: Unable to load certificate file\n");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "Error: Unable to load private key file\n");
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }

    if (ctx == NULL)
    {
        fprintf(stderr, "Error: SSL context not initialized\n");
        exit(EXIT_FAILURE);
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LOCAL_PORT_TO_CLIENT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 10) == -1)
    {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d\n", LOCAL_PORT_TO_CLIENT);

    while (1)
    {
        client_len = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == -1)
        {
            perror("accept failed");
            continue;
        }

        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // TODO: Create SSL structure for this connection and perform SSL handshake
        SSL *tls_connection = SSL_new(ctx);
        SSL_set_fd(tls_connection, client_socket);
        int handshake = SSL_accept(tls_connection);
        if (handshake <= 0)
        {
            ERR_print_errors_fp(stderr);
            SSL_free(tls_connection);
            close(client_socket);
            continue;
        }
        else
        {
            printf("SSL handshake successful\n");
        }

        handle_request(tls_connection);

        SSL_shutdown(tls_connection);

        // TODO: Clean up SSL connection
        SSL_free(tls_connection);
        close(client_socket);
    }

    close(server_socket);
    // TODO: Clean up SSL context

    return 0;
}

int file_exists(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (file != NULL)
    {
        fclose(file);
        return 1;
    }
    return 0;
}

// TODO: Parse HTTP request, extract file path, and route to appropriate handler
// Consider: URL decoding, default files, routing logic for different file types
void handle_request(SSL *ssl)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // TODO: Read request from SSL connection
    size_t req_len = 0;
    if (!read_request_headers(ssl, buffer, sizeof(buffer), &req_len))
    {
        return;
    }
    bytes_read = (ssize_t)req_len;

    if (bytes_read <= 0)
    {
        return;
    }

    buffer[bytes_read] = '\0';

    char request_line[BUFFER_SIZE];
    strncpy(request_line, buffer, sizeof(request_line) - 1);
    request_line[sizeof(request_line) - 1] = '\0';

    char *method = strtok(request_line, " \t\r\n");
    char *path = strtok(NULL, " \t\r\n");
    char *http_version = strtok(NULL, "\r\n");

    if (!method || !path || !http_version)
    {
        const char *resp =
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "Content-Length: 12\r\n\r\n"
            "Bad Request";
        send_all_ssl(ssl, resp, (int)strlen(resp));
        return;
    }

    if (strcmp(method, "GET") != 0)
    {
        const char *resp =
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "Content-Length: 18\r\n\r\n"
            "Method Not Allowed";
        send_all_ssl(ssl, resp, (int)strlen(resp));
        return;
    }

    char path_buf[BUFFER_SIZE];
    strncpy(path_buf, path, sizeof(path_buf) - 1);
    path_buf[sizeof(path_buf) - 1] = '\0';

    char *q = strchr(path_buf, '?');
    if (q)
        *q = '\0';

    url_decode_inplace(path_buf);

    if (strcmp(path_buf, "/") == 0 || path_buf[0] == '\0')
    {
        strncpy(path_buf, "/index.html", sizeof(path_buf) - 1);
        path_buf[sizeof(path_buf) - 1] = '\0';
    }

    const char *p = path_buf;
    if (*p == '/')
        p++;

    char local_path[BUFFER_SIZE];
    snprintf(local_path, sizeof(local_path), "%s", p);

    if (file_exists(local_path))
    {
        printf("Sending local file %s\n", local_path);
        send_local_file(ssl, local_path);
    }
    else
    {
        printf("Proxying remote file %s\n", local_path);
        proxy_remote_file(ssl, buffer);
    }
}

// TODO: Serve local file with correct Content-Type header
// Support: .html, .txt, .jpg, .m3u8, and files without extension
void send_local_file(SSL *ssl, const char *path)
{
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (!file)
    {
        printf("File %s not found\n", path);
        const char *body =
            "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
            "<body><h1>404 Not Found</h1></body></html>";
        char header[256];
        int body_len = (int)strlen(body);
        int header_len = snprintf(header, sizeof(header),
                                  "HTTP/1.1 404 Not Found\r\n"
                                  "Content-Type: text/html; charset=UTF-8\r\n"
                                  "Content-Length: %d\r\n\r\n",
                                  body_len);
        // TODO: Send response via SSL
        send_all_ssl(ssl, header, header_len);
        send_all_ssl(ssl, body, body_len);
        return;
    }

    struct stat st;
    long file_size = 0;
    if (stat(path, &st) == 0)
    {
        file_size = (long)st.st_size;
    }

    const char *ctype = content_type_for_path(path);

    char header[512];
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 200 OK\r\n"
                              "Content-Type: %s\r\n"
                              "Content-Length: %ld\r\n"
                              "Connection: close\r\n\r\n",
                              ctype, file_size);

    // TODO: Send response header and file content via SSL
    send_all_ssl(ssl, header, header_len);

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        // TODO: Send file data via SSL
        if (!send_all_ssl(ssl, buffer, (int)bytes_read))
        {
            break;
        }
    }

    fclose(file);
}

// TODO: Forward request to backend server and relay response to client
// Handle connection failures appropriately
void proxy_remote_file(SSL *ssl, const char *request)
{
    int remote_socket;
    struct sockaddr_in remote_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket == -1)
    {
        printf("Failed to create remote socket\n");
        const char *resp =
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "Content-Length: 11\r\n\r\n"
            "Bad Gateway";
        send_all_ssl(ssl, resp, (int)strlen(resp));
        return;
    }

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, REMOTE_HOST, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(REMOTE_PORT);

    if (connect(remote_socket, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) == -1)
    {
        printf("Failed to connect to remote server\n");
        close(remote_socket);
        const char *resp =
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "Content-Length: 11\r\n\r\n"
            "Bad Gateway";
        send_all_ssl(ssl, resp, (int)strlen(resp));
        return;
    }

    send(remote_socket, request, strlen(request), 0);

    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0)
    {
        // TODO: Forward response to client via SSL
        if (!send_all_ssl(ssl, buffer, (int)bytes_read))
        {
            break;
        }
    }

    close(remote_socket);
}
