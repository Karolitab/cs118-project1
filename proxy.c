#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>

#define BUFFER_SIZE 1024
#define LOCAL_PORT_TO_CLIENT 8443
#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT 5001

void handle_request(SSL *ssl);
void send_local_file(SSL *ssl, const char *path);
void proxy_remote_file(SSL *ssl, const char *request);
int file_exists(const char *filename);

static int g_is_head = 0;

static int ssl_write_all(SSL *ssl, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t off = 0;

    while (off < len)
    {
        int w = SSL_write(ssl, p + off, (int)(len - off));
        if (w <= 0)
            return -1;
        off += (size_t)w;
    }
    return 0;
}

static int hex_value(char c)
{
    if ('0' <= c && c <= '9')
        return c - '0';
    if ('a' <= c && c <= 'f')
        return 10 + (c - 'a');
    if ('A' <= c && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

static void url_decode(const char *src, char *dst, size_t dst_size)
{
    if (!src || !dst || dst_size == 0)
        return;

    size_t di = 0;
    for (size_t si = 0; src[si] != '\0' && di + 1 < dst_size; si++)
    {
        if (src[si] == '%' && src[si + 1] != '\0' && src[si + 2] != '\0' &&
            isxdigit((unsigned char)src[si + 1]) && isxdigit((unsigned char)src[si + 2]))
        {
            int hi = hex_value(src[si + 1]);
            int lo = hex_value(src[si + 2]);
            if (hi >= 0 && lo >= 0)
            {
                dst[di++] = (char)((hi << 4) | lo);
                si += 2;
                continue;
            }
        }
        dst[di++] = src[si];
    }
    dst[di] = '\0';
}

static const char *file_type(const char *path)
{
    const char *ext = strrchr(path, '.');
    if (!ext)
        return "application/octet-stream";

    if (strcmp(ext, ".html") == 0)
        return "text/html; charset=UTF-8";
    if (strcmp(ext, ".txt") == 0)
        return "text/plain; charset=UTF-8";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0)
        return "image/jpeg";
    if (strcmp(ext, ".m3u8") == 0)
        return "application/vnd.apple.mpegurl";

    return "application/octet-stream";
}

static void send_404(SSL *ssl)
{
    const char *body =
        "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
        "<body><h1>404 Not Found</h1></body></html>";

    char header[512];
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 404 Not Found\r\n"
                              "Content-Type: text/html; charset=UTF-8\r\n"
                              "Content-Length: %zu\r\n"
                              "\r\n",
                              strlen(body));

    (void)ssl_write_all(ssl, header, (size_t)header_len);
    if (!g_is_head)
        (void)ssl_write_all(ssl, body, strlen(body));
}

static void send_400(SSL *ssl)
{
    const char *body = "Bad Request\n";
    char header[256];
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 400 Bad Request\r\n"
                              "Content-Type: text/plain; charset=UTF-8\r\n"
                              "Content-Length: %zu\r\n"
                              "\r\n",
                              strlen(body));
    (void)ssl_write_all(ssl, header, (size_t)header_len);
    if (!g_is_head)
        (void)ssl_write_all(ssl, body, strlen(body));
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

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

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

        printf("Accepted connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

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

        handle_request(tls_connection);

        SSL_shutdown(tls_connection);
        SSL_free(tls_connection);
        close(client_socket);
    }

    close(server_socket);
    SSL_CTX_free(ctx);
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
    char request[8192];

    int total = 0;
    request[0] = '\0';

    while (1)
    {
        int r = SSL_read(ssl, buffer, (int)sizeof(buffer));
        if (r <= 0)
            return;

        if (total + r >= (int)sizeof(request) - 1)
        {
            send_400(ssl);
            return;
        }

        memcpy(request + total, buffer, (size_t)r);
        total += r;
        request[total] = '\0';

        if (strstr(request, "\r\n\r\n") != NULL)
            break;
    }

    /* Parse request line */
    char *line_end = strstr(request, "\r\n");
    if (!line_end)
    {
        send_400(ssl);
        return;
    }

    char first_line[1024];
    int line_len = (int)(line_end - request);
    if (line_len <= 0 || line_len >= (int)sizeof(first_line))
    {
        send_400(ssl);
        return;
    }
    memcpy(first_line, request, (size_t)line_len);
    first_line[line_len] = '\0';

    char method[16], raw_path[1024], version[16];
    if (sscanf(first_line, "%15s %1023s %15s", method, raw_path, version) != 3)
    {
        send_400(ssl);
        return;
    }

    g_is_head = (strcmp(method, "HEAD") == 0);

    char decoded_path[1024];
    url_decode(raw_path, decoded_path, sizeof(decoded_path));

    char file_name[1024];

    if (strcmp(decoded_path, "/") == 0)
    {
        strcpy(file_name, "index.html");
    }
    else if (decoded_path[0] == '/')
    {
        strncpy(file_name, decoded_path + 1, sizeof(file_name) - 1);
        file_name[sizeof(file_name) - 1] = '\0';
    }
    else
    {
        strncpy(file_name, decoded_path, sizeof(file_name) - 1);
        file_name[sizeof(file_name) - 1] = '\0';
    }

    if (strstr(file_name, "..") != NULL)
    {
        send_404(ssl);
        return;
    }

    send_local_file(ssl, file_name);
}

// TODO: Serve local file with correct Content-Type header
// Support: .html, .txt, .jpg, .m3u8, and files without extension
void send_local_file(SSL *ssl, const char *path)
{
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];

    if (!file)
    {
        send_404(ssl);
        return;
    }

    /* Determine file size */
    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        send_404(ssl);
        return;
    }
    long fsize = ftell(file);
    if (fsize < 0)
    {
        fclose(file);
        send_404(ssl);
        return;
    }
    rewind(file);

    const char *mime = file_type(path);

    char header[512];
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 200 OK\r\n"
                              "Content-Type: %s\r\n"
                              "Content-Length: %ld\r\n"
                              "\r\n",
                              mime, fsize);

    if (ssl_write_all(ssl, header, (size_t)header_len) < 0)
    {
        fclose(file);
        return;
    }

    if (g_is_head)
    {
        fclose(file);
        return;
    }

    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        if (ssl_write_all(ssl, buffer, n) < 0)
        {
            fclose(file);
            return;
        }
    }

    fclose(file);
}

// TODO: Forward request to backend server and relay response to client
// Handle connection failures appropriately
void proxy_remote_file(SSL *ssl, const char *request)
{
    (void)ssl;
    (void)request;
}
