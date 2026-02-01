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
        if (src[si] == '%' &&
            src[si + 1] != '\0' &&
            src[si + 2] != '\0' &&
            isxdigit((unsigned char)src[si + 1]) &&
            isxdigit((unsigned char)src[si + 2]))
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

    server_socket = socket(AF_INET, SOCK_STREAM, 0); // IPv4 socket stream default protocol
    if (server_socket == -1)
    {
        perror("socket failed"); // failure to create socket
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)); // lets addres get reused

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;                   // ipv4
    server_addr.sin_addr.s_addr = INADDR_ANY;           // all network interfaces (localhost, wifi, etc)
    server_addr.sin_port = htons(LOCAL_PORT_TO_CLIENT); // listen in port 8443

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    { // reserve port for socket
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 10) == -1)
    { // turn into listening socket allow 10 pending requests
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d\n", LOCAL_PORT_TO_CLIENT);

    while (1)
    { // wait for client connections
        client_len = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len); // create socket for specific client connection gives back file descriptor
        if (client_socket == -1)
        {
            perror("accept failed");
            continue;
        }

        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // TODO: Create SSL structure for this connection and perform SSL handshake
        SSL *tls_connection = SSL_new(ctx);         // tls session using the tls config(ctx)certificate, key, create a secure connection for one client
        SSL_set_fd(tls_connection, client_socket);  // attach tls session to client tcp socket, tells tls connection what tcp socket to use for send and recieve
        int handshake = SSL_accept(tls_connection); // perform the tls handshake for this tls session
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

        /* HTTPS server functionality starts here (HTTP parsing + file serving) */
        handle_request(tls_connection);

        // TODO: Clean up SSL connection
        SSL_shutdown(tls_connection);
        SSL_free(tls_connection); // cleans up for the next client and avoid memory leaks
        close(client_socket);
    }

    close(server_socket);
    // TODO: Clean up SSL context
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
    ssize_t bytes_read;

    /* Read until end of headers */
    char request[8192];
    int total = 0;
    request[0] = '\0';

    // TODO: Read request from SSL connection
    while (1)
    {
        bytes_read = SSL_read(ssl, buffer, (int)sizeof(buffer));
        if (bytes_read <= 0)
        {
            return;
        }

        if (total + bytes_read >= (int)sizeof(request) - 1)
        {
            /* Too large; just stop */
            return;
        }

        memcpy(request + total, buffer, (size_t)bytes_read);
        total += (int)bytes_read;
        request[total] = '\0';

        if (strstr(request, "\r\n\r\n") != NULL)
            break;
    }

    /* Parse request line: METHOD SP PATH SP VERSION */
    char *line_end = strstr(request, "\r\n");
    if (!line_end)
        return;

    char first_line[1024];
    int line_len = (int)(line_end - request);
    if (line_len <= 0 || line_len >= (int)sizeof(first_line))
        return;

    memcpy(first_line, request, (size_t)line_len);
    first_line[line_len] = '\0';

    char method[16], path[1024], version[16];
    if (sscanf(first_line, "%15s %1023s %15s", method, path, version) != 3)
        return;

    char decoded_path[1024];
    url_decode(path, decoded_path, sizeof(decoded_path));

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

    /* Serve local file if it exists; otherwise 404 */
    if (file_exists(file_name))
    {
        send_local_file(ssl, file_name);
    }
    else
    {
        send_local_file(ssl, file_name); /* send_local_file handles 404 internally */
    }
}

// TODO: Serve local file with correct Content-Type header
// Support: .html, .txt, .jpg, .m3u8, and files without extension
void send_local_file(SSL *ssl, const char *path)
{
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];

    if (!file)
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

        // TODO: Send response via SSL
        if (header_len > 0)
            SSL_write(ssl, header, header_len);
        SSL_write(ssl, body, (int)strlen(body));
        return;
    }

    const char *content_type = "application/octet-stream";
    const char *ext = strrchr(path, '.');
    if (ext)
    {
        if (strcmp(ext, ".html") == 0)
        {
            content_type = "text/html; charset=UTF-8";
        }
        else if (strcmp(ext, ".txt") == 0)
        {
            content_type = "text/plain; charset=UTF-8";
        }
        else if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0)
        {
            content_type = "image/jpeg";
        }
        else if (strcmp(ext, ".m3u8") == 0)
        {
            content_type = "application/vnd.apple.mpegurl";
        }
    }

    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        return;
    }
    long fsize = ftell(file);
    if (fsize < 0)
    {
        fclose(file);
        return;
    }
    rewind(file);

    char header[512];
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 200 OK\r\n"
                              "Content-Type: %s\r\n"
                              "Content-Length: %ld\r\n"
                              "\r\n",
                              content_type, fsize);

    // TODO: Send response header and file content via SSL
    if (header_len > 0)
        SSL_write(ssl, header, header_len);

    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        size_t sent = 0;
        while (sent < n)
        {
            int w = SSL_write(ssl, buffer + sent, (int)(n - sent));
            if (w <= 0)
            {
                fclose(file);
                return;
            }
            sent += (size_t)w;
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
        return;
    }

    send(remote_socket, request, strlen(request), 0);

    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0)
    {
        // TODO: Forward response to client via SSL
        size_t sent = 0;
        while (sent < (size_t)bytes_read)
        {
            int w = SSL_write(ssl, buffer + sent, (int)((size_t)bytes_read - sent));
            if (w <= 0)
            {
                close(remote_socket);
                return;
            }
            sent += (size_t)w;
        }
    }

    close(remote_socket);
}
