#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
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

// TODO: Parse command-line arguments (-b/-r/-p) and override defaults.
// Keep behavior consistent with the project spec.
void parse_args(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
}

int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    parse_args(argc, argv);

    // TODO: Initialize OpenSSL library
    SSL_library_init();
    //or for newer OPENSSL_init_ssl(0, NULL);
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    
    // TODO: Create SSL context and load certificate/private key files
    // Files: "server.crt" and "server.key"

    //SSL_CTX *ssl_ctx;

    // For a server:
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if ( SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <=0) {
        fprintf(stderr, "Error: Unable to load certificate file\n");
        exit(EXIT_FAILURE);
    }
    if( SSL_CTX_use_PrivateKey_file(ctx,"server.key", SSL_FILETYPE_PEM) <=0) {
        fprintf(stderr, "Error: Unable to load private key file\n");
        exit(EXIT_FAILURE);
    }   
    if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr, "Private key does not match the certificate\n");
    exit(EXIT_FAILURE);
    }

    if (ctx== NULL) {
        fprintf(stderr, "Error: SSL context not initialized\n");
        exit(EXIT_FAILURE);
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0); // IPv4 socket stream default protocol 
    if (server_socket == -1) {
        perror("socket failed"); //failure to create socket
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)); //lets addres get reused

    server_addr.sin_family = AF_INET; //ipv4
    server_addr.sin_addr.s_addr = INADDR_ANY; //all network interfaces (localhost, wifi, etc)
    server_addr.sin_port = htons(LOCAL_PORT_TO_CLIENT); //listen in port 8443

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) { //reserve port for socket 
        perror("bind failed");
        exit(EXIT_FAILURE);
    }


    if (listen(server_socket, 10) == -1) { //turn into listening socket allow 10 pending requests 
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d\n", LOCAL_PORT_TO_CLIENT);

    while (1) { //wait for client connections
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len); //create socket for specific client connection gives back file descriptor
        if (client_socket == -1) {
            perror("accept failed");
            continue;
        }
        
        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // TODO: Create SSL structure for this connection and perform SSL handshake
        SSL *tls_connection = SSL_new(ctx); //tls session using the tls config(ctx)certificate, key, create a secure connection for one client 
        SSL_set_fd(tls_connection, client_socket); //attach tls session to client tcp socket, tells tls connection what tcp socket to use for send and recieve
        int handshake = SSL_accept(tls_connection); //perform the tls handshake for this tls session 
        if (handshake <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(tls_connection);
            close(client_socket);
            continue;
        } else {
            printf("SSL handshake successful\n");
        }
        
        // TODO: Clean up SSL connection
        SSL_free(tls_connection); //cleans up for the next client and avoid memory leaks
        close(client_socket);
    }

    close(server_socket);
    // TODO: Clean up SSL context
    
    return 0;
}

int file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file != NULL) {
        fclose(file);
        return 1;
    }
    return 0;
}

// TODO: Parse HTTP request, extract file path, and route to appropriate handler
// Consider: URL decoding, default files, routing logic for different file types
void handle_request(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // TODO: Read request from SSL connection
    bytes_read = 0;
    
    if (bytes_read <= 0) {
        return;
    }

    buffer[bytes_read] = '\0';
    char *request = malloc(strlen(buffer) + 1);
    strcpy(request, buffer);
    
    char *method = strtok(request, " ");
    char *file_name = strtok(NULL, " ");
    file_name++;
    if (strlen(file_name) == 0) {
        strcat(file_name, "index.html");
    }
    char *http_version = strtok(NULL, " ");

    if (file_exists(file_name)) {
        printf("Sending local file %s\n", file_name);
        send_local_file(ssl, file_name);
    } else {
        printf("Proxying remote file %s\n", file_name);
        proxy_remote_file(ssl, buffer);
    }
}

// TODO: Serve local file with correct Content-Type header
// Support: .html, .txt, .jpg, .m3u8, and files without extension
void send_local_file(SSL *ssl, const char *path) {
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (!file) {
        printf("File %s not found\n", path);
        char *response = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                         "<body><h1>404 Not Found</h1></body></html>";
        // TODO: Send response via SSL
        
        return;
    }

    char *response;
    if (strstr(path, ".html")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/html; charset=UTF-8\r\n\r\n";
    } else {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
    }

    // TODO: Send response header and file content via SSL
    

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // TODO: Send file data via SSL
        
    }

    fclose(file);
}

// TODO: Forward request to backend server and relay response to client
// Handle connection failures appropriately
void proxy_remote_file(SSL *ssl, const char *request) {
    int remote_socket;
    struct sockaddr_in remote_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket == -1) {
        printf("Failed to create remote socket\n");
        return;
    }

    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, REMOTE_HOST, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(REMOTE_PORT);

    if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == -1) {
        printf("Failed to connect to remote server\n");
        close(remote_socket);
        return;
    }

    send(remote_socket, request, strlen(request), 0);

    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0) {
        // TODO: Forward response to client via SSL
        
    }

    close(remote_socket);
}
