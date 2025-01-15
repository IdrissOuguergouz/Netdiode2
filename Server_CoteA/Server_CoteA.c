#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#define PORT 2222
#define BUFFER_SIZE 1024
#define RECEIVER_SERVER_IP "192.168.24.142" // Replace with Receiving Server IP
#define RECEIVER_SERVER_PORT 3333          // Port for Receiving Server
#define TOKEN_LENGTH 16

// Function to generate a random authentication token
void generate_auth_token(char *token) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < TOKEN_LENGTH; i++) {
        token[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    token[TOKEN_LENGTH] = '\0';
}

// Function to encode data in Base64
char *base64_encode(const unsigned char *data, size_t len) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, data, len);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &buffer_ptr);
    char *b64_text = (char *)malloc(buffer_ptr->length + 1);
    memcpy(b64_text, buffer_ptr->data, buffer_ptr->length);
    b64_text[buffer_ptr->length] = '\0';

    BIO_free_all(bio);
    return b64_text;
}

// Function to forward file and destination to Receiving Server
void forward_to_receiver(const char *file_path, const char *destination_ip) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    struct sockaddr_in receiver_addr;
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons(RECEIVER_SERVER_PORT);

    if (inet_pton(AF_INET, RECEIVER_SERVER_IP, &receiver_addr.sin_addr) <= 0) {
        perror("Invalid Receiving Server IP address");
        close(sockfd);
        return;
    }

    if (connect(sockfd, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr)) < 0) {
        perror("Connection to Receiving Server failed");
        close(sockfd);
        return;
    }

    printf("Forwarding file and destination to Receiving Server...\n");

    // Send destination IP followed by a delimiter
    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "%s\n", destination_ip);
    send(sockfd, message, strlen(message), 0);

    // Read and encode file in Base64
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Failed to open file");
        close(sockfd);
        return;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *file_buffer = (unsigned char *)malloc(file_size);
    fread(file_buffer, 1, file_size, file);

    char *encoded_data = base64_encode(file_buffer, file_size);
    free(file_buffer);
    fclose(file);

    // Send encoded file data
    send(sockfd, encoded_data, strlen(encoded_data), 0);
    free(encoded_data);

    close(sockfd);
    printf("File and destination successfully forwarded to Receiving Server.\n");
}

// Function to handle client connections
void handle_client(int client_socket, const char *auth_token) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    // Step 1: Receive authentication token
    bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        fprintf(stderr, "Error receiving token.\n");
        close(client_socket);
        return;
    }
    buffer[bytes_received] = '\0';

    if (strcmp(buffer, auth_token) != 0) {
        fprintf(stderr, "Invalid token: %s\n", buffer);
        send(client_socket, "AUTH_FAIL", 9, 0);
        close(client_socket);
        return;
    }
    send(client_socket, "AUTH_SUCCESS", 12, 0);

    // Step 2: Receive destination machine IP
    bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        fprintf(stderr, "Error receiving destination IP.\n");
        close(client_socket);
        return;
    }
    buffer[bytes_received] = '\0';
    char destination_ip[BUFFER_SIZE];
    strncpy(destination_ip, buffer, BUFFER_SIZE);

    printf("Destination IP received: %s\n", destination_ip);

    // Step 3: Receive file
    FILE *file = fopen("received_file", "wb");
    if (!file) {
        perror("Error opening file");
        close(client_socket);
        return;
    }

    printf("Receiving file...\n");
    while ((bytes_received = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
        fwrite(buffer, 1, bytes_received, file);
    }
    fclose(file);
    printf("File received successfully.\n");

    // Step 4: Forward to Receiving Server
    forward_to_receiver("received_file", destination_ip);

    close(client_socket);
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    char auth_token[TOKEN_LENGTH + 1];
    srand(time(NULL));
    generate_auth_token(auth_token);
    printf("Generated authentication token: %s\n", auth_token);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Transfer Server listening on port %d...\n", PORT);

    while ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len)) >= 0) {
        printf("Client connected from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        handle_client(client_socket, auth_token);
    }

    close(server_socket);
    return 0;
}

