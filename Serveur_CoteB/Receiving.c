#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define PORT 3333
#define BUFFER_SIZE 1024

// Function to decode Base64 data
unsigned char *base64_decode(const char *data, size_t *len) {
    BIO *bio, *b64;
    size_t decode_len = strlen(data) * 3 / 4;
    unsigned char *decoded_data = (unsigned char *)malloc(decode_len);

    bio = BIO_new_mem_buf(data, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *len = BIO_read(bio, decoded_data, decode_len);
    BIO_free_all(bio);

    return decoded_data;
}

// Function to forward the file to the destination machine
void forward_to_destination(const char *destination_ip, const char *file_path) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(4444); // Destination machine port

    if (inet_pton(AF_INET, destination_ip, &dest_addr.sin_addr) <= 0) {
        perror("Invalid Destination IP address");
        close(sockfd);
        return;
    }

    if (connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Connection to Destination Machine failed");
        close(sockfd);
        return;
    }

    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Failed to open file");
        close(sockfd);
        return;
    }

    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        send(sockfd, buffer, bytes_read, 0);
    }

    fclose(file);
    close(sockfd);
    printf("File forwarded to destination machine (%s).\n", destination_ip);
}

// Function to handle the transfer server
void handle_transfer_server(int client_socket) {
    char buffer[BUFFER_SIZE * 2];
    char destination_ip[BUFFER_SIZE];
    ssize_t bytes_received;
    size_t destination_ip_length = 0;

    // Step 1: Receive destination IP
    while ((bytes_received = recv(client_socket, buffer + destination_ip_length, 1, 0)) > 0) {
        if (buffer[destination_ip_length] == '\n') {
            buffer[destination_ip_length] = '\0'; // Replace newline with null terminator
            strncpy(destination_ip, buffer, BUFFER_SIZE);
            break;
        }
        destination_ip_length++;
    }

    if (bytes_received <= 0) {
        perror("Error receiving destination IP");
        close(client_socket);
        return;
    }

    printf("Received destination IP: %s\n", destination_ip);

    // Step 2: Receive Base64-encoded file data
    FILE *file = fopen("decoded_file.b64", "wb"); // Save Base64 data for debugging
    if (!file) {
        perror("Failed to open file for Base64 data");
        close(client_socket);
        return;
    }

    while ((bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        fwrite(buffer, 1, bytes_received, file);
    }
    fclose(file);

    if (bytes_received < 0) {
        perror("Error receiving encoded file data");
        close(client_socket);
        return;
    }

    printf("Base64 data received successfully. Decoding...\n");

    // Step 3: Decode Base64 data
    file = fopen("decoded_file.b64", "rb");
    if (!file) {
        perror("Failed to open Base64 file for decoding");
        close(client_socket);
        return;
    }

    fseek(file, 0, SEEK_END);
    size_t base64_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *base64_data = (char *)malloc(base64_size + 1);
    fread(base64_data, 1, base64_size, file);
    base64_data[base64_size] = '\0';
    fclose(file);

    size_t decoded_len;
    unsigned char *decoded_file = base64_decode(base64_data, &decoded_len);
    free(base64_data);

    // Save decoded file
    file = fopen("decoded_file", "wb");
    if (!file) {
        perror("Failed to open decoded file for writing");
        free(decoded_file);
        close(client_socket);
        return;
    }
    fwrite(decoded_file, 1, decoded_len, file);
    fclose(file);
    free(decoded_file);

    printf("File successfully received and decoded.\n");

    // Step 4: Forward file to destination
    forward_to_destination(destination_ip, "decoded_file");
    close(client_socket);
}


int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

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

    printf("Receiving Server listening on port %d...\n", PORT);

    while ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len)) >= 0) {
        printf("Transfer Server connected from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        handle_transfer_server(client_socket);
    }

    close(server_socket);
    return 0;
}
