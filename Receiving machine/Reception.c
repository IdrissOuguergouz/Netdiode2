#include <gtk/gtk.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <cjson/cJSON.h>
#pragma comment(lib, "ws2_32.lib") // Link Winsock2

#define AES_KEY_SIZE 32
#define CLIENT_ID "7ceba98ca03"
#define PRIVATE_KEY_PATH "private_key.pem"
#define TRANSFER_DIR "./transfer_dir"
#define BUFFER_SIZE 4096
#define SERVER_PORT 2222

GtkWidget *entry_ip, *treeview;
char server_ip[50] = "";

// Initialize Winsock
void init_winsock() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
}

// Send JSON
int send_json(SOCKET sock, const char *json) {
    printf("[LOG] Sending JSON: %s\n", json);
    return send(sock, json, strlen(json), 0);
}

// Receive JSON
int recv_json(SOCKET sock, char *buffer, size_t size) {
    int received = recv(sock, buffer, size - 1, 0);
    if (received > 0) {
        buffer[received] = '\0';
        printf("[LOG] Received JSON: %s\n", buffer);
    } else {
        printf("[ERROR] No response received or connection closed.\n");
    }
    return received;
}

// Store user-entered IP
void save_ip(GtkWidget *widget, gpointer data) {
    const char *ip_text = gtk_entry_get_text(GTK_ENTRY(entry_ip)); // ✅ CORRECTED

    if (strlen(ip_text) == 0) {
        printf("[ERROR] Server IP not set!\n");
        return;
    }

    strncpy(server_ip, ip_text, sizeof(server_ip) - 1);
    server_ip[sizeof(server_ip) - 1] = '\0'; // Ensure null termination

    printf("[LOG] Server IP updated to: %s\n", server_ip);
}
// Base64 Encoding
char *base64_encode(const unsigned char *buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, buffer, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &buffer_ptr);

    char *encoded = malloc(buffer_ptr->length + 1);
    memcpy(encoded, buffer_ptr->data, buffer_ptr->length);
    encoded[buffer_ptr->length] = '\0';

    BIO_free_all(bio);
    return encoded;
}

// Load Private Key
EVP_PKEY *load_private_key() {
    printf("[LOG] Loading private key from: %s\n", PRIVATE_KEY_PATH);

    FILE *fp = fopen(PRIVATE_KEY_PATH, "r");
    if (!fp) {
        perror("[ERROR] Failed to open private key file");
        return NULL;
    }

    EVP_PKEY *private_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!private_key) {
        printf("[ERROR] Failed to load private key\n");
    } else {
        printf("[LOG] Private key successfully loaded\n");
    }
    return private_key;
}

// Sign Nonce
char *sign_nonce(const char *nonce, size_t nonce_len) {
    printf("[LOG] Signing nonce: %s\n", nonce);

    EVP_PKEY *private_key = load_private_key();
    if (!private_key) {
        fprintf(stderr, "[ERROR] Failed to load private key\n");
        return NULL;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, private_key);

    EVP_DigestSignUpdate(mdctx, nonce, nonce_len);

    size_t sig_len = 0;
    EVP_DigestSignFinal(mdctx, NULL, &sig_len);
    unsigned char *signature = malloc(sig_len);
    EVP_DigestSignFinal(mdctx, signature, &sig_len);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(private_key);

    char *signature_base64 = base64_encode(signature, sig_len);

    free(signature);
    return signature_base64;
}

// Refresh File List
void refresh_file_list(GtkWidget *widget, gpointer data) {
    printf("[LOG] Refreshing file list...\n");

    GtkListStore *store;
    GtkTreeIter iter;

    store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(treeview)));
    gtk_list_store_clear(store);

    DIR *dir = opendir(TRANSFER_DIR);
    if (!dir) {
        perror("[ERROR] Failed to open directory");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] != '.') {
            gtk_list_store_append(store, &iter);
            gtk_list_store_set(store, &iter, 0, entry->d_name, -1);
        }
    }
    closedir(dir);
}
// Fonction pour dériver une clé avec PBKDF2-HMAC-SHA256
int derive_key_pbkdf2(const unsigned char *password, size_t password_len,
                      const unsigned char *salt, size_t salt_len,
                      unsigned char *key, size_t key_len) {
    int iterations = 10000;  // Ajustable selon le niveau de sécurité souhaité

    if (PKCS5_PBKDF2_HMAC((const char *)password, password_len, 
                          salt, salt_len, iterations, EVP_sha256(), 
                          key_len, key) != 1) {
        fprintf(stderr, "Erreur de dérivation de la clé avec PBKDF2\n");
        return -1;
    }
    return 1;
}
// Fonction pour chiffrer avec AES-256-CBC et ajouter l'en-tête "Salted__"
int encrypt_aes(const unsigned char *plaintext, size_t plaintext_len,
                unsigned char *ciphertext, unsigned char *key, unsigned char *iv) {
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // Générer un sel aléatoire de 8 octets
    unsigned char salt[8];
    RAND_bytes(salt, sizeof(salt));

    // Ajouter l'en-tête "Salted__" suivi du sel
    memcpy(ciphertext, "Salted__", 8);
    memcpy(ciphertext + 8, salt, 8);

    // Initialiser le chiffrement avec PBKDF2 pour dériver la clé AES
    unsigned char derived_key[AES_KEY_SIZE];
    if (derive_key_pbkdf2(key, AES_KEY_SIZE, salt, sizeof(salt), derived_key, AES_KEY_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived_key, iv);
    int len;
    EVP_EncryptUpdate(ctx, ciphertext + 16, &len, plaintext, plaintext_len);
    int ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + 16 + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len + 16;  // Ajouter 16 octets pour "Salted__" + sel
}
char *encrypt_rsa(const unsigned char *plaintext, size_t plaintext_len, EVP_PKEY *public_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(public_key, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);

    size_t encrypted_len;
    EVP_PKEY_encrypt(ctx, NULL, &encrypted_len, plaintext, plaintext_len);
    unsigned char *encrypted = malloc(encrypted_len);
    EVP_PKEY_encrypt(ctx, encrypted, &encrypted_len, plaintext, plaintext_len);
    EVP_PKEY_CTX_free(ctx);

    char *encoded = base64_encode(encrypted, encrypted_len);
    free(encrypted);
    return encoded;
}
EVP_PKEY *load_public_key(const char *public_key_path) {
    FILE *key_file = fopen(public_key_path, "r");
    if (!key_file) {
        perror("[ERROR] Failed to load server public key");
        return NULL;
    }
    EVP_PKEY *public_key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);
    return public_key;
}
size_t base64_decode(const char *input, unsigned char *output) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new_mem_buf(input, -1);
    bio = BIO_push(b64, bio);

    // Désactiver le saut de ligne dans le Base64
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    const size_t input_len = strlen(input);
    const size_t output_len = BIO_read(bio, output, input_len);
    BIO_free_all(bio);
    return output_len;
}
void authenticate_with_server(GtkWidget *widget, gpointer data) {
    const char *server_ip = gtk_entry_get_text(GTK_ENTRY(entry_ip));
    if (!server_ip || strlen(server_ip) == 0) {
        printf("[ERROR] Server IP not set!\n");
        return;
    }

    printf("[LOG] Connecting to server at %s:2222...\n", server_ip);

    // Setup socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[ERROR] Socket creation failed");
        return;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(2222);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[ERROR] Connection failed");
        close(sock);
        return;
    }

	// Step 1: Request nonce
	cJSON *request_nonce_json = cJSON_CreateObject();
    cJSON_AddStringToObject(request_nonce_json, "request", "nonce");
	
	char *request_nonce = cJSON_Print(request_nonce_json);
    cJSON_Delete(request_nonce_json);
    printf("[LOG] Sending JSON: %s\n", request_nonce);

    // Load the server's public key for encryption
    EVP_PKEY *nonce_server_pub_key = load_public_key("server_pubkey.pem");
    if (!nonce_server_pub_key) {
        printf("[ERROR] Failed to load server public key!\n");
        free(request_nonce);
        close(sock);
        return;
    }

    // Generate AES key & IV
    unsigned char nonce_aes_key[AES_KEY_SIZE];
    unsigned char nonce_iv[16];
    RAND_bytes(nonce_aes_key, sizeof(nonce_aes_key));
    RAND_bytes(nonce_iv, sizeof(nonce_iv));

    printf("[LOG] Generated AES Key and IV\n");

    // Encrypt the authentication JSON using AES
    unsigned char encrypted_nonce_payload[2048];
    int encrypted_nonce_payload_len = encrypt_aes((unsigned char *)request_nonce, strlen(request_nonce), encrypted_nonce_payload, nonce_aes_key, nonce_iv);
    free(request_nonce);
    
    if (encrypted_nonce_payload_len < 0) {
        printf("[ERROR] AES encryption failed!\n");
        EVP_PKEY_free(nonce_server_pub_key);
        close(sock);
        return;
    }

    // Encrypt the AES key using RSA
    char *encrypted_nonce_aes_key_base64 = encrypt_rsa(nonce_aes_key, AES_KEY_SIZE, nonce_server_pub_key);
    EVP_PKEY_free(nonce_server_pub_key);
    if (!encrypted_nonce_aes_key_base64) {
        printf("[ERROR] RSA encryption failed!\n");
        close(sock);
        return;
    }

    printf("[LOG] AES Key encrypted with RSA: %s\n", encrypted_nonce_aes_key_base64);

    // Convert encrypted payload & IV to Base64
    char encrypted_nonce_payload_base64[4096];
    EVP_EncodeBlock((unsigned char *)encrypted_nonce_payload_base64, encrypted_nonce_payload, encrypted_nonce_payload_len);

    char nonce_iv_base64[64];
    EVP_EncodeBlock((unsigned char *)nonce_iv_base64, nonce_iv, sizeof(nonce_iv));

    // Construct final encrypted authentication JSON
    cJSON *final_request_nonce_json = cJSON_CreateObject();
    cJSON_AddStringToObject(final_request_nonce_json, "aes_key", encrypted_nonce_aes_key_base64);
    cJSON_AddStringToObject(final_request_nonce_json, "aes_iv", nonce_iv_base64);
    cJSON_AddStringToObject(final_request_nonce_json, "payload", encrypted_nonce_payload_base64);
    
    char *final_request_nonce = cJSON_Print(final_request_nonce_json);
    cJSON_Delete(final_request_nonce_json);
    free(encrypted_nonce_aes_key_base64);

    printf("[LOG] Sending encrypted authentication JSON:\n%s\n", final_request_nonce);
    send(sock, final_request_nonce, strlen(final_request_nonce), 0);
    free(final_request_nonce);

    // Step 2: Receive nonce
    char buffer[1024] = {0};
    int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        printf("[ERROR] No response received or connection closed.\n");
        close(sock);
        return;
    }

    printf("[LOG] Server response: %s\n", buffer);  // Debugging log

    // Parse JSON and extract nonce
    cJSON *json = cJSON_Parse(buffer);
    if (!json) {
        printf("[ERROR] Failed to parse server response!\n");
        close(sock);
        return;
    }

    cJSON *nonce_item = cJSON_GetObjectItem(json, "nonce");
    if (!nonce_item || !cJSON_IsString(nonce_item)) {
        printf("[ERROR] Nonce missing or invalid!\n");
        cJSON_Delete(json);
        close(sock);
        return;
    }

    char nonce[64];
    strncpy(nonce, nonce_item->valuestring, sizeof(nonce) - 1);
    nonce[sizeof(nonce) - 1] = '\0'; // Ensure null termination

    printf("[LOG] Nonce received: %s\n", nonce);
    cJSON_Delete(json);
	close(sock);

    // Step 3: Sign the nonce using private key
	char decoded_nonce[16];
	size_t decoded_nonce_len = base64_decode(nonce, decoded_nonce);
	char *signature_base64 = sign_nonce(decoded_nonce, decoded_nonce_len);

	if (!signature_base64) {
		printf("[ERROR] Signing nonce failed!\n");
		return;
	}

	printf("[LOG] Nonce Signature (Base64): %s\n", signature_base64);

	// Step 4: Reopen auth_socket Connection
    int auth_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (auth_sock < 0) {
        perror("[ERROR] auth_socket creation failed");
        return;
    }

    if (connect(auth_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[ERROR] Connection failed");
        close(auth_sock);
        return;
    }

    // Step 5: Create authentication JSON
    cJSON *auth_json = cJSON_CreateObject();
	cJSON_AddStringToObject(auth_json, "request", "file");
    cJSON_AddStringToObject(auth_json, "nonce", nonce);
    cJSON_AddStringToObject(auth_json, "signature", signature_base64);
    cJSON_AddStringToObject(auth_json, "client_id", CLIENT_ID);

    char *auth_json_string = cJSON_Print(auth_json);
    cJSON_Delete(auth_json);

    printf("[LOG] Authentication JSON:\n%s\n", auth_json_string);

    // Step 6: Load the server's public key for encryption
    EVP_PKEY *server_pub_key = load_public_key("server_pubkey.pem");
    if (!server_pub_key) {
        printf("[ERROR] Failed to load server public key!\n");
        free(auth_json_string);
        close(auth_sock);
        return;
    }

    // Step 7: Generate AES key & IV
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char iv[16];
    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(iv, sizeof(iv));

    printf("[LOG] Generated AES Key and IV\n");

    // Step 8: Encrypt the authentication JSON using AES
    unsigned char encrypted_payload[2048];
    int encrypted_payload_len = encrypt_aes((unsigned char *)auth_json_string, strlen(auth_json_string), encrypted_payload, aes_key, iv);
    free(auth_json_string);
    
    if (encrypted_payload_len < 0) {
        printf("[ERROR] AES encryption failed!\n");
        EVP_PKEY_free(server_pub_key);
        close(auth_sock);
        return;
    }

    // Step 9: Encrypt the AES key using RSA
    char *encrypted_aes_key_base64 = encrypt_rsa(aes_key, AES_KEY_SIZE, server_pub_key);
    EVP_PKEY_free(server_pub_key);
    if (!encrypted_aes_key_base64) {
        printf("[ERROR] RSA encryption failed!\n");
        close(auth_sock);
        return;
    }

    printf("[LOG] AES Key encrypted with RSA: %s\n", encrypted_aes_key_base64);

    // Step 10: Convert encrypted payload & IV to Base64
    char encrypted_payload_base64[4096];
    EVP_EncodeBlock((unsigned char *)encrypted_payload_base64, encrypted_payload, encrypted_payload_len);

    char iv_base64[64];
    EVP_EncodeBlock((unsigned char *)iv_base64, iv, sizeof(iv));

    // Step 11: Construct final encrypted authentication JSON
    cJSON *final_auth_json = cJSON_CreateObject();
    cJSON_AddStringToObject(final_auth_json, "aes_key", encrypted_aes_key_base64);
    cJSON_AddStringToObject(final_auth_json, "aes_iv", iv_base64);
    cJSON_AddStringToObject(final_auth_json, "payload", encrypted_payload_base64);
    
    char *final_auth_json_string = cJSON_Print(final_auth_json);
    cJSON_Delete(final_auth_json);
    free(encrypted_aes_key_base64);

    printf("[LOG] Sending encrypted authentication JSON:\n%s\n", final_auth_json_string);
    send(auth_sock, final_auth_json_string, strlen(final_auth_json_string), 0);
    free(final_auth_json_string);

    // Step 12: Receive authentication response
    memset(buffer, 0, sizeof(buffer));
    bytes_received = recv(auth_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        printf("[ERROR] No response received or connection closed.\n");
        close(auth_sock);
        return;
    }

    printf("[LOG] Authentication response: %s\n", buffer);
    
    if (strstr(buffer, "succÃ¨s")) {
        printf("[LOG] Authentication successful!\n");
    } else {
        printf("[ERROR] Authentication failed!\n");
    }

    close(auth_sock);
}
int main(int argc, char *argv[]) {
	setvbuf(stdout, NULL, _IONBF, 0); // Disable output buffering
    gtk_init(&argc, &argv);

    GtkWidget *window, *vbox, *hbox, *label_ip, *button_connect, *button_refresh, *scrollwin;
    GtkListStore *store;
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;

    // Create main window
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Reception Client");
    gtk_window_set_default_size(GTK_WINDOW(window), 500, 400);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // IP Input Section
    hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    label_ip = gtk_label_new("Server IP:");
    gtk_box_pack_start(GTK_BOX(hbox), label_ip, FALSE, FALSE, 0);

    entry_ip = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(hbox), entry_ip, TRUE, TRUE, 0);

    button_connect = gtk_button_new_with_label("Connect");
    g_signal_connect(button_connect, "clicked", G_CALLBACK(save_ip), NULL);
	g_signal_connect(button_connect, "clicked", G_CALLBACK(authenticate_with_server), NULL);
    gtk_box_pack_start(GTK_BOX(hbox), button_connect, FALSE, FALSE, 0);

    // File List View
    store = gtk_list_store_new(1, G_TYPE_STRING);
    treeview = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
    g_object_unref(store);

    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Received Files", renderer, "text", 0, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);

    scrollwin = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scrollwin), treeview);
    gtk_box_pack_start(GTK_BOX(vbox), scrollwin, TRUE, TRUE, 0);

    // Refresh Button
    button_refresh = gtk_button_new_with_label("Refresh");
    g_signal_connect(button_refresh, "clicked", G_CALLBACK(refresh_file_list), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), button_refresh, FALSE, FALSE, 0);

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}
